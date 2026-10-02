import type {
  AuditEvent,
  SplitChildInput,
  SplitOperation,
  SplitResult,
  SplitThreatRequest,
  Threat,
  ThreatModelState,
} from '@/models/domain'

export const CURRENT_SCHEMA_VERSION = 2

const RELATION_FIELDS = [
  'componentIds',
  'flowIds',
  'externalDependencyIds',
  'attackPathIds',
  'controlIds',
  'riskIds',
] as const

export type RelationField = (typeof RELATION_FIELDS)[number]

export const RELATION_LABELS: Record<RelationField, string> = {
  componentIds: '组件',
  flowIds: '数据流',
  externalDependencyIds: '外部依赖',
  attackPathIds: '攻击路径',
  controlIds: '控制',
  riskIds: '风险',
}

/**
 * 旧数据迁移：
 * - 补齐 splitOperations 集合
 * - 威胁缺来源时按原威胁回填（originThreatId / rootThreatId = 自身 id）
 * - 缓解任务缺来源时按原威胁回填（originThreatId = threatId）
 * - 写入 schemaVersion，迁移发生时补一条审计
 * 多次加载保持幂等：已是新版本的状态原样返回。
 */
export const migrateState = (
  state: ThreatModelState,
  now: string = new Date().toISOString(),
): { state: ThreatModelState; migrated: boolean } => {
  if (state.schemaVersion && state.schemaVersion >= CURRENT_SCHEMA_VERSION) {
    return { state, migrated: false }
  }

  const next: ThreatModelState = structuredClone(state)
  next.splitOperations ??= []

  next.threats = next.threats.map((threat) => ({
    ...threat,
    originThreatId: threat.originThreatId ?? threat.id,
    rootThreatId: threat.rootThreatId ?? threat.id,
  }))

  next.mitigations = next.mitigations.map((task) => ({
    ...task,
    originThreatId: task.originThreatId ?? task.threatId,
  }))

  next.schemaVersion = CURRENT_SCHEMA_VERSION
  next.migratedAt = now

  const event: AuditEvent = {
    id: `aud-migration-${CURRENT_SCHEMA_VERSION}`,
    entityType: 'state',
    entityId: 'schema',
    action: '旧数据迁移',
    actor: '系统',
    createdAt: now,
    detail: `检测到缺少来源标记的旧数据，已按原威胁回填来源并升级到结构 v${CURRENT_SCHEMA_VERSION}。`,
  }
  next.audit = [event, ...next.audit]

  return { state: next, migrated: true }
}

/**
 * 幂等键只由「父威胁 + 修订基线 + 分配方案」的语义内容决定，
 * 与窗口、时间、随机 id 无关，因此两个窗口提交相同拆分只会生成一份结果。
 */
export const buildIdempotencyKey = (request: SplitThreatRequest): string => {
  const normalized = {
    parent: request.parentThreatId,
    baseRevision: request.baseRevision,
    children: request.children.map((child) => ({
      title: child.title.trim(),
      scenario: child.scenario.trim(),
      severity: child.severity,
      componentIds: [...child.componentIds].sort(),
      flowIds: [...child.flowIds].sort(),
      externalDependencyIds: [...child.externalDependencyIds].sort(),
      attackPathIds: [...child.attackPathIds].sort(),
      controlIds: [...child.controlIds].sort(),
      riskIds: [...child.riskIds].sort(),
      mitigationIds: [...child.mitigationIds].sort(),
    })),
  }
  return JSON.stringify(normalized)
}

/** 由幂等键派生确定性的操作与子威胁 id，保证检查点重放不会产生重复实体。 */
const hashKey = (value: string): string => {
  let hash = 5381
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 33) ^ value.charCodeAt(index)
  }
  return (hash >>> 0).toString(36)
}

export const deriveOperationId = (idempotencyKey: string): string =>
  `sop-${hashKey(idempotencyKey)}`

export const deriveChildThreatId = (idempotencyKey: string, index: number): string =>
  `thr-${hashKey(`${idempotencyKey}#child${index}`)}`

export interface ValidationResult {
  valid: boolean
  errors: string[]
}

const collectChildIds = (children: SplitChildInput[], field: RelationField): string[] =>
  children.flatMap((child) => child[field])

const findDuplicates = (ids: string[]): string[] => {
  const seen = new Set<string>()
  const duplicates = new Set<string>()
  ids.forEach((id) => {
    if (seen.has(id)) duplicates.add(id)
    seen.add(id)
  })
  return [...duplicates]
}

/** 校验拆分请求：至少一个场景、同一对象不能归给两个子威胁、所有对象必须来自主威胁。 */
export const validateSplitRequest = (
  state: ThreatModelState,
  request: SplitThreatRequest,
): ValidationResult => {
  const errors: string[] = []
  const parent = state.threats.find((threat) => threat.id === request.parentThreatId)

  if (!parent) {
    return { valid: false, errors: ['主威胁不存在或已被删除。'] }
  }
  if (request.children.length === 0) {
    errors.push('至少需要定义一个拆分子场景。')
  }

  const codeTitles = new Set<string>()
  request.children.forEach((child, index) => {
    const label = `子威胁 ${index + 1}`
    if (!child.title.trim()) errors.push(`${label} 的标题不能为空。`)
    else if (codeTitles.has(child.title.trim())) {
      errors.push(`子威胁标题「${child.title.trim()}」重复。`)
    } else {
      codeTitles.add(child.title.trim())
    }
    if (!child.scenario.trim()) errors.push(`${label} 的场景说明不能为空。`)
  })

  RELATION_FIELDS.forEach((field) => {
    const duplicates = findDuplicates(collectChildIds(request.children, field))
    if (duplicates.length > 0) {
      const names = duplicates
        .map((id) => parentNameForId(state, field, id))
        .join('、')
      errors.push(`${RELATION_LABELS[field]}「${names}」不能同时归给两个子威胁。`)
    }

    const parentIds = new Set(parent[field])
    collectChildIds(request.children, field).forEach((id) => {
      if (!parentIds.has(id)) {
        errors.push(`${RELATION_LABELS[field]}「${parentNameForId(state, field, id)}」不属于主威胁，无法分配。`)
      }
    })
  })

  // 缓解任务同样满足独占：同一条任务不能归给两个子威胁，且必须当前挂在主威胁上。
  const assignedMitigations = request.children.flatMap((child) => child.mitigationIds)
  findDuplicates(assignedMitigations).forEach((id) => {
    errors.push(`缓解任务「${mitigationName(state, id)}」不能同时归给两个子威胁。`)
  })
  const parentMitigationIds = new Set(
    state.mitigations.filter((task) => task.threatId === parent.id).map((task) => task.id),
  )
  assignedMitigations.forEach((id) => {
    if (!parentMitigationIds.has(id)) {
      errors.push(`缓解任务「${mitigationName(state, id)}」不属于主威胁，无法迁移。`)
    }
  })

  return { valid: errors.length === 0, errors }
}

const parentNameForId = (state: ThreatModelState, field: RelationField, id: string): string => {
  switch (field) {
    case 'componentIds':
      return state.components.find((item) => item.id === id)?.name ?? id
    case 'flowIds':
      return state.flows.find((item) => item.id === id)?.name ?? id
    case 'externalDependencyIds':
      return state.dependencies.find((item) => item.id === id)?.name ?? id
    case 'attackPathIds':
      return state.attackPaths.find((item) => item.id === id)?.name ?? id
    case 'controlIds':
      return state.controls.find((item) => item.id === id)?.name ?? id
    case 'riskIds':
      return state.risks.find((item) => item.id === id)?.title ?? id
  }
}

const mitigationName = (state: ThreatModelState, id: string): string =>
  state.mitigations.find((item) => item.id === id)?.title ?? id

export interface ApplySplitInput {
  request: SplitThreatRequest
  idempotencyKey: string
  now: string
  actor: string
}

export interface ApplySplitOutput {
  operation: SplitOperation
  parent: Threat
  children: Threat[]
}

/**
 * 在状态上应用拆分（纯函数，返回新状态）：
 * - 未被任何子威胁选中的关系留在主威胁
 * - 父威胁与子威胁都使用新修订，父威胁原会签因修订号不匹配而失效
 * - 子威胁单独进入会签（reviewStatus = in_review）
 */
export const applySplit = (
  source: ThreatModelState,
  input: ApplySplitInput,
): { state: ThreatModelState; output: ApplySplitOutput } => {
  const validation = validateSplitRequest(source, input.request)
  if (!validation.valid) {
    throw new SplitValidationError(validation.errors)
  }

  const state: ThreatModelState = structuredClone(source)
  const parentIndex = state.threats.findIndex(
    (threat) => threat.id === input.request.parentThreatId,
  )
  const parentSnapshot = structuredClone(state.threats[parentIndex]) as Threat
  const newRevision = state.currentRevision + 1
  const operationId = deriveOperationId(input.idempotencyKey)
  const rootId = parentSnapshot.rootThreatId ?? parentSnapshot.originThreatId ?? parentSnapshot.id

  const childThreats: Threat[] = input.request.children.map((child, index) =>
    buildChildThreat({
      parent: parentSnapshot,
      child,
      index,
      childId: deriveChildThreatId(input.idempotencyKey, index),
      operationId,
      rootId,
      revision: newRevision,
    }),
  )

  // 未选中的关系留在主威胁；其余按场景剔除。
  const remainingParent: Threat = {
    ...parentSnapshot,
    componentIds: retainRelations(parentSnapshot.componentIds, input.request.children, 'componentIds'),
    flowIds: retainRelations(parentSnapshot.flowIds, input.request.children, 'flowIds'),
    externalDependencyIds: retainRelations(
      parentSnapshot.externalDependencyIds,
      input.request.children,
      'externalDependencyIds',
    ),
    attackPathIds: retainRelations(parentSnapshot.attackPathIds, input.request.children, 'attackPathIds'),
    controlIds: retainRelations(parentSnapshot.controlIds, input.request.children, 'controlIds'),
    riskIds: retainRelations(parentSnapshot.riskIds, input.request.children, 'riskIds'),
    status: 'open',
    reviewStatus: 'in_review',
    revision: newRevision,
    parentThreatId: parentSnapshot.parentThreatId,
    rootThreatId: rootId,
    originThreatId: parentSnapshot.originThreatId ?? parentSnapshot.id,
    splitGroupId: operationId,
  }
  state.threats[parentIndex] = remainingParent

  // 子威胁紧跟主威胁，便于谱系阅读。
  state.threats.splice(parentIndex + 1, 0, ...childThreats)

  // 迁移被分配的缓解任务；未选中的任务留在主威胁。
  const assignedMitigationIds = input.request.children.flatMap((child) => child.mitigationIds)
  const assignedSet = new Set(assignedMitigationIds)
  const mitigationTarget = new Map<string, string>()
  childThreats.forEach((child, index) => {
    input.request.children[index].mitigationIds.forEach((taskId) => {
      mitigationTarget.set(taskId, child.id)
    })
  })
  state.mitigations = state.mitigations.map((task) => {
    const targetId = mitigationTarget.get(task.id)
    if (!targetId) return task
    return { ...task, threatId: targetId, originThreatId: parentSnapshot.id }
  })

  const operation: SplitOperation = {
    id: operationId,
    idempotencyKey: input.idempotencyKey,
    parentThreatId: parentSnapshot.id,
    parentRevisionBefore: parentSnapshot.revision,
    parentSnapshot,
    children: childThreats,
    assignedMitigationIds,
    status: 'committed',
    actor: input.actor,
    createdAt: input.now,
  }
  state.splitOperations.unshift(operation)
  state.currentRevision = newRevision

  state.audit.unshift({
    id: `aud-${operationId}`,
    entityType: 'split',
    entityId: operationId,
    action: '拆分威胁',
    actor: input.actor,
    createdAt: input.now,
    detail: `主威胁 ${parentSnapshot.code} 拆分为 ${childThreats.length} 个子场景；原会签已按修订失效，子威胁单独进入会签；${
      assignedSet.size
    } 条缓解任务随场景迁移，未选中关系保留在主威胁。`,
  })

  return {
    state,
    output: { operation, parent: remainingParent, children: childThreats },
  }
}

const retainRelations = (
  parentIds: string[],
  children: SplitChildInput[],
  field: RelationField,
): string[] => {
  const moved = new Set(collectChildIds(children, field))
  return parentIds.filter((id) => !moved.has(id))
}

const buildChildThreat = (params: {
  parent: Threat
  child: SplitChildInput
  index: number
  childId: string
  operationId: string
  rootId: string
  revision: number
}): Threat => {
  const { parent, child, childId, operationId, rootId, revision } = params
  return {
    id: childId,
    code: `${parent.code}.${params.index + 1}`,
    title: child.title.trim(),
    category: parent.category,
    description: `由 ${parent.code} 拆分：${child.scenario.trim()}`,
    severity: child.severity,
    status: 'open',
    componentIds: [...child.componentIds],
    flowIds: [...child.flowIds],
    externalDependencyIds: [...child.externalDependencyIds],
    attackPathIds: [...child.attackPathIds],
    controlIds: [...child.controlIds],
    riskIds: [...child.riskIds],
    reviewStatus: 'in_review',
    revision,
    parentThreatId: parent.id,
    rootThreatId: rootId,
    originThreatId: parent.originThreatId ?? parent.id,
    splitGroupId: operationId,
  }
}

export class SplitValidationError extends Error {
  errors: string[]

  constructor(errors: string[]) {
    super(errors.join('；'))
    this.name = 'SplitValidationError'
    this.errors = errors
  }
}

export class SplitConflictError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SplitConflictError'
  }
}

/** 子威胁已有自己的会签意见后，撤销会让这些意见失效，需要显式确认。 */
export const undoBlockers = (state: ThreatModelState, operationId: string): string[] => {
  const operation = state.splitOperations.find((item) => item.id === operationId)
  if (!operation) return ['拆分操作不存在。']
  if (operation.status === 'undone') return ['该拆分已经撤销。']

  const blockers: string[] = []
  const childIds = new Set(operation.children.map((child) => child.id))
  const liveChildIds = new Set(
    state.threats.filter((threat) => childIds.has(threat.id)).map((threat) => threat.id),
  )
  if (liveChildIds.size !== operation.children.length) {
    blockers.push('部分子威胁已被删除，无法安全撤销，请先人工核对谱系。')
  }

  const childDecisions = state.decisions.filter(
    (decision) => childIds.has(decision.threatId) && liveChildIds.has(decision.threatId),
  )
  const liveChildRevisions = new Map(
    operation.children
      .map((stored) => state.threats.find((threat) => threat.id === stored.id))
      .filter((threat): threat is Threat => Boolean(threat))
      .map((threat) => [threat.id, threat.revision] as const),
  )
  const currentDecisions = childDecisions.filter(
    (decision) => liveChildRevisions.get(decision.threatId) === decision.revision,
  )
  if (currentDecisions.length > 0) {
    blockers.push(`子威胁已收到 ${currentDecisions.length} 条会签意见，撤销将使其失效。`)
  }

  return blockers
}

/**
 * 撤销拆分（纯函数）：
 * - 主威胁恢复拆分前快照（含原关系、原修订、原会签重新可见）
 * - 迁移走的缓解任务回到主威胁
 * - 删除子威胁及其全部会签意见
 * - 操作保留为 undone，谱系可追溯
 */
export const undoSplit = (
  source: ThreatModelState,
  operationId: string,
  options: { force?: boolean; now: string; actor: string },
): ThreatModelState => {
  const blockers = undoBlockers(source, operationId)
  const hardBlockers = blockers.filter((message) => !message.includes('会签意见'))
  if (hardBlockers.length > 0) throw new SplitValidationError(hardBlockers)
  if (blockers.length > 0 && !options.force) {
    throw new SplitConflictError(blockers.join('；'))
  }

  const state: ThreatModelState = structuredClone(source)
  const operationIndex = state.splitOperations.findIndex((item) => item.id === operationId)
  const operation = state.splitOperations[operationIndex]

  state.threats = state.threats.filter(
    (threat) => !operation.children.some((child) => child.id === threat.id),
  )

  const parentIndex = state.threats.findIndex((threat) => threat.id === operation.parentThreatId)
  if (parentIndex >= 0) {
    state.threats[parentIndex] = structuredClone(operation.parentSnapshot) as Threat
  }

  const childIds = new Set(operation.children.map((child) => child.id))
  state.mitigations = state.mitigations.map((task) => {
    if (!childIds.has(task.threatId)) return task
    return { ...task, threatId: operation.parentThreatId, originThreatId: operation.parentThreatId }
  })

  state.decisions = state.decisions.filter((decision) => !childIds.has(decision.threatId))

  state.splitOperations[operationIndex] = {
    ...operation,
    status: 'undone',
    undoneAt: options.now,
  }

  state.audit.unshift({
    id: `aud-undo-${operationId}`,
    entityType: 'split',
    entityId: operationId,
    action: '撤销拆分',
    actor: options.actor,
    createdAt: options.now,
    detail: `主威胁 ${operation.parentSnapshot.code} 已恢复拆分前状态，${operation.children.length} 个子威胁及其会签已移除，原会签重新生效。`,
  })

  return state
}

/** 从检查点重放时调用：已落库则幂等返回同一份结果。 */
export const findCommittedByKey = (
  state: ThreatModelState,
  idempotencyKey: string,
): SplitOperation | undefined =>
  state.splitOperations.find(
    (operation) => operation.idempotencyKey === idempotencyKey && operation.status === 'committed',
  )

/** 组装服务层返回结果，标注是否命中并发去重。 */
export const toSplitResult = (
  operation: SplitOperation,
  deduplicated: boolean,
): SplitResult => ({ operation, deduplicated })

/** 会签中心使用：父威胁原修订上的意见在拆分后不再计入进度。 */
export const activeThreatRevision = (state: ThreatModelState, threatId: string): number =>
  state.threats.find((threat) => threat.id === threatId)?.revision ?? 0
