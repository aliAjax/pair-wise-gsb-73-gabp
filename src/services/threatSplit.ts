import type {
  AuditEvent,
  ReviewStatus,
  Severity,
  SplitOperation,
  SplitOperationChild,
  Threat,
  ThreatModelState,
  VersionSnapshot,
} from '@/models/domain'
import { createId } from '@/services/repository'

export type ThreatRelationType =
  | 'componentIds'
  | 'flowIds'
  | 'externalDependencyIds'
  | 'attackPathIds'
  | 'controlIds'
  | 'riskIds'
  | 'mitigationIds'

export interface SplitThreatInput {
  code: string
  title: string
  description: string
  severity: Severity
  assignments: Record<ThreatRelationType, string[]>
}

export interface SplitThreatsRequest {
  parentThreatId: string
  children: SplitThreatInput[]
}

export interface SplitThreatsResult {
  duplicated: boolean
  operation: SplitOperation
  parent: Threat
  children: Threat[]
}

const RELATION_TYPES: ThreatRelationType[] = [
  'componentIds',
  'flowIds',
  'externalDependencyIds',
  'attackPathIds',
  'controlIds',
  'riskIds',
  'mitigationIds',
]

const THREAT_RELATION_TYPES = RELATION_TYPES.filter(
  (type): type is Exclude<ThreatRelationType, 'mitigationIds'> => type !== 'mitigationIds',
)

const relationTypeLabel = (type: ThreatRelationType): string =>
  ({
    componentIds: '组件',
    flowIds: '数据流',
    externalDependencyIds: '外部依赖',
    attackPathIds: '攻击路径',
    controlIds: '控制',
    riskIds: '风险',
    mitigationIds: '缓解任务',
  })[type]

const uniqueSorted = (values: string[]): string[] => [...new Set(values)].sort()

const stableStringify = (value: unknown): string =>
  JSON.stringify(value, (_key, current) => {
    if (Array.isArray(current)) return current
    if (current && typeof current === 'object') {
      return Object.fromEntries(
        Object.entries(current as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)),
      )
    }
    return current
  })

export const getSplitRequestKey = (request: SplitThreatsRequest): string => {
  const normalized = {
    parentThreatId: request.parentThreatId,
    children: request.children.map((child) => ({
      code: child.code.trim(),
      title: child.title.trim(),
      description: child.description.trim(),
      severity: child.severity,
      assignments: Object.fromEntries(
        RELATION_TYPES.map((type) => [type, uniqueSorted(child.assignments[type] ?? [])]),
      ),
    })),
  }
  return `split:${stableStringify(normalized)}`
}

const activeOperations = (state: ThreatModelState): SplitOperation[] =>
  state.splitOperations.filter((operation) => !operation.revokedAt)

const assertNoDuplicateAssignments = (request: SplitThreatsRequest): void => {
  const seen = new Map<string, string>()
  request.children.forEach((child, childIndex) => {
    RELATION_TYPES.forEach((type) => {
      uniqueSorted(child.assignments[type] ?? []).forEach((id) => {
        const key = `${type}:${id}`
        const previousIndex = seen.get(key)
        if (previousIndex !== undefined) {
          throw new Error(
            `${type} 中的对象 ${id} 已分配给子场景 ${previousIndex + 1}，不能同时归给子场景 ${childIndex + 1}`,
          )
        }
        seen.set(key, String(childIndex))
      })
    })
  })
}

export const validateSplitRequest = (
  state: ThreatModelState,
  request: SplitThreatsRequest,
): Threat => {
  const parent = state.threats.find((threat) => threat.id === request.parentThreatId)
  if (!parent) throw new Error('未找到需要拆分的主威胁')
  if (parent.parentThreatId) throw new Error('子威胁不能继续拆分')
  if (parent.splitParent) throw new Error('该主威胁已有未撤销的拆分')
  if (activeOperations(state).some((operation) => operation.parentThreatId === parent.id)) {
    throw new Error('该主威胁已有正在会签的子威胁，请先撤销现有拆分')
  }
  if (request.children.length === 0) throw new Error('至少需要配置一个子威胁场景')

  assertNoDuplicateAssignments(request)

  const validRelations: Record<Exclude<ThreatRelationType, 'mitigationIds'>, Set<string>> = {
    componentIds: new Set(state.components.map((item) => item.id)),
    flowIds: new Set(state.flows.map((item) => item.id)),
    externalDependencyIds: new Set(state.dependencies.map((item) => item.id)),
    attackPathIds: new Set(state.attackPaths.map((item) => item.id)),
    controlIds: new Set(state.controls.map((item) => item.id)),
    riskIds: new Set(state.risks.map((item) => item.id)),
  }

  const parentMitigationIds = new Set(
    state.mitigations.filter((task) => task.threatId === parent.id).map((task) => task.id),
  )
  request.children.forEach((child, index) => {
    if (!child.code.trim() || !child.title.trim() || !child.description.trim()) {
      throw new Error(`子场景 ${index + 1} 的编号、标题和场景描述不能为空`)
    }
    if (state.threats.some((threat) => threat.code === child.code.trim())) {
      throw new Error(`威胁编号 ${child.code} 已存在`)
    }
    if (child.assignments.componentIds.length === 0 && child.assignments.flowIds.length === 0) {
      throw new Error(`子场景 ${index + 1} 至少需要关联一个组件或数据流`)
    }
    THREAT_RELATION_TYPES.forEach((type) => {
      const values = child.assignments[type] ?? []
      if (new Set(values).size !== values.length) {
        throw new Error(`子场景 ${index + 1} 的${relationTypeLabel(type)}不能重复选择`)
      }
      const unknownId = uniqueSorted(values).find(
        (id) => !validRelations[type].has(id),
      )
      if (unknownId) throw new Error(`${relationTypeLabel(type)} ${unknownId} 不存在`)
      const outsideParent = uniqueSorted(child.assignments[type] ?? []).find(
        (id) => !parent[type].includes(id),
      )
      if (outsideParent) {
        throw new Error(`${relationTypeLabel(type)} ${outsideParent} 不属于主威胁，不能拆分`)
      }
    })
    const mitigationValues = child.assignments.mitigationIds ?? []
    if (new Set(mitigationValues).size !== mitigationValues.length) {
      throw new Error(`子场景 ${index + 1} 的缓解任务不能重复选择`)
    }
    const unknownMitigation = mitigationValues.find((id) => !parentMitigationIds.has(id))
    if (unknownMitigation) {
      throw new Error(`缓解措施 ${unknownMitigation} 不属于主威胁，不能拆分到子场景`)
    }
  })

  return parent
}

const createAuditEvent = (
  entityType: string,
  entityId: string,
  action: string,
  detail: string,
): AuditEvent => ({
  id: createId('aud'),
  entityType,
  entityId,
  action,
  actor: '当前用户',
  createdAt: new Date().toISOString(),
  detail,
})

export const applySplitThreats = (
  sourceState: ThreatModelState,
  request: SplitThreatsRequest,
): { state: ThreatModelState; result: SplitThreatsResult } => {
  const state: ThreatModelState = structuredClone(sourceState)
  const requestKey = getSplitRequestKey(request)
  const existing = state.splitOperations.find((operation) => operation.requestKey === requestKey)
  const parentIndex = state.threats.findIndex((threat) => threat.id === request.parentThreatId)
  if (!existing && parentIndex < 0) throw new Error('未找到需要拆分的主威胁')

  if (existing && !existing.revokedAt) {
    const existingParent = state.threats.find((threat) => threat.id === existing.parentThreatId)
    const existingChildren = state.threats.filter((threat) => existing.childThreatIds.includes(threat.id))
    if (existingParent && existingChildren.length === existing.childThreatIds.length) {
      return {
        state: sourceState,
        result: {
          duplicated: true,
          operation: existing,
          parent: existingParent,
          children: existingChildren,
        },
      }
    }
  }

  const originalParent = validateSplitRequest(state, request)
  const revision = state.currentRevision + 1
  const operationId = createId('split')
  const operationChildren: SplitOperationChild[] = []
  const childThreats: Threat[] = []

  const nextParent: Threat = {
    ...originalParent,
    splitParent: true,
    splitOperationId: operationId,
    revision,
    reviewStatus: 'draft',
  }

  request.children.forEach((input) => {
    const id = createId('thr')
    const relationArrays = Object.fromEntries(
      THREAT_RELATION_TYPES.map((type) => [type, uniqueSorted(input.assignments[type] ?? [])]),
    ) as Pick<Threat, Exclude<ThreatRelationType, 'mitigationIds'>>

    const child: Threat = {
      id,
      code: input.code.trim(),
      title: input.title.trim(),
      category: originalParent.category,
      description: input.description.trim(),
      severity: input.severity,
      status: originalParent.status,
      ...relationArrays,
      reviewStatus: 'in_review',
      revision,
      parentThreatId: originalParent.id,
      splitOperationId: operationId,
    }
    childThreats.push(child)
    operationChildren.push({
      threatId: id,
      code: child.code,
      title: child.title,
      description: child.description,
      severity: child.severity,
      ...relationArrays,
      mitigationIds: uniqueSorted(input.assignments.mitigationIds ?? []),
    })

    THREAT_RELATION_TYPES.forEach((type) => {
      nextParent[type] = nextParent[type].filter((idInParent) => !child[type].includes(idInParent))
    })
  })

  const assignedMitigationIds = new Set(
    request.children.flatMap((child) => child.assignments.mitigationIds ?? []),
  )
  const migratedMitigationIds = uniqueSorted([...assignedMitigationIds])

  state.mitigations.forEach((task) => {
    if (task.threatId !== originalParent.id || !assignedMitigationIds.has(task.id)) return
    const ownerChild = request.children.find((child) =>
      child.assignments.mitigationIds.includes(task.id),
    )
    if (!ownerChild) return
    const index = request.children.indexOf(ownerChild)
    task.threatId = childThreats[index].id
    task.sourceThreatId = originalParent.id
    task.splitOperationId = operationId
  })

  const previousVersion = state.versions[0]
  const snapshot: VersionSnapshot = {
    id: createId('ver'),
    revision,
    label: `v1.${revision} 威胁拆分`,
    createdAt: new Date().toISOString(),
    author: '当前用户',
    notes: `${originalParent.code} 拆分为 ${childThreats.length} 个场景，原会签失效并由子威胁单独会签。`,
    threatIds: state.threats.map((threat) => threat.id).concat(childThreats.map((threat) => threat.id)),
    componentIds: state.components.map((component) => component.id),
    flowIds: state.flows.map((flow) => flow.id),
    controlIds: state.controls.map((control) => control.id),
    riskIds: state.risks.map((risk) => risk.id),
    affectedThreatIds: childThreats.map((threat) => threat.id),
  }

  const operation: SplitOperation = {
    id: operationId,
    requestKey,
    parentThreatId: originalParent.id,
    childThreatIds: childThreats.map((threat) => threat.id),
    migratedMitigationIds,
    children: operationChildren,
    createdAt: new Date().toISOString(),
    previousParentReviewStatus: originalParent.reviewStatus,
    previousParentRevision: originalParent.revision,
    versionId: snapshot.id,
    previousVersionId: previousVersion?.id,
  }

  state.threats[parentIndex] = nextParent
  state.threats.unshift(...childThreats)
  state.splitOperations.unshift(operation)
  state.currentRevision = revision
  state.versions.unshift(snapshot)
  state.audit.unshift(
    createAuditEvent(
      'split',
      operationId,
      '威胁拆分',
      `${originalParent.code} 拆分为 ${childThreats.length} 个子场景；原会签失效，子威胁单独会签。`,
    ),
    createAuditEvent(
      'threat',
      originalParent.id,
      '原会签失效',
      `拆分后未分配关系保留在主威胁，主威胁暂不进入本轮会签。`,
    ),
  )

  return {
    state,
    result: { duplicated: false, operation, parent: nextParent, children: childThreats },
  }
}

const uniqueById = <T extends { id: string }>(items: T[]): T[] => {
  const map = new Map<string, T>()
  items.forEach((item) => map.set(item.id, item))
  return [...map.values()]
}

export const revokeSplitThreats = (sourceState: ThreatModelState, operationId: string): ThreatModelState => {
  const state = structuredClone(sourceState)
  const operation = state.splitOperations.find((item) => item.id === operationId)
  if (!operation) throw new Error('未找到拆分记录')
  if (operation.revokedAt) throw new Error('该拆分已经撤销')
  if (state.versions[0]?.id !== operation.versionId) {
    throw new Error('拆分后已产生新版本，请先处理后续版本再撤销')
  }

  const parent = state.threats.find((threat) => threat.id === operation.parentThreatId)
  if (!parent) throw new Error('未找到主威胁')
  const childIds = new Set(operation.childThreatIds)

  state.threats = state.threats.filter((threat) => !childIds.has(threat.id))
  state.decisions = state.decisions.filter((decision) => !childIds.has(decision.threatId))

  THREAT_RELATION_TYPES.forEach((type) => {
    parent[type] = uniqueById([
      ...parent[type].map((id) => ({ id })),
      ...(operation.children ?? []).flatMap((child) => child[type].map((id) => ({ id }))),
    ]).map((item) => item.id)
  })

  parent.reviewStatus = operation.previousParentReviewStatus as ReviewStatus
  parent.revision = operation.previousParentRevision
  parent.splitParent = false
  delete parent.splitOperationId

  const migratedIds = new Set(operation.migratedMitigationIds)
  state.mitigations.forEach((task) => {
    if (task.threatId === parent.id && migratedIds.has(task.id)) {
      task.threatId = parent.id
    }
    if (task.splitOperationId === operation.id) {
      task.threatId = parent.id
      delete task.splitOperationId
      if (task.sourceThreatId === parent.id) delete task.sourceThreatId
    }
  })

  operation.revokedAt = new Date().toISOString()
  state.versions = state.versions.filter((version) => version.id !== operation.versionId)
  state.currentRevision = operation.previousParentRevision
  state.audit.unshift(
    createAuditEvent(
      'split',
      operation.id,
      '撤销拆分',
      `${parent.code} 的子威胁已撤回，关系和会签前状态已回填到主威胁。`,
    ),
  )

  return state
}
