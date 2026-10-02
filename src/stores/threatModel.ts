import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type {
  ActorRole,
  AuditEvent,
  DecisionType,
  Threat,
  ThreatModelState,
  VersionSnapshot,
} from '@/models/domain'
import {
  createId,
  loadStateWithMeta,
  resetState,
  saveState,
  subscribeToExternalChanges,
} from '@/services/repository'
import {
  dashboardMetrics,
  decisionsForThreat,
  getValidationIssues,
  reviewProgress,
} from '@/services/selectors'
import { undoSplit, undoBlockers } from '@/services/splitEngine'
import {
  executeSplit,
  pendingCheckpointCount,
  recoverPendingSplits,
  type RecoveryReport,
} from '@/services/splitService'
import {
  browserKV,
  isFailureInjectionEnabled,
  listCheckpoints,
  markCheckpointUndone,
  setFailureInjection,
} from '@/services/splitLedger'
import type { SplitResult, SplitThreatRequest } from '@/models/domain'

type CollectionKey =
  | 'zones'
  | 'components'
  | 'dependencies'
  | 'flows'
  | 'controls'
  | 'evidence'
  | 'threats'
  | 'attackPaths'
  | 'risks'
  | 'mitigations'
  | 'decisions'

interface IdentifiedEntity {
  id: string
}

export const useThreatModelStore = defineStore('threat-model', () => {
  const initial = loadStateWithMeta()
  const data = ref<ThreatModelState>(initial.state)
  const lastSavedAt = ref(new Date().toISOString())
  const lastMigrationAt = ref(initial.migrated ? initial.state.migratedAt ?? null : null)
  const startupRecovery = ref<RecoveryReport | null>(null)
  const failureInjectionOn = ref(isFailureInjectionEnabled(browserKV))

  // 启动时从检查点恢复上次未完成的拆分（跨窗口提交后本窗口崩溃也可自愈）。
  const pendingAtBoot = pendingCheckpointCount()
  if (pendingAtBoot > 0) {
    const recovery = recoverPendingSplits()
    data.value = recovery.state
    startupRecovery.value = recovery.report
  }

  // 另一个窗口写入后，本窗口回读同一份状态，避免覆盖并发结果。
  subscribeToExternalChanges(() => {
    const reloaded = loadStateWithMeta()
    data.value = reloaded.state
  })

  const metrics = computed(() => dashboardMetrics(data.value))
  const issues = computed(() => getValidationIssues(data.value))
  const pendingReviews = computed(() =>
    data.value.threats.filter((threat) => threat.reviewStatus === 'in_review'),
  )

  const persist = (): void => {
    saveState(data.value)
    lastSavedAt.value = new Date().toISOString()
  }

  const appendAudit = (
    entityType: string,
    entityId: string,
    action: string,
    detail: string,
  ): void => {
    const event: AuditEvent = {
      id: createId('aud'),
      entityType,
      entityId,
      action,
      actor: '当前用户',
      createdAt: new Date().toISOString(),
      detail,
    }
    data.value.audit.unshift(event)
  }

  const saveEntity = (collection: CollectionKey, item: IdentifiedEntity): void => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === item.id)
    if (index >= 0) {
      target[index] = item
    } else {
      target.unshift(item)
    }
    const label = 'name' in item && typeof item.name === 'string' ? item.name : item.id
    appendAudit(collection, item.id, index >= 0 ? '更新' : '新增', `${label} 已保存`)
    persist()
  }

  const removeEntity = (collection: CollectionKey, id: string): void => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === id)
    if (index < 0) return
    target.splice(index, 1)
    appendAudit(collection, id, '删除', '记录已从当前版本移除')
    persist()
  }

  const updateBoundary = (boundary: ThreatModelState['boundary']): void => {
    data.value.boundary = boundary
    appendAudit('boundary', boundary.id, '更新', `${boundary.name} 的系统边界已更新`)
    persist()
  }

  const saveThreat = (threat: Threat): void => {
    saveEntity('threats', threat)
  }

  const createVersion = (
    label: string,
    notes: string,
    affectedThreatIds: string[],
  ): VersionSnapshot => {
    const revision = data.value.currentRevision + 1
    const snapshot: VersionSnapshot = {
      id: createId('ver'),
      revision,
      label,
      createdAt: new Date().toISOString(),
      author: '当前用户',
      notes,
      threatIds: data.value.threats.map((threat) => threat.id),
      componentIds: data.value.components.map((component) => component.id),
      flowIds: data.value.flows.map((flow) => flow.id),
      controlIds: data.value.controls.map((control) => control.id),
      riskIds: data.value.risks.map((risk) => risk.id),
      affectedThreatIds,
    }
    data.value.currentRevision = revision
    data.value.versions.unshift(snapshot)
    data.value.threats = data.value.threats.map((threat) => {
      if (!affectedThreatIds.includes(threat.id)) {
        return { ...threat, revision }
      }
      return { ...threat, revision, reviewStatus: 'in_review' }
    })
    appendAudit(
      'version',
      snapshot.id,
      '创建版本',
      `${label} 已创建，${affectedThreatIds.length} 条威胁进入重新审核`,
    )
    persist()
    return snapshot
  }

  const submitDecision = (
    threatId: string,
    role: ActorRole,
    decision: DecisionType,
    actor: string,
    comment: string,
  ): void => {
    const threat = data.value.threats.find((item) => item.id === threatId)
    if (!threat) return
    data.value.decisions = data.value.decisions.filter(
      (item) => !(item.threatId === threatId && item.role === role && item.revision === threat.revision),
    )
    data.value.decisions.unshift({
      id: createId('dec'),
      threatId,
      role,
      actor,
      decision,
      comment,
      createdAt: new Date().toISOString(),
      revision: threat.revision,
    })

    const currentDecisions = decisionsForThreat(data.value.decisions, threatId, threat.revision)
    const requiredRoles: ActorRole[] = ['development', 'security', 'business']
    const allSubmitted = requiredRoles.every((requiredRole) =>
      currentDecisions.some((item) => item.role === requiredRole),
    )
    if (currentDecisions.some((item) => item.decision === 'rejected')) {
      threat.reviewStatus = 'rejected'
    } else if (
      allSubmitted &&
      currentDecisions.every((item) => item.decision === 'approved')
    ) {
      threat.reviewStatus = 'approved'
    } else {
      threat.reviewStatus = 'in_review'
    }

    const decisionLabel: Record<DecisionType, string> = {
      accept: '接受',
      degrade: '降级',
      evidence_required: '要求补证',
      approved: '会签通过',
      rejected: '驳回',
    }
    appendAudit(
      'threat',
      threatId,
      decisionLabel[decision],
      `${actor}（${role}）提交会签意见`,
    )
    persist()
  }

  const updateMitigationStatus = (
    taskId: string,
    status: ThreatModelState['mitigations'][number]['status'],
  ): void => {
    const task = data.value.mitigations.find((item) => item.id === taskId)
    if (!task) return
    task.status = status
    appendAudit('mitigation', task.id, '更新状态', `${task.title} 更新为 ${status}`)
    persist()
  }

  const acceptRisk = (riskId: string, expiresAt: string, condition: string): void => {
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    risk.status = 'accepted'
    risk.acceptanceExpiresAt = expiresAt
    risk.acceptanceCondition = condition
    appendAudit('risk', risk.id, '接受风险', `接受有效至 ${expiresAt}：${condition}`)
    persist()
  }

  const closeRisk = (riskId: string): void => {
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    risk.status = 'closed'
    appendAudit('risk', risk.id, '关闭风险', '风险已关闭并从开放风险中移除')
    persist()
  }

  /**
   * 提交父子拆分。
   * 账本协调 + 确定性 id：另一个窗口提交了相同拆分时返回 deduplicated=true。
   * 写入失败时抛 SplitSubmissionError，调用方提示从检查点恢复。
   */
  const submitSplit = (request: SplitThreatRequest): SplitResult => {
    const outcome = executeSplit(data.value, request)
    data.value = outcome.state
    lastSavedAt.value = new Date().toISOString()
    return outcome.result
  }

  /**
   * 模拟两个窗口同时提交同一份拆分：
   * 第二次提交必须命中去重，最终只生成一份结果。
   */
  const simulateConcurrentSplit = (
    request: SplitThreatRequest,
  ): { first: SplitResult; second: SplitResult } => {
    const firstOutcome = executeSplit(data.value, request)
    data.value = firstOutcome.state
    // 第二个窗口：不使用第一个窗口的内存状态，而是像真实窗口一样回读持久化状态。
    const reloaded = loadStateWithMeta().state
    const secondOutcome = executeSplit(reloaded, request)
    data.value = secondOutcome.state
    lastSavedAt.value = new Date().toISOString()
    return { first: firstOutcome.result, second: secondOutcome.result }
  }

  /** 手动触发检查点恢复（启动时已自动执行一次）。 */
  const recoverSplits = (): RecoveryReport => {
    const outcome = recoverPendingSplits()
    data.value = outcome.state
    lastSavedAt.value = new Date().toISOString()
    return outcome.report
  }

  const pendingCheckpoints = computed(() => listCheckpoints())

  const toggleFailureInjection = (enabled: boolean): void => {
    setFailureInjection(enabled, browserKV)
    failureInjectionOn.value = enabled
  }

  /** 撤销拆分；子威胁已有会签时需要 force=true。 */
  const undoThreatSplit = (operationId: string, force = false): void => {
    const operation = data.value.splitOperations.find((item) => item.id === operationId)
    const next = undoSplit(data.value, operationId, {
      force,
      now: new Date().toISOString(),
      actor: '当前用户',
    })
    data.value = next
    persist()
    if (operation) markCheckpointUndone(operation.idempotencyKey, browserKV)
  }

  const splitUndoBlockers = (operationId: string): string[] =>
    undoBlockers(data.value, operationId)

  const splitOperationsForThreat = (threatId: string) =>
    data.value.splitOperations.filter(
      (operation) =>
        operation.parentThreatId === threatId ||
        operation.children.some((child) => child.id === threatId || child.parentThreatId === threatId),
    )

  const resetDemo = (): void => {
    data.value = resetState()
    lastSavedAt.value = new Date().toISOString()
    startupRecovery.value = null
  }

  const exportReport = (): string => {
    const lines = [
      `# ${data.value.boundary.name} 威胁建模报告`,
      '',
      `生成时间：${new Date().toISOString()}`,
      `当前版本：v1.${data.value.currentRevision}`,
      `建模范围：${data.value.boundary.inScope}`,
      `排除范围：${data.value.boundary.outOfScope}`,
      '',
      '## 风险摘要',
      `- 资产与组件：${data.value.components.length}`,
      `- 威胁：${data.value.threats.length}`,
      `- 开放关键威胁：${metrics.value.critical}`,
      `- 威胁覆盖率：${metrics.value.coverage}%`,
      `- 待处理校验问题：${issues.value.length}`,
      '',
      '## 威胁清单',
      ...data.value.threats.map(
        (threat) =>
          `- ${threat.code} [${threat.severity}/${threat.reviewStatus}] ${threat.title}：${threat.description}`,
      ),
      '',
      '## 风险接受',
      ...data.value.risks
        .filter((risk) => risk.status === 'accepted')
        .map(
          (risk) =>
            `- ${risk.code} ${risk.title}，有效至 ${risk.acceptanceExpiresAt ?? '未设置'}，条件：${risk.acceptanceCondition ?? '未填写'}`,
        ),
      '',
      '## 校验问题',
      ...issues.value.map((issue) => `- [${issue.severity}] ${issue.title}：${issue.detail}`),
      '',
      '## 会签记录',
      ...data.value.decisions.map(
        (decision) =>
          `- ${decision.createdAt} ${decision.actor}（${decision.role}）${decision.decision}：${decision.comment}`,
      ),
      '',
      '## 威胁拆分谱系',
      ...(data.value.splitOperations.length === 0
        ? ['- 暂无拆分记录。']
        : data.value.splitOperations.map((operation) => {
            const statusLabel = operation.status === 'committed' ? '生效中' : '已撤销'
            const children = operation.children
              .map((child) => `${child.code} ${child.title}`)
              .join('；')
            return `- [${statusLabel}] ${operation.parentSnapshot.code} → ${children}（操作 ${operation.id}，${operation.createdAt}）`
          })),
    ]
    return lines.join('\n')
  }

  return {
    data,
    lastSavedAt,
    lastMigrationAt,
    startupRecovery,
    failureInjectionOn,
    pendingCheckpoints,
    metrics,
    issues,
    pendingReviews,
    saveEntity,
    removeEntity,
    updateBoundary,
    saveThreat,
    createVersion,
    submitDecision,
    updateMitigationStatus,
    acceptRisk,
    closeRisk,
    submitSplit,
    simulateConcurrentSplit,
    recoverSplits,
    toggleFailureInjection,
    undoThreatSplit,
    splitUndoBlockers,
    splitOperationsForThreat,
    resetDemo,
    exportReport,
    reviewProgress,
  }
})
