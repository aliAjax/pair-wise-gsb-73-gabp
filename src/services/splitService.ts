import type { SplitThreatRequest, ThreatModelState, SplitResult } from '@/models/domain'
import { loadStateWithMeta, saveState, StateWriteError } from '@/services/repository'
import {
  applySplit,
  buildIdempotencyKey,
  deriveOperationId,
  findCommittedByKey,
  SplitConflictError,
  toSplitResult,
  validateSplitRequest,
} from '@/services/splitEngine'
import {
  claimCheckpoint,
  listCheckpoints,
  markCheckpointCommitted,
  recordCheckpointFailure,
  removeCheckpoint,
  type SplitCheckpoint,
} from '@/services/splitLedger'

export { SplitConflictError, SplitValidationError } from '@/services/splitEngine'

export class SplitSubmissionError extends Error {
  checkpointId: string

  constructor(message: string, checkpointId: string) {
    super(message)
    this.name = 'SplitSubmissionError'
    this.checkpointId = checkpointId
  }
}

const nowIso = (): string => new Date().toISOString()

/**
 * 执行一次拆分提交。source 是该「窗口」看到的当前状态。
 * 账本是跨窗口共享的权威协调者：
 * - 抢到检查点的窗口应用拆分并写状态；
 * - 没抢到的窗口回读已持久化的状态，复用同一份结果（dedup=true），
 *   或从检查点确定性重放，保证两个窗口同时提交只生成一份结果。
 */
export const executeSplit = (
  source: ThreatModelState,
  request: SplitThreatRequest,
): { state: ThreatModelState; result: SplitResult } => {
  const idempotencyKey = buildIdempotencyKey(request)

  const claimed = claimCheckpoint({
    id: deriveOperationId(idempotencyKey),
    idempotencyKey,
    request,
    status: 'prepared',
    createdAt: nowIso(),
    failureCount: 0,
  })

  // 另一个窗口已经建立了相同拆分的检查点：以它持久化的状态为准。
  if (claimed.currentLostRace) {
    const persisted = loadStateWithMeta().state
    const committed = findCommittedByKey(persisted, idempotencyKey)
    if (committed) {
      return { state: persisted, result: toSplitResult(committed, true) }
    }
    // 对手窗口可能在状态写入阶段失败了：从检查点重放，id 由幂等键确定性派生。
    return replayCheckpoint(persisted, claimed.checkpoint)
  }

  // 当前窗口是提交者：先做乐观并发与内容校验。
  const parent = source.threats.find((threat) => threat.id === request.parentThreatId)
  if (!parent) throw new SplitConflictError('主威胁不存在或已被删除。')
  if (parent.revision !== request.baseRevision) {
    removeCheckpoint(claimed.checkpoint.id)
    throw new SplitConflictError('主威胁在拆分窗口打开后已被修改，请刷新后重新拆分。')
  }
  const validation = validateSplitRequest(source, request)
  if (!validation.valid) {
    removeCheckpoint(claimed.checkpoint.id)
    throw new SplitConflictError(validation.errors.join('；'))
  }

  const { state: nextState, output } = applySplit(source, {
    request,
    idempotencyKey,
    now: nowIso(),
    actor: '当前用户',
  })

  try {
    saveState(nextState)
  } catch (error) {
    const message = error instanceof StateWriteError ? error.message : '未知写入错误'
    recordCheckpointFailure(claimed.checkpoint.id, message)
    throw new SplitSubmissionError(
      `状态写入失败，拆分检查点已保留，可从检查点恢复。原因：${message}`,
      claimed.checkpoint.id,
    )
  }

  markCheckpointCommitted(claimed.checkpoint.id)
  return { state: nextState, result: toSplitResult(output.operation, false) }
}

/** 从检查点重放（roll-forward）。状态已含该操作时直接复用，保持幂等。 */
export const replayCheckpoint = (
  source: ThreatModelState,
  checkpoint: SplitCheckpoint,
): { state: ThreatModelState; result: SplitResult } => {
  const persisted = source
  const existing = findCommittedByKey(persisted, checkpoint.idempotencyKey)
  if (existing) {
    return { state: persisted, result: toSplitResult(existing, true) }
  }

  const { state: nextState, output } = applySplit(persisted, {
    request: checkpoint.request,
    idempotencyKey: checkpoint.idempotencyKey,
    now: checkpoint.createdAt,
    actor: '检查点恢复',
  })

  try {
    saveState(nextState)
  } catch (error) {
    const message = error instanceof StateWriteError ? error.message : '未知写入错误'
    recordCheckpointFailure(checkpoint.id, message)
    throw new SplitSubmissionError(
      `检查点恢复时状态写入仍然失败：${message}`,
      checkpoint.id,
    )
  }

  markCheckpointCommitted(checkpoint.id)
  return { state: nextState, result: toSplitResult(output.operation, true) }
}

export interface RecoveryReport {
  recovered: SplitResult[]
  skipped: number
}

/**
 * 启动或手动触发：扫描所有未完成检查点并恢复。
 * 无论上次崩溃在「状态写入前」还是「状态写入后、提交标记前」，
 * 确定性 id 与幂等键保证最终只有一份结果。
 */
export const recoverPendingSplits = (): { state: ThreatModelState; report: RecoveryReport } => {
  let state = loadStateWithMeta().state
  const recovered: SplitResult[] = []
  let skipped = 0

  for (const checkpoint of listCheckpoints()) {
    if (checkpoint.status === 'committed') {
      // 状态中已有权威记录，检查点仅作冗余，清理即可。
      if (findCommittedByKey(state, checkpoint.idempotencyKey)) {
        removeCheckpoint(checkpoint.id)
      }
      continue
    }

    try {
      const outcome = replayCheckpoint(state, checkpoint)
      state = outcome.state
      recovered.push(outcome.result)
      removeCheckpoint(checkpoint.id)
    } catch {
      skipped += 1
    }
  }

  return { state, report: { recovered, skipped } }
}

export const pendingCheckpointCount = (): number =>
  listCheckpoints().filter((checkpoint) => checkpoint.status === 'prepared').length
