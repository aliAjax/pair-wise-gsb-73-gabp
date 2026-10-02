/**
 * 检查点账本：拆分提交是「两阶段」操作。
 * 阶段 1（prepared）：把请求、幂等键、确定性 id 落到独立的账本键，即使随后状态写入失败也不丢。
 * 阶段 2（committed）：状态原子写入成功后，把检查点标记为 committed 并保留用于跨窗口查询。
 *
 * 两个窗口同时提交时：账本写入 + 回读校验保证只有一个窗口成为提交者，
 * 另一个窗口读取已存在的检查点，重放/复用同一份结果（幂等键派生相同 id）。
 */
export interface KVStore {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

export interface SplitCheckpoint {
  id: string
  idempotencyKey: string
  request: import('@/models/domain').SplitThreatRequest
  status: 'prepared' | 'committed' | 'undone'
  createdAt: string
  committedAt?: string
  /** 写入失败计数与最近错误，供恢复界面展示 */
  failureCount: number
  lastError?: string
}

export interface CheckpointLedger {
  checkpoints: SplitCheckpoint[]
}

const LEDGER_KEY = 'scapex-split-checkpoints-v1'

/** 测试 / 演示用故障注入开关（localStorage 中持久，跨窗口同样生效）。 */
const FAILURE_KEY = 'scapex-split-fail-state-write'

export const browserKV: KVStore = {
  getItem: (key) => localStorage.getItem(key),
  setItem: (key, value) => localStorage.setItem(key, value),
  removeItem: (key) => localStorage.removeItem(key),
}

const readLedger = (kv: KVStore): CheckpointLedger => {
  const raw = kv.getItem(LEDGER_KEY)
  if (!raw) return { checkpoints: [] }
  try {
    const parsed = JSON.parse(raw) as CheckpointLedger
    return Array.isArray(parsed.checkpoints) ? parsed : { checkpoints: [] }
  } catch {
    return { checkpoints: [] }
  }
}

const writeLedger = (kv: KVStore, ledger: CheckpointLedger): void => {
  kv.setItem(LEDGER_KEY, JSON.stringify(ledger))
}

export const listCheckpoints = (kv: KVStore = browserKV): SplitCheckpoint[] =>
  readLedger(kv).checkpoints

export const findCheckpointByKey = (
  idempotencyKey: string,
  kv: KVStore = browserKV,
): SplitCheckpoint | undefined =>
  readLedger(kv).checkpoints.find((checkpoint) => checkpoint.idempotencyKey === idempotencyKey)

/**
 * 声明检查点。已存在同幂等键检查点时直接返回该检查点（并标记 currentLostRace），
 * 这是两个窗口同时提交只生成一份结果的核心：先写账本者赢。
 */
export const claimCheckpoint = (
  checkpoint: SplitCheckpoint,
  kv: KVStore = browserKV,
): { checkpoint: SplitCheckpoint; currentLostRace: boolean } => {
  const ledger = readLedger(kv)
  const existing = ledger.checkpoints.find(
    (item) => item.idempotencyKey === checkpoint.idempotencyKey && item.status !== 'undone',
  )
  if (existing) return { checkpoint: existing, currentLostRace: true }
  // 同键的旧检查点对应已撤销的拆分，删除后重新声明，允许撤销后再次拆分。
  ledger.checkpoints = ledger.checkpoints.filter(
    (item) => !(item.idempotencyKey === checkpoint.idempotencyKey && item.status === 'undone'),
  )
  ledger.checkpoints.push(checkpoint)
  writeLedger(kv, ledger)

  // 回读校验：跨窗口并发下，可能两个标签页都通过了上面的检查。
  const confirmed = readLedger(kv).checkpoints.find(
    (item) => item.idempotencyKey === checkpoint.idempotencyKey,
  )
  if (confirmed && confirmed.id !== checkpoint.id) {
    return { checkpoint: confirmed, currentLostRace: true }
  }
  return { checkpoint, currentLostRace: false }
}

export const markCheckpointCommitted = (
  id: string,
  kv: KVStore = browserKV,
): SplitCheckpoint | undefined => {
  const ledger = readLedger(kv)
  const target = ledger.checkpoints.find((item) => item.id === id)
  if (!target) return undefined
  target.status = 'committed'
  target.committedAt = new Date().toISOString()
  target.lastError = undefined
  writeLedger(kv, ledger)
  return target
}

export const recordCheckpointFailure = (
  id: string,
  error: string,
  kv: KVStore = browserKV,
): SplitCheckpoint | undefined => {
  const ledger = readLedger(kv)
  const target = ledger.checkpoints.find((item) => item.id === id)
  if (!target) return undefined
  target.failureCount += 1
  target.lastError = error
  writeLedger(kv, ledger)
  return target
}

export const markCheckpointUndone = (
  idempotencyKey: string,
  kv: KVStore = browserKV,
): void => {
  const ledger = readLedger(kv)
  ledger.checkpoints.forEach((item) => {
    if (item.idempotencyKey === idempotencyKey) item.status = 'undone'
  })
  writeLedger(kv, ledger)
}

export const removeCheckpoint = (id: string, kv: KVStore = browserKV): void => {
  const ledger = readLedger(kv)
  ledger.checkpoints = ledger.checkpoints.filter((item) => item.id !== id)
  writeLedger(kv, ledger)
}

/** 演示：打开后下一次状态保存将抛出，模拟状态写入失败、检查点待恢复。 */
export const setFailureInjection = (enabled: boolean, kv: KVStore = browserKV): void => {
  if (enabled) kv.setItem(FAILURE_KEY, '1')
  else kv.removeItem(FAILURE_KEY)
}

export const isFailureInjectionEnabled = (kv: KVStore = browserKV): boolean =>
  kv.getItem(FAILURE_KEY) === '1'
