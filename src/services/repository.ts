import type { ThreatModelState } from '@/models/domain'
import { createSeedState } from '@/models/seed'
import { migrateState } from '@/services/splitEngine'
import { browserKV, isFailureInjectionEnabled } from '@/services/splitLedger'

const STORAGE_KEY = 'scapex-threat-model-v1'

const clone = <T>(value: T): T => structuredClone(value)

export interface LoadResult {
  state: ThreatModelState
  /** 本次加载是否发生了旧数据迁移（来源回填） */
  migrated: boolean
}

export const loadStateWithMeta = (): LoadResult => {
  const raw = localStorage.getItem(STORAGE_KEY)
  if (!raw) {
    const seed = createSeedState()
    localStorage.setItem(STORAGE_KEY, JSON.stringify(seed))
    return { state: seed, migrated: false }
  }

  let parsed: ThreatModelState
  try {
    parsed = JSON.parse(raw) as ThreatModelState
  } catch {
    const seed = createSeedState()
    localStorage.setItem(STORAGE_KEY, JSON.stringify(seed))
    return { state: seed, migrated: false }
  }

  // 旧数据缺来源时按原威胁回填，迁移结果立即落库。
  const { state, migrated } = migrateState(parsed)
  if (migrated) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state))
  }
  return { state, migrated }
}

export const loadState = (): ThreatModelState => loadStateWithMeta().state

export class StateWriteError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'StateWriteError'
  }
}

export const saveState = (state: ThreatModelState): void => {
  if (isFailureInjectionEnabled(browserKV)) {
    throw new StateWriteError('模拟故障：状态持久化失败（检查点已保留，可从检查点恢复）')
  }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(clone(state)))
}

export const resetState = (): ThreatModelState => {
  const seed = createSeedState()
  saveState(seed)
  return seed
}

export const createId = (prefix: string): string =>
  `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`

/** 跨窗口：其他标签页提交拆分后，本窗口重新读取最新状态。 */
export const subscribeToExternalChanges = (onChange: () => void): (() => void) => {
  const handler = (event: StorageEvent): void => {
    if (event.key === STORAGE_KEY || event.key === null) onChange()
  }
  window.addEventListener('storage', handler)
  return () => window.removeEventListener('storage', handler)
}
