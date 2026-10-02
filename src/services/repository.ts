import type { SplitOperation, ThreatModelState } from '@/models/domain'
import { createSeedState } from '@/models/seed'

const STORAGE_KEY = 'scapex-threat-model-v1'
const CHECKPOINT_KEY = 'scapex-threat-model-v1-checkpoint'
const MODEL_LOCK_NAME = 'scapex-threat-model-v1-lock'
const FALLBACK_LOCK_TTL_MS = 10_000
const FALLBACK_LOCK_TIMEOUT_MS = 30_000

const clone = <T>(value: T): T => structuredClone(value)

interface TransactionCheckpoint {
  schemaVersion: 1
  status: 'prepared' | 'main_written' | 'committed'
  before: ThreatModelState
  next: ThreatModelState | null
  createdAt: string
}

const asRecord = (value: unknown): Record<string, unknown> | null =>
  value && typeof value === 'object' ? (value as Record<string, unknown>) : null

const asArray = (value: unknown): unknown[] => (Array.isArray(value) ? value : [])

const normalizeThreat = (
  value: unknown,
  activeOperations: SplitOperation[],
): Record<string, unknown> => {
  const record = asRecord(value) ?? {}
  const id = typeof record.id === 'string' ? record.id : ''
  const operation = activeOperations.find((item) => item.childThreatIds.includes(id))
  if (id && operation) {
    record.parentThreatId ??= operation.parentThreatId
    record.splitOperationId ??= operation.id
  }
  if (
    id &&
    !record.parentThreatId &&
    typeof record.splitOperationId === 'string'
  ) {
    const split = activeOperations.find((item) => item.id === record.splitOperationId)
    if (split) record.parentThreatId = split.parentThreatId
  }
  if (id) {
    record.splitParent ??= activeOperations.some(
      (item) => item.parentThreatId === id && !item.childThreatIds.includes(id),
    )
  }

  const relationKeys = [
    'componentIds',
    'flowIds',
    'externalDependencyIds',
    'attackPathIds',
    'controlIds',
    'riskIds',
  ]
  relationKeys.forEach((key) => {
    if (!Array.isArray(record[key])) record[key] = []
  })
  return record
}

const normalizeState = (value: unknown): ThreatModelState => {
  const state = (asRecord(value) ?? {}) as Record<string, unknown> & Partial<ThreatModelState>
  state.splitOperations = asArray(state.splitOperations)
    .map((item) => asRecord(item))
    .filter((item): item is Record<string, unknown> => Boolean(item && item.id && item.parentThreatId))
    .map((item) => {
      const operation = {
        ...item,
        childThreatIds: asArray(item.childThreatIds).filter((id): id is string => typeof id === 'string'),
        migratedMitigationIds: asArray(item.migratedMitigationIds).filter(
          (id): id is string => typeof id === 'string',
        ),
      } as SplitOperation
      return operation
    })

  const splitOperations = state.splitOperations as SplitOperation[]
  const activeOperations = splitOperations.filter((operation) => !operation.revokedAt)

  const threats = asArray(state.threats)
    .map((item) => normalizeThreat(item, activeOperations))
    .filter((item) => typeof item.id === 'string') as unknown as ThreatModelState['threats']
  state.threats = threats
  const childByThreatId = new Map(
    threats
      .filter((threat) => threat.parentThreatId)
      .map((threat) => [threat.id, threat]),
  )

  state.mitigations = asArray(state.mitigations).map((item) => {
    const task = { ...(asRecord(item) ?? {}) }
    if (typeof task.threatId === 'string') {
      const child = childByThreatId.get(task.threatId)
      if (child) {
        task.sourceThreatId ??= child.parentThreatId
        task.splitOperationId ??= child.splitOperationId
      } else {
        task.sourceThreatId ??= task.threatId
      }
    }
    return task
  }) as unknown as ThreatModelState['mitigations']

  state.decisions = asArray(state.decisions) as ThreatModelState['decisions']
  state.versions = asArray(state.versions) as ThreatModelState['versions']
  state.audit = asArray(state.audit) as ThreatModelState['audit']

  const mitigations = state.mitigations ?? []
  splitOperations.forEach((operation) => {
    if (!operation.migratedMitigationIds || operation.migratedMitigationIds.length === 0) {
      operation.migratedMitigationIds = mitigations
        .filter(
          (task) =>
            task.splitOperationId === operation.id &&
            operation.childThreatIds.includes(task.threatId),
        )
        .map((task) => task.id)
    }
    if (!operation.children) {
      operation.children = operation.childThreatIds
        .map((childId) =>
          (state.threats ?? []).find((threat) => threat.id === childId),
        )
        .filter((threat): threat is ThreatModelState['threats'][number] => Boolean(threat))
        .map((threat) => ({
          threatId: threat.id,
          code: threat.code,
          title: threat.title,
          description: threat.description,
          severity: threat.severity,
          componentIds: threat.componentIds,
          flowIds: threat.flowIds,
          externalDependencyIds: threat.externalDependencyIds,
          attackPathIds: threat.attackPathIds,
          controlIds: threat.controlIds,
          riskIds: threat.riskIds,
          mitigationIds: mitigations
            .filter((task) => task.threatId === threat.id)
            .map((task) => task.id),
        }))
    }
  })

  return state as ThreatModelState
}

const readJson = (key: string): unknown | null => {
  const raw = localStorage.getItem(key)
  if (!raw) return null
  return JSON.parse(raw)
}

const writeJson = (key: string, value: unknown): void => {
  localStorage.setItem(key, JSON.stringify(value))
}

const readMain = (): ThreatModelState | null => {
  try {
    const parsed = readJson(STORAGE_KEY)
    return parsed ? normalizeState(parsed) : null
  } catch {
    return null
  }
}

const clearCheckpoint = (force = false): void => {
  try {
    localStorage.removeItem(CHECKPOINT_KEY)
  } catch {
    if (force) {
      try {
        localStorage.setItem(CHECKPOINT_KEY, '')
        localStorage.removeItem(CHECKPOINT_KEY)
      } catch {
        // A stale checkpoint is harmless: the next load will converge to its committed state.
      }
    }
  }
}

const recoverFromCheckpoint = (): ThreatModelState => {
  const fallback = readMain() ?? createSeedState()
  let checkpoint: TransactionCheckpoint | null = null
  try {
    const parsed = readJson(CHECKPOINT_KEY) as Partial<TransactionCheckpoint> | null
    if (parsed && parsed.schemaVersion === 1 && parsed.before) {
      checkpoint = {
        schemaVersion: 1,
        status:
          parsed.status === 'committed'
            ? 'committed'
            : parsed.status === 'main_written'
              ? 'main_written'
              : 'prepared',
        before: normalizeState(parsed.before),
        next: parsed.next ? normalizeState(parsed.next) : null,
        createdAt: typeof parsed.createdAt === 'string' ? parsed.createdAt : '',
      }
    }
  } catch {
    checkpoint = null
  }
  if (!checkpoint || checkpoint.schemaVersion !== 1) {
    clearCheckpoint()
    return fallback
  }

  if ((checkpoint.status === 'committed' || checkpoint.status === 'main_written') && checkpoint.next) {
    const recovered = normalizeState(checkpoint.next)
    writeJson(STORAGE_KEY, recovered)
    clearCheckpoint()
    return recovered
  }

  if (checkpoint.next) {
    const restored = normalizeState(checkpoint.before)
    try {
      writeJson(STORAGE_KEY, restored)
      clearCheckpoint()
    } catch {
      clearCheckpoint(true)
    }
    return restored
  }

  const restored = normalizeState(checkpoint.before)
  writeJson(STORAGE_KEY, restored)
  clearCheckpoint()
  return restored
}

export const loadState = (): ThreatModelState => {
  let checkpointExists = false
  try {
    checkpointExists = Boolean(localStorage.getItem(CHECKPOINT_KEY))
  } catch {
    checkpointExists = false
  }

  if (checkpointExists) return recoverFromCheckpoint()

  const state = readMain()
  if (state) return state

  const seed = createSeedState()
  try {
    writeJson(STORAGE_KEY, seed)
  } catch {
    // The application remains usable even when browser storage is unavailable.
  }
  return seed
}

export const loadPersistedState = (): ThreatModelState => loadState()

export const saveState = (state: ThreatModelState): void => {
  writeJson(STORAGE_KEY, clone(state))
}

export const commitStateTransactionally = (
  before: ThreatModelState,
  next: ThreatModelState,
): ThreatModelState => {
  const checkpoint: TransactionCheckpoint = {
    schemaVersion: 1,
    status: 'prepared',
    before: clone(before),
    next: clone(next),
    createdAt: new Date().toISOString(),
  }
  writeJson(CHECKPOINT_KEY, checkpoint)

  try {
    writeJson(STORAGE_KEY, next)
    checkpoint.status = 'main_written'
    writeJson(CHECKPOINT_KEY, checkpoint)
    clearCheckpoint()
    return next
  } catch (error) {
    try {
      writeJson(STORAGE_KEY, checkpoint.before)
      clearCheckpoint()
    } catch {
      // Leave the durable checkpoint for the next window to recover.
    }
    throw error
  }
}

const acquireFallbackLock = async (): Promise<string> => {
  const token = `${Date.now()}-${Math.random().toString(36).slice(2)}`
  const startedAt = Date.now()
  while (Date.now() - startedAt < FALLBACK_LOCK_TIMEOUT_MS) {
    let raw: string | null = null
    try {
      raw = localStorage.getItem(MODEL_LOCK_NAME)
    } catch {
      raw = null
    }
    const holder = raw ? (JSON.parse(raw) as { token?: string; expiresAt?: number }) : null
    if (!holder || !holder.expiresAt || holder.expiresAt < Date.now()) {
      try {
        localStorage.setItem(
          MODEL_LOCK_NAME,
          JSON.stringify({ token, expiresAt: Date.now() + FALLBACK_LOCK_TTL_MS }),
        )
        const verify = JSON.parse(localStorage.getItem(MODEL_LOCK_NAME) ?? '{}') as {
          token?: string
        }
        if (verify.token === token) return token
      } catch {
        // Retry when another tab wins the synchronous storage race.
      }
    }
    await new Promise((resolve) => window.setTimeout(resolve, 50))
  }
  throw new Error('模型写入锁等待超时，请稍后重试')
}

const releaseFallbackLock = (token: string): void => {
  try {
    const holder = JSON.parse(localStorage.getItem(MODEL_LOCK_NAME) ?? '{}') as { token?: string }
    if (holder.token === token) localStorage.removeItem(MODEL_LOCK_NAME)
  } catch {
    // An expired lock can be safely ignored.
  }
}

export const withModelTransactionLock = async <T>(
  operation: () => Promise<T> | T,
): Promise<T> => {
  if (typeof navigator !== 'undefined' && 'locks' in navigator && navigator.locks) {
    return navigator.locks.request(MODEL_LOCK_NAME, operation)
  }

  const token = await acquireFallbackLock()
  try {
    return await operation()
  } finally {
    releaseFallbackLock(token)
  }
}

export const resetState = (): ThreatModelState => {
  const seed = createSeedState()
  saveState(seed)
  return seed
}

export const createId = (prefix: string): string =>
  `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`
