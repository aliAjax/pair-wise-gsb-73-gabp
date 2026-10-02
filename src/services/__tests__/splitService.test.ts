import assert from 'node:assert/strict'
import { createSeedState } from '@/models/seed'
import { buildIdempotencyKey } from '@/services/splitEngine'
import { executeSplit, recoverPendingSplits, replayCheckpoint } from '@/services/splitService'
import {
  claimCheckpoint,
  listCheckpoints,
  setFailureInjection,
} from '@/services/splitLedger'
import { SplitSubmissionError } from '@/services/splitService'

// ---- 测试基座：localStorage 与每个窗口独立的内存状态 ----
const createMemoryStorage = () => {
  const map = new Map()
  return {
    getItem: (key) => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => void map.set(key, String(value)),
    removeItem: (key) => void map.delete(key),
    _map: map,
  }
}

const STATE_KEY = 'scapex-threat-model-v1'
const LEDGER_KEY = 'scapex-split-checkpoints-v1'
const storage = createMemoryStorage()
storage.setItem(STATE_KEY, JSON.stringify(createSeedState()))

globalThis.localStorage = storage

const request = () => ({
  parentThreatId: 'thr-01',
  baseRevision: 2,
  children: [
    {
      title: '公网枚举滥用会话',
      scenario: '攻击者枚举公网入口获取有效会话。',
      severity: 'critical',
      componentIds: ['cmp-01'],
      flowIds: ['flow-01'],
      externalDependencyIds: [],
      attackPathIds: ['path-01'],
      controlIds: [],
      riskIds: ['risk-01'],
      mitigationIds: ['mit-01'],
    },
    {
      title: '网关令牌绕过',
      scenario: '令牌在网关上被重放。',
      severity: 'high',
      componentIds: ['cmp-02'],
      flowIds: [],
      externalDependencyIds: [],
      attackPathIds: [],
      controlIds: ['ctl-01'],
      riskIds: [],
      mitigationIds: ['mit-02'],
    },
  ],
})

const readPersisted = () => JSON.parse(storage.getItem(STATE_KEY))

let passed = 0
const test = (name, fn) => {
  fn()
  passed += 1
  console.log(`  ✓ ${name}`)
}

test('两个窗口同时提交相同拆分：只生成一份结果，第二窗口命中去重', () => {
  // 两个窗口各自从同一持久化状态启动
  const windowA = readPersisted()
  const windowB = readPersisted()
  const req = request()

  const first = executeSplit(windowA, req)
  assert.equal(first.result.deduplicated, false)
  const second = executeSplit(windowB, req)
  assert.equal(second.result.deduplicated, true)

  // 子威胁 id 相同（确定性派生），最终状态只有两个子威胁
  assert.deepEqual(
    first.result.operation.children.map((c) => c.id).sort(),
    second.result.operation.children.map((c) => c.id).sort(),
  )
  const persisted = readPersisted()
  const children = persisted.threats.filter((t) => t.parentThreatId === 'thr-01')
  assert.equal(children.length, 2)
  const operations = persisted.splitOperations.filter(
    (op) => op.idempotencyKey === buildIdempotencyKey(req),
  )
  assert.equal(operations.length, 1)
})

test('窗口打开期间主威胁被改过（baseRevision 不匹配）：拒绝提交', () => {
  const stale = readPersisted()
  // thr-01 已在拆分后变为修订 3，窗口仍带 baseRevision=2
  const req = request()
  req.children = [req.children[0]]
  assert.throws(() => executeSplit(stale, req), /已被修改/)
})

test('状态写入失败：保留 prepared 检查点并抛出可识别错误', () => {
  const fresh = createSeedState()
  storage.setItem(STATE_KEY, JSON.stringify(fresh))
  storage.removeItem(LEDGER_KEY) // 与前序用例的检查点隔离
  setFailureInjection(true)
  const req = request()
  try {
    assert.throws(() => executeSplit(readPersisted(), req), SplitSubmissionError)
  } finally {
    setFailureInjection(false)
  }
  const pending = listCheckpoints().filter((c) => c.status === 'prepared')
  assert.ok(pending.some((c) => c.idempotencyKey === buildIdempotencyKey(req)))
  // 状态没有被破坏：仍是拆分前数据
  const persisted = readPersisted()
  assert.equal(persisted.threats.some((t) => t.parentThreatId === 'thr-01'), false)
})

test('从检查点恢复：确定性重放，只生成一份结果并清理检查点', () => {
  const before = readPersisted()
  const prepared = listCheckpoints().find((c) => c.status === 'prepared')
  const replayed = replayCheckpoint(before, prepared)
  assert.equal(replayed.result.deduplicated, true)
  const persisted = readPersisted()
  const children = persisted.threats.filter((t) => t.parentThreatId === 'thr-01')
  assert.equal(children.length, 2)
  // 恢复后检查点已标记并清理
  assert.equal(listCheckpoints().filter((c) => c.status === 'prepared').length, 0)
})

test('重复恢复是幂等的：再次全量恢复不会产生重复子威胁', () => {
  const report = recoverPendingSplits()
  assert.equal(report.report.recovered.length, 0)
  const persisted = readPersisted()
  assert.equal(persisted.threats.filter((t) => t.parentThreatId === 'thr-01').length, 2)
})

test('检查点竞争：第二个 claim 相同幂等键时落败', () => {
  const a = claimCheckpoint({
    id: 'ckp-x',
    idempotencyKey: 'same-key',
    request: request(),
    status: 'prepared',
    createdAt: 't',
    failureCount: 0,
  })
  assert.equal(a.currentLostRace, false)
  const b = claimCheckpoint({
    id: 'ckp-y',
    idempotencyKey: 'same-key',
    request: request(),
    status: 'prepared',
    createdAt: 't',
    failureCount: 0,
  })
  assert.equal(b.currentLostRace, true)
  assert.equal(b.checkpoint.id, 'ckp-x')
})

console.log(`\n编排层 ${passed} 个用例全部通过。`)
