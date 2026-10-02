import assert from 'node:assert/strict'
import { createSeedState } from '@/models/seed'
import {
  migrateState,
  buildIdempotencyKey,
  validateSplitRequest,
  applySplit,
  undoSplit,
  undoBlockers,
  findCommittedByKey,
  deriveOperationId,
  deriveChildThreatId,
  CURRENT_SCHEMA_VERSION,
} from '@/services/splitEngine'

let passed = 0
const test = (name, fn) => {
  fn()
  passed += 1
  console.log(`  ✓ ${name}`)
}

// ---------- 旧数据迁移：缺来源按原威胁回填 ----------
test('旧数据迁移：威胁与缓解任务缺来源时按原威胁回填', () => {
  const legacy = createSeedState()
  delete legacy.schemaVersion
  delete legacy.splitOperations
  legacy.threats.forEach((threat) => {
    delete threat.originThreatId
    delete threat.rootThreatId
  })
  legacy.mitigations.forEach((task) => delete task.originThreatId)

  const { state, migrated } = migrateState(legacy)
  assert.equal(migrated, true)
  assert.equal(state.schemaVersion, CURRENT_SCHEMA_VERSION)
  state.threats.forEach((threat) => {
    assert.equal(threat.originThreatId, threat.id)
    assert.equal(threat.rootThreatId, threat.id)
  })
  state.mitigations.forEach((task) => assert.equal(task.originThreatId, task.threatId))
  assert.ok(Array.isArray(state.splitOperations))
  assert.ok(state.audit[0].action.includes('迁移'))
})

test('迁移幂等：已是新版本的状态不重复迁移', () => {
  const fresh = createSeedState()
  const { migrated } = migrateState(fresh)
  assert.equal(migrated, false)
})

// ---------- 拆分主流程 ----------
const splitRequest = () => ({
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
      scenario: '令牌在网关上被重放绕过来源限制。',
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

test('拆分：未选中关系留在主威胁，选中对象进入子威胁', () => {
  const state = createSeedState()
  const key = buildIdempotencyKey(splitRequest())
  const { state: next, output } = applySplit(state, {
    request: splitRequest(),
    idempotencyKey: key,
    now: '2026-10-02T00:00:00Z',
    actor: '测试员',
  })

  const parent = next.threats.find((t) => t.id === 'thr-01')
  assert.ok(parent)
  assert.deepEqual(parent.componentIds, []) // cmp-01 / cmp-02 均被分走
  assert.deepEqual(parent.flowIds, [])
  // 子威胁
  assert.equal(output.children.length, 2)
  const child1 = output.children[0]
  assert.equal(child1.code, 'TM-001.1')
  assert.deepEqual(child1.componentIds, ['cmp-01'])
  assert.equal(child1.parentThreatId, 'thr-01')
  assert.equal(child1.rootThreatId, 'thr-01')
  assert.equal(child1.reviewStatus, 'in_review')
  assert.equal(child1.revision, 3)
  // 父威胁以新修订重新会签，原修订 2 的会签因此失效
  assert.equal(parent.revision, 3)
  assert.equal(parent.reviewStatus, 'in_review')
  assert.equal(next.currentRevision, 3)
  // 缓解任务迁移；未选中的留在主威胁（这里两条都迁移了）
  const m1 = next.mitigations.find((m) => m.id === 'mit-01')
  assert.equal(m1.threatId, child1.id)
  assert.equal(m1.originThreatId, 'thr-01')
  const m2 = next.mitigations.find((m) => m.id === 'mit-02')
  assert.equal(m2.threatId, output.children[1].id)
  // 操作登记
  assert.equal(next.splitOperations[0].status, 'committed')
  assert.equal(next.splitOperations[0].children.length, 2)
})

test('拆分：未勾选任何对象时关系全部留在主威胁', () => {
  const state = createSeedState()
  const request = {
    parentThreatId: 'thr-02',
    baseRevision: 2,
    children: [
      {
        title: '仅场景描述的子威胁',
        scenario: '独立场景。',
        severity: 'medium',
        componentIds: [],
        flowIds: [],
        externalDependencyIds: [],
        attackPathIds: [],
        controlIds: [],
        riskIds: [],
        mitigationIds: [],
      },
    ],
  }
  const { state: next } = applySplit(state, {
    request,
    idempotencyKey: buildIdempotencyKey(request),
    now: '2026-10-02T00:00:00Z',
    actor: '测试员',
  })
  const parent = next.threats.find((t) => t.id === 'thr-02')
  assert.deepEqual(parent.componentIds, ['cmp-04', 'cmp-05'])
  assert.deepEqual(parent.flowIds, ['flow-04'])
  const child = next.threats.find((t) => t.id === deriveChildThreatId(buildIdempotencyKey(request), 0))
  assert.deepEqual(child.componentIds, [])
})

test('校验：同一对象不能同时归给两个子威胁', () => {
  const state = createSeedState()
  const bad = splitRequest()
  bad.children[1].componentIds = ['cmp-01'] // 与子威胁 1 冲突
  const result = validateSplitRequest(state, bad)
  assert.equal(result.valid, false)
  assert.ok(result.errors.some((e) => e.includes('不能同时归给两个子威胁')))
})

test('校验：非主威胁拥有的对象不允许分配', () => {
  const state = createSeedState()
  const bad = splitRequest()
  bad.children[0].componentIds = ['cmp-04'] // cmp-04 不属于 thr-01
  const result = validateSplitRequest(state, bad)
  assert.equal(result.valid, false)
  assert.ok(result.errors.some((e) => e.includes('不属于主威胁')))
})

test('校验：同一缓解任务不能归给两个子威胁', () => {
  const state = createSeedState()
  const bad = splitRequest()
  bad.children[1].mitigationIds = ['mit-01']
  const result = validateSplitRequest(state, bad)
  assert.equal(result.valid, false)
  assert.ok(result.errors.some((e) => e.includes('缓解任务') && e.includes('不能同时归给两个子威胁')))
})

test('校验：至少一个子场景；标题与场景必填', () => {
  const state = createSeedState()
  assert.equal(validateSplitRequest(state, { ...splitRequest(), children: [] }).valid, false)
  const bad = splitRequest()
  bad.children[0].title = '  '
  bad.children[0].scenario = ''
  assert.ok(validateSplitRequest(state, bad).errors.length >= 2)
})

// ---------- 确定性与幂等 ----------
test('幂等键与 id 对相同方案是确定性的，对象顺序不影响', () => {
  const a = splitRequest()
  const b = splitRequest()
  b.children[0].componentIds = ['cmp-01'].reverse()
  b.children[0].flowIds = [...a.children[0].flowIds].sort()
  assert.equal(buildIdempotencyKey(a), buildIdempotencyKey(b))
  const key = buildIdempotencyKey(a)
  assert.equal(deriveOperationId(key), deriveOperationId(key))
  assert.equal(deriveChildThreatId(key, 0), deriveChildThreatId(key, 0))
})

test('幂等：相同方案在已应用状态中可被 findCommittedByKey 找到', () => {
  const state = createSeedState()
  const key = buildIdempotencyKey(splitRequest())
  const { state: next } = applySplit(state, {
    request: splitRequest(),
    idempotencyKey: key,
    now: 'x',
    actor: 'a',
  })
  assert.ok(findCommittedByKey(next, key))
})

// ---------- 撤销 ----------
test('撤销：父威胁恢复快照，子威胁及其会签被删除，迁移任务回到主威胁', () => {
  const state = createSeedState()
  const key = buildIdempotencyKey(splitRequest())
  const applied = applySplit(state, {
    request: splitRequest(),
    idempotencyKey: key,
    now: '2026-10-02T00:00:00Z',
    actor: '测试员',
  }).state

  const operationId = deriveOperationId(key)
  // 给子威胁补一条会签（其修订为 3）
  const childId = deriveChildThreatId(key, 0)
  applied.decisions.unshift({
    id: 'dec-child',
    threatId: childId,
    actor: '某人',
    role: 'security',
    decision: 'approved',
    comment: '子威胁意见',
    createdAt: '2026-10-02T01:00:00Z',
    revision: 3,
  })

  const blockers = undoBlockers(applied, operationId)
  assert.ok(blockers.some((b) => b.includes('会签意见')))
  assert.throws(() => undoSplit(applied, operationId, { now: 'x', actor: 'a' }))

  const undone = undoSplit(applied, operationId, { force: true, now: '2026-10-03T00:00:00Z', actor: '测试员' })
  const parent = undone.threats.find((t) => t.id === 'thr-01')
  assert.deepEqual(parent.componentIds, ['cmp-01', 'cmp-02'])
  assert.deepEqual(parent.flowIds, ['flow-01'])
  assert.equal(parent.revision, 2)
  assert.equal(parent.reviewStatus, 'in_review') // 恢复拆分前快照
  assert.equal(undone.threats.some((t) => t.parentThreatId === 'thr-01'), false)
  assert.equal(undone.decisions.some((d) => d.threatId === childId), false)
  assert.equal(undone.mitigations.find((m) => m.id === 'mit-01').threatId, 'thr-01')
  const op = undone.splitOperations.find((o) => o.id === operationId)
  assert.equal(op.status, 'undone')
})

test('撤销：子威胁无会签时可直接撤销', () => {
  const state = createSeedState()
  const request = splitRequest()
  const key = buildIdempotencyKey(request)
  const applied = applySplit(state, { request, idempotencyKey: key, now: 'x', actor: 'a' }).state
  assert.doesNotThrow(() =>
    undoSplit(applied, deriveOperationId(key), { now: 'y', actor: 'a' }),
  )
})

test('撤销后允许用相同方案重新拆分，产生新的 committed 操作', () => {
  const state = createSeedState()
  const request = splitRequest()
  const key = buildIdempotencyKey(request)
  const applied = applySplit(state, { request, idempotencyKey: key, now: 'x', actor: 'a' }).state
  const undone = undoSplit(applied, deriveOperationId(key), { now: 'y', actor: 'a' })
  // 相同幂等键在撤销状态下不再视为已提交
  assert.equal(findCommittedByKey(undone, key), undefined)
  const reapplied = applySplit(undone, { request, idempotencyKey: key, now: 'z', actor: 'a' })
  const parent = reapplied.state.threats.find((t) => t.id === 'thr-01')
  assert.equal(parent.revision, 4) // 3（首次拆分）+ 1（重新拆分）
  assert.equal(reapplied.state.threats.filter((t) => t.parentThreatId === 'thr-01').length, 2)
})

console.log(`\n引擎层 ${passed} 个用例全部通过。`)
