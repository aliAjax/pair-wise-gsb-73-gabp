export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type ReviewStatus = 'draft' | 'in_review' | 'approved' | 'rejected'
export type ThreatStatus = 'open' | 'mitigating' | 'mitigated' | 'accepted'
export type ControlStatus = 'effective' | 'degraded' | 'failed' | 'planned'
export type ActorRole = 'development' | 'security' | 'business'
export type DecisionType = 'accept' | 'degrade' | 'evidence_required' | 'approved' | 'rejected'

export interface SystemBoundary {
  id: string
  name: string
  description: string
  owner: string
  inScope: string
  outOfScope: string
}

export interface TrustZone {
  id: string
  name: string
  level: 'internet' | 'dmz' | 'internal' | 'restricted'
  description: string
}

export interface ArchitectureComponent {
  id: string
  name: string
  type: 'service' | 'asset' | 'data_store' | 'gateway' | 'client'
  zoneId: string
  criticality: Severity
  owner: string
  description: string
}

export interface ExternalDependency {
  id: string
  name: string
  vendor: string
  purpose: string
  dataClass: 'public' | 'internal' | 'confidential' | 'restricted'
  owner: string
  status: 'active' | 'review_due' | 'retired'
}

export interface DataFlow {
  id: string
  name: string
  sourceId: string
  targetId: string
  protocol: string
  dataClass: 'public' | 'internal' | 'confidential' | 'restricted'
  crossesTrustBoundary: boolean
  description: string
}

export interface ControlEvidence {
  id: string
  controlId: string
  title: string
  kind: 'test' | 'config' | 'ticket' | 'scan' | 'attestation'
  reference: string
  collectedAt: string
  expiresAt: string
  owner: string
  valid: boolean
}

export interface SecurityControl {
  id: string
  name: string
  type: 'preventive' | 'detective' | 'corrective'
  status: ControlStatus
  owner: string
  componentId: string
  description: string
  evidenceIds: string[]
}

export interface AttackPath {
  id: string
  name: string
  entryPoint: string
  target: string
  steps: string[]
  likelihood: 1 | 2 | 3 | 4 | 5
}

export interface Risk {
  id: string
  code: string
  title: string
  likelihood: 1 | 2 | 3 | 4 | 5
  impact: 1 | 2 | 3 | 4 | 5
  status: 'open' | 'mitigating' | 'accepted' | 'closed'
  owner: string
  acceptanceExpiresAt?: string
  acceptanceCondition?: string
}

export interface Threat {
  id: string
  code: string
  title: string
  category: 'spoofing' | 'tampering' | 'repudiation' | 'information_disclosure' | 'denial_of_service' | 'elevation'
  description: string
  severity: Severity
  status: ThreatStatus
  componentIds: string[]
  flowIds: string[]
  externalDependencyIds: string[]
  attackPathIds: string[]
  controlIds: string[]
  riskIds: string[]
  reviewStatus: ReviewStatus
  revision: number
  /** 父子拆分：直接父威胁 id；主威胁自身不携带该字段 */
  parentThreatId?: string
  /** 拆分谱系根威胁 id，多级拆分时保持不变 */
  rootThreatId?: string
  /** 最近一次拆分操作 id，用于谱系展示 */
  splitGroupId?: string
  /** 来源威胁 id；旧数据迁移时按原威胁回填（即威胁自身 id） */
  originThreatId?: string
}

export interface MitigationTask {
  id: string
  threatId: string
  title: string
  owner: string
  dueAt: string
  status: 'todo' | 'in_progress' | 'verifying' | 'done'
  action: 'restrict' | 'monitor' | 'encrypt' | 'isolate' | 'allow_with_condition'
  detail: string
  evidenceIds: string[]
  conflictGroup?: string
  /** 来源威胁 id；旧数据迁移时按原威胁回填（即 threatId） */
  originThreatId?: string
}

/** 拆分时按场景声明的子威胁输入（对象 id 必须来自父威胁） */
export interface SplitChildInput {
  title: string
  scenario: string
  severity: Severity
  componentIds: string[]
  flowIds: string[]
  externalDependencyIds: string[]
  attackPathIds: string[]
  controlIds: string[]
  riskIds: string[]
  /** 从主威胁迁移到子威胁的现有缓解任务 id */
  mitigationIds: string[]
}

export interface SplitThreatRequest {
  parentThreatId: string
  /** 打开拆分窗口时父威胁的修订号，用于乐观并发控制 */
  baseRevision: number
  children: SplitChildInput[]
}

export interface SplitOperation {
  id: string
  idempotencyKey: string
  parentThreatId: string
  parentRevisionBefore: number
  /** 拆分前父威胁的完整快照，撤销时原样恢复 */
  parentSnapshot: Threat
  /** 本次拆分落库的子威胁 */
  children: Threat[]
  /** 迁移到子威胁的缓解任务 id */
  assignedMitigationIds: string[]
  status: 'committed' | 'undone'
  actor: string
  createdAt: string
  undoneAt?: string
}

export interface SplitResult {
  operation: SplitOperation
  /** true 表示命中并发去重，返回的是另一个窗口已生成的同一份结果 */
  deduplicated: boolean
}

export interface ReviewDecision {
  id: string
  threatId: string
  actor: string
  role: ActorRole
  decision: DecisionType
  comment: string
  createdAt: string
  revision: number
}

export interface VersionSnapshot {
  id: string
  revision: number
  label: string
  createdAt: string
  author: string
  notes: string
  threatIds: string[]
  componentIds: string[]
  flowIds: string[]
  controlIds: string[]
  riskIds: string[]
  affectedThreatIds: string[]
}

export interface AuditEvent {
  id: string
  entityType: string
  entityId: string
  action: string
  actor: string
  createdAt: string
  detail: string
}

export interface ThreatModelState {
  boundary: SystemBoundary
  zones: TrustZone[]
  components: ArchitectureComponent[]
  dependencies: ExternalDependency[]
  flows: DataFlow[]
  controls: SecurityControl[]
  evidence: ControlEvidence[]
  threats: Threat[]
  attackPaths: AttackPath[]
  risks: Risk[]
  mitigations: MitigationTask[]
  decisions: ReviewDecision[]
  versions: VersionSnapshot[]
  audit: AuditEvent[]
  splitOperations: SplitOperation[]
  /** 本地持久化结构版本；旧数据（无该字段）加载时迁移并回填来源 */
  schemaVersion?: number
  /** 最近一次旧数据迁移时间 */
  migratedAt?: string
  currentRevision: number
}

export interface ValidationIssue {
  id: string
  kind: 'uncovered_component' | 'control_failed' | 'risk_acceptance_expired' | 'mitigation_conflict' | 'missing_evidence'
  severity: Severity
  title: string
  detail: string
  entityId: string
}

export interface VersionChange {
  category: string
  id: string
}

export interface VersionDifference {
  added: VersionChange[]
  removed: VersionChange[]
  changed: string[]
}
