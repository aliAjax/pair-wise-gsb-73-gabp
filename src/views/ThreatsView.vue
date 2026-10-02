<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import MultiSelect from 'primevue/multiselect'
import Select from 'primevue/select'
import Textarea from 'primevue/textarea'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import ThreatSplitDialog from '@/components/ThreatSplitDialog.vue'
import { SplitConflictError } from '@/services/splitEngine'
import type { Threat } from '@/models/domain'
import { createId } from '@/services/repository'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const confirm = useConfirm()

const keyword = ref('')
const severityFilter = ref<string | null>(null)
const statusFilter = ref<string | null>(null)
const categoryFilter = ref<string | null>(null)
const selectedId = ref(store.data.threats[0]?.id ?? '')
const editorVisible = ref(false)

const severityOptions = [
  { label: '严重', value: 'critical' },
  { label: '高', value: 'high' },
  { label: '中', value: 'medium' },
  { label: '低', value: 'low' },
]
const statusOptions = [
  { label: '开放', value: 'open' },
  { label: '处置中', value: 'mitigating' },
  { label: '已缓解', value: 'mitigated' },
  { label: '已接受', value: 'accepted' },
]
const reviewOptions = [
  { label: '草稿', value: 'draft' },
  { label: '审核中', value: 'in_review' },
  { label: '已通过', value: 'approved' },
  { label: '已驳回', value: 'rejected' },
]
const categoryOptions = [
  { label: '身份伪造', value: 'spoofing' },
  { label: '数据篡改', value: 'tampering' },
  { label: '否认操作', value: 'repudiation' },
  { label: '信息泄露', value: 'information_disclosure' },
  { label: '拒绝服务', value: 'denial_of_service' },
  { label: '权限提升', value: 'elevation' },
]

const threatForm = reactive<Threat>({
  id: '',
  code: '',
  title: '',
  category: 'information_disclosure',
  description: '',
  severity: 'medium',
  status: 'open',
  componentIds: [],
  flowIds: [],
  externalDependencyIds: [],
  attackPathIds: [],
  controlIds: [],
  riskIds: [],
  reviewStatus: 'draft',
  revision: store.data.currentRevision,
})

const filteredThreats = computed(() => {
  const normalized = keyword.value.trim().toLowerCase()
  return store.data.threats.filter((threat) => {
    const textMatches =
      !normalized ||
      threat.title.toLowerCase().includes(normalized) ||
      threat.code.toLowerCase().includes(normalized) ||
      threat.description.toLowerCase().includes(normalized)
    return (
      textMatches &&
      (!severityFilter.value || threat.severity === severityFilter.value) &&
      (!statusFilter.value || threat.status === statusFilter.value) &&
      (!categoryFilter.value || threat.category === categoryFilter.value)
    )
  })
})

const selectedThreat = computed(
  () => store.data.threats.find((threat) => threat.id === selectedId.value) ?? null,
)
const relatedComponents = computed(
  () =>
    selectedThreat.value?.componentIds
      .map((id) => store.data.components.find((component) => component.id === id))
      .filter(Boolean) ?? [],
)
const relatedControls = computed(
  () =>
    selectedThreat.value?.controlIds
      .map((id) => store.data.controls.find((control) => control.id === id))
      .filter(Boolean) ?? [],
)
const relatedPaths = computed(
  () =>
    selectedThreat.value?.attackPathIds
      .map((id) => store.data.attackPaths.find((path) => path.id === id))
      .filter(Boolean) ?? [],
)

const clearFilters = (): void => {
  keyword.value = ''
  severityFilter.value = null
  statusFilter.value = null
  categoryFilter.value = null
}

const editThreat = (): void => {
  if (!selectedThreat.value) return
  Object.assign(threatForm, structuredClone(selectedThreat.value))
  editorVisible.value = true
}

const addThreat = (): void => {
  const sequence = store.data.threats.length + 1
  Object.assign(threatForm, {
    id: '',
    code: `TM-${String(sequence).padStart(3, '0')}`,
    title: '',
    category: 'information_disclosure',
    description: '',
    severity: 'medium',
    status: 'open',
    componentIds: [],
    flowIds: [],
    externalDependencyIds: [],
    attackPathIds: [],
    controlIds: [],
    riskIds: [],
    reviewStatus: 'draft',
    revision: store.data.currentRevision,
  } satisfies Threat)
  editorVisible.value = true
}

const splitDialogVisible = ref(false)

const openSplit = (): void => {
  if (!selectedThreat.value) return
  splitDialogVisible.value = true
}

const codeOf = (id: string): string =>
  store.data.threats.find((threat) => threat.id === id)?.code ?? id

const childThreats = computed(() =>
  selectedThreat.value
    ? store.data.threats.filter((threat) => threat.parentThreatId === selectedThreat.value?.id)
    : [],
)

const parentThreat = computed(
  () =>
    store.data.threats.find((threat) => threat.id === selectedThreat.value?.parentThreatId) ?? null,
)

const lastSplitOperation = computed(() =>
  selectedThreat.value
    ? store.data.splitOperations.find(
        (operation) =>
          operation.parentThreatId === selectedThreat.value?.id && operation.status === 'committed',
      ) ?? null
    : null,
)

const requestUndo = (): void => {
  if (!selectedThreat.value || !lastSplitOperation.value) return
  const operationId = lastSplitOperation.value.id
  const blockers = store.splitUndoBlockers(operationId)
  const needsForce = blockers.some((message) => message.includes('会签意见'))
  const message = needsForce
    ? `${blockers.join('；')} 确认撤销将删除这些子威胁会签并恢复原会签，是否继续？`
    : '将恢复主威胁拆分前状态，迁移的对象与缓解任务回到主威胁，原会签重新生效。是否继续？'
  confirm.require({
    header: '撤销威胁拆分',
    message,
    acceptLabel: needsForce ? '强制撤销' : '确认撤销',
    rejectLabel: '取消',
    accept: () => {
      try {
        store.undoThreatSplit(operationId, needsForce)
        toast.add({ severity: 'success', summary: '拆分已撤销', detail: '主威胁已恢复，原会签重新生效。', life: 3500 })
      } catch (error) {
        toast.add({
          severity: 'error',
          summary: '撤销失败',
          detail: error instanceof SplitConflictError ? error.message : '当前状态不允许撤销。',
          life: 4500,
        })
      }
    },
  })
}

const saveThreat = (): void => {
  if (!threatForm.code.trim() || !threatForm.title.trim() || !threatForm.description.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '编号、标题和描述不能为空', life: 3000 })
    return
  }
  if (threatForm.componentIds.length === 0 && threatForm.flowIds.length === 0) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '至少关联一个组件或数据流', life: 3000 })
    return
  }
  const duplicateCode = store.data.threats.some(
    (threat) => threat.code === threatForm.code && threat.id !== threatForm.id,
  )
  if (duplicateCode) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '威胁编号已存在', life: 3000 })
    return
  }

  const saved: Threat = {
    ...threatForm,
    id: threatForm.id || createId('thr'),
    revision: threatForm.id ? store.data.currentRevision + 1 : store.data.currentRevision,
    reviewStatus: threatForm.id ? 'in_review' : threatForm.reviewStatus,
  }
  store.saveThreat(saved)
  selectedId.value = saved.id
  editorVisible.value = false
  toast.add({
    severity: 'success',
    summary: '威胁已保存',
    detail: saved.id === threatForm.id ? '修订后已进入重新审核' : saved.title,
    life: 3000,
  })
}
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="威胁分析"
      title="威胁清单"
      description="把威胁、攻击路径、现有控制和风险关联到具体组件或数据流，并跟踪修订后的审核状态。"
    />

    <section class="panel filter-panel">
      <div class="toolbar-row">
        <div class="toolbar-field keyword-field">
          <span>关键词</span>
          <InputText v-model="keyword" placeholder="搜索编号、标题或描述" />
        </div>
        <div class="toolbar-field">
          <span>严重级别</span>
          <Select
            v-model="severityFilter"
            :options="severityOptions"
            option-label="label"
            option-value="value"
            placeholder="全部"
            show-clear
          />
        </div>
        <div class="toolbar-field">
          <span>处置状态</span>
          <Select
            v-model="statusFilter"
            :options="statusOptions"
            option-label="label"
            option-value="value"
            placeholder="全部"
            show-clear
          />
        </div>
        <div class="toolbar-field">
          <span>威胁类别</span>
          <Select
            v-model="categoryFilter"
            :options="categoryOptions"
            option-label="label"
            option-value="value"
            placeholder="全部"
            show-clear
          />
        </div>
        <div class="filter-actions">
          <Button label="清空" severity="secondary" text @click="clearFilters" />
          <Button label="新增威胁" icon="pi pi-plus" @click="addThreat" />
        </div>
      </div>
    </section>

    <div class="threat-workspace">
      <section class="panel list-panel">
        <div class="panel-header">
          <h2 class="panel-title">威胁结果 {{ filteredThreats.length }} 条</h2>
        </div>
        <DataTable
          :value="filteredThreats"
          dataKey="id"
          selectionMode="single"
          :selection="selectedThreat"
          size="small"
          scrollable
          scrollHeight="640px"
          @row-click="({ data }) => (selectedId = data.id)"
        >
          <Column field="code" header="编号" style="width: 108px">
            <template #body="{ data }">
              <strong class="threat-code">{{ data.code }}</strong>
              <i
                v-if="data.parentThreatId"
                class="pi pi-sitemap lineage-dot"
                title="拆分子威胁"
              ></i>
            </template>
          </Column>
          <Column field="title" header="威胁" />
          <Column header="级别" style="width: 74px">
            <template #body="{ data }">
              <StatusTag :value="data.severity" kind="severity" />
            </template>
          </Column>
          <Column header="状态" style="width: 90px">
            <template #body="{ data }">
              <StatusTag :value="data.status" kind="status" />
            </template>
          </Column>
          <template #empty>
            <div class="empty-state">没有符合条件的威胁。</div>
          </template>
        </DataTable>
      </section>

      <aside class="panel detail-panel">
        <template v-if="selectedThreat">
          <div class="detail-head">
            <div>
              <div class="threat-code">{{ selectedThreat.code }}</div>
              <h2>{{ selectedThreat.title }}</h2>
              <span v-if="selectedThreat.parentThreatId" class="lineage-chip">
                <i class="pi pi-sitemap"></i> 子威胁 · 源自 {{ codeOf(selectedThreat.parentThreatId) }}
              </span>
              <span v-else-if="childThreats.length > 0" class="lineage-chip parent">
                <i class="pi pi-sitemap"></i> 主威胁 · {{ childThreats.length }} 个子场景
              </span>
            </div>
            <div class="detail-actions">
              <Button icon="pi pi-pencil" label="编辑" outlined @click="editThreat" />
              <Button icon="pi pi-clone" label="拆分" severity="info" outlined @click="openSplit" />
            </div>
          </div>
          <div class="status-line">
            <StatusTag :value="selectedThreat.severity" kind="severity" />
            <StatusTag :value="selectedThreat.status" kind="status" />
            <StatusTag :value="selectedThreat.reviewStatus" kind="review" />
            <span class="muted">v1.{{ selectedThreat.revision }}</span>
          </div>

          <p class="description">{{ selectedThreat.description }}</p>

          <section class="detail-section">
            <h3>关联组件</h3>
            <div class="relation-list">
              <div v-for="component in relatedComponents" :key="component?.id" class="relation-item">
                <strong>{{ component?.name }}</strong>
                <span>{{ component?.type }} · {{ component?.owner }}</span>
              </div>
            </div>
          </section>

          <section class="detail-section">
            <h3>攻击路径</h3>
            <div v-for="path in relatedPaths" :key="path?.id" class="path-item">
              <strong>{{ path?.name }}</strong>
              <ol>
                <li v-for="step in path?.steps" :key="step">{{ step }}</li>
              </ol>
            </div>
            <div v-if="relatedPaths.length === 0" class="muted">尚未关联攻击路径。</div>
          </section>

          <section class="detail-section" v-if="childThreats.length > 0 || parentThreat">
            <h3>拆分谱系</h3>
            <div v-if="parentThreat" class="lineage-line">
              <span class="muted">父威胁</span>
              <strong>{{ parentThreat.code }} {{ parentThreat.title }}</strong>
            </div>
            <div v-for="child in childThreats" :key="child.id" class="lineage-line">
              <span class="muted">子威胁</span>
              <strong>{{ child.code }} {{ child.title }}</strong>
              <StatusTag :value="child.reviewStatus" kind="review" />
            </div>
            <Button
              v-if="lastSplitOperation"
              label="撤销本次拆分"
              icon="pi pi-undo"
              severity="warning"
              text
              size="small"
              @click="requestUndo"
            />
          </section>

          <section class="detail-section">
            <h3>现有控制</h3>
            <div v-for="control in relatedControls" :key="control?.id" class="control-line">
              <div>
                <strong>{{ control?.name }}</strong>
                <span>{{ control?.type }} · {{ control?.owner }}</span>
              </div>
              <StatusTag v-if="control" :value="control.status" kind="status" />
            </div>
          </section>
        </template>
        <div v-else class="empty-state">从左侧选择一条威胁查看分析详情。</div>
      </aside>
    </div>

    <ThreatSplitDialog
      v-model:visible="splitDialogVisible"
      :threat="selectedThreat"
    />

    <Dialog
      v-model:visible="editorVisible"
      :header="threatForm.id ? '编辑威胁并触发重新审核' : '新增威胁'"
      modal
      :style="{ width: '860px' }"
    >
      <div class="editor-form">
        <div class="field">
          <label>威胁编号</label>
          <InputText v-model="threatForm.code" />
        </div>
        <div class="field">
          <label>严重级别</label>
          <Select
            v-model="threatForm.severity"
            :options="severityOptions"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field field-wide">
          <label>威胁标题</label>
          <InputText v-model="threatForm.title" />
        </div>
        <div class="field">
          <label>威胁类别</label>
          <Select
            v-model="threatForm.category"
            :options="categoryOptions"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field">
          <label>处置状态</label>
          <Select
            v-model="threatForm.status"
            :options="statusOptions"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field field-wide">
          <label>威胁描述</label>
          <Textarea v-model="threatForm.description" rows="4" />
        </div>
        <div class="field field-wide">
          <label>关联组件</label>
          <MultiSelect
            v-model="threatForm.componentIds"
            :options="store.data.components"
            option-label="name"
            option-value="id"
            display="chip"
            filter
          />
        </div>
        <div class="field">
          <label>关联数据流</label>
          <MultiSelect
            v-model="threatForm.flowIds"
            :options="store.data.flows"
            option-label="name"
            option-value="id"
            display="chip"
            filter
          />
        </div>
        <div class="field">
          <label>外部依赖</label>
          <MultiSelect
            v-model="threatForm.externalDependencyIds"
            :options="store.data.dependencies"
            option-label="name"
            option-value="id"
            display="chip"
          />
        </div>
        <div class="field">
          <label>攻击路径</label>
          <MultiSelect
            v-model="threatForm.attackPathIds"
            :options="store.data.attackPaths"
            option-label="name"
            option-value="id"
            display="chip"
          />
        </div>
        <div class="field">
          <label>现有控制</label>
          <MultiSelect
            v-model="threatForm.controlIds"
            :options="store.data.controls"
            option-label="name"
            option-value="id"
            display="chip"
          />
        </div>
        <div class="field">
          <label>关联风险</label>
          <MultiSelect
            v-model="threatForm.riskIds"
            :options="store.data.risks"
            option-label="title"
            option-value="id"
            display="chip"
          />
        </div>
        <div class="field">
          <label>审核状态</label>
          <Select
            v-model="threatForm.reviewStatus"
            :options="reviewOptions"
            option-label="label"
            option-value="value"
          />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="editorVisible = false" />
        <Button label="保存威胁" icon="pi pi-check" @click="saveThreat" />
      </template>
    </Dialog>
  </div>
</template>

<style scoped>
.filter-panel {
  padding: 14px 16px;
}

.keyword-field {
  min-width: 280px;
}

.threat-workspace {
  display: grid;
  grid-template-columns: minmax(620px, 1.2fr) minmax(390px, 0.8fr);
  gap: 16px;
  align-items: start;
}

.list-panel {
  min-width: 0;
  overflow: hidden;
}

.threat-code {
  color: #3268a6;
  font-family: monospace;
  font-size: 12px;
}

.lineage-dot {
  margin-left: 6px;
  color: #7b94b6;
  font-size: 11px;
}

.detail-actions {
  display: flex;
  gap: 8px;
  flex-shrink: 0;
}

.lineage-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  margin-top: 8px;
  padding: 2px 9px;
  border-radius: 10px;
  background: #eef3fa;
  color: #41658f;
  font-size: 10px;
}

.lineage-chip.parent {
  background: #eef7f0;
  color: #34684c;
}

.lineage-line {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  border: 1px solid #e4e8ef;
  border-radius: 5px;
}

.lineage-line + .lineage-line {
  margin-top: 6px;
}

.detail-panel {
  position: sticky;
  top: 82px;
  max-height: calc(100vh - 106px);
  overflow: auto;
}

.detail-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 18px;
  padding: 18px;
  border-bottom: 1px solid #e5e9ef;
}

.detail-head h2 {
  margin: 6px 0 0;
  font-size: 18px;
  line-height: 1.4;
}

.status-line {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 18px;
}

.description {
  margin: 0;
  padding: 0 18px 18px;
  color: #4f5b70;
  font-size: 13px;
  line-height: 1.7;
}

.detail-section {
  padding: 16px 18px;
  border-top: 1px solid #e8ebf0;
}

.detail-section h3 {
  margin: 0 0 12px;
  font-size: 13px;
}

.relation-list {
  display: grid;
  gap: 8px;
}

.relation-item,
.control-line {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 10px;
  border: 1px solid #e2e6ec;
  border-radius: 5px;
}

.relation-item {
  display: grid;
  justify-content: stretch;
}

.relation-item span,
.control-line span {
  color: #727d90;
  font-size: 11px;
}

.path-item {
  padding: 11px;
  border-left: 3px solid #8aa4c3;
  background: #f7f9fb;
}

.path-item strong {
  font-size: 12px;
}

.path-item ol {
  margin: 8px 0 0;
  padding-left: 19px;
  color: #5b687d;
  font-size: 12px;
  line-height: 1.7;
}

.control-line + .control-line {
  margin-top: 8px;
}
</style>
