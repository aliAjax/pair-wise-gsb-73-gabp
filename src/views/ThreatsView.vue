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
import type { Severity, Threat } from '@/models/domain'
import { createId } from '@/services/repository'
import type { SplitThreatInput, ThreatRelationType } from '@/services/threatSplit'
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
const splitVisible = ref(false)
const splitSubmitting = ref(false)
const splitDraftKey = ref(0)

interface SplitChildDraft {
  localId: string
  code: string
  title: string
  description: string
  severity: Severity
  assignments: Record<ThreatRelationType, string[]>
}

const createEmptyAssignments = (): Record<ThreatRelationType, string[]> => ({
  componentIds: [],
  flowIds: [],
  externalDependencyIds: [],
  attackPathIds: [],
  controlIds: [],
  riskIds: [],
  mitigationIds: [],
})

const splitChildren = ref<SplitChildDraft[]>([])

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

type RelationField = Exclude<ThreatRelationType, 'mitigationIds'>
const relationFields: RelationField[] = [
  'componentIds',
  'flowIds',
  'externalDependencyIds',
  'attackPathIds',
  'controlIds',
  'riskIds',
]
const relationLabels: Record<ThreatRelationType, string> = {
  componentIds: '组件',
  flowIds: '数据流',
  externalDependencyIds: '外部依赖',
  attackPathIds: '攻击路径',
  controlIds: '缓解/控制',
  riskIds: '风险',
  mitigationIds: '缓解任务',
}

const parentMitigations = computed(() =>
  store.data.mitigations.filter((task) => task.threatId === selectedThreat.value?.id),
)

const relationOptions = computed(() => ({
  componentIds: store.data.components,
  flowIds: store.data.flows,
  externalDependencyIds: store.data.dependencies,
  attackPathIds: store.data.attackPaths,
  controlIds: store.data.controls,
  riskIds: store.data.risks,
  mitigationIds: parentMitigations.value,
}))

const allRelationTypes: ThreatRelationType[] = [...relationFields, 'mitigationIds']

const parentRemainingCounts = computed(() => {
  const counts = {} as Record<ThreatRelationType, number>
  allRelationTypes.forEach((type) => {
    const parentIds =
      type === 'mitigationIds'
        ? parentMitigations.value.map((task) => task.id)
        : selectedThreat.value?.[type] ?? []
    const assignedIds = new Set(splitChildren.value.flatMap((child) => child.assignments[type]))
    counts[type] = parentIds.filter((id) => !assignedIds.has(id)).length
  })
  return counts
})

const childAssignmentCounts = (child: SplitChildDraft): number =>
  allRelationTypes.reduce((total, type) => total + child.assignments[type].length, 0)

const optionLabelFor = (type: ThreatRelationType): string =>
  type === 'riskIds' || type === 'mitigationIds' ? 'title' : 'name'

const availableFor = (child: SplitChildDraft, type: ThreatRelationType) => {
  const parentIds =
    type === 'mitigationIds'
      ? parentMitigations.value.map((task) => task.id)
      : selectedThreat.value?.[type] ?? []
  const assignedByOthers = new Set(
    splitChildren.value
      .filter((item) => item.localId !== child.localId)
      .flatMap((item) => item.assignments[type]),
  )
  return parentIds
    .filter((id) => !assignedByOthers.has(id))
    .map((id) => relationOptions.value[type].find((item) => item.id === id))
    .filter(Boolean)
}

const childThreats = computed(() => {
  const operationId = selectedThreat.value?.splitOperationId
  return store.data.threats.filter(
    (threat) => threat.parentThreatId === selectedThreat.value?.id && threat.splitOperationId === operationId,
  )
})

const canSplitSelected = computed(
  () => Boolean(selectedThreat.value && !selectedThreat.value.parentThreatId && !selectedThreat.value.splitParent),
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

const nextChildCode = (): string => {
  const sequence = store.data.threats.length + splitChildren.value.length + 1
  return `TM-${String(sequence).padStart(3, '0')}`
}

const createSplitChild = (): SplitChildDraft => {
  splitDraftKey.value += 1
  return {
    localId: `draft-${splitDraftKey.value}`,
    code: nextChildCode(),
    title: '',
    description: '',
    severity: selectedThreat.value?.severity ?? 'medium',
    assignments: createEmptyAssignments(),
  }
}

const openSplit = (): void => {
  if (!selectedThreat.value || !canSplitSelected.value) return
  splitChildren.value = [
    {
      ...createSplitChild(),
      title: `${selectedThreat.value.title} · 场景一`,
      description: selectedThreat.value.description,
    },
  ]
  splitVisible.value = true
}

const addSplitChild = (): void => {
  splitChildren.value.push(createSplitChild())
}

const removeSplitChild = (localId: string): void => {
  splitChildren.value = splitChildren.value.filter((child) => child.localId !== localId)
}

const submitSplit = async (): Promise<void> => {
  if (!selectedThreat.value) return
  if (splitChildren.value.length === 0) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '至少保留一个子威胁场景', life: 3000 })
    return
  }

  splitSubmitting.value = true
  try {
    const children: SplitThreatInput[] = splitChildren.value.map((child) => ({
      code: child.code,
      title: child.title,
      description: child.description,
      severity: child.severity,
      assignments: child.assignments,
    }))
    const result = await store.splitThreats({
      parentThreatId: selectedThreat.value.id,
      children,
    })
    selectedId.value = result.children[0]?.id ?? result.parent.id
    splitVisible.value = false
    toast.add({
      severity: 'success',
      summary: result.duplicated ? '拆分结果已复用' : '威胁已拆分',
      detail: result.duplicated
        ? '检测到相同拆分请求，已返回同一份结果'
        : '原会签已失效，子威胁已分别进入会签',
      life: 3200,
    })
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: '拆分失败',
      detail: error instanceof Error ? error.message : '已从检查点恢复，请重试',
      life: 4000,
    })
  } finally {
    splitSubmitting.value = false
  }
}

const confirmRevokeSplit = (): void => {
  if (!selectedThreat.value?.splitOperationId) return
  const operationId = selectedThreat.value.splitOperationId
  const parentId = selectedThreat.value.parentThreatId ?? selectedThreat.value.id
  confirm.require({
    message: '撤销后子威胁及其会签意见将删除，已分配关系会回填到主威胁，并恢复拆分前会签状态。',
    header: '撤销父子拆分',
    icon: 'pi pi-exclamation-triangle',
    acceptLabel: '撤销拆分',
    rejectLabel: '保留',
    accept: async () => {
      try {
        await store.revokeThreatSplit(operationId)
        selectedId.value = parentId
        toast.add({ severity: 'success', summary: '拆分已撤销', detail: '主威胁已恢复', life: 3000 })
      } catch (error) {
        toast.add({
          severity: 'error',
          summary: '撤销失败',
          detail: error instanceof Error ? error.message : '请检查版本后重试',
          life: 3500,
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
          <Column field="code" header="编号" style="width: 92px">
            <template #body="{ data }">
              <strong class="threat-code">{{ data.code }}</strong>
            </template>
          </Column>
          <Column field="title" header="威胁">
            <template #body="{ data }">
              <div>{{ data.title }}</div>
              <span v-if="data.parentThreatId" class="lineage-tag child-tag">子威胁</span>
              <span v-else-if="data.splitParent" class="lineage-tag parent-tag">主威胁</span>
            </template>
          </Column>
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
            </div>
            <div class="detail-actions">
              <Button
                v-if="selectedThreat.splitOperationId"
                label="撤销拆分"
                icon="pi pi-undo"
                severity="danger"
                outlined
                size="small"
                @click="confirmRevokeSplit"
              />
              <Button icon="pi pi-pencil" label="编辑" outlined size="small" @click="editThreat" />
              <Button
                label="父子拆分"
                icon="pi pi-sitemap"
                size="small"
                :disabled="!canSplitSelected"
                @click="openSplit"
              />
            </div>
          </div>
          <div class="status-line">
            <StatusTag :value="selectedThreat.severity" kind="severity" />
            <StatusTag :value="selectedThreat.status" kind="status" />
            <StatusTag :value="selectedThreat.reviewStatus" kind="review" />
            <span class="muted">v1.{{ selectedThreat.revision }}</span>
          </div>

          <p class="description">{{ selectedThreat.description }}</p>

          <div v-if="selectedThreat?.parentThreatId" class="split-banner child-banner">
            <i class="pi pi-sitemap"></i>
            <span>
              子威胁，来源：
              <button type="button" @click="selectedId = selectedThreat?.parentThreatId ?? ''">
                {{ store.data.threats.find((item) => item.id === selectedThreat?.parentThreatId)?.code ?? '原威胁' }}
              </button>
            </span>
          </div>
          <div v-else-if="selectedThreat?.splitParent" class="split-banner parent-banner">
            <i class="pi pi-database"></i>
            <span>主威胁：未选中的关系保留在这里；子威胁单独进入会签。</span>
          </div>

          <section v-if="childThreats.length > 0" class="detail-section child-links">
            <h3>子威胁会签</h3>
            <button
              v-for="child in childThreats"
              :key="child.id"
              type="button"
              class="child-link"
              @click="selectedId = child.id"
            >
              <span>{{ child.code }}</span>
              <strong>{{ child.title }}</strong>
              <StatusTag :value="child.reviewStatus" kind="review" />
            </button>
          </section>

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

    <Dialog
      v-model:visible="splitVisible"
      :header="`父子拆分 · ${selectedThreat?.code ?? ''}`"
      modal
      :style="{ width: '1120px' }"
      class="split-dialog"
    >
      <div class="split-editor">
        <div class="split-intro">
          <div>
            <strong>{{ selectedThreat?.title }}</strong>
            <p>把组件、数据流、攻击路径、风险和缓解措施按场景分配给子威胁；未分配的关系继续留在主威胁。</p>
          </div>
          <div class="remaining-summary">
            <span v-for="type in allRelationTypes" :key="type" class="remaining-pill">
              {{ relationLabels[type] }} 留主 {{ parentRemainingCounts[type] }}
            </span>
          </div>
        </div>

        <div class="split-child-grid">
          <article v-for="(child, index) in splitChildren" :key="child.localId" class="split-child-card">
            <header>
              <strong>子场景 {{ index + 1 }} · {{ childAssignmentCounts(child) }} 个对象</strong>
              <Button
                v-if="splitChildren.length > 1"
                icon="pi pi-trash"
                severity="danger"
                text
                rounded
                @click="removeSplitChild(child.localId)"
              />
            </header>
            <div class="split-child-form">
              <div class="field">
                <label>子威胁编号</label>
                <InputText v-model="child.code" />
              </div>
              <div class="field">
                <label>严重级别</label>
                <Select v-model="child.severity" :options="severityOptions" option-label="label" option-value="value" />
              </div>
              <div class="field field-wide">
                <label>场景标题</label>
                <InputText v-model="child.title" />
              </div>
              <div class="field field-wide">
                <label>场景描述</label>
                <Textarea v-model="child.description" rows="3" />
              </div>

              <div v-for="type in relationFields" :key="type" class="field split-assignment">
                <label>{{ relationLabels[type] }}</label>
                <MultiSelect
                  v-model="child.assignments[type]"
                  :options="availableFor(child, type)"
                  :option-label="optionLabelFor(type)"
                  option-value="id"
                  display="chip"
                  filter
                  :placeholder="`选择归属于子场景的${relationLabels[type]}`"
                />
              </div>
              <div class="field split-assignment">
                <label>{{ relationLabels.mitigationIds }}</label>
                <MultiSelect
                  v-model="child.assignments.mitigationIds"
                  :options="availableFor(child, 'mitigationIds')"
                  :option-label="optionLabelFor('mitigationIds')"
                  option-value="id"
                  display="chip"
                  filter
                  placeholder="选择需要随场景迁移的缓解任务"
                />
              </div>
            </div>
          </article>
        </div>

        <Button label="增加子场景" icon="pi pi-plus" severity="secondary" outlined @click="addSplitChild" />
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined :disabled="splitSubmitting" @click="splitVisible = false" />
        <Button
          :label="splitSubmitting ? '提交中…' : '提交拆分'"
          icon="pi pi-check"
          :loading="splitSubmitting"
          @click="submitSplit"
        />
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

.lineage-tag {
  display: inline-block;
  margin-top: 4px;
  padding: 2px 6px;
  border-radius: 999px;
  font-size: 10px;
  font-weight: 700;
}

.child-tag {
  color: #2d5f96;
  background: #eef5ff;
}

.parent-tag {
  color: #805b18;
  background: #fff5df;
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

.detail-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.split-banner {
  display: flex;
  align-items: center;
  gap: 9px;
  margin: 0 18px 16px;
  padding: 10px 12px;
  border-radius: 6px;
  font-size: 12px;
}

.split-banner i {
  font-size: 13px;
}

.child-banner {
  border: 1px solid #bfd7f2;
  background: #f3f8ff;
  color: #2d5f96;
}

.parent-banner {
  border: 1px solid #ead7ae;
  background: #fffaf0;
  color: #805b18;
}

.split-banner button {
  padding: 0;
  border: 0;
  color: inherit;
  font-weight: 700;
  text-decoration: underline;
  background: transparent;
  cursor: pointer;
}

.split-editor {
  display: grid;
  gap: 16px;
}

.split-intro {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  padding: 14px;
  border: 1px solid #dce4ee;
  border-radius: 7px;
  background: #f8fafc;
}

.split-intro p {
  margin: 6px 0 0;
  color: #657188;
  font-size: 12px;
  line-height: 1.6;
}

.remaining-summary {
  display: flex;
  align-content: flex-start;
  justify-content: flex-end;
  gap: 6px;
  flex-wrap: wrap;
  max-width: 430px;
}

.remaining-pill {
  padding: 4px 8px;
  border: 1px solid #d7deea;
  border-radius: 999px;
  color: #526078;
  background: #fff;
  font-size: 11px;
  white-space: nowrap;
}

.split-child-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
  gap: 14px;
}

.split-child-card {
  padding: 14px;
  border: 1px solid #dce2ea;
  border-radius: 7px;
  background: #fff;
}

.split-child-card > header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 14px;
}

.split-child-form {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.split-child-form .field-wide,
.split-child-form .split-assignment {
  grid-column: 1 / -1;
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

.child-links {
  display: grid;
  gap: 8px;
}

.child-link {
  display: grid;
  grid-template-columns: 70px minmax(0, 1fr) auto;
  align-items: center;
  gap: 10px;
  width: 100%;
  padding: 10px;
  border: 1px solid #d7e2f0;
  border-radius: 6px;
  text-align: left;
  background: #f8fbff;
  cursor: pointer;
}

.child-link span {
  color: #3268a6;
  font-family: monospace;
  font-size: 11px;
}

.child-link strong {
  font-size: 12px;
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
