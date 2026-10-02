<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Select from 'primevue/select'
import Textarea from 'primevue/textarea'
import MultiSelect from 'primevue/multiselect'
import ToggleSwitch from 'primevue/toggleswitch'
import { useToast } from 'primevue/usetoast'
import type {
  SplitChildInput,
  SplitThreatRequest,
  Threat,
} from '@/models/domain'
import {
  RELATION_LABELS,
  validateSplitRequest,
  type RelationField,
} from '@/services/splitEngine'
import { SplitConflictError } from '@/services/splitEngine'
import { SplitSubmissionError } from '@/services/splitService'
import { useThreatModelStore } from '@/stores/threatModel'

const props = defineProps<{
  visible: boolean
  threat: Threat | null
}>()

const emit = defineEmits<{
  'update:visible': [value: boolean]
  done: []
}>()

const store = useThreatModelStore()
const toast = useToast()

const severityOptions = [
  { label: '严重', value: 'critical' },
  { label: '高', value: 'high' },
  { label: '中', value: 'medium' },
  { label: '低', value: 'low' },
]

interface ChildRow extends SplitChildInput {
  key: string
}

let rowSeed = 0
const createChildRow = (): ChildRow => ({
  key: `child-${Date.now()}-${rowSeed++}`,
  title: '',
  scenario: '',
  severity: props.threat?.severity ?? 'medium',
  componentIds: [],
  flowIds: [],
  externalDependencyIds: [],
  attackPathIds: [],
  controlIds: [],
  riskIds: [],
  mitigationIds: [],
})

const children = ref<ChildRow[]>([createChildRow()])
const simulateTwoWindows = ref(false)
const failStateWrite = ref(false)

watch(
  () => props.visible,
  (visible) => {
    if (visible) {
      children.value = [createChildRow()]
      simulateTwoWindows.value = false
      failStateWrite.value = false
    }
  },
)

const dialogVisible = computed({
  get: () => props.visible,
  set: (value) => emit('update:visible', value),
})

const relationOptions = computed(() => {
  const threat = props.threat
  if (!threat) return null
  return {
    componentIds: store.data.components.filter((item) => threat.componentIds.includes(item.id)),
    flowIds: store.data.flows.filter((item) => threat.flowIds.includes(item.id)),
    externalDependencyIds: store.data.dependencies.filter((item) =>
      threat.externalDependencyIds.includes(item.id),
    ),
    attackPathIds: store.data.attackPaths.filter((item) =>
      threat.attackPathIds.includes(item.id),
    ),
    controlIds: store.data.controls.filter((item) => threat.controlIds.includes(item.id)),
    riskIds: store.data.risks.filter((item) => threat.riskIds.includes(item.id)),
  }
})

const parentMitigations = computed(() =>
  props.threat
    ? store.data.mitigations.filter((task) => task.threatId === props.threat?.id)
    : [],
)

const availableOptions = (row: ChildRow, field: RelationField) => {
  const all = relationOptions.value?.[field] ?? []
  const taken = takenByOthers(row, field)
  return all.filter((item) => !taken.has(item.id))
}

const takenByOthers = (row: ChildRow, field: RelationField): Set<string> => {
  const taken = new Set<string>()
  children.value.forEach((other) => {
    if (other.key === row.key) return
    other[field].forEach((id) => taken.add(id))
  })
  return taken
}

const takenMitigationIds = (row: ChildRow): Set<string> => {
  const taken = new Set<string>()
  children.value.forEach((other) => {
    if (other.key === row.key) return
    other.mitigationIds.forEach((id) => taken.add(id))
  })
  return taken
}

const availableMitigations = (row: ChildRow) =>
  parentMitigations.value.filter((task) => !takenMitigationIds(row).has(task.id))

const optionText = (field: RelationField, item: { name?: string; title?: string }): string =>
  (field === 'riskIds' ? item.title : item.name) ?? ''

/** 主威胁中未被任何子威胁选中、将保留在主威胁的对象数。 */
const remaining = (field: RelationField): number => {
  const parentIds = props.threat?.[field] ?? []
  const moved = new Set(children.value.flatMap((row) => row[field]))
  return parentIds.filter((id) => !moved.has(id)).length
}

const addChild = (): void => {
  children.value.push(createChildRow())
}

const removeChild = (key: string): void => {
  children.value = children.value.filter((row) => row.key !== key)
}

const buildRequest = (): SplitThreatRequest | null => {
  if (!props.threat) return null
  return {
    parentThreatId: props.threat.id,
    baseRevision: props.threat.revision,
    children: children.value.map(({ title, scenario, severity, ...relations }) => ({
      title,
      scenario,
      severity,
      componentIds: relations.componentIds,
      flowIds: relations.flowIds,
      externalDependencyIds: relations.externalDependencyIds,
      attackPathIds: relations.attackPathIds,
      controlIds: relations.controlIds,
      riskIds: relations.riskIds,
      mitigationIds: relations.mitigationIds,
    })),
  }
}

const validationErrors = computed<string[]>(() => {
  const request = buildRequest()
  if (!request || !props.threat) return []
  return validateSplitRequest(store.data, request).errors
})

const submit = (): void => {
  const request = buildRequest()
  if (!request || !props.threat) return

  store.toggleFailureInjection(failStateWrite.value)

  try {
    if (simulateTwoWindows.value) {
      const outcome = store.simulateConcurrentSplit(request)
      dialogVisible.value = false
      toast.add({
        severity: outcome.second.deduplicated ? 'success' : 'warn',
        summary: '两窗口并发提交完成',
        detail: outcome.second.deduplicated
          ? `两个窗口只生成一份结果：${outcome.first.operation.children.length} 个子威胁（第二窗口命中去重）`
          : '警告：并发未去重，请检查账本',
        life: 5000,
      })
    } else {
      const result = store.submitSplit(request)
      dialogVisible.value = false
      toast.add({
        severity: 'success',
        summary: '拆分已提交',
        detail: `生成 ${result.operation.children.length} 个子威胁，主威胁与子威胁已分别进入会签，原会签按修订失效。`,
        life: 4000,
      })
    }
    emit('done')
  } catch (error) {
    if (error instanceof SplitSubmissionError) {
      toast.add({
        severity: 'error',
        summary: '状态写入失败',
        detail: `${error.message} 可点击「从检查点恢复」。`,
        life: 7000,
      })
    } else if (error instanceof SplitConflictError) {
      toast.add({ severity: 'error', summary: '拆分被拒绝', detail: error.message, life: 5000 })
    } else {
      toast.add({
        severity: 'error',
        summary: '拆分失败',
        detail: error instanceof Error ? error.message : String(error),
        life: 5000,
      })
    }
  } finally {
    store.toggleFailureInjection(false)
  }
}

const recover = (): void => {
  const report = store.recoverSplits()
  if (report.recovered.length > 0) {
    const reused = report.recovered.some((item) => item.deduplicated)
    toast.add({
      severity: 'success',
      summary: '已从检查点恢复',
      detail: `重放 ${report.recovered.length} 份拆分结果，${reused ? '幂等复用，未产生重复数据。' : '已落库。'}`,
      life: 6000,
    })
  } else if (report.skipped > 0) {
    toast.add({
      severity: 'warn',
      summary: '恢复未完成',
      detail: `${report.skipped} 个检查点仍然无法写入，请排查存储后重试。`,
      life: 6000,
    })
  } else {
    toast.add({ severity: 'info', summary: '没有待恢复的检查点', detail: '', life: 3000 })
  }
}

const relationFields = Object.keys(RELATION_LABELS) as RelationField[]
</script>

<template>
  <Dialog
    v-model:visible="dialogVisible"
    :header="threat ? `拆分威胁 ${threat.code}：${threat.title}` : '拆分威胁'"
    modal
    :style="{ width: '980px' }"
  >
    <div v-if="threat" class="split-dialog">
      <p class="split-hint">
        把混在一条威胁里的组件、数据流、攻击路径与缓解措施按场景分到子威胁。
        <strong>同一对象不能同时归给两个子威胁</strong>；未勾选的关系留在主威胁。拆分后原会签按修订失效，子威胁单独进入会签。
      </p>

      <div class="remaining-bar">
        <span v-for="field in relationFields" :key="field" class="remaining-chip">
          {{ RELATION_LABELS[field] }} 留在主威胁：<strong>{{ remaining(field) }}</strong>
        </span>
      </div>

      <div v-for="(row, index) in children" :key="row.key" class="child-card">
        <div class="child-card-head">
          <h3>子威胁 {{ index + 1 }} · 编号 {{ threat.code }}.{{ index + 1 }}</h3>
          <Button
            v-if="children.length > 1"
            icon="pi pi-trash"
            severity="danger"
            text
            rounded
            aria-label="删除该子场景"
            @click="removeChild(row.key)"
          />
        </div>
        <div class="child-grid">
          <div class="field field-wide">
            <label>子威胁标题</label>
            <InputText v-model="row.title" :placeholder="`例如：${threat.title}（公网枚举场景）`" />
          </div>
          <div class="field">
            <label>严重级别</label>
            <Select
              v-model="row.severity"
              :options="severityOptions"
              option-label="label"
              option-value="value"
            />
          </div>
          <div class="field field-wide">
            <label>场景说明</label>
            <Textarea v-model="row.scenario" rows="2" placeholder="描述该子威胁对应的攻击场景" />
          </div>

          <div v-for="field in relationFields" :key="field" class="field field-wide">
            <label>
              归属{{ RELATION_LABELS[field] }}
              <span class="field-hint">
                已选 {{ row[field].length }} / 主威胁 {{ threat[field].length }}
              </span>
            </label>
            <MultiSelect
              v-model="row[field]"
              :options="availableOptions(row, field)"
              :option-label="(item) => optionText(field, item)"
              option-value="id"
              display="chip"
              filter
              :placeholder="`勾选归给本场景的${RELATION_LABELS[field]}，不勾选则留在主威胁`"
            />
          </div>

          <div class="field field-wide">
            <label>
              迁移缓解任务
              <span class="field-hint">已选 {{ row.mitigationIds.length }}</span>
            </label>
            <MultiSelect
              v-model="row.mitigationIds"
              :options="availableMitigations(row)"
              option-label="title"
              option-value="id"
              display="chip"
              filter
              placeholder="随该场景迁移的现有缓解任务"
            />
          </div>
        </div>
      </div>

      <Button label="增加一个子场景" icon="pi pi-plus" severity="secondary" outlined @click="addChild" />

      <ul v-if="validationErrors.length > 0" class="validation-box">
        <li v-for="error in validationErrors" :key="error">{{ error }}</li>
      </ul>

      <div class="demo-box">
        <h4>并发与故障演练</h4>
        <div class="demo-row">
          <ToggleSwitch v-model="simulateTwoWindows" :input-id="`sim-${threat.id}`" />
          <label :for="`sim-${threat.id}`">模拟两个窗口同时提交（应只生成一份结果，第二窗口命中去重）</label>
        </div>
        <div class="demo-row">
          <ToggleSwitch v-model="failStateWrite" :input-id="`fail-${threat.id}`" />
          <label :for="`fail-${threat.id}`">注入状态写入失败（保留检查点，随后恢复）</label>
        </div>
        <Button
          label="从检查点恢复"
          icon="pi pi-history"
          severity="secondary"
          text
          @click="recover"
        />
      </div>
    </div>

    <template #footer>
      <Button label="取消" severity="secondary" outlined @click="dialogVisible = false" />
      <Button
        label="提交拆分"
        icon="pi pi-check"
        :disabled="validationErrors.length > 0"
        @click="submit"
      />
    </template>
  </Dialog>
</template>

<style scoped>
.split-hint {
  margin: 0 0 12px;
  padding: 10px 12px;
  border-radius: 6px;
  background: #f4f7fb;
  color: #51607a;
  font-size: 12px;
  line-height: 1.7;
}

.remaining-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 14px;
}

.remaining-chip {
  padding: 3px 10px;
  border: 1px solid #dde3ec;
  border-radius: 12px;
  background: #fff;
  color: #6a7588;
  font-size: 11px;
}

.remaining-chip strong {
  color: #2e5f9e;
}

.child-card {
  margin-bottom: 14px;
  padding: 14px 16px;
  border: 1px solid #d9e0ea;
  border-radius: 8px;
  background: #fbfcfe;
}

.child-card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
}

.child-card-head h3 {
  margin: 0;
  font-size: 13px;
  color: #32527a;
}

.child-grid {
  display: grid;
  grid-template-columns: 1fr 160px;
  gap: 10px 14px;
}

.field {
  display: grid;
  gap: 5px;
}

.field-wide {
  grid-column: 1 / -1;
}

.field label {
  font-size: 11px;
  color: #5b677c;
}

.field-hint {
  margin-left: 8px;
  color: #93a0b3;
}

.validation-box {
  margin: 12px 0;
  padding: 10px 14px;
  border: 1px solid #f0c2c2;
  border-radius: 6px;
  background: #fdf3f3;
  color: #b23c3c;
  font-size: 12px;
  line-height: 1.8;
}

.demo-box {
  margin-top: 16px;
  padding: 12px 14px;
  border: 1px dashed #c5d0df;
  border-radius: 7px;
  background: #f8fafd;
}

.demo-box h4 {
  margin: 0 0 8px;
  font-size: 12px;
  color: #46546c;
}

.demo-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
  color: #5b677c;
  font-size: 12px;
}
</style>
