<script setup lang="ts">
import { onMounted } from 'vue'
import ConfirmDialog from 'primevue/confirmdialog'
import Toast from 'primevue/toast'
import { useToast } from 'primevue/usetoast'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()

onMounted(() => {
  if (store.lastMigrationAt) {
    toast.add({
      severity: 'info',
      summary: '旧数据已迁移',
      detail: '检测到缺少来源标记的旧数据，已按原威胁回填来源字段（originThreatId），拆分谱系可正常追溯。',
      life: 6000,
    })
  }
  const recovery = store.startupRecovery
  if (recovery && recovery.recovered.length > 0) {
    toast.add({
      severity: 'warn',
      summary: '已从检查点恢复拆分',
      detail: `检测到 ${recovery.recovered.length} 个未完成的拆分检查点，已确定性重放并只生成一份结果。`,
      life: 7000,
    })
  }
})
</script>

<template>
  <RouterView />
  <Toast position="top-right" />
  <ConfirmDialog />
</template>
