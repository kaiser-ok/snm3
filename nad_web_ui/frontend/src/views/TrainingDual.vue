<template>
  <div class="training-dual">
    <!-- 模式說明卡片 -->
    <el-card shadow="never" class="mode-info-card">
      <template #header>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span>雙視角異常偵測</span>
          <el-tooltip placement="right" raw-content>
            <template #content>
              <div style="max-width: 500px; line-height: 1.8;">
                <h3 style="color: #409EFF; margin: 0 0 12px 0;">🔍 雙視角分析說明</h3>
                <p><strong>By Src (來源 IP 視角):</strong></p>
                <ul>
                  <li>分析每個來源 IP 的行為模式</li>
                  <li>偵測：掃描攻擊、DDoS 來源、惡意流量發送者</li>
                  <li>關鍵特徵：unique_dsts (目標數量)、流量特徵</li>
                </ul>
                <p><strong>By Dst (目標 IP 視角):</strong></p>
                <ul>
                  <li>分析每個目標 IP 被連接的模式</li>
                  <li>偵測：DDoS 目標、被掃描主機、異常服務器</li>
                  <li>關鍵特徵：unique_srcs (來源數量)、連線特徵</li>
                </ul>
              </div>
            </template>
            <el-icon style="cursor: help; color: #409EFF;">
              <InfoFilled />
            </el-icon>
          </el-tooltip>
        </div>
      </template>
      <el-alert type="info" :closable="false">
        兩種視角互補，可同時訓練並使用，提供更全面的異常偵測能力
      </el-alert>
    </el-card>

    <!-- 模式切換 Tabs -->
    <el-tabs v-model="activeMode" @tab-change="handleModeChange" class="mode-tabs">
      <!-- By Src Tab -->
      <el-tab-pane name="by_src">
        <template #label>
          <span style="font-size: 15px;">
            📤 來源 IP 視角 (By Src)
          </span>
        </template>
        <ModelTrainingPanel
          mode="by_src"
          :config="trainingStore.configBySrc"
          :progress="trainingStore.progressBySrc"
          :training="trainingStore.trainingBySrc"
        />
      </el-tab-pane>

      <!-- By Dst Tab -->
      <el-tab-pane name="by_dst">
        <template #label>
          <span style="font-size: 15px;">
            📥 目標 IP 視角 (By Dst)
          </span>
        </template>
        <ModelTrainingPanel
          mode="by_dst"
          :config="trainingStore.configByDst"
          :progress="trainingStore.progressByDst"
          :training="trainingStore.trainingByDst"
        />
      </el-tab-pane>
    </el-tabs>

    <!-- 設備映射配置 (共用，保持原有實作) -->
    <!-- 這部分內容從原 Training.vue 複製 -->
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useTrainingStore } from '@/stores/training'
import { InfoFilled } from '@element-plus/icons-vue'
import ModelTrainingPanel from '@/components/ModelTrainingPanel.vue'

const trainingStore = useTrainingStore()
const activeMode = ref('by_src')

onMounted(async () => {
  // 載入兩個模式的配置
  await trainingStore.fetchConfig()
})

function handleModeChange(mode) {
  console.log('切換到模式:', mode)
}
</script>

<style scoped>
.training-dual {
  display: flex;
  flex-direction: column;
  gap: 20px;
  width: 100%;
}

.mode-info-card {
  margin-bottom: 0;
}

.mode-tabs {
  margin-top: 20px;
}

.mode-tabs :deep(.el-tabs__item) {
  font-size: 15px;
  font-weight: 500;
}

.mode-tabs :deep(.el-tabs__item.is-active) {
  color: #409EFF;
  font-weight: 600;
}
</style>
