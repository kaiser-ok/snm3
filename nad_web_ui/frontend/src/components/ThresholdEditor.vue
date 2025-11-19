<template>
  <el-dialog
    v-model="dialogVisible"
    title="編輯二值特徵閾值"
    width="900px"
    :before-close="handleClose"
  >
    <div class="threshold-editor">
      <!-- 說明 -->
      <el-alert type="info" :closable="false" style="margin-bottom: 20px;">
        <template #title>調整二值特徵的判斷標準</template>
        這些閾值用於判斷網路行為是否符合特定模式（如高連線數、掃描行為等）
      </el-alert>

      <!-- Loading -->
      <div v-if="loading" style="text-align: center; padding: 40px;">
        <el-icon class="is-loading" :size="40"><Loading /></el-icon>
        <div style="margin-top: 10px;">載入中...</div>
      </div>

      <!-- 閾值編輯表單 -->
      <el-form v-else :model="thresholds" label-width="280px" label-position="left">
        <!-- 基本閾值 -->
        <el-divider content-position="left">
          <span style="font-weight: 600; font-size: 16px;">📊 基本行為閾值</span>
        </el-divider>

        <el-form-item>
          <template #label>
            <div class="label-with-desc">
              <span class="label-text">高連線數閾值</span>
              <span class="label-desc">flow_count 超過此值時，is_high_connection = 1</span>
            </div>
          </template>
          <el-input-number
            v-model="thresholds.high_connection"
            :min="1"
            :max="10000"
            :step="10"
            controls-position="right"
            style="width: 200px;"
          />
          <span class="unit-text">連線數</span>
        </el-form-item>

        <el-form-item>
          <template #label>
            <div class="label-with-desc">
              <span class="label-text">大流量閾值</span>
              <span class="label-desc">max_bytes 超過此值時，is_large_flow = 1</span>
            </div>
          </template>
          <el-input-number
            v-model="thresholds.large_flow"
            :min="1024"
            :max="1073741824"
            :step="1048576"
            controls-position="right"
            style="width: 200px;"
          />
          <span class="unit-text">bytes（{{ formatBytes(thresholds.large_flow) }}）</span>
        </el-form-item>

        <el-form-item>
          <template #label>
            <div class="label-with-desc">
              <span class="label-text">小封包閾值</span>
              <span class="label-desc">avg_bytes 低於此值時，is_small_packet = 1</span>
            </div>
          </template>
          <el-input-number
            v-model="thresholds.small_packet"
            :min="1"
            :max="10000"
            :step="10"
            controls-position="right"
            style="width: 200px;"
          />
          <span class="unit-text">bytes</span>
        </el-form-item>

        <!-- 掃描行為閾值 -->
        <el-divider content-position="left">
          <span style="font-weight: 600; font-size: 16px;">🔍 掃描行為閾值</span>
        </el-divider>

        <el-form-item>
          <template #label>
            <div class="label-with-desc">
              <span class="label-text">掃描目標數量閾值</span>
              <span class="label-desc">unique_dsts 超過此值（且符合平均流量條件）時，is_scanning_pattern = 1</span>
            </div>
          </template>
          <el-input-number
            v-model="thresholds.scanning_dsts"
            :min="1"
            :max="100"
            :step="1"
            controls-position="right"
            style="width: 200px;"
          />
          <span class="unit-text">個目標</span>
        </el-form-item>

        <el-form-item>
          <template #label>
            <div class="label-with-desc">
              <span class="label-text">掃描平均流量上限</span>
              <span class="label-desc">avg_bytes 低於此值（且符合目標數量條件）時，is_scanning_pattern = 1</span>
            </div>
          </template>
          <el-input-number
            v-model="thresholds.scanning_avg_bytes"
            :min="100"
            :max="100000"
            :step="100"
            controls-position="right"
            style="width: 200px;"
          />
          <span class="unit-text">bytes</span>
        </el-form-item>

        <!-- 伺服器回應特徵閾值 -->
        <el-divider content-position="left">
          <span style="font-weight: 600; font-size: 16px;">🖥️ 伺服器回應特徵閾值</span>
        </el-divider>

        <el-alert type="warning" :closable="false" style="margin-bottom: 15px; font-size: 13px;">
          is_likely_server_response 用於識別來自固定服務埠的回應流量（如 Web 伺服器）
        </el-alert>

        <el-form-item>
          <template #label>
            <div class="label-with-desc">
              <span class="label-text">源埠分散度上限</span>
              <span class="label-desc">src_port_diversity 低於此值表示使用固定服務埠</span>
            </div>
          </template>
          <el-input-number
            v-model="thresholds.server_response_src_port_diversity_max"
            :min="0.01"
            :max="1.0"
            :step="0.01"
            :precision="2"
            controls-position="right"
            style="width: 200px;"
          />
        </el-form-item>

        <el-form-item>
          <template #label>
            <div class="label-with-desc">
              <span class="label-text">目的埠分散度下限</span>
              <span class="label-desc">dst_port_diversity 高於此值表示客戶端使用隨機埠</span>
            </div>
          </template>
          <el-input-number
            v-model="thresholds.server_response_dst_port_diversity_min"
            :min="0.01"
            :max="1.0"
            :step="0.01"
            :precision="2"
            controls-position="right"
            style="width: 200px;"
          />
        </el-form-item>

        <el-form-item>
          <template #label>
            <div class="label-with-desc">
              <span class="label-text">源埠數量上限</span>
              <span class="label-desc">unique_src_ports 低於此值表示使用少數固定埠</span>
            </div>
          </template>
          <el-input-number
            v-model="thresholds.server_response_unique_src_ports_max"
            :min="1"
            :max="1000"
            :step="10"
            controls-position="right"
            style="width: 200px;"
          />
          <span class="unit-text">個埠</span>
        </el-form-item>

        <el-form-item>
          <template #label>
            <div class="label-with-desc">
              <span class="label-text">連線數下限</span>
              <span class="label-desc">flow_count 高於此值才考慮為伺服器回應</span>
            </div>
          </template>
          <el-input-number
            v-model="thresholds.server_response_flow_count_min"
            :min="1"
            :max="10000"
            :step="10"
            controls-position="right"
            style="width: 200px;"
          />
          <span class="unit-text">連線數</span>
        </el-form-item>

        <el-form-item>
          <template #label>
            <div class="label-with-desc">
              <span class="label-text">平均流量上限</span>
              <span class="label-desc">avg_bytes 低於此值才考慮為伺服器回應</span>
            </div>
          </template>
          <el-input-number
            v-model="thresholds.server_response_avg_bytes_max"
            :min="1000"
            :max="1000000"
            :step="1000"
            controls-position="right"
            style="width: 200px;"
          />
          <span class="unit-text">bytes</span>
        </el-form-item>
      </el-form>
    </div>

    <template #footer>
      <span class="dialog-footer">
        <el-button @click="handleClose">取消</el-button>
        <el-button @click="resetToDefault" :disabled="loading">重置為預設</el-button>
        <el-button
          type="primary"
          @click="handleSave"
          :disabled="loading"
        >
          儲存設定
        </el-button>
      </span>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { Loading } from '@element-plus/icons-vue'
import api from '@/services/api'

const props = defineProps({
  modelValue: Boolean
})

const emit = defineEmits(['update:modelValue', 'saved'])

const dialogVisible = computed({
  get: () => props.modelValue,
  set: (val) => emit('update:modelValue', val)
})

const loading = ref(false)

// 閾值配置
const thresholds = ref({
  high_connection: 352,
  large_flow: 7914975,
  scanning_avg_bytes: 2200,
  scanning_dsts: 30,
  small_packet: 456,
  server_response_src_port_diversity_max: 0.1,
  server_response_dst_port_diversity_min: 0.3,
  server_response_unique_src_ports_max: 100,
  server_response_flow_count_min: 100,
  server_response_avg_bytes_max: 50000
})

// 預設值（用於重置）
const defaultThresholds = {
  high_connection: 352,
  large_flow: 7914975,
  scanning_avg_bytes: 2200,
  scanning_dsts: 30,
  small_packet: 456,
  server_response_src_port_diversity_max: 0.1,
  server_response_dst_port_diversity_min: 0.3,
  server_response_unique_src_ports_max: 100,
  server_response_flow_count_min: 100,
  server_response_avg_bytes_max: 50000
}

// 格式化 bytes 顯示
const formatBytes = (bytes) => {
  if (bytes >= 1073741824) {
    return `${(bytes / 1073741824).toFixed(2)} GB`
  } else if (bytes >= 1048576) {
    return `${(bytes / 1048576).toFixed(2)} MB`
  } else if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(2)} KB`
  }
  return `${bytes} B`
}

// 載入當前閾值
const loadThresholds = async () => {
  loading.value = true
  try {
    const response = await api.get('/training/thresholds')

    if (response.data.status === 'success') {
      thresholds.value = response.data.thresholds
    } else {
      ElMessage.error('載入閾值失敗: ' + (response.data.error || '未知錯誤'))
    }
  } catch (error) {
    console.error('載入閾值錯誤:', error)
    ElMessage.error('載入閾值失敗: ' + (error.response?.data?.error || error.message))
  } finally {
    loading.value = false
  }
}

// 重置為預設值
const resetToDefault = () => {
  thresholds.value = { ...defaultThresholds }
  ElMessage.success('已重置為預設值')
}

// 儲存閾值
const handleSave = async () => {
  loading.value = true
  try {
    const response = await api.put('/training/thresholds', thresholds.value)

    if (response.data.status === 'success') {
      ElMessage.success(response.data.message)
      emit('saved')
      dialogVisible.value = false
    } else {
      ElMessage.error(response.data.error || '儲存失敗')
    }
  } catch (error) {
    console.error('儲存閾值錯誤:', error)
    ElMessage.error('儲存閾值失敗: ' + (error.response?.data?.error || error.message))
  } finally {
    loading.value = false
  }
}

const handleClose = () => {
  dialogVisible.value = false
}

// 當對話框開啟時載入閾值
watch(() => props.modelValue, (newVal) => {
  if (newVal) {
    loadThresholds()
  }
})
</script>

<style scoped>
.threshold-editor {
  max-height: 600px;
  overflow-y: auto;
}

.label-with-desc {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.label-text {
  font-weight: 500;
  color: #303133;
  font-size: 14px;
}

.label-desc {
  font-size: 12px;
  color: #909399;
  font-weight: normal;
  line-height: 1.4;
}

.unit-text {
  margin-left: 10px;
  color: #909399;
  font-size: 13px;
}

:deep(.el-form-item) {
  margin-bottom: 22px;
}

:deep(.el-form-item__label) {
  line-height: 1.4;
  height: auto;
  padding-bottom: 8px;
}

:deep(.el-divider__text) {
  background-color: #fff;
}
</style>
