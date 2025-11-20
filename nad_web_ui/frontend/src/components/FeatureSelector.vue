<template>
  <el-dialog
    v-model="dialogVisible"
    title="選擇訓練特徵"
    width="800px"
    :before-close="handleClose"
  >
    <div class="feature-selector">
      <!-- 說明 -->
      <el-alert type="info" :closable="false" style="margin-bottom: 20px;">
        <template #title>選擇用於訓練的特徵向量</template>
        已選擇 <strong>{{ totalSelected }}</strong> 個特徵（可用：{{ totalAvailable }} 個）
        <br/>
        <span style="color: #909399; font-size: 13px;">至少需要選擇 3 個特徵</span>
      </el-alert>

      <!-- Loading -->
      <div v-if="loading" style="text-align: center; padding: 40px;">
        <el-icon class="is-loading" :size="40"><Loading /></el-icon>
        <div style="margin-top: 10px;">載入中...</div>
      </div>

      <!-- 特徵選擇 -->
      <div v-else class="feature-categories">
        <!-- 基礎特徵 -->
        <el-card shadow="never" class="feature-category">
          <template #header>
            <div class="category-header">
              <span>📊 基礎特徵</span>
              <el-checkbox
                v-model="selectAllStates.basic"
                @change="toggleCategory('basic')"
                :indeterminate="isIndeterminate('basic')"
              >
                全選
              </el-checkbox>
            </div>
          </template>
          <el-checkbox-group v-model="selected.basic" class="feature-list">
            <el-checkbox
              v-for="(info, key) in features.basic"
              :key="key"
              :label="key"
              class="feature-item"
            >
              <div class="feature-label">
                <span class="feature-name">{{ info.name }}</span>
                <span class="feature-desc">{{ info.description }}</span>
              </div>
            </el-checkbox>
          </el-checkbox-group>
        </el-card>

        <!-- 衍生特徵 -->
        <el-card shadow="never" class="feature-category">
          <template #header>
            <div class="category-header">
              <span>🔢 衍生特徵</span>
              <el-checkbox
                v-model="selectAllStates.derived"
                @change="toggleCategory('derived')"
                :indeterminate="isIndeterminate('derived')"
              >
                全選
              </el-checkbox>
            </div>
          </template>
          <el-checkbox-group v-model="selected.derived" class="feature-list">
            <el-checkbox
              v-for="(info, key) in features.derived"
              :key="key"
              :label="key"
              class="feature-item"
            >
              <div class="feature-label">
                <span class="feature-name">{{ info.name }}</span>
                <span class="feature-desc">{{ info.description }}</span>
              </div>
            </el-checkbox>
          </el-checkbox-group>
        </el-card>

        <!-- 二值特徵 -->
        <el-card shadow="never" class="feature-category">
          <template #header>
            <div class="category-header">
              <span>🏷️ 二值特徵</span>
              <el-checkbox
                v-model="selectAllStates.binary"
                @change="toggleCategory('binary')"
                :indeterminate="isIndeterminate('binary')"
              >
                全選
              </el-checkbox>
            </div>
          </template>
          <el-checkbox-group v-model="selected.binary" class="feature-list">
            <el-checkbox
              v-for="(info, key) in features.binary"
              :key="key"
              :label="key"
              class="feature-item"
            >
              <div class="feature-label">
                <span class="feature-name">{{ info.name }}</span>
                <span class="feature-desc">{{ info.description }}</span>
              </div>
            </el-checkbox>
          </el-checkbox-group>
          <div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid #ebeef5;">
            <el-button @click="openThresholdEditor" :disabled="loading" size="small" style="width: 100%;">
              ⚙️ 編輯二值特徵閾值
            </el-button>
          </div>
        </el-card>

        <!-- 對數特徵 -->
        <el-card shadow="never" class="feature-category">
          <template #header>
            <div class="category-header">
              <span>📈 對數特徵</span>
              <el-checkbox
                v-model="selectAllStates.log_transform"
                @change="toggleCategory('log_transform')"
                :indeterminate="isIndeterminate('log_transform')"
              >
                全選
              </el-checkbox>
            </div>
          </template>
          <el-checkbox-group v-model="selected.log_transform" class="feature-list">
            <el-checkbox
              v-for="(info, key) in features.log_transform"
              :key="key"
              :label="key"
              class="feature-item"
            >
              <div class="feature-label">
                <span class="feature-name">{{ info.name }}</span>
                <span class="feature-desc">{{ info.description }}</span>
              </div>
            </el-checkbox>
          </el-checkbox-group>
        </el-card>

        <!-- 設備類型特徵 -->
        <el-card shadow="never" class="feature-category">
          <template #header>
            <div class="category-header">
              <span>🖥️ 設備類型特徵</span>
              <el-checkbox
                v-model="selectAllStates.device_type"
                @change="toggleCategory('device_type')"
                :indeterminate="isIndeterminate('device_type')"
              >
                全選
              </el-checkbox>
            </div>
          </template>
          <el-checkbox-group v-model="selected.device_type" class="feature-list">
            <el-checkbox
              v-for="(info, key) in features.device_type"
              :key="key"
              :label="key"
              class="feature-item"
            >
              <div class="feature-label">
                <span class="feature-name">{{ info.name }}</span>
                <span class="feature-desc">{{ info.description }}</span>
              </div>
            </el-checkbox>
          </el-checkbox-group>
        </el-card>

        <!-- 時間序列特徵 (可選) -->
        <el-card shadow="never" class="feature-category" v-if="features.time_series && Object.keys(features.time_series).length > 0">
          <template #header>
            <div class="category-header">
              <span>⏰ 時間序列特徵（可選）</span>
              <el-checkbox
                v-model="selectAllStates.time_series"
                @change="toggleCategory('time_series')"
                :indeterminate="isIndeterminate('time_series')"
              >
                全選
              </el-checkbox>
            </div>
          </template>
          <el-alert type="warning" :closable="false" style="margin-bottom: 10px; font-size: 12px;">
            ⚠️ 時間特徵會考慮時間因素（小時、星期等），適用於偵測時間模式異常，預設不啟用
          </el-alert>
          <el-checkbox-group v-model="selected.time_series" class="feature-list">
            <el-checkbox
              v-for="(info, key) in features.time_series"
              :key="key"
              :label="key"
              class="feature-item"
            >
              <div class="feature-label">
                <span class="feature-name">{{ info.name }}</span>
                <span class="feature-desc">{{ info.description }}</span>
              </div>
            </el-checkbox>
          </el-checkbox-group>
        </el-card>
      </div>
    </div>

    <template #footer>
      <span class="dialog-footer">
        <el-button @click="handleClose">取消</el-button>
        <el-button @click="resetToDefault" :disabled="loading">重置為預設</el-button>
        <el-button
          type="primary"
          @click="handleSave"
          :disabled="totalSelected < 3 || loading"
        >
          儲存設定
        </el-button>
      </span>
    </template>
  </el-dialog>

  <!-- 閾值編輯器 -->
  <ThresholdEditor
    v-model="thresholdEditorVisible"
    @saved="handleThresholdSaved"
  />
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { Loading } from '@element-plus/icons-vue'
import api from '@/services/api'
import ThresholdEditor from './ThresholdEditor.vue'

const props = defineProps({
  modelValue: Boolean,
  mode: {
    type: String,
    default: 'by_src'
  }
})

const emit = defineEmits(['update:modelValue', 'saved'])

const dialogVisible = computed({
  get: () => props.modelValue,
  set: (val) => emit('update:modelValue', val)
})

const loading = ref(false)
const thresholdEditorVisible = ref(false)

const features = ref({
  basic: {},
  derived: {},
  binary: {},
  log_transform: {},
  device_type: {},
  time_series: {}
})

const selected = ref({
  basic: [],
  derived: [],
  binary: [],
  log_transform: [],
  device_type: [],
  time_series: []
})

const selectAllStates = ref({
  basic: false,
  derived: false,
  binary: false,
  log_transform: false,
  device_type: false,
  time_series: false
})

const totalAvailable = computed(() => {
  return Object.values(features.value).reduce((sum, cat) => sum + Object.keys(cat).length, 0)
})

const totalSelected = computed(() => {
  return Object.values(selected.value).reduce((sum, cat) => sum + cat.length, 0)
})

// 檢查是否為不確定狀態（部分選中）
const isIndeterminate = (category) => {
  const selectedCount = selected.value[category]?.length || 0
  const totalCount = Object.keys(features.value[category] || {}).length
  return selectedCount > 0 && selectedCount < totalCount
}

// 切換分類全選
const toggleCategory = (category) => {
  if (selectAllStates.value[category]) {
    selected.value[category] = Object.keys(features.value[category] || {})
  } else {
    selected.value[category] = []
  }
}

// 監控選擇變化，更新全選狀態
watch(() => selected.value, (newVal) => {
  for (const category in newVal) {
    const selectedCount = newVal[category]?.length || 0
    const totalCount = Object.keys(features.value[category] || {}).length
    selectAllStates.value[category] = selectedCount === totalCount && totalCount > 0
  }
}, { deep: true })

// 載入可用特徵
const loadFeatures = async () => {
  loading.value = true
  try {
    const response = await api.get('/training/features', {
      params: { mode: props.mode }
    })

    console.log('API Response:', response.data)

    if (response.data.status === 'success') {
      features.value = response.data.available_features
      selected.value = response.data.current_selection || {
        basic: [],
        derived: [],
        binary: [],
        log_transform: [],
        device_type: [],
        time_series: []
      }

      console.log('Features loaded:', features.value)
      console.log('Selected features:', selected.value)
      console.log('Total available:', response.data.total_available)
      console.log('Total selected:', response.data.total_selected)

      // 初始化全選狀態
      for (const category in selected.value) {
        const selectedCount = selected.value[category]?.length || 0
        const totalCount = Object.keys(features.value[category] || {}).length
        selectAllStates.value[category] = selectedCount === totalCount && totalCount > 0
      }
    } else {
      ElMessage.error('載入失敗: ' + (response.data.error || '未知錯誤'))
    }
  } catch (error) {
    console.error('載入特徵列表錯誤:', error)
    ElMessage.error('載入特徵列表失敗: ' + (error.response?.data?.error || error.message))
  } finally {
    loading.value = false
  }
}

// 重置為預設
const resetToDefault = () => {
  for (const category in features.value) {
    selected.value[category] = Object.keys(features.value[category])
    selectAllStates.value[category] = true
  }
  ElMessage.success('已重置為預設選項')
}

// 儲存設定
const handleSave = async () => {
  if (totalSelected.value < 3) {
    ElMessage.warning('至少需要選擇 3 個特徵')
    return
  }

  loading.value = true
  try {
    const response = await api.put('/training/features', {
      mode: props.mode,
      selected_features: selected.value
    })

    if (response.data.status === 'success') {
      ElMessage.success(response.data.message)
      emit('saved')
      dialogVisible.value = false
    } else {
      ElMessage.error(response.data.error || '儲存失敗')
    }
  } catch (error) {
    ElMessage.error('儲存特徵設定失敗: ' + (error.response?.data?.error || error.message))
  } finally {
    loading.value = false
  }
}

const handleClose = () => {
  dialogVisible.value = false
}

// 閾值編輯器相關函數
const openThresholdEditor = () => {
  thresholdEditorVisible.value = true
}

const handleThresholdSaved = () => {
  ElMessage.success('閾值設定已更新')
}

// 當對話框開啟時載入特徵
watch(() => props.modelValue, (newVal) => {
  if (newVal) {
    loadFeatures()
  }
})
</script>

<style scoped>
.feature-selector {
  max-height: 600px;
  overflow-y: auto;
}

.feature-categories {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.feature-category {
  border: 1px solid #ebeef5;
}

.category-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-weight: 600;
}

.feature-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
  gap: 12px;
}

.feature-item {
  height: auto;
  white-space: normal;
  line-height: 1.4;
  padding: 8px 0;
  border-bottom: 1px solid #f0f0f0;
}

.feature-item:last-child {
  border-bottom: none;
}

.feature-label {
  display: flex;
  flex-direction: column;
  gap: 4px;
  margin-left: 8px;
}

.feature-name {
  font-weight: 500;
  color: #303133;
  font-size: 14px;
}

.feature-desc {
  font-size: 12px;
  color: #909399;
}

:deep(.el-checkbox__label) {
  white-space: normal;
  line-height: 1.5;
}
</style>
