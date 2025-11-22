/**
 * 檢測 Store
 */
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { detectionAPI } from '@/services/api'
import { ElMessage } from 'element-plus'

export const useDetectionStore = defineStore('detection', () => {
  // 狀態
  const modelStatus = ref(null)
  const currentJob = ref(null)
  const results = ref(null)
  const loading = ref(false)
  const polling = ref(false)

  // 計算屬性
  const totalAnomalies = computed(() => {
    return results.value?.total_anomalies || 0
  })

  const buckets = computed(() => {
    return results.value?.buckets || []
  })

  // 方法：獲取模型狀態
  async function fetchModelStatus() {
    try {
      const { data } = await detectionAPI.getStatus()
      modelStatus.value = data
      return data
    } catch (error) {
      ElMessage.error('獲取模型狀態失敗')
      throw error
    }
  }

  // 方法：執行檢測（同步）
  async function runDetection(minutes) {
    loading.value = true
    try {
      // 直接執行檢測並獲取結果（不需要輪詢）
      const { data } = await detectionAPI.runDetection(minutes)

      if (data.status === 'success') {
        results.value = data.results
        ElMessage.success('檢測完成！')
        return results.value
      } else {
        throw new Error(data.error || '檢測失敗')
      }
    } catch (error) {
      ElMessage.error('檢測失敗：' + (error.response?.data?.error || error.message))
      throw error
    } finally {
      loading.value = false
    }
  }

  // 方法：執行檢測（使用自訂時間範圍）
  async function runDetectionWithCustomTime(startTime, endTime) {
    loading.value = true
    try {
      // 使用自訂時間範圍執行檢測
      const { data } = await detectionAPI.runDetectionWithCustomTime(startTime, endTime)

      if (data.status === 'success') {
        results.value = data.results
        ElMessage.success('檢測完成！')
        return results.value
      } else {
        throw new Error(data.error || '檢測失敗')
      }
    } catch (error) {
      ElMessage.error('檢測失敗：' + (error.response?.data?.error || error.message))
      throw error
    } finally {
      loading.value = false
    }
  }

  // 方法：輪詢檢測結果
  async function pollResults(jobId, maxAttempts = 60) {
    polling.value = true
    let attempts = 0

    const poll = async () => {
      try {
        const { data } = await detectionAPI.getResults(jobId)

        if (data.status === 'completed') {
          results.value = data.results
          polling.value = false
          return true
        } else if (data.status === 'failed') {
          polling.value = false
          throw new Error(data.error || '檢測失敗')
        } else {
          // 繼續輪詢
          attempts++
          if (attempts < maxAttempts) {
            await new Promise(resolve => setTimeout(resolve, 1000))
            return poll()
          } else {
            polling.value = false
            throw new Error('檢測超時')
          }
        }
      } catch (error) {
        polling.value = false
        throw error
      }
    }

    return poll()
  }

  // 方法：獲取異常統計
  async function fetchStats(days = 7) {
    try {
      const { data } = await detectionAPI.getStats(days)
      return data.stats
    } catch (error) {
      ElMessage.error('獲取統計失敗')
      throw error
    }
  }

  // 重置狀態
  function reset() {
    results.value = null
    currentJob.value = null
    loading.value = false
    polling.value = false
  }

  return {
    // 狀態
    modelStatus,
    currentJob,
    results,
    loading,
    polling,

    // 計算屬性
    totalAnomalies,
    buckets,

    // 方法
    fetchModelStatus,
    runDetection,
    runDetectionWithCustomTime,
    fetchStats,
    reset
  }
})
