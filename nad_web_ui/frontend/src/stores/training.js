/**
 * 訓練 Store
 */
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { trainingAPI } from '@/services/api'
import { ElMessage } from 'element-plus'

export const useTrainingStore = defineStore('training', () => {
  // 狀態
  const config = ref(null)
  const trainingJob = ref(null)
  const progress = ref({
    step: '',
    message: '',
    percent: 0
  })
  const history = ref([])
  const loading = ref(false)
  const training = ref(false)

  // 雙模式支援
  const configBySrc = ref(null)
  const configByDst = ref(null)
  const trainingJobBySrc = ref(null)
  const trainingJobByDst = ref(null)
  const progressBySrc = ref({ step: '', message: '', percent: 0 })
  const progressByDst = ref({ step: '', message: '', percent: 0 })
  const trainingBySrc = ref(false)
  const trainingByDst = ref(false)

  // 方法：獲取配置（支援模式參數）
  async function fetchConfig(mode = null) {
    try {
      const { data } = await trainingAPI.getConfig(mode)
      if (data.status === 'success') {
        if (mode === 'by_src') {
          configBySrc.value = data
        } else if (mode === 'by_dst') {
          configByDst.value = data
        } else {
          // 返回兩者
          config.value = data
          if (data.models) {
            configBySrc.value = { ...data, model_info: data.models.by_src, mode: 'by_src' }
            configByDst.value = { ...data, model_info: data.models.by_dst, mode: 'by_dst' }
          }
        }
        return data
      }
    } catch (error) {
      ElMessage.error('獲取配置失敗')
      throw error
    }
  }

  // 方法：更新配置
  async function updateConfig(newConfig) {
    loading.value = true
    try {
      const { data } = await trainingAPI.updateConfig(newConfig)
      if (data.status === 'success') {
        ElMessage.success('配置更新成功')
        await fetchConfig() // 重新獲取配置
        return data
      }
    } catch (error) {
      ElMessage.error('更新配置失敗：' + (error.response?.data?.error || error.message))
      throw error
    } finally {
      loading.value = false
    }
  }

  // 方法：開始訓練（支援模式參數）
  async function startTraining(params) {
    loading.value = true
    const mode = params.mode || 'by_src'

    if (mode === 'by_src') {
      trainingBySrc.value = true
    } else {
      trainingByDst.value = true
    }
    training.value = true

    try {
      const { data } = await trainingAPI.startTraining(params)

      if (mode === 'by_src') {
        trainingJobBySrc.value = data.job_id
      } else {
        trainingJobByDst.value = data.job_id
      }
      trainingJob.value = data.job_id

      // 連接 SSE 監聽進度
      connectSSE(data.job_id, mode)

      return data
    } catch (error) {
      training.value = false
      if (mode === 'by_src') {
        trainingBySrc.value = false
      } else {
        trainingByDst.value = false
      }
      ElMessage.error('啟動訓練失敗：' + (error.response?.data?.error || error.message))
      throw error
    } finally {
      loading.value = false
    }
  }

  // 方法：連接 SSE 監聽訓練進度
  function connectSSE(jobId, mode = 'by_src') {
    const url = trainingAPI.getTrainingStatus(jobId)
    const eventSource = new EventSource(url)

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)

        // 更新進度
        if (data.type === 'progress') {
          const progressData = {
            step: data.progress?.step || '',
            message: data.progress?.message || '',
            percent: data.progress?.percent || 0
          }
          progress.value = progressData

          if (mode === 'by_src') {
            progressBySrc.value = progressData
          } else {
            progressByDst.value = progressData
          }
        }

        // 訓練完成
        if (data.type === 'completed' || data.status === 'completed') {
          training.value = false
          const completedProgress = {
            step: 'completed',
            message: '訓練完成！',
            percent: 100
          }
          progress.value = completedProgress

          if (mode === 'by_src') {
            trainingBySrc.value = false
            progressBySrc.value = completedProgress
          } else {
            trainingByDst.value = false
            progressByDst.value = completedProgress
          }

          ElMessage.success(`訓練完成！(${mode === 'by_src' ? '來源 IP 模式' : '目標 IP 模式'})`)
          eventSource.close()

          // 重新獲取配置和歷史
          fetchConfig()
          fetchHistory()
        }

        // 訓練失敗
        if (data.type === 'failed' || data.status === 'failed') {
          training.value = false
          if (mode === 'by_src') {
            trainingBySrc.value = false
          } else {
            trainingByDst.value = false
          }
          ElMessage.error('訓練失敗：' + (data.error || '未知錯誤'))
          eventSource.close()
        }
      } catch (error) {
        console.error('解析 SSE 數據失敗:', error)
      }
    }

    eventSource.onerror = (error) => {
      console.error('SSE 連接錯誤:', error)
      training.value = false
      if (mode === 'by_src') {
        trainingBySrc.value = false
      } else {
        trainingByDst.value = false
      }
      eventSource.close()
    }

    return eventSource
  }

  // 方法：獲取訓練歷史
  async function fetchHistory() {
    try {
      const { data } = await trainingAPI.getHistory()
      if (data.status === 'success') {
        history.value = data.history
        return data.history
      }
    } catch (error) {
      console.error('獲取訓練歷史失敗:', error)
    }
  }

  // 重置進度
  function resetProgress() {
    progress.value = {
      step: '',
      message: '',
      percent: 0
    }
    training.value = false
    trainingJob.value = null
  }

  return {
    // 狀態
    config,
    trainingJob,
    progress,
    history,
    loading,
    training,

    // 雙模式狀態
    configBySrc,
    configByDst,
    trainingJobBySrc,
    trainingJobByDst,
    progressBySrc,
    progressByDst,
    trainingBySrc,
    trainingByDst,

    // 方法
    fetchConfig,
    updateConfig,
    startTraining,
    fetchHistory,
    resetProgress
  }
})
