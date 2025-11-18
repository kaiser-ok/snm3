/**
 * API 服務層
 * 封裝所有後端 API 調用
 */
import axios from 'axios'

// 創建 axios 實例
const api = axios.create({
  baseURL: '/api',
  timeout: 60000, // 增加到 60 秒
  headers: {
    'Content-Type': 'application/json'
  }
})

// 請求攔截器
api.interceptors.request.use(
  config => {
    console.log('API Request:', config.method.toUpperCase(), config.url)
    return config
  },
  error => {
    return Promise.reject(error)
  }
)

// 響應攔截器
api.interceptors.response.use(
  response => {
    return response
  },
  error => {
    console.error('API Error:', error.response?.data || error.message)
    return Promise.reject(error)
  }
)

/**
 * 檢測 API
 */
export const detectionAPI = {
  // 獲取模型狀態
  getStatus() {
    return api.get('/detection/status')
  },

  // 執行異常檢測
  runDetection(minutes) {
    return api.post('/detection/run', { minutes })
  },

  // 獲取檢測結果
  getResults(jobId) {
    return api.get(`/detection/results/${jobId}`)
  },

  // 獲取異常統計
  getStats(days = 7) {
    return api.get('/detection/stats', { params: { days } })
  }
}

/**
 * 訓練 API
 */
export const trainingAPI = {
  // 獲取訓練配置（支援模式參數）
  getConfig(mode = null) {
    const params = mode ? { mode } : {}
    return api.get('/training/config', { params })
  },

  // 更新訓練配置
  updateConfig(config) {
    return api.put('/training/config', config)
  },

  // 開始訓練（支援 mode 參數）
  startTraining(params) {
    return api.post('/training/start', params)
  },

  // 獲取訓練歷史
  getHistory() {
    return api.get('/training/history')
  },

  // SSE 訓練狀態（需特殊處理）
  getTrainingStatus(jobId) {
    return `/api/training/status/${jobId}`
  }
}

/**
 * 分析 API
 */
export const analysisAPI = {
  // 分析特定 IP
  analyzeIP(data) {
    return api.post('/analysis/ip', data)
  },

  // 獲取 Top Talkers
  getTopTalkers(minutes = 60, limit = 20) {
    return api.get('/analysis/top-talkers', {
      params: { minutes, limit }
    })
  },

  // 獲取 LLM 安全分析報告（需要更長超時時間）
  // 支援傳入 model_id, use_openrouter, custom_prompt, response_format 等參數
  getLLMSecurityReport(data) {
    return api.post('/analysis/llm-security-report', data, {
      timeout: 120000 // LLM API 需要 120 秒超時
    })
  }
}

/**
 * 健康檢查
 */
export const healthAPI = {
  check() {
    return api.get('/health')
  }
}

export default api
