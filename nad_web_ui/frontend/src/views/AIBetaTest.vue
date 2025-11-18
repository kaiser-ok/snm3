<template>
  <div class="ai-beta-test">
    <!-- 頁面標題 -->
    <el-card shadow="never">
      <template #header>
        <div class="card-header">
          <span>
            <el-icon><TrendCharts /></el-icon>
            AI Beta 測試 - 多模型比較
          </span>
          <el-tag type="warning">實驗性功能</el-tag>
        </div>
      </template>

      <el-alert
        title="此功能允許您同時測試多個 LLM 模型的安全分析能力"
        type="info"
        :closable="false"
        show-icon
      >
        <p>選擇多個模型後，系統會並行調用它們進行分析，最後使用 GPT-4o 評選出最佳回答。</p>
      </el-alert>
    </el-card>

    <!-- 分析資訊 -->
    <el-card v-if="analysisData" shadow="never" class="info-card">
      <template #header>
        <span>
          <el-icon><Monitor /></el-icon>
          分析目標
        </span>
      </template>

      <el-descriptions :column="3" border>
        <el-descriptions-item label="IP 地址">
          <el-text tag="b" size="large">{{ analysisData.ip }}</el-text>
        </el-descriptions-item>
        <el-descriptions-item label="時間範圍">
          {{ formatDuration(analysisData.time_range?.duration_minutes) || 'N/A' }}
        </el-descriptions-item>
        <el-descriptions-item label="設備類型" v-if="analysisData.device_type">
          {{ analysisData.device_emoji }} {{ analysisData.device_type }}
        </el-descriptions-item>
      </el-descriptions>
    </el-card>

    <!-- 模型選擇 -->
    <el-card shadow="never" class="model-selection-card">
      <template #header>
        <span>
          <el-icon><Setting /></el-icon>
          模型選擇
        </span>
      </template>

      <el-alert
        title="提示：免費模型可能因速率限制而失敗"
        type="info"
        :closable="false"
        show-icon
        style="margin-bottom: 16px"
      >
        <p>免費模型有嚴格的速率限制，建議選擇付費模型以獲得更穩定的結果。</p>
      </el-alert>

      <el-checkbox-group v-model="selectedModels" :min="1">
        <div class="model-grid">
          <el-card
            v-for="model in availableModels"
            :key="model.id"
            class="model-card"
            :class="{ 'selected': selectedModels.includes(model.id) }"
            shadow="hover"
          >
            <el-checkbox :label="model.id" :value="model.id">
              <div class="model-info">
                <div class="model-name">{{ model.name }}</div>
                <div class="model-provider">{{ model.provider }}</div>
                <el-tag v-if="model.free" type="success" size="small">
                  免費 (有速率限制)
                </el-tag>
                <el-tag v-else type="info" size="small">付費</el-tag>
              </div>
            </el-checkbox>
          </el-card>
        </div>
      </el-checkbox-group>

      <el-divider />

      <div class="action-buttons">
        <el-button
          type="primary"
          size="large"
          @click="runComparison"
          :loading="isAnalyzing"
          :disabled="!selectedModels.length || !analysisData"
        >
          <el-icon><Document /></el-icon>
          開始分析 ({{ selectedModels.length }} 個模型)
        </el-button>
        <el-button
          type="info"
          size="large"
          @click="showPromptDialog"
          :disabled="!analysisData"
        >
          <el-icon><View /></el-icon>
          查看提示詞
        </el-button>
        <el-button size="large" @click="router.back()">
          返回
        </el-button>
      </div>
    </el-card>

    <!-- 分析進度 -->
    <el-card v-if="isAnalyzing" shadow="never" class="progress-card">
      <template #header>
        <span>
          <el-icon><Loading /></el-icon>
          分析進度
        </span>
      </template>

      <div class="progress-container">
        <el-progress
          :percentage="overallProgress"
          :stroke-width="20"
          :status="overallProgress === 100 ? 'success' : undefined"
        >
          <template #default="{ percentage }">
            <span style="font-size: 16px; font-weight: 600">{{ percentage }}%</span>
          </template>
        </el-progress>

        <div class="model-progress-list">
          <div
            v-for="model in selectedModels"
            :key="model"
            class="model-progress-item"
          >
            <span class="model-name-progress">{{ getModelName(model) }}</span>
            <el-tag
              :type="getProgressTagType(modelProgress[model])"
              size="small"
            >
              {{ modelProgress[model] || '等待中' }}
            </el-tag>
          </div>
        </div>
      </div>
    </el-card>

    <!-- 分析結果 -->
    <el-card v-if="results && results.length > 0" shadow="never" class="results-card">
      <template #header>
        <div class="card-header">
          <span>
            <el-icon><Trophy /></el-icon>
            分析結果
          </span>
        </div>
      </template>

      <!-- 最佳答案 -->
      <div v-if="bestAnswer" class="best-answer-section">
        <h3>🏆 GPT-4o 評選最佳回答</h3>
        <el-card class="best-answer-card" shadow="always">
          <template #header>
            <div class="best-answer-header">
              <el-tag type="success" size="large" effect="dark">
                <el-icon><Medal /></el-icon>
                最佳模型: {{ getModelName(bestAnswer.model_id) }}
              </el-tag>
              <el-tag type="info" size="large">
                評分: {{ bestAnswer.score }}/100
              </el-tag>
            </div>
          </template>

          <div class="evaluation-reason">
            <h4>評選理由：</h4>
            <div v-html="renderMarkdown(bestAnswer.reason)"></div>
          </div>

          <el-divider />

          <div class="best-answer-content">
            <h4>回答內容：</h4>
            <div v-html="renderMarkdown(bestAnswer.analysis)"></div>
          </div>
        </el-card>
      </div>

      <el-divider />

      <!-- 所有模型回答 -->
      <h3>📊 所有模型回答</h3>
      <el-collapse v-model="activeCollapse" accordion>
        <el-collapse-item
          v-for="(result, index) in results"
          :key="result.model_id"
          :name="result.model_id"
        >
          <template #title>
            <div class="collapse-title">
              <span class="model-rank">#{{ index + 1 }}</span>
              <span class="model-name-title">{{ getModelName(result.model_id) }}</span>
              <el-tag
                v-if="result.model_id === bestAnswer?.model_id"
                type="success"
                size="small"
                effect="dark"
              >
                最佳
              </el-tag>
              <el-tag
                :type="result.status === 'success' ? 'success' : 'danger'"
                size="small"
              >
                {{ result.status === 'success' ? '成功' : '失敗' }}
              </el-tag>
              <el-tag v-if="result.tokens_used" type="info" size="small">
                {{ result.tokens_used.total }} tokens
              </el-tag>
            </div>
          </template>

          <div v-if="result.status === 'success'" class="result-content">
            <div v-html="renderMarkdown(result.analysis)"></div>

            <el-divider />

            <div class="result-meta">
              <el-descriptions :column="3" size="small" border>
                <el-descriptions-item label="模型">{{ result.model_id }}</el-descriptions-item>
                <el-descriptions-item label="Prompt Tokens">{{ result.tokens_used?.prompt || 0 }}</el-descriptions-item>
                <el-descriptions-item label="Completion Tokens">{{ result.tokens_used?.completion || 0 }}</el-descriptions-item>
                <el-descriptions-item label="總 Tokens">{{ result.tokens_used?.total || 0 }}</el-descriptions-item>
                <el-descriptions-item label="分析時間" :span="2">{{ result.analysis_time || 'N/A' }}</el-descriptions-item>
              </el-descriptions>
            </div>
          </div>

          <div v-else class="result-error">
            <el-alert
              :title="`${getModelName(result.model_id)} 分析失敗`"
              :type="getErrorType(result.error)"
              :closable="false"
              show-icon
            >
              <div v-html="formatError(result.error)"></div>
            </el-alert>
          </div>
        </el-collapse-item>
      </el-collapse>
    </el-card>

    <el-empty v-else-if="!isAnalyzing" description="請選擇模型並開始分析" />

    <!-- 提示詞顯示對話框 -->
    <el-dialog
      v-model="promptDialogVisible"
      title="LLM 提示詞預覽"
      width="900px"
    >
      <el-alert
        title="此為發送給所有 LLM 模型的提示詞內容"
        type="info"
        :closable="false"
        show-icon
        style="margin-bottom: 20px"
      />

      <div class="prompt-preview">
        <pre>{{ generatedPrompt }}</pre>
      </div>

      <template #footer>
        <el-button type="primary" @click="promptDialogVisible = false">
          關閉
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { marked } from 'marked'
import { analysisAPI } from '@/services/api'
import {
  TrendCharts,
  Monitor,
  Setting,
  Document,
  Loading,
  Trophy,
  Medal,
  View
} from '@element-plus/icons-vue'

const route = useRoute()
const router = useRouter()

const selectedModels = ref([])
const isAnalyzing = ref(false)
const results = ref([])
const bestAnswer = ref(null)
const activeCollapse = ref('')
const analysisData = ref(null)
const modelProgress = ref({})
const promptDialogVisible = ref(false)
const generatedPrompt = ref('')

// 可用模型列表 (包含 OpenRouter 和 OpenAI 模型)
const availableModels = ref([
  {
    id: 'meta-llama/llama-4-scout',
    name: 'Llama 4 Scout',
    provider: 'Meta (via OpenRouter)',
    free: false
  },
  {
    id: 'qwen/qwen3-vl-8b-thinking',
    name: 'Qwen3 VL 8B Thinking',
    provider: 'Alibaba (via OpenRouter)',
    free: false
  },
  {
    id: 'qwen/qwen3-next-80b-a3b-instruct',
    name: 'Qwen3 Next 80B',
    provider: 'Alibaba (via OpenRouter)',
    free: false
  },
  {
    id: 'qwen/qwen3-235b-a22b-thinking-2507',
    name: 'Qwen3 235B Thinking',
    provider: 'Alibaba (via OpenRouter)',
    free: false
  },
  {
    id: 'deepseek/deepseek-v3.2-exp',
    name: 'DeepSeek V3.2 Exp',
    provider: 'DeepSeek (via OpenRouter)',
    free: false
  },
  {
    id: 'google/gemma-3-27b-it',
    name: 'Gemma 3 27B',
    provider: 'Google (via OpenRouter)',
    free: false
  },
  {
    id: 'google/gemini-2.5-flash-preview-09-2025',
    name: 'Gemini 2.5 Flash Preview',
    provider: 'Google (via OpenRouter)',
    free: false
  },
  {
    id: 'x-ai/grok-4-fast',
    name: 'Grok 4 Fast',
    provider: 'xAI (via OpenRouter)',
    free: false
  },
  {
    id: 'openai/gpt-5.1',
    name: 'GPT-5.1',
    provider: 'OpenAI (via OpenRouter)',
    free: false
  },
  {
    id: 'google/gemini-2.0-flash-exp:free',
    name: 'Gemini 2.0 Flash (Free)',
    provider: 'Google (via OpenRouter)',
    free: true
  },
  {
    id: 'anthropic/claude-3.5-sonnet',
    name: 'Claude 3.5 Sonnet',
    provider: 'Anthropic (via OpenRouter)',
    free: false
  },
  {
    id: 'openai/gpt-4o',
    name: 'GPT-4o',
    provider: 'OpenAI (Direct)',
    free: false
  }
])

// 計算總體進度
const overallProgress = computed(() => {
  if (!selectedModels.value.length) return 0

  const completedCount = Object.values(modelProgress.value).filter(
    status => status === '完成' || status === '失敗'
  ).length

  return Math.round((completedCount / selectedModels.value.length) * 100)
})

onMounted(async () => {
  // 從 query 獲取參數
  const ip = route.query.ip
  const minutes = parseInt(route.query.minutes) || 60
  const topN = parseInt(route.query.topN) || 10

  if (!ip) {
    ElMessage.warning('缺少 IP 參數，返回上一頁')
    router.back()
    return
  }

  // 先執行 IP 分析獲取完整數據
  try {
    ElMessage.info('正在獲取分析數據...')
    const { data } = await analysisAPI.analyzeIP({
      ip,
      minutes,
      top_n: topN
    })

    if (data.status === 'success') {
      analysisData.value = data
      ElMessage.success('分析數據已載入')
    } else {
      ElMessage.error('獲取分析數據失敗')
      router.back()
    }
  } catch (error) {
    ElMessage.error('獲取分析數據失敗：' + (error.response?.data?.error || error.message))
    router.back()
  }
})

function getModelName(modelId) {
  const model = availableModels.value.find(m => m.id === modelId)
  return model ? model.name : modelId
}

function getProgressTagType(status) {
  if (status === '完成') return 'success'
  if (status === '失敗') return 'danger'
  if (status === '分析中') return 'warning'
  return 'info'
}

async function runComparison() {
  if (!selectedModels.value.length) {
    ElMessage.warning('請至少選擇一個模型')
    return
  }

  if (!analysisData.value) {
    ElMessage.warning('分析數據未載入')
    return
  }

  isAnalyzing.value = true
  results.value = []
  bestAnswer.value = null
  modelProgress.value = {}

  // 初始化進度
  selectedModels.value.forEach(model => {
    modelProgress.value[model] = '等待中'
  })

  try {
    ElMessage.info(`開始使用 ${selectedModels.value.length} 個模型進行分析...`)

    // 並行調用所有模型
    const analysisPromises = selectedModels.value.map(async (modelId) => {
      try {
        modelProgress.value[modelId] = '分析中'
        const startTime = Date.now()

        const { data } = await analysisAPI.getLLMSecurityReport({
          analysis_data: analysisData.value,
          model_id: modelId,
          use_openrouter: true
        })

        const analysisTime = ((Date.now() - startTime) / 1000).toFixed(2)

        if (data.status === 'success') {
          modelProgress.value[modelId] = '完成'
          return {
            model_id: modelId,
            status: 'success',
            analysis: data.analysis,
            tokens_used: data.tokens_used,
            analysis_time: `${analysisTime}s`,
            model: data.model
          }
        } else {
          modelProgress.value[modelId] = '失敗'
          return {
            model_id: modelId,
            status: 'error',
            error: data.error || '分析失敗',
            analysis_time: `${analysisTime}s`
          }
        }
      } catch (error) {
        modelProgress.value[modelId] = '失敗'
        return {
          model_id: modelId,
          status: 'error',
          error: error.response?.data?.error || error.message,
          analysis_time: 'N/A'
        }
      }
    })

    // 等待所有模型完成
    results.value = await Promise.all(analysisPromises)

    const successfulResults = results.value.filter(r => r.status === 'success')
    const failedResults = results.value.filter(r => r.status === 'error')

    if (successfulResults.length === 0) {
      ElMessage.error('所有模型分析都失敗了')
      return
    }

    // 顯示詳細的成功/失敗訊息
    if (failedResults.length > 0) {
      const failedModels = failedResults.map(r => getModelName(r.model_id)).join('、')
      ElMessage.warning({
        message: `${successfulResults.length}/${results.value.length} 個模型分析成功。失敗的模型：${failedModels}`,
        duration: 5000,
        showClose: true
      })
    } else {
      ElMessage.success(`所有 ${results.value.length} 個模型分析成功！`)
    }

    // 如果有多個成功的結果，使用 GPT-4o 評選最佳答案
    if (successfulResults.length > 1) {
      try {
        ElMessage.info('正在使用 GPT-4o 評選最佳答案...')
        bestAnswer.value = await judgeBestAnswer(successfulResults)

        if (bestAnswer.value) {
          ElMessage.success('最佳答案評選完成')
          activeCollapse.value = bestAnswer.value.model_id
        }
      } catch (error) {
        ElMessage.warning('評選失敗，使用第一個成功的結果')
        bestAnswer.value = {
          model_id: successfulResults[0].model_id,
          analysis: successfulResults[0].analysis,
          tokens_used: successfulResults[0].tokens_used,
          score: 0,
          reason: `評選失敗: ${error.message}`
        }
        activeCollapse.value = successfulResults[0].model_id
      }
    } else if (successfulResults.length === 1) {
      // 只有一個成功結果，直接使用
      bestAnswer.value = {
        model_id: successfulResults[0].model_id,
        analysis: successfulResults[0].analysis,
        tokens_used: successfulResults[0].tokens_used,
        score: 100,
        reason: '唯一成功的分析結果'
      }
      activeCollapse.value = successfulResults[0].model_id
    }

  } catch (error) {
    ElMessage.error('分析過程發生錯誤：' + error.message)
  } finally {
    isAnalyzing.value = false
  }
}

async function judgeBestAnswer(successfulResults) {
  // 使用 GPT-4o 評選最佳答案
  const judgePrompt = buildJudgePrompt(successfulResults)

  const { data } = await analysisAPI.getLLMSecurityReport({
    ...analysisData.value,
    custom_prompt: judgePrompt,
    model_id: 'gpt-4o',
    use_openrouter: false,
    response_format: 'json'
  })

  if (data.status === 'success') {
    try {
      const judgment = JSON.parse(data.analysis)
      const bestModelId = judgment.best_model_id
      const bestResult = successfulResults.find(r => r.model_id === bestModelId)

      if (bestResult) {
        return {
          model_id: bestResult.model_id,
          analysis: bestResult.analysis,
          tokens_used: bestResult.tokens_used,
          score: judgment.score || 0,
          reason: judgment.reason || '未提供評選理由'
        }
      }
    } catch (e) {
      console.error('解析評判結果失敗:', e)
    }
  }

  // 評判失敗，返回第一個結果
  return {
    model_id: successfulResults[0].model_id,
    analysis: successfulResults[0].analysis,
    tokens_used: successfulResults[0].tokens_used,
    score: 0,
    reason: '評判失敗，使用第一個成功的結果'
  }
}

function buildJudgePrompt(results) {
  let prompt = `請評估以下多個 AI 模型對網路安全分析問題的回答質量。

**各模型回答:**

`
  results.forEach((result, idx) => {
    prompt += `
### 模型 ${idx + 1}: ${result.model_id}

${result.analysis}

---
`
  })

  prompt += `
請根據以下標準評估這些回答：

1. **準確性** (30分): 分析是否準確識別安全威脅，判斷是否合理
2. **深度** (25分): 分析是否深入，是否提供有價值的洞察
3. **完整性** (20分): 是否涵蓋所有重要方面（安全摘要、關鍵觀察、風險評估、建議措施等）
4. **可操作性** (15分): 建議是否具體可行
5. **專業性** (10分): 用語是否專業，表達是否清晰

請以 JSON 格式返回評估結果：

{
  "best_model_id": "最佳模型的完整 ID",
  "score": 85,
  "reason": "選擇理由（3-5 句話，說明為什麼這個答案最好）"
}

請確保返回有效的 JSON 格式。`

  return prompt
}

function renderMarkdown(markdown) {
  if (!markdown) return ''
  return marked(markdown)
}

function getErrorType(error) {
  if (!error) return 'error'

  const errorLower = error.toLowerCase()

  // Rate limiting is a warning, not a critical error
  if (errorLower.includes('rate limit') || errorLower.includes('429')) {
    return 'warning'
  }

  // Other errors
  return 'error'
}

function formatError(error) {
  if (!error) return '未知錯誤'

  // Parse rate limiting errors
  if (error.includes('429') || error.toLowerCase().includes('rate limit')) {
    let message = '<p><strong>速率限制</strong></p>'

    if (error.includes('temporarily rate-limited upstream')) {
      message += '<p>此模型目前在上游提供商處暫時受到速率限制。</p>'
      message += '<ul>'
      message += '<li>免費模型有嚴格的速率限制</li>'
      message += '<li>建議：稍後重試或選擇其他付費模型</li>'

      if (error.includes('add your own key')) {
        message += '<li>進階選項：在 OpenRouter 設定中添加您自己的 API 金鑰以累積速率限制</li>'
      }
      message += '</ul>'
    } else {
      message += `<p>${error}</p>`
    }

    return message
  }

  // Parse authentication errors
  if (error.toLowerCase().includes('auth') || error.toLowerCase().includes('api key')) {
    return `<p><strong>認證錯誤</strong></p><p>${error}</p><p>請檢查 API 金鑰設定。</p>`
  }

  // Parse model not found errors
  if (error.toLowerCase().includes('not found') || error.toLowerCase().includes('model')) {
    return `<p><strong>模型錯誤</strong></p><p>${error}</p><p>此模型可能不可用或 ID 錯誤。</p>`
  }

  // Default error formatting
  return `<p>${error}</p>`
}

function formatDuration(minutes) {
  if (!minutes) return 'N/A'

  if (minutes < 60) {
    return `${minutes.toFixed(0)} 分鐘`
  } else if (minutes < 1440) {
    const hours = minutes / 60
    return `${hours.toFixed(1)} 小時`
  } else {
    const days = minutes / 1440
    return `${days.toFixed(1)} 天`
  }
}

async function showPromptDialog() {
  if (!analysisData.value) {
    ElMessage.warning('分析數據未載入')
    return
  }

  try {
    // 調用後端 API 獲取生成的提示詞
    ElMessage.info('正在生成提示詞預覽...')

    // 使用特殊的 dry_run 模式獲取提示詞（不實際調用 LLM）
    const { data } = await analysisAPI.getLLMSecurityReport({
      analysis_data: analysisData.value,
      dry_run: true
    })

    if (data.status === 'success' && data.prompt) {
      generatedPrompt.value = data.prompt
      promptDialogVisible.value = true
    } else {
      // 如果後端不支援 dry_run，就在前端生成預覽
      generatedPrompt.value = generatePromptPreview(analysisData.value)
      promptDialogVisible.value = true
    }
  } catch (error) {
    // 如果 API 調用失敗，在前端生成預覽
    generatedPrompt.value = generatePromptPreview(analysisData.value)
    promptDialogVisible.value = true
  }
}

function generatePromptPreview(data) {
  // 生成提示詞預覽（簡化版本）
  const ip = data.ip || 'N/A'
  const deviceType = data.device_type || 'N/A'
  const hours = (data.time_range?.duration_minutes || 0) / 60
  const stats = data.summary || {}

  return `請分析以下 IP 的網路流量數據，並提供安全評估報告。

**網路環境說明**
此網路環境屬於 TANet (Taiwan Academic Network，台灣學術網路) 的一部分。

**基本資訊**
- IP 地址: ${ip}
- 設備類型: ${deviceType}
- 分析時間範圍: 過去 ${hours.toFixed(1)} 小時

**流量統計**
- 總流量數: ${(stats.total_flows || 0).toLocaleString()} flows
- 總位元組: ${(stats.total_bytes || 0).toLocaleString()} bytes
- 總封包數: ${(stats.total_packets || 0).toLocaleString()} packets
- 不重複目的地: ${(stats.unique_destinations || 0).toLocaleString()} IPs
- 不重複目的埠: ${(stats.unique_dst_ports || 0).toLocaleString()} ports
- 不重複來源埠: ${(stats.unique_src_ports || 0).toLocaleString()} ports

**威脅分類**
${data.threat_classification ? `
- 類型: ${data.threat_classification.class_name} (${data.threat_classification.class_name_en})
- 嚴重性: ${data.threat_classification.severity}
- 置信度: ${(data.threat_classification.confidence * 100).toFixed(1)}%
- 描述: ${data.threat_classification.description}
` : '無威脅分類資訊'}

請根據以上數據提供：
1. 安全摘要
2. ${data.ip_info?.is_public ? 'IP 資訊分析' : '設備類型分析'}
3. 關鍵觀察
4. IP 間互動推測
5. 風險綜合評估
6. 建議措施

（注：這是簡化版預覽，實際發送的提示詞包含更多詳細資訊）`
}
</script>

<style scoped>
.ai-beta-test {
  display: flex;
  flex-direction: column;
  gap: 20px;
  width: 100%;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-weight: 600;
  font-size: 16px;
}

.card-header span {
  display: flex;
  align-items: center;
  gap: 8px;
}

.info-card,
.model-selection-card,
.progress-card,
.results-card {
  margin-top: 0;
}

.model-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 16px;
  margin-top: 16px;
}

.model-card {
  transition: all 0.3s;
  cursor: pointer;
}

.model-card.selected {
  border: 2px solid #409eff;
  box-shadow: 0 2px 12px rgba(64, 158, 255, 0.3);
}

.model-card :deep(.el-card__body) {
  padding: 16px;
}

.model-info {
  margin-left: 8px;
}

.model-name {
  font-weight: 600;
  font-size: 14px;
  color: #303133;
  margin-bottom: 4px;
}

.model-provider {
  font-size: 12px;
  color: #909399;
  margin-bottom: 8px;
}

.action-buttons {
  display: flex;
  gap: 12px;
  justify-content: center;
  margin-top: 16px;
}

.progress-container {
  padding: 20px 0;
}

.model-progress-list {
  margin-top: 24px;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: 12px;
}

.model-progress-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px;
  background-color: #f5f7fa;
  border-radius: 4px;
}

.model-name-progress {
  font-weight: 500;
  color: #606266;
}

.best-answer-section {
  margin-bottom: 32px;
}

.best-answer-section h3 {
  color: #409eff;
  font-size: 20px;
  margin-bottom: 16px;
}

.best-answer-card {
  border: 2px solid #67c23a;
}

.best-answer-header {
  display: flex;
  gap: 12px;
  align-items: center;
}

.evaluation-reason,
.best-answer-content {
  margin-top: 16px;
}

.evaluation-reason h4,
.best-answer-content h4 {
  color: #606266;
  font-size: 16px;
  margin-bottom: 12px;
}

.evaluation-reason :deep(p),
.best-answer-content :deep(p) {
  line-height: 1.8;
  color: #303133;
}

.evaluation-reason :deep(ul),
.best-answer-content :deep(ul) {
  margin-left: 20px;
}

.collapse-title {
  display: flex;
  align-items: center;
  gap: 12px;
  width: 100%;
}

.model-rank {
  font-weight: 600;
  color: #909399;
  font-size: 16px;
  min-width: 30px;
}

.model-name-title {
  font-weight: 600;
  color: #303133;
  flex: 1;
}

.result-content {
  padding: 20px;
  line-height: 1.8;
}

.result-content :deep(h2) {
  color: #409eff;
  font-size: 18px;
  margin-top: 20px;
  margin-bottom: 12px;
  border-bottom: 2px solid #409eff;
  padding-bottom: 8px;
}

.result-content :deep(h3) {
  color: #606266;
  font-size: 16px;
  margin-top: 16px;
  margin-bottom: 10px;
}

.result-content :deep(ul) {
  margin-left: 20px;
  margin-bottom: 16px;
}

.result-content :deep(li) {
  margin: 8px 0;
}

.result-content :deep(p) {
  margin: 12px 0;
  color: #303133;
}

.result-content :deep(strong) {
  color: #409eff;
  font-weight: 600;
}

.result-meta {
  margin-top: 20px;
}

.result-error {
  padding: 20px;
}

.results-card h3 {
  color: #606266;
  font-size: 18px;
  margin-bottom: 16px;
  padding-left: 4px;
}

.prompt-preview {
  background-color: #f5f7fa;
  border: 1px solid #dcdfe6;
  border-radius: 4px;
  padding: 16px;
  max-height: 600px;
  overflow-y: auto;
}

.prompt-preview pre {
  margin: 0;
  font-family: 'Courier New', Courier, monospace;
  font-size: 13px;
  line-height: 1.6;
  color: #303133;
  white-space: pre-wrap;
  word-wrap: break-word;
}
</style>
