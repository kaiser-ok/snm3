<template>
  <div class="dashboard">
    <!-- Netflow 數據健康警告 -->
    <el-alert
      v-if="dataHealthAlert.show"
      :title="dataHealthAlert.title"
      :type="dataHealthAlert.type"
      :description="dataHealthAlert.description"
      show-icon
      :closable="false"
      style="margin-bottom: 20px"
    />

    <!-- 結果顯示 -->
    <el-card v-if="detectionStore.results" class="results-panel" shadow="never">
      <template #header>
        <div class="card-header">
          <span>異常IP分布圖 ({{ getTimeRangeLabel(selectedMinutes) }})</span>
          <el-tag
            type="danger"
            size="large"
            style="cursor: pointer"
            @click="scrollToTopIPs"
          >
            發現 {{ detectionStore.totalAnomalies }} 個異常IP
          </el-tag>
        </div>
      </template>

      <!-- ECharts 柱狀圖 -->
      <div ref="chartContainer" class="chart-container"></div>

      <!-- ECharts 餅圖 - 行為特徵分布 -->
      <div ref="pieChartContainer" class="pie-chart-container">
        <div class="pie-chart-title">
          {{ pieChartTitle }}
          <el-button
            v-if="selectedBucket"
            type="text"
            size="small"
            @click="resetPieChart"
            style="margin-left: 10px"
          >
            <el-icon><RefreshLeft /></el-icon>
            重置
          </el-button>
        </div>
        <div ref="pieChart" class="pie-chart"></div>
      </div>

      <!-- Top 10 異常 IP 列表 - 只在沒有選中特定時段時顯示 -->
      <div v-if="!selectedBucket" ref="topIPsContainer" class="top-ips-container">
        <el-divider>
          <el-icon><TrendCharts /></el-icon>
          <span style="margin-left: 8px">Top 10 異常 IP（依出現次數排序）</span>
        </el-divider>

        <el-table :data="topAnomalousIPs" stripe max-height="500">
          <el-table-column type="index" label="排名" width="70" />

          <el-table-column width="80">
            <template #header>
              <span>類型</span>
              <el-tooltip
                content="設備類型：🏭 伺服器 | 💻 工作站 | 🛠️ IoT設備 | 🌐 外部 | 🎯 目的地聚合異常"
                placement="top"
              >
                <el-icon style="margin-left: 4px; cursor: help;">
                  <InfoFilled />
                </el-icon>
              </el-tooltip>
            </template>
            <template #default="{ row }">
              <span style="font-size: 20px">{{ row.device_emoji }}</span>
            </template>
          </el-table-column>

          <el-table-column label="IP 地址" width="160">
            <template #default="{ row }">
              <span>{{ row.dst_ip || row.src_ip }}</span>
            </template>
          </el-table-column>

          <el-table-column label="出現次數" width="100" sortable>
            <template #default="{ row }">
              <el-tag type="danger">{{ row.occurrence_count }} 次</el-tag>
            </template>
          </el-table-column>

          <el-table-column width="140" sortable>
            <template #header>
              <span>平均異常分數</span>
              <el-tooltip
                placement="top"
                raw-content
              >
                <template #content>
                  <div style="max-width: 300px;">
                    Isolation Forest 計算的異常分數<br/>
                    • 數值範圍：0.0 ~ 1.0<br/>
                    • 系統關注閥值：≥0.6
                  </div>
                </template>
                <el-icon style="margin-left: 4px; cursor: help;">
                  <InfoFilled />
                </el-icon>
              </el-tooltip>
            </template>
            <template #default="{ row }">
              <el-tag :type="getScoreType(row.avg_anomaly_score)">
                {{ row.avg_anomaly_score.toFixed(4) }}
              </el-tag>
            </template>
          </el-table-column>

          <el-table-column prop="threat_class" label="威脅類型" width="150">
            <template #default="{ row }">
              <el-tag v-if="row.threat_class" :type="getSeverityType(row.severity)">
                {{ row.threat_class }}
              </el-tag>
            </template>
          </el-table-column>

          <el-table-column width="140" sortable>
            <template #header>
              <span>分類置信度</span>
              <el-tooltip
                placement="top"
                raw-content
              >
                <template #content>
                  <div style="max-width: 300px;">
                    Classifier 對威脅類型分類的可靠度評分<br/>
                    • 數值範圍：0% ~ 100%<br/>
                    • 越高表示威脅類型判斷越可靠<br/>
                    • 50% 通常表示「未知異常」
                  </div>
                </template>
                <el-icon style="margin-left: 4px; cursor: help;">
                  <InfoFilled />
                </el-icon>
              </el-tooltip>
            </template>
            <template #default="{ row }">
              {{ (row.latest_threat_confidence * 100).toFixed(0) }}%
            </template>
          </el-table-column>

          <el-table-column prop="severity" label="嚴重性" width="100">
            <template #default="{ row }">
              <el-tag v-if="row.severity" :type="getSeverityType(row.severity)" size="small">
                {{ row.severity }}
              </el-tag>
            </template>
          </el-table-column>

          <el-table-column label="總連線數" width="120" sortable>
            <template #default="{ row }">
              {{ row.total_flow_count.toLocaleString() }}
            </template>
          </el-table-column>

          <el-table-column label="來源數" width="100">
            <template #default="{ row }">
              <span v-if="row.is_dst_anomaly && row.unique_srcs > 0">
                {{ row.unique_srcs }} 個
              </span>
              <span v-else>-</span>
            </template>
          </el-table-column>

          <el-table-column label="操作" width="120" fixed="right">
            <template #default="{ row }">
              <el-button
                size="small"
                @click="analyzeIP(row.dst_ip || row.src_ip)"
              >
                詳細分析
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>

      <!-- 選中時間段的異常 IP 清單 -->
      <div v-if="selectedBucket" class="selected-bucket-details">
        <el-divider>
          <div class="bucket-header">
            <div>
              <el-icon><Clock /></el-icon>
              <span style="margin-left: 8px">{{ formatTime(selectedBucket.time_bucket) }} - {{ selectedBucket.anomaly_count }} 個異常</span>
            </div>
            <el-button size="small" @click="clearSelectedBucket" type="primary" plain>
              <el-icon><Back /></el-icon>
              返回 Top 10
            </el-button>
          </div>
        </el-divider>

        <el-table :data="selectedBucket.anomalies" stripe max-height="400">
          <el-table-column label="設備" width="80">
            <template #default="{ row }">
              <span style="font-size: 20px">{{ row.device_emoji }}</span>
            </template>
          </el-table-column>

          <el-table-column label="IP 地址" width="150">
            <template #default="{ row }">
              <span>{{ row.dst_ip || row.src_ip }}</span>
            </template>
          </el-table-column>

          <el-table-column label="異常分數" width="120">
            <template #default="{ row }">
              <el-tag :type="getScoreType(row.anomaly_score)">
                {{ row.anomaly_score.toFixed(4) }}
              </el-tag>
            </template>
          </el-table-column>

          <el-table-column label="置信度" width="100">
            <template #default="{ row }">
              {{ (row.confidence * 100).toFixed(0) }}%
            </template>
          </el-table-column>

          <el-table-column prop="flow_count" label="連線數" width="100">
            <template #default="{ row }">
              {{ row.flow_count.toLocaleString() }}
            </template>
          </el-table-column>

          <el-table-column prop="unique_dsts" label="目的地" width="100" />

          <el-table-column prop="threat_class" label="威脅類型" width="150">
            <template #default="{ row }">
              <el-tag v-if="row.threat_class" :type="getSeverityType(row.severity)">
                {{ row.threat_class }}
              </el-tag>
            </template>
          </el-table-column>

          <el-table-column label="操作" width="120">
            <template #default="{ row }">
              <el-button
                size="small"
                @click="analyzeIPFromBucket(row.dst_ip || row.src_ip, selectedBucket.time_bucket)"
              >
                詳細分析
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </el-card>

    <!-- 無結果提示 -->
    <el-empty
      v-else-if="!detectionStore.loading && !detectionStore.polling"
      description="尚未執行檢測，請點擊上方按鈕開始"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import { useDetectionStore } from '@/stores/detection'
import { Clock, TrendCharts, Back, InfoFilled, RefreshLeft } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import * as echarts from 'echarts'

const router = useRouter()
const detectionStore = useDetectionStore()

const selectedMinutes = ref(1440)  // 預設 24 小時（固定）
const chartContainer = ref(null)
const pieChartContainer = ref(null)
const pieChart = ref(null)
const topIPsContainer = ref(null)
const selectedBucket = ref(null)
const pieChartTitle = ref('行為特徵分布（全時段）')
let chartInstance = null
let pieChartInstance = null

// 計算數據健康狀態警告
const dataHealthAlert = computed(() => {
  const dataHealth = detectionStore.results?.data_health

  if (!dataHealth) {
    return { show: false }
  }

  // 根據狀態返回不同的警告配置
  if (dataHealth.status === 'error') {
    return {
      show: true,
      title: 'Netflow 數據異常',
      type: 'error',
      description: dataHealth.message + (dataHealth.last_data_time
        ? ` (最後更新: ${new Date(dataHealth.last_data_time).toLocaleString('zh-TW')})`
        : '')
    }
  } else if (dataHealth.status === 'warning') {
    return {
      show: true,
      title: 'Netflow 數據警告',
      type: 'warning',
      description: dataHealth.message + (dataHealth.last_data_time
        ? ` (最後更新: ${new Date(dataHealth.last_data_time).toLocaleString('zh-TW')})`
        : '')
    }
  }

  return { show: false }
})

// 計算 Top 10 異常 IP（包含來源 IP 和目的地聚合異常）
const topAnomalousIPs = computed(() => {
  if (!detectionStore.buckets || detectionStore.buckets.length === 0) {
    return []
  }

  // 聚合所有時間段的異常 IP/異常
  const ipMap = new Map()

  detectionStore.buckets.forEach(bucket => {
    bucket.anomalies.forEach(anomaly => {
      // 使用 src_ip 或 dst_ip（用於目的地異常）
      const isDstAnomaly = !anomaly.src_ip && anomaly.device_type === 'dst_anomaly'
      const ip = anomaly.src_ip || anomaly.dst_ip || `unknown_${anomaly.time_bucket}`

      if (!ipMap.has(ip)) {
        ipMap.set(ip, {
          src_ip: anomaly.src_ip,
          dst_ip: anomaly.dst_ip,
          is_dst_anomaly: isDstAnomaly,
          device_emoji: isDstAnomaly ? '🎯' : anomaly.device_emoji,
          occurrence_count: 0,
          total_anomaly_score: 0,
          total_confidence: 0,
          total_threat_confidence: 0,
          total_flow_count: 0,
          threat_class: anomaly.threat_class,
          severity: anomaly.severity,
          unique_dsts: anomaly.unique_dsts,
          unique_srcs: isDstAnomaly ? (anomaly.features?.unique_srcs || 0) : 0,
          latest_threat_confidence: anomaly.threat_confidence || 0.5,
          latest_time_bucket: anomaly.time_bucket
        })
      }

      const ipData = ipMap.get(ip)
      ipData.occurrence_count += 1
      ipData.total_anomaly_score += anomaly.anomaly_score
      ipData.total_confidence += anomaly.confidence
      ipData.total_threat_confidence += (anomaly.threat_confidence || 0.5)
      ipData.total_flow_count += anomaly.flow_count

      // 更新 unique_srcs（用於目的地異常）
      if (isDstAnomaly && anomaly.features?.unique_srcs) {
        ipData.unique_srcs = Math.max(ipData.unique_srcs, anomaly.features.unique_srcs)
      }

      // 保留最新（最高優先級）的威脅分類
      // 如果新記錄的嚴重性更高，或時間更新，則更新威脅分類
      const shouldUpdate = !ipData.threat_class ||
          (anomaly.severity === 'HIGH' && ipData.severity !== 'HIGH') ||
          (anomaly.severity === 'MEDIUM' && ipData.severity === 'LOW') ||
          (anomaly.time_bucket > ipData.latest_time_bucket)

      if (shouldUpdate) {
        ipData.threat_class = anomaly.threat_class
        ipData.severity = anomaly.severity
        ipData.latest_threat_confidence = anomaly.threat_confidence || 0.5
        ipData.latest_time_bucket = anomaly.time_bucket
      }
    })
  })

  // 轉換為陣列並計算平均值
  const ipList = Array.from(ipMap.values()).map(ip => ({
    ...ip,
    avg_anomaly_score: ip.total_anomaly_score / ip.occurrence_count,
    avg_confidence: ip.total_confidence / ip.occurrence_count,
    avg_threat_confidence: ip.total_threat_confidence / ip.occurrence_count,
    display_name: ip.is_dst_anomaly ? '🎯 目的地聚合異常' : ip.src_ip
  }))

  // 按出現次數降序排序，取前 10
  return ipList
    .sort((a, b) => b.occurrence_count - a.occurrence_count)
    .slice(0, 10)
})

// 載入時獲取模型狀態並自動執行檢測
onMounted(async () => {
  try {
    await detectionStore.fetchModelStatus()
    // 自動執行檢測
    await handleRunDetection()
  } catch (error) {
    console.error('獲取模型狀態失敗:', error)
  }
})

// 監聽檢測結果變化，更新圖表
watch(() => detectionStore.results, async (newResults) => {
  if (newResults && detectionStore.buckets.length > 0) {
    await nextTick()
    initChart()
    initPieChart()
  }
}, { deep: true })

// 執行檢測
async function handleRunDetection() {
  try {
    selectedBucket.value = null // 清空選中的 bucket
    await detectionStore.runDetection(selectedMinutes.value)
  } catch (error) {
    console.error('檢測失敗:', error)
  }
}

// 初始化圖表
function initChart() {
  if (!chartContainer.value) return

  // 銷毀舊圖表實例
  if (chartInstance) {
    chartInstance.dispose()
  }

  // 創建新圖表實例
  chartInstance = echarts.init(chartContainer.value)

  const buckets = detectionStore.buckets
  const xAxisData = buckets.map(b => b.time_bucket)  // 使用原始時間字串
  const yAxisData = buckets.map(b => b.anomaly_count)

  // 檢查所有數據是否在同一天
  const isSameDate = checkIfSameDate(xAxisData)

  const option = {
    title: {
      show: false  // 隱藏標題以節省空間
    },
    tooltip: {
      trigger: 'axis',
      axisPointer: {
        type: 'shadow'
      },
      formatter: function(params) {
        const data = params[0]
        const timeStr = xAxisData[data.dataIndex]
        // 如果同一天，只顯示時間；否則顯示完整日期時間
        const formattedTime = isSameDate ? formatTimeShort(timeStr) : formatTime(timeStr)
        return `${formattedTime}<br/>異常IP數: ${data.value}`
      }
    },
    grid: {
      left: '50px',
      right: '20px',
      top: '20px',
      bottom: '60px'  // 增加底部空間以顯示標籤
    },
    xAxis: {
      type: 'category',
      data: xAxisData,
      axisLabel: {
        rotate: 45,  // 旋轉標籤避免重疊
        fontSize: 10,
        interval: 0,  // 顯示所有標籤
        formatter: function(value) {
          // 如果所有數據在同一天，只顯示時間；否則顯示日期+時間
          return formatTimeHourOnly(value, isSameDate)
        }
      }
    },
    yAxis: {
      type: 'value',
      name: '異常IP數',
      nameTextStyle: {
        fontSize: 11
      },
      minInterval: 1,
      axisLabel: {
        fontSize: 10
      }
    },
    series: [
      {
        name: '異常數',
        type: 'bar',
        data: yAxisData,
        itemStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: '#f56c6c' },
            { offset: 1, color: '#e6a23c' }
          ])
        },
        emphasis: {
          itemStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: '#ff4d4f' },
              { offset: 1, color: '#ff7a45' }
            ])
          }
        }
      }
    ]
  }

  chartInstance.setOption(option)

  // 點擊柱狀圖事件
  chartInstance.on('click', function(params) {
    const bucketIndex = params.dataIndex
    selectedBucket.value = buckets[bucketIndex]

    // 更新餅圖為該時段的特徵分布
    updatePieChartForBucket(buckets[bucketIndex])

    // 平滑滾動到詳情表格
    nextTick(() => {
      const detailsEl = document.querySelector('.selected-bucket-details')
      if (detailsEl) {
        detailsEl.scrollIntoView({ behavior: 'smooth', block: 'start' })
      }
    })
  })

  // 響應式調整
  window.addEventListener('resize', () => {
    chartInstance?.resize()
  })
}

// 初始化餅圖 - 行為特徵分布
function initPieChart() {
  if (!pieChart.value) return

  // 銷毀舊圖表實例
  if (pieChartInstance) {
    pieChartInstance.dispose()
  }

  // 創建新圖表實例
  pieChartInstance = echarts.init(pieChart.value)

  const buckets = detectionStore.buckets

  // 統計所有異常記錄的行為特徵數量（一個記錄可能有多個特徵）
  const featureStats = {
    '高連線數': 0,
    '掃描模式': 0,
    '小封包': 0,
    '大流量': 0,
    '伺服器回應': 0
  }

  buckets.forEach(bucket => {
    bucket.anomalies.forEach(anomaly => {
      // ES 中的 behavior_features 是字串格式，包含多個特徵用逗號分隔
      const behaviorFeatures = anomaly.behavior_features || ''

      // 統計各種行為特徵（字串包含檢查）
      if (behaviorFeatures.includes('高連線數')) {
        featureStats['高連線數']++
      }
      if (behaviorFeatures.includes('掃描模式')) {
        featureStats['掃描模式']++
      }
      if (behaviorFeatures.includes('小封包')) {
        featureStats['小封包']++
      }
      if (behaviorFeatures.includes('大流量')) {
        featureStats['大流量']++
      }
      if (behaviorFeatures.includes('伺服器回應')) {
        featureStats['伺服器回應']++
      }
    })
  })

  // 轉換為 ECharts 餅圖數據格式，過濾掉數量為 0 的項目
  const pieData = Object.entries(featureStats)
    .filter(([_, value]) => value > 0)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value) // 按數量降序排序

  // 如果沒有數據，顯示提示
  if (pieData.length === 0) {
    pieData.push({ name: '無特徵數據', value: 1 })
  }

  const option = {
    tooltip: {
      trigger: 'item',
      formatter: '{b}: {c} 件 ({d}%)'
    },
    legend: {
      orient: 'horizontal',
      bottom: 10,
      left: 'center',
      type: 'scroll'
    },
    series: [
      {
        name: '行為特徵',
        type: 'pie',
        radius: ['40%', '70%'],
        center: ['50%', '45%'],
        avoidLabelOverlap: true,
        itemStyle: {
          borderRadius: 8,
          borderColor: '#fff',
          borderWidth: 2
        },
        label: {
          show: true,
          formatter: '{b}\n{c} 件',
          fontSize: 12
        },
        emphasis: {
          label: {
            show: true,
            fontSize: 14,
            fontWeight: 'bold'
          },
          itemStyle: {
            shadowBlur: 10,
            shadowOffsetX: 0,
            shadowColor: 'rgba(0, 0, 0, 0.5)'
          }
        },
        data: pieData,
        color: ['#f56c6c', '#e6a23c', '#409eff', '#67c23a', '#9370db']
      }
    ]
  }

  pieChartInstance.setOption(option)

  // 響應式調整
  window.addEventListener('resize', () => {
    pieChartInstance?.resize()
  })
}

// 格式化時間（完整版）
function formatTime(timeStr) {
  const date = new Date(timeStr)
  return date.toLocaleString('zh-TW', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  })
}

// 格式化時間（簡短版，用於圖表 X 軸）
function formatTimeShort(timeStr) {
  const date = new Date(timeStr)
  return date.toLocaleString('zh-TW', {
    hour: '2-digit',
    minute: '2-digit'
  })
}

// 檢查所有時間戳是否在同一天
function checkIfSameDate(timeStrings) {
  if (!timeStrings || timeStrings.length === 0) return false

  const dates = timeStrings.map(ts => {
    const d = new Date(ts)
    return d.toDateString()  // 返回日期部分（不含時間）
  })

  // 檢查所有日期是否相同
  return dates.every(d => d === dates[0])
}

// 格式化時間為整點（用於 X 軸標籤）
function formatTimeHourOnly(timeStr, showDateOnly = false) {
  const date = new Date(timeStr)
  const minutes = date.getMinutes()

  // 只在整點（00分, 05分）時顯示標籤，因為 ES bucket 可能在 :05, :15, :25 等
  if (minutes === 0 || minutes === 5) {
    // 如果所有數據在同一天，只顯示時間
    if (showDateOnly) {
      return date.toLocaleString('zh-TW', {
        hour: '2-digit',
        minute: '2-digit'
      })
    }

    // 否則顯示日期+時間
    return date.toLocaleString('zh-TW', {
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  return ''  // 非整點不顯示
}

// 獲取分數標籤類型
function getScoreType(score) {
  if (score >= 0.7) return 'danger'
  if (score >= 0.6) return 'warning'
  return 'info'
}

// 獲取嚴重性標籤類型
function getSeverityType(severity) {
  const types = {
    'HIGH': 'danger',
    'MEDIUM': 'warning',
    'LOW': 'info'
  }
  return types[severity] || 'info'
}

// 跳轉到 IP 分析頁面 - 從 Top 10 異常 IP 列表
function analyzeIP(ip) {
  router.push({
    name: 'IPAnalysis',
    query: {
      ip,
      minutes: 1440  // 24 小時 = 1440 分鐘
      // top_n 移除，讓程式自動判斷顯示筆數
    }
  })
}

// 跳轉到 IP 分析頁面 - 從特定時間段
function analyzeIPFromBucket(ip, timeBucket) {
  // 計算該時間段的實際時間範圍
  // timeBucket 格式: "2025-11-17T10:05:00.000Z"
  const startTime = new Date(timeBucket)
  const endTime = new Date(startTime.getTime() + 5 * 60 * 1000)  // +5 分鐘

  router.push({
    name: 'IPAnalysis',
    query: {
      ip,
      start_time: startTime.toISOString(),  // 使用實際開始時間
      end_time: endTime.toISOString(),      // 使用實際結束時間
      time_bucket: timeBucket  // 保留用於顯示
      // top_n 移除，讓程式自動判斷顯示筆數
    }
  })
}

// 滾動到 Top 10 IP 列表
function scrollToTopIPs() {
  nextTick(() => {
    const topIPsEl = topIPsContainer.value
    if (topIPsEl) {
      topIPsEl.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  })
}

// 清除選中的時段，返回 Top 10 視圖
function clearSelectedBucket() {
  selectedBucket.value = null
  resetPieChart()
  nextTick(() => {
    scrollToTopIPs()
  })
}

// 將分鐘數轉換為可讀的時段標籤
function getTimeRangeLabel(minutes) {
  if (minutes >= 1440) {
    const days = Math.floor(minutes / 1440)
    return `${days}天`
  } else if (minutes >= 60) {
    const hours = Math.floor(minutes / 60)
    return `${hours}小時`
  } else {
    return `${minutes}分鐘`
  }
}

// 更新餅圖為特定時段的特徵分布
function updatePieChartForBucket(bucket) {
  if (!pieChartInstance) return

  // 統計該時段的行為特徵
  const featureStats = {
    '高連線數': 0,
    '掃描模式': 0,
    '小封包': 0,
    '大流量': 0,
    '伺服器回應': 0
  }

  bucket.anomalies.forEach(anomaly => {
    const behaviorFeatures = anomaly.behavior_features || ''

    if (behaviorFeatures.includes('高連線數')) {
      featureStats['高連線數']++
    }
    if (behaviorFeatures.includes('掃描模式')) {
      featureStats['掃描模式']++
    }
    if (behaviorFeatures.includes('小封包')) {
      featureStats['小封包']++
    }
    if (behaviorFeatures.includes('大流量')) {
      featureStats['大流量']++
    }
    if (behaviorFeatures.includes('伺服器回應')) {
      featureStats['伺服器回應']++
    }
  })

  // 轉換為餅圖數據
  const pieData = Object.entries(featureStats)
    .filter(([_, value]) => value > 0)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)

  if (pieData.length === 0) {
    pieData.push({ name: '無特徵數據', value: 1 })
  }

  // 更新標題
  pieChartTitle.value = `行為特徵分布（${formatTime(bucket.time_bucket)}）`

  // 更新餅圖
  pieChartInstance.setOption({
    series: [{
      data: pieData
    }]
  })
}

// 重置餅圖為全時段統計
function resetPieChart() {
  pieChartTitle.value = '行為特徵分布（全時段）'
  initPieChart()
}
</script>

<style scoped>
.dashboard {
  display: flex;
  flex-direction: column;
  gap: 20px;
  width: 100%;
  max-width: 100%;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-weight: 600;
}

.results-panel {
  margin-top: 20px;
  width: 100%;
}

.chart-container {
  width: 100%;
  height: 200px;
  margin-top: 20px;
}

.pie-chart-container {
  width: 100%;
  margin-top: 30px;
  padding: 20px;
  background: #f9f9f9;
  border-radius: 8px;
}

.pie-chart-title {
  font-size: 16px;
  font-weight: 600;
  color: #303133;
  margin-bottom: 15px;
  text-align: center;
}

.pie-chart {
  width: 100%;
  height: 350px;
}

.top-ips-container {
  margin-top: 30px;
}

.top-ips-container :deep(.el-divider__text) {
  display: flex;
  align-items: center;
  font-size: 16px;
  font-weight: 600;
  color: #303133;
}

.top-ips-container :deep(.el-table) {
  width: 100%;
}

.selected-bucket-details {
  margin-top: 30px;
}

.selected-bucket-details :deep(.el-divider__text) {
  width: 100%;
}

.bucket-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
  font-size: 15px;
  font-weight: 500;
  color: #303133;
}

.bucket-header > div {
  display: flex;
  align-items: center;
}

.selected-bucket-details :deep(.el-table) {
  width: 100%;
}
</style>
