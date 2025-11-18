<template>
  <div class="ip-analysis">
    <!-- 搜尋面板 -->
    <el-card shadow="never">
      <template #header>
        <span>IP 行為分析</span>
      </template>

      <el-form :inline="true">
        <el-form-item label="IP 地址">
          <el-input
            v-model="ipAddress"
            placeholder="例如: 192.168.10.135"
            style="width: 220px"
            :disabled="loading"
            @keyup.enter="handleAnalyze"
          />
        </el-form-item>

        <el-form-item label="時間範圍">
          <el-select v-model="minutes" placeholder="選擇時間範圍" style="width: 150px" :disabled="loading">
            <el-option label="10 分鐘" :value="10" />
            <el-option label="30 分鐘" :value="30" />
            <el-option label="1 小時" :value="60" />
            <el-option label="3 小時" :value="180" />
            <el-option label="6 小時" :value="360" />
            <el-option label="12 小時" :value="720" />
            <el-option label="24 小時" :value="1440" />
            <el-option label="48 小時" :value="2880" />
          </el-select>
        </el-form-item>

        <el-form-item v-if="loading">
          <el-tag type="info">
            <el-icon class="is-loading"><Loading /></el-icon>
            分析中...
          </el-tag>
        </el-form-item>

        <el-form-item v-if="results && !loading">
          <el-button
            type="success"
            @click="handleLLMAnalysis"
            :loading="llmLoading"
          >
            <el-icon><ChatDotRound /></el-icon>
            AI 安全報告
          </el-button>
          <el-button
            type="primary"
            @click="handleBetaTest"
            plain
          >
            <el-icon><Discount /></el-icon>
            Beta
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- 結果顯示 -->
    <div v-if="results">
      <!-- 基本資訊 -->
      <el-card shadow="never" class="info-card">
        <template #header>
          <div class="card-header">
            <span>
              <el-icon><Monitor /></el-icon>
              基本資訊
            </span>
            <el-tag size="large">{{ results.device_emoji }} {{ results.device_type }}</el-tag>
          </div>
        </template>

        <el-descriptions :column="3" border>
          <el-descriptions-item label="分析 IP">
            <el-text tag="b" size="large">{{ results.ip }}</el-text>
          </el-descriptions-item>
          <el-descriptions-item label="時間範圍">
            {{ formatDuration(results.time_range?.duration_minutes) }}
            <el-tag v-if="timeBucket" type="info" size="small" style="margin-left: 8px">
              特定時段分析
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="設備類型">
            {{ results.device_emoji }} {{ results.device_type }}
          </el-descriptions-item>
          <el-descriptions-item v-if="timeBucket" label="分析時段" :span="3">
            <el-tag type="primary" size="large">
              {{ formatTimeBucket(timeBucket) }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="分析起始">
            {{ formatDateTime(results.time_range?.start) }}
          </el-descriptions-item>
          <el-descriptions-item label="分析結束">
            {{ formatDateTime(results.time_range?.end) }}
          </el-descriptions-item>
          <el-descriptions-item label="顯示模式">
            <el-tag v-if="topN" type="success">
              顯示前 {{ topN }} 筆資料 (自動模式)
            </el-tag>
            <el-tag v-else type="info">
              載入中...
            </el-tag>
          </el-descriptions-item>
        </el-descriptions>
      </el-card>

      <!-- 步驟1: 異常行為特徵檢測 -->
      <el-card v-if="results.behavior_analysis?.behaviors?.length" shadow="never" class="behavior-card">
        <template #header>
          <div class="card-header">
            <span>
              <el-icon><DataLine /></el-icon>
              步驟 1：異常行為特徵檢測
              <el-tooltip
                effect="dark"
                placement="top"
                raw-content
              >
                <template #content>
                  <div style="max-width: 400px;">
                    <p><strong>Isolation Forest 異常檢測</strong></p>
                    <p style="margin: 8px 0;">
                      系統使用機器學習演算法 (Isolation Forest) 分析此 IP 的流量特徵，<br/>
                      檢測到以下異常行為模式。
                    </p>
                    <p style="margin: 8px 0;">
                      只有異常置信度 > 60% 的流量會被記錄並進入下一階段的威脅分類。
                    </p>
                  </div>
                </template>
                <el-icon style="margin-left: 4px; cursor: help; color: #409eff;">
                  <InfoFilled />
                </el-icon>
              </el-tooltip>
            </span>
          </div>
        </template>

        <el-alert
          title="偵測到異常流量行為"
          type="warning"
          :closable="false"
          show-icon
        >
          <div class="behaviors-section">
            <p style="margin-bottom: 12px;">以下行為特徵觸發了異常檢測：</p>
            <el-space wrap>
              <el-tag
                v-for="behavior in results.behavior_analysis.behaviors"
                :key="behavior"
                type="warning"
                size="large"
                effect="dark"
              >
                {{ behavior }}
              </el-tag>
            </el-space>
          </div>
        </el-alert>
      </el-card>

      <!-- 步驟2: 威脅評估與分類 -->
      <el-card v-if="results.threat_classification" shadow="never" class="threat-card">
        <template #header>
          <div class="card-header">
            <span>
              <el-icon><Warning /></el-icon>
              步驟 2：威脅評估與分類
              <el-tooltip
                effect="dark"
                placement="top"
                raw-content
              >
                <template #content>
                  <div style="max-width: 400px;">
                    <p><strong>威脅分類 (Threat Classification)</strong></p>
                    <p style="margin: 8px 0;">
                      基於步驟 1 檢測到的異常行為特徵，系統進一步分析威脅類型。
                    </p>
                    <p style="margin: 8px 0;">
                      常見威脅類型包括：埠掃描、網路掃描、DDoS 攻擊、資料外洩等。
                    </p>
                    <p style="margin: 8px 0;">
                      <strong>註：</strong>「未知異常」表示系統檢測到異常行為，但無法歸類為已知威脅類型，建議人工審查。
                    </p>
                  </div>
                </template>
                <el-icon style="margin-left: 4px; cursor: help; color: #409eff;">
                  <InfoFilled />
                </el-icon>
              </el-tooltip>
            </span>
          </div>
        </template>

        <el-alert
          :title="`${results.threat_classification.severity_emoji} ${results.threat_classification.class_name} (${results.threat_classification.class_name_en})`"
          :type="getSeverityAlertType(results.threat_classification.severity)"
          :closable="false"
          show-icon
        >
          <el-descriptions :column="2" border class="threat-desc">
            <el-descriptions-item label="檢測時間" :span="2">
              <el-tag type="info" size="large">
                {{ formatDetectionTime(results.threat_classification.detection_time) }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item v-if="results.threat_classification.anomaly_confidence">
              <template #label>
                異常置信度
                <el-tooltip effect="dark" placement="top">
                  <template #content>
                    <div style="max-width: 300px;">
                      <strong>Isolation Forest 異常檢測置信度</strong><br/>
                      表示此 IP 的流量行為被判定為異常的確定程度。<br/>
                      只有 > 60% 的異常流量會被系統記錄。
                    </div>
                  </template>
                  <el-icon style="margin-left: 4px; cursor: help; font-size: 14px;">
                    <InfoFilled />
                  </el-icon>
                </el-tooltip>
              </template>
              <el-tag type="success" size="large">
                {{ (results.threat_classification.anomaly_confidence * 100).toFixed(1) }}%
              </el-tag>
              <el-text type="info" size="small" style="margin-left: 8px">
                (Isolation Forest 檢測)
              </el-text>
            </el-descriptions-item>
            <el-descriptions-item>
              <template #label>
                威脅分類置信度
                <el-tooltip effect="dark" placement="top">
                  <template #content>
                    <div style="max-width: 300px;">
                      <strong>威脅類型判定置信度</strong><br/>
                      表示系統對此異常流量的威脅類型判斷的確定程度。<br/>
                      50% 通常表示「未知異常」，需要人工進一步分析。
                    </div>
                  </template>
                  <el-icon style="margin-left: 4px; cursor: help; font-size: 14px;">
                    <InfoFilled />
                  </el-icon>
                </el-tooltip>
              </template>
              <el-progress
                :percentage="(results.threat_classification.confidence * 100)"
                :color="getConfidenceColor(results.threat_classification.confidence)"
                :stroke-width="20"
              />
            </el-descriptions-item>
            <el-descriptions-item label="嚴重性">
              <el-tag :type="getSeverityAlertType(results.threat_classification.severity)" size="large">
                {{ results.threat_classification.severity }}
              </el-tag>
              <el-tag type="info" size="large" style="margin-left: 8px">
                優先級: {{ results.threat_classification.priority }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="描述" :span="2">
              {{ results.threat_classification.description }}
            </el-descriptions-item>
          </el-descriptions>

          <div v-if="results.threat_classification.indicators?.length" class="indicators-section">
            <h4>🔍 關鍵指標</h4>
            <ul>
              <li v-for="(indicator, index) in results.threat_classification.indicators" :key="index">
                {{ indicator }}
              </li>
            </ul>
          </div>

          <div v-if="results.threat_classification.response?.length" class="response-section">
            <h4>💡 建議行動</h4>
            <el-tag type="danger" size="large">{{ results.threat_classification.response[0] }}</el-tag>
          </div>
        </el-alert>
      </el-card>

      <!-- 流量統計 -->
      <el-card shadow="never" class="stats-card">
        <template #header>
          <div class="card-header">
            <span>
              <el-icon><DataLine /></el-icon>
              異常流量統計摘要
              <el-tag v-if="results.threat_classification" type="info" size="small" style="margin-left: 8px">
                {{ formatDetectionTimeRange(results.threat_classification.detection_time) }}
              </el-tag>
            </span>
          </div>
        </template>

        <el-row :gutter="16">
          <el-col :span="6">
            <el-statistic title="總流量數" :value="results.summary?.total_flows || 0" :precision="0">
              <template #suffix>flows</template>
            </el-statistic>
          </el-col>
          <el-col :span="6">
            <el-statistic title="總封包數" :value="results.summary?.total_packets || 0" :precision="0">
              <template #suffix>packets</template>
            </el-statistic>
          </el-col>
          <el-col :span="6">
            <div class="custom-statistic">
              <div class="statistic-title">總位元組</div>
              <div class="statistic-value">{{ formatBytes(results.summary?.total_bytes || 0) }}</div>
            </div>
          </el-col>
          <el-col :span="6">
            <div class="custom-statistic">
              <div class="statistic-title">平均封包大小</div>
              <div class="statistic-value">{{ formatBytes(results.summary?.avg_bytes || 0) }}</div>
            </div>
          </el-col>
        </el-row>

        <el-divider />

        <el-row :gutter="16">
          <el-col :span="6">
            <el-statistic title="不重複目的地" :value="getUniqueDestinationsCount()" :precision="0">
              <template #suffix>IPs</template>
            </el-statistic>
          </el-col>
          <el-col :span="6">
            <el-statistic title="不重複來源埠" :value="results.summary?.unique_src_ports || 0" :precision="0">
              <template #suffix>ports</template>
            </el-statistic>
          </el-col>
          <el-col :span="6">
            <el-statistic title="不重複目的埠" :value="results.summary?.unique_dst_ports || 0" :precision="0">
              <template #suffix>ports</template>
            </el-statistic>
          </el-col>
          <el-col :span="6">
            <el-statistic
              title="埠分散度"
              :value="getPortDispersion(results.summary)"
              :precision="2"
            >
              <template #suffix>
                <el-tag
                  :type="getDispersionType(getPortDispersion(results.summary))"
                  size="small"
                >
                  {{ getDispersionLabel(getPortDispersion(results.summary)) }}
                </el-tag>
              </template>
            </el-statistic>
          </el-col>
        </el-row>
      </el-card>

      <!-- Top 目的地 -->
      <el-card v-if="results.details?.top_destinations?.length" shadow="never" class="details-card">
        <template #header>
          <div class="card-header">
            <span>
              <el-icon><Position /></el-icon>
              Top 通訊目的地
              <el-tag v-if="!showAllDestinations && hasMoreDestinations" type="info" size="small" style="margin-left: 8px;">
                顯示前 10 名，共 {{ results.details.top_destinations.length }} 名
              </el-tag>
              <el-tag v-else-if="results.details.top_destinations.length > 10" type="success" size="small" style="margin-left: 8px;">
                顯示全部 {{ results.details.top_destinations.length }} 名
              </el-tag>
            </span>
          </div>
        </template>

        <el-table :data="displayedDestinations" stripe border>
          <el-table-column type="index" label="#" width="60" :index="(index) => index + 1" />
          <el-table-column prop="dst_ip" label="目的 IP" width="180" />
          <el-table-column prop="flow_count" label="流量數" width="120" sortable>
            <template #default="{ row }">
              {{ row.flow_count.toLocaleString() }}
            </template>
          </el-table-column>
          <el-table-column label="總位元組" width="150" sortable :sort-method="(a, b) => a.total_bytes - b.total_bytes">
            <template #default="{ row }">
              {{ formatBytes(row.total_bytes) }}
            </template>
          </el-table-column>
          <el-table-column label="流量佔比" width="200">
            <template #default="{ row }">
              <el-progress
                :percentage="(row.total_bytes / results.summary.total_bytes * 100)"
                :format="(p) => p.toFixed(1) + '%'"
              />
            </template>
          </el-table-column>
        </el-table>

        <!-- 展開/收合按鈕 -->
        <div v-if="hasMoreDestinations" style="text-align: center; margin-top: 12px;">
          <el-button
            :type="showAllDestinations ? 'info' : 'primary'"
            size="small"
            @click="showAllDestinations = !showAllDestinations"
          >
            {{ showAllDestinations ? '收合列表' : `展開更多 (還有 ${results.details.top_destinations.length - 10} 筆)` }}
            <el-icon style="margin-left: 4px;">
              <component :is="showAllDestinations ? 'ArrowUp' : 'ArrowDown'" />
            </el-icon>
          </el-button>
        </div>
      </el-card>

      <!-- 埠號分佈 -->
      <el-row :gutter="16" v-if="hasPortDistribution()">
        <el-col :span="12">
          <el-card shadow="never" class="details-card">
            <template #header>
              <div class="card-header">
                <span>
                  <el-icon><Connection /></el-icon>
                  Top 目的埠號分佈
                </span>
              </div>
            </template>

            <el-table :data="getTopPorts(results.details.port_distribution)" stripe border max-height="400">
              <el-table-column type="index" label="#" width="60" />
              <el-table-column prop="port" label="埠號" width="100" />
              <el-table-column prop="count" label="連線數" sortable>
                <template #default="{ row }">
                  {{ row.count.toLocaleString() }}
                </template>
              </el-table-column>
              <el-table-column label="佔比" width="150">
                <template #default="{ row }">
                  <el-progress
                    :percentage="row.percentage"
                    :format="(p) => p.toFixed(1) + '%'"
                    :stroke-width="12"
                  />
                </template>
              </el-table-column>
            </el-table>
          </el-card>
        </el-col>

        <el-col :span="12">
          <el-card shadow="never" class="details-card">
            <template #header>
              <div class="card-header">
                <span>
                  <el-icon><Document /></el-icon>
                  協定分佈
                </span>
              </div>
            </template>

            <el-table :data="getProtocolData(results.details.protocol_breakdown)" stripe border max-height="400">
              <el-table-column type="index" label="#" width="60" />
              <el-table-column prop="protocol" label="協定編號" width="100" />
              <el-table-column prop="protocolName" label="協定名稱" width="120">
                <template #default="{ row }">
                  <el-tag :type="row.protocolName === 'TCP' ? 'success' : row.protocolName === 'UDP' ? 'warning' : 'info'" size="small">
                    {{ row.protocolName }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="count" label="流量數" sortable>
                <template #default="{ row }">
                  {{ row.count.toLocaleString() }}
                </template>
              </el-table-column>
              <el-table-column label="佔比" width="150">
                <template #default="{ row }">
                  <el-progress
                    :percentage="row.percentage"
                    :format="(p) => p.toFixed(1) + '%'"
                    :stroke-width="12"
                  />
                </template>
              </el-table-column>
            </el-table>
          </el-card>
        </el-col>
      </el-row>

      <!-- 詳細數據不可用提示 -->
      <el-card v-else-if="results && !hasPortDistribution()" shadow="never" class="details-card">
        <el-alert
          title="詳細流量數據不可用"
          type="info"
          :closable="false"
          show-icon
        >
          <p>原始 NetFlow 記錄已過期或被清理，僅保留聚合統計資訊。</p>
          <p>埠號分佈和協定分佈數據暫時無法顯示。</p>
        </el-alert>
      </el-card>
    </div>

    <el-empty v-else description="請輸入 IP 地址並點擊分析按鈕" />

    <!-- LLM 安全報告對話框 -->
    <el-dialog
      v-model="llmDialogVisible"
      title="AI 安全分析報告"
      width="800px"
      :close-on-click-modal="false"
      :close-on-press-escape="false"
    >
      <!-- Loading 進度 -->
      <div v-if="llmLoading" class="llm-loading">
        <el-progress :percentage="llmProgress" :stroke-width="12" status="success">
          <template #default="{ percentage }">
            <span style="font-size: 14px">{{ percentage }}%</span>
          </template>
        </el-progress>
        <div class="progress-text">
          <el-icon class="is-loading"><Loading /></el-icon>
          <span style="margin-left: 8px">{{ llmProgressText }}</span>
        </div>
      </div>

      <!-- 分析結果 -->
      <div v-else-if="llmReport && llmReport.status === 'success'" class="llm-report">
        <div id="pdf-content" class="report-content">
          <!-- 報告標題與製作日期 -->
          <div class="report-header">
            <h1 style="color: #409eff; font-size: 24px; margin-bottom: 8px;">AI 安全分析報告</h1>
            <div class="report-date">
              <el-tag type="info" size="small">
                <el-icon><Calendar /></el-icon>
                製作日期: {{ reportGeneratedDate }}
              </el-tag>
              <el-tag type="primary" size="small" style="margin-left: 8px;">
                <el-icon><Monitor /></el-icon>
                分析 IP: {{ results.ip }}
              </el-tag>
              <el-tag v-if="results.device_type" type="success" size="small" style="margin-left: 8px;">
                {{ results.device_emoji }} {{ results.device_type }}
              </el-tag>
            </div>
            <div class="report-timerange" style="margin-top: 12px;">
              <el-tag type="warning" size="small">
                <el-icon><Clock /></el-icon>
                分析時間範圍: {{ formatDateTime(results.time_range?.start) }} ~ {{ formatDateTime(results.time_range?.end) }}
                ({{ results.time_range?.duration_minutes }} 分鐘)
              </el-tag>
            </div>
          </div>
          <el-divider />

          <!-- Part 1: AI Agent 分析 -->
          <div class="pdf-part-1">
            <h1 style="color: #409eff; font-size: 22px; margin-bottom: 20px; border-bottom: 3px solid #409eff; padding-bottom: 10px;">
              📋 Part 1: AI Agent 安全分析
            </h1>

            <div class="pdf-section">
              <h2 style="color: #409eff; border-bottom: 2px solid #409eff;">🤖 AI 深度分析</h2>
              <div v-html="renderMarkdown(llmReport.analysis)"></div>
            </div>
          </div>

          <!-- Part 2: 異常偵測結果與統計數據 (新頁面) -->
          <div class="pdf-page-break"></div>
          <div class="pdf-part-2">
            <h1 style="color: #e6a23c; font-size: 22px; margin-bottom: 20px; border-bottom: 3px solid #e6a23c; padding-bottom: 10px;">
              📊 Part 2: 異常偵測結果與流量統計
            </h1>

            <!-- Isolation Forest 說明 -->
            <div class="pdf-section">
              <h2 style="color: #67c23a; border-bottom: 2px solid #67c23a;">🔍 偵測方法說明</h2>
              <div class="method-explanation">
                <p><strong>採用技術：Isolation Forest（孤立森林）</strong></p>
                <p>Isolation Forest 是一種基於異常檢測的機器學習演算法，專門用於識別數據中的異常值。其核心原理是：異常數據點更容易被「孤立」。</p>

                <p><strong>運作原理：</strong></p>
                <ul>
                  <li><strong>隨機分割：</strong>演算法隨機選擇特徵和分割值，建立多棵決策樹</li>
                  <li><strong>孤立路徑：</strong>異常點因為與正常數據差異大，通常在較少的分割次數後就會被孤立</li>
                  <li><strong>異常分數：</strong>根據孤立一個數據點所需的平均路徑長度計算異常分數，路徑越短表示越異常</li>
                </ul>

                <p><strong>應用於網路流量分析：</strong></p>
                <ul>
                  <li>分析特徵包括：流量數、埠分散度、封包大小、通訊模式等</li>
                  <li>自動學習正常網路行為基準</li>
                  <li>識別偏離正常模式的異常流量行為</li>
                  <li>提供威脅分類和置信度評估</li>
                </ul>
              </div>
            </div>

          <!-- 威脅評估 -->
          <div v-if="results.threat_classification" class="pdf-section">
            <h2 style="color: #f56c6c; border-bottom: 2px solid #f56c6c;">🚨 威脅評估</h2>
            <div class="threat-summary">
              <p><strong>威脅類型：</strong>{{ results.threat_classification.severity_emoji }} {{ results.threat_classification.class_name }} ({{ results.threat_classification.class_name_en }})</p>
              <p><strong>嚴重性：</strong>{{ results.threat_classification.severity }} | <strong>優先級：</strong>{{ results.threat_classification.priority }}</p>
              <p><strong>置信度：</strong>{{ (results.threat_classification.confidence * 100).toFixed(1) }}%</p>
              <p><strong>檢測時間：</strong>{{ formatDetectionTime(results.threat_classification.detection_time) }}</p>
              <p><strong>描述：</strong>{{ results.threat_classification.description }}</p>

              <div v-if="results.threat_classification.indicators?.length">
                <p><strong>🔍 關鍵指標：</strong></p>
                <ul>
                  <li v-for="(indicator, index) in results.threat_classification.indicators" :key="index">
                    {{ indicator }}
                  </li>
                </ul>
              </div>

              <div v-if="results.threat_classification.response?.length">
                <p><strong>💡 建議行動：</strong></p>
                <ul>
                  <li v-for="(action, index) in results.threat_classification.response" :key="index">
                    {{ action }}
                  </li>
                </ul>
              </div>
            </div>
          </div>

          <!-- 異常流量統計摘要 -->
          <div class="pdf-section">
            <h2 style="color: #409eff; border-bottom: 2px solid #409eff;">📊 異常流量統計摘要</h2>
            <div class="stats-summary">
              <p><strong>分析時間範圍：</strong>{{ formatDateTime(results.time_range?.start) }} ~ {{ formatDateTime(results.time_range?.end) }}</p>
              <p><strong>時間長度：</strong>{{ formatDuration(results.time_range?.duration_minutes) }}</p>
              <p><strong>總流量數：</strong>{{ (results.summary?.total_flows || 0).toLocaleString() }} flows</p>
              <p><strong>總封包數：</strong>{{ (results.summary?.total_packets || 0).toLocaleString() }} packets</p>
              <p><strong>總位元組：</strong>{{ formatBytes(results.summary?.total_bytes || 0) }}</p>
              <p><strong>平均封包大小：</strong>{{ formatBytes(results.summary?.avg_bytes || 0) }}</p>
              <p><strong>不重複目的地：</strong>{{ (results.summary?.unique_destinations || 0).toLocaleString() }} IPs</p>
              <p><strong>不重複來源埠：</strong>{{ (results.summary?.unique_src_ports || 0).toLocaleString() }} ports</p>
              <p><strong>不重複目的埠：</strong>{{ (results.summary?.unique_dst_ports || 0).toLocaleString() }} ports</p>
              <p><strong>埠分散度：</strong>{{ getPortDispersion(results.summary).toFixed(2) }} ({{ getDispersionLabel(getPortDispersion(results.summary)) }})</p>
            </div>
          </div>

          <!-- Top 通訊目的地 -->
          <div v-if="results.details?.top_destinations?.length" class="pdf-section">
            <h2 style="color: #67c23a; border-bottom: 2px solid #67c23a;">🎯 Top {{ results.details.top_destinations.length }} 通訊目的地</h2>
            <table class="pdf-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>目的 IP</th>
                  <th>流量數</th>
                  <th>總位元組</th>
                  <th>佔比</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(dest, index) in results.details.top_destinations.slice(0, topN)" :key="index">
                  <td>{{ index + 1 }}</td>
                  <td>{{ dest.dst_ip }}</td>
                  <td>{{ dest.flow_count.toLocaleString() }}</td>
                  <td>{{ formatBytes(dest.total_bytes) }}</td>
                  <td>{{ (dest.total_bytes / results.summary.total_bytes * 100).toFixed(1) }}%</td>
                </tr>
              </tbody>
            </table>
          </div>

          <!-- Top 目的埠號 -->
          <div v-if="hasPortDistribution()" class="pdf-section">
            <h2 style="color: #e6a23c; border-bottom: 2px solid #e6a23c;">🔌 Top 目的埠號分佈</h2>
            <table class="pdf-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>埠號</th>
                  <th>連線數</th>
                  <th>佔比</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(port, index) in getTopPorts(results.details.port_distribution).slice(0, topN)" :key="index">
                  <td>{{ index + 1 }}</td>
                  <td>{{ port.port }}</td>
                  <td>{{ port.count.toLocaleString() }}</td>
                  <td>{{ port.percentage.toFixed(1) }}%</td>
                </tr>
              </tbody>
            </table>
          </div>

          <!-- 協定分佈 -->
          <div v-if="results.details?.protocol_breakdown" class="pdf-section">
            <h2 style="color: #909399; border-bottom: 2px solid #909399;">📡 協定分佈</h2>
            <table class="pdf-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>協定編號</th>
                  <th>協定名稱</th>
                  <th>流量數</th>
                  <th>佔比</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(proto, index) in getProtocolData(results.details.protocol_breakdown)" :key="index">
                  <td>{{ index + 1 }}</td>
                  <td>{{ proto.protocol }}</td>
                  <td>{{ proto.protocolName }}</td>
                  <td>{{ proto.count.toLocaleString() }}</td>
                  <td>{{ proto.percentage.toFixed(1) }}%</td>
                </tr>
              </tbody>
            </table>
          </div>
          </div>
          <!-- End of Part 2 -->
        </div>

        <el-divider />
        <div class="report-meta">
          <el-tag size="small">模型: {{ llmReport.model }}</el-tag>
          <el-tag size="small" type="info" style="margin-left: 8px">
            Tokens: {{ llmReport.tokens_used?.total || 0 }}
          </el-tag>
        </div>
      </div>
      <div v-else-if="llmReport && llmReport.status === 'disabled'" class="llm-error">
        <el-alert
          title="AI 功能未啟用"
          type="warning"
          :closable="false"
          show-icon
        >
          <p>{{ llmReport.error }}</p>
          <p>請在後端設置 OPENAI_API_KEY 環境變數以啟用此功能。</p>
        </el-alert>
      </div>
      <div v-else-if="llmReport && llmReport.status === 'error'" class="llm-error">
        <el-alert
          title="分析失敗"
          type="error"
          :closable="false"
          show-icon
        >
          <p>{{ llmReport.error }}</p>
        </el-alert>
      </div>
      <div v-else class="llm-loading">
        <el-skeleton :rows="8" animated />
      </div>

      <!-- 明確的關閉按鈕 -->
      <template #footer>
        <div class="dialog-footer">
          <el-button
            v-if="llmReport && llmReport.status === 'success'"
            type="success"
            @click="downloadPDF"
            :loading="pdfGenerating"
            size="default"
          >
            <el-icon><Download /></el-icon>
            下載 PDF 報告
          </el-button>
          <el-button type="primary" @click="llmDialogVisible = false" size="default">
            關閉
          </el-button>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted, watch, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { analysisAPI } from '@/services/api'
import { Monitor, Warning, DataLine, Position, Connection, Document, ChatDotRound, Loading, Calendar, Download, Discount, Clock, InfoFilled, ArrowUp, ArrowDown } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { marked } from 'marked'
import jsPDF from 'jspdf'
import html2canvas from 'html2canvas'

const route = useRoute()
const router = useRouter()

const ipAddress = ref('')
const minutes = ref(60)  // 改為分鐘，預設 60 分鐘 = 1 小時
const startTime = ref(null)  // 分析開始時間（從 Dashboard 傳來）
const endTime = ref(null)    // 分析結束時間（從 Dashboard 傳來）
const topN = ref(10)  // Top N 參數
const loading = ref(false)
const results = ref(null)
const timeBucket = ref(null)  // 儲存時間段資訊（如果從 bucket 進來）
const llmLoading = ref(false)
const llmDialogVisible = ref(false)
const llmReport = ref(null)
const llmProgress = ref(0)
const llmProgressText = ref('')
const pdfGenerating = ref(false)
const showAllDestinations = ref(false)  // 控制是否展開所有目的地

// 計算報告生成日期
const reportGeneratedDate = computed(() => {
  const now = new Date()
  return now.toLocaleString('zh-TW', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  })
})

// 計算顯示的目的地列表（根據展開狀態）
const displayedDestinations = computed(() => {
  if (!results.value?.details?.top_destinations) return []
  const destinations = results.value.details.top_destinations
  // 如果展開或總數 <= 10，顯示全部；否則只顯示前 10
  return showAllDestinations.value || destinations.length <= 10
    ? destinations
    : destinations.slice(0, 10)
})

// 計算是否需要顯示展開按鈕
const hasMoreDestinations = computed(() => {
  return results.value?.details?.top_destinations?.length > 10
})

onMounted(() => {
  // 從 query 獲取參數（從 Dashboard 跳轉過來）
  if (route.query.ip) {
    ipAddress.value = route.query.ip

    // 如果有具體的時間範圍（從特定時間段跳轉）
    if (route.query.start_time && route.query.end_time) {
      startTime.value = route.query.start_time
      endTime.value = route.query.end_time
    } else if (route.query.minutes) {
      // 如果只有 minutes 參數（從 Top 10 跳轉），使用它
      minutes.value = parseInt(route.query.minutes)
    }

    // 如果有 top_n 參數，使用它；否則設為 null（自動模式）
    if (route.query.top_n) {
      topN.value = parseInt(route.query.top_n)
    } else {
      topN.value = null  // null 表示自動模式
    }

    // 如果有時間段資訊，儲存它
    if (route.query.time_bucket) {
      timeBucket.value = route.query.time_bucket
    }

    handleAnalyze()
  }
})

// 監聽時間範圍變化，自動重新分析
watch(minutes, (newMinutes) => {
  if (ipAddress.value && results.value) {
    // 當使用者手動改變時間範圍，清除具體的開始/結束時間
    startTime.value = null
    endTime.value = null
    // 只有當已有 IP 且已執行過分析時才自動重新執行
    handleAnalyze()
  }
})

async function handleAnalyze() {
  if (!ipAddress.value) {
    ElMessage.warning('請輸入 IP 地址')
    return
  }

  loading.value = true
  try {
    const requestData = {
      ip: ipAddress.value
    }

    // 優先使用具體的時間範圍（從特定時間段跳轉）
    if (startTime.value && endTime.value) {
      requestData.start_time = startTime.value
      requestData.end_time = endTime.value
    } else {
      // 否則使用 minutes（從 Top 10 跳轉或手動輸入）
      requestData.minutes = minutes.value
    }

    // 如果有指定 topN，則傳遞
    if (topN.value !== null) {
      requestData.top_n = topN.value
    }

    const { data } = await analysisAPI.analyzeIP(requestData)

    if (data.status === 'success') {
      results.value = data

      // 自動模式：根據不重複目的地數量設置 topN（最多 100）
      if (topN.value === null && data.summary?.unique_destinations) {
        topN.value = Math.min(data.summary.unique_destinations, 100)
      }

      // 重置展開狀態（新分析時預設收合）
      showAllDestinations.value = false

      ElMessage.success('分析完成')
    } else {
      ElMessage.error(data.error || '分析失敗')
    }
  } catch (error) {
    ElMessage.error('分析失敗：' + (error.response?.data?.error || error.message))
  } finally {
    loading.value = false
  }
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
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

function getSeverityAlertType(severity) {
  const types = {
    'HIGH': 'error',
    'MEDIUM': 'warning',
    'LOW': 'info'
  }
  return types[severity] || 'info'
}

function getConfidenceColor(confidence) {
  if (confidence >= 0.8) return '#f56c6c'
  if (confidence >= 0.6) return '#e6a23c'
  return '#409eff'
}

function getPortDispersion(summary) {
  if (!summary || !summary.unique_dst_ports || !summary.total_flows) return 0
  return summary.unique_dst_ports / summary.total_flows
}

function getDispersionType(dispersion) {
  if (dispersion > 0.5) return 'danger'
  if (dispersion > 0.3) return 'warning'
  return 'success'
}

function getDispersionLabel(dispersion) {
  if (dispersion > 0.5) return '高度分散'
  if (dispersion > 0.3) return '中度分散'
  return '集中'
}

function hasPortDistribution() {
  if (!results.value || !results.value.details) return false
  const portDist = results.value.details.port_distribution
  const protocolDist = results.value.details.protocol_breakdown
  return (portDist && Object.keys(portDist).length > 0) ||
         (protocolDist && Object.keys(protocolDist).length > 0)
}

// 計算實際的不重複目的地數量
// 使用聚合統計的 unique_destinations 作為實際數量
function getUniqueDestinationsCount() {
  if (!results.value) return 0
  return results.value.summary?.unique_destinations || 0
}

// 獲取目的地顯示文字
function getDestinationDisplayText() {
  if (!results.value) return ''

  const totalCount = results.value.summary?.unique_destinations || 0
  const displayCount = results.value.details?.top_destinations?.length || 0

  // 如果顯示的數量等於總數，不需要額外說明
  if (displayCount >= totalCount) {
    return ''
  }

  // 如果顯示的少於總數，說明只顯示了部分
  return `，顯示前 ${displayCount} 個`
}

function getTopPorts(portDist) {
  if (!portDist) return []

  // 排除 port 0（非 TCP/UDP 流量）
  const filteredEntries = Object.entries(portDist).filter(([port]) => port !== '0')

  const total = filteredEntries.reduce((sum, [, count]) => sum + count, 0)
  return filteredEntries
    .map(([port, count]) => ({
      port: port,
      count: count,
      percentage: (count / total) * 100
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20)
}

// 協定編號對應表（IANA Protocol Numbers）
function getProtocolName(protocolNumber) {
  const protocols = {
    '1': 'ICMP',
    '6': 'TCP',
    '17': 'UDP',
    '41': 'IPv6',
    '47': 'GRE',
    '50': 'ESP',
    '51': 'AH',
    '58': 'ICMPv6',
    '88': 'EIGRP',
    '89': 'OSPF',
    '103': 'PIM',
    '132': 'SCTP'
  }
  return protocols[protocolNumber] || `Protocol ${protocolNumber}`
}

function getProtocolData(protocolBreakdown) {
  if (!protocolBreakdown) return []
  const total = Object.values(protocolBreakdown).reduce((sum, count) => sum + count, 0)
  return Object.entries(protocolBreakdown)
    .map(([protocol, count]) => ({
      protocol: protocol,
      protocolName: getProtocolName(protocol),
      count: count,
      percentage: (count / total) * 100
    }))
    .sort((a, b) => b.count - a.count)
}

function handleBetaTest() {
  if (!results.value) {
    ElMessage.warning('請先執行 IP 分析')
    return
  }

  // 導航到 AI Beta Test 頁面，傳遞分析結果
  router.push({
    name: 'ai-beta',
    query: {
      ip: ipAddress.value,
      minutes: minutes.value,
      topN: topN.value
    }
  })
}

async function handleLLMAnalysis() {
  if (!results.value) {
    ElMessage.warning('請先執行 IP 分析')
    return
  }

  llmDialogVisible.value = true
  llmLoading.value = true
  llmReport.value = null
  llmProgress.value = 0
  llmProgressText.value = '準備分析資料...'

  try {
    // 優化的進度更新 - 在 60% 等待 AI 回應
    const progressInterval = setInterval(() => {
      if (llmProgress.value < 20) {
        llmProgress.value += 10
        llmProgressText.value = '準備分析資料...'
      } else if (llmProgress.value < 40) {
        llmProgress.value += 10
        llmProgressText.value = '正在調用 AI 模型進行深度分析...'
      } else if (llmProgress.value < 60) {
        llmProgress.value += 5
        llmProgressText.value = '等待 AI 回應...'
      }
    }, 400)

    const { data } = await analysisAPI.getLLMSecurityReport({
      analysis_data: results.value,
      use_openrouter: true  // 使用 OpenRouter 調用 Gemini
    })

    clearInterval(progressInterval)
    llmProgress.value = 80
    llmProgressText.value = '處理分析結果...'

    // 短暫延遲
    await new Promise(resolve => setTimeout(resolve, 200))

    llmProgress.value = 100
    llmProgressText.value = '分析完成'
    llmReport.value = data

    if (data.status === 'success') {
      ElMessage.success('AI 分析完成')
    } else if (data.status === 'disabled') {
      ElMessage.warning('AI 功能未啟用')
    } else {
      ElMessage.error('AI 分析失敗')
    }
  } catch (error) {
    llmProgress.value = 0
    llmProgressText.value = ''
    llmReport.value = {
      status: 'error',
      error: error.response?.data?.error || error.message
    }
    ElMessage.error('AI 分析失敗：' + (error.response?.data?.error || error.message))
  } finally {
    llmLoading.value = false
  }
}

function renderMarkdown(markdown) {
  if (!markdown) return ''
  return marked(markdown)
}

// 格式化檢測時間（完整格式）
function formatDetectionTime(isoTime) {
  if (!isoTime) return 'N/A'
  const date = new Date(isoTime)
  return date.toLocaleString('zh-TW', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

// 格式化檢測時間範圍（10分鐘時段）
function formatDetectionTimeRange(isoTime) {
  if (!isoTime) return ''

  // 使用實際的分析時間範圍
  if (results.value?.time_range) {
    const startTime = new Date(results.value.time_range.start)
    const endTime = new Date(results.value.time_range.end)
    const durationMinutes = results.value.time_range.duration_minutes || 0

    const formatTime = (date) => {
      return date.toLocaleString('zh-TW', {
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
      })
    }

    // 根據時間長度顯示不同的標籤
    let label = '分析時段'
    if (durationMinutes <= 10) {
      label = `${durationMinutes}分鐘時段`
    } else if (durationMinutes < 60) {
      label = `${durationMinutes}分鐘時段`
    } else if (durationMinutes < 1440) {
      label = `${Math.round(durationMinutes / 60)}小時時段`
    } else {
      label = `${Math.round(durationMinutes / 1440)}天時段`
    }

    return `${label}: ${formatTime(startTime)} ~ ${formatTime(endTime)}`
  }

  // 備用邏輯（如果沒有 time_range 資訊）
  const startTime = new Date(isoTime)
  const endTime = new Date(startTime.getTime() + 10 * 60 * 1000) // +10分鐘

  const formatTime = (date) => {
    return date.toLocaleString('zh-TW', {
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  return `時段: ${formatTime(startTime)} ~ ${formatTime(endTime)}`
}

// 格式化時間段（用於顯示來源 bucket）
function formatTimeBucket(isoTime) {
  if (!isoTime) return ''
  const date = new Date(isoTime)
  return date.toLocaleString('zh-TW', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

// 格式化日期時間（完整版）
function formatDateTime(isoTime) {
  if (!isoTime) return 'N/A'
  const date = new Date(isoTime)
  return date.toLocaleString('zh-TW', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

// 下載 PDF 報告
async function downloadPDF() {
  if (!llmReport.value || llmReport.value.status !== 'success') {
    ElMessage.warning('沒有可下載的報告')
    return
  }

  pdfGenerating.value = true
  ElMessage.info('正在生成 PDF，請稍候...')

  try {
    // 創建 PDF
    const pdf = new jsPDF({
      orientation: 'portrait',
      unit: 'mm',
      format: 'a4'
    })

    const imgWidth = 190 // A4 寬度（mm）- 左右各留 10mm 邊距
    const pageHeight = 277 // A4 高度（mm）- 上下各留 10mm 邊距

    // 獲取報告標題和 Part 1
    const headerElement = document.querySelector('#pdf-content .report-header')
    const part1Element = document.querySelector('#pdf-content .pdf-part-1')

    if (!headerElement || !part1Element) {
      throw new Error('找不到報告內容')
    }

    // Part 1: 生成標題和 AI 分析部分
    ElMessage.info('正在生成 Part 1...')

    // 創建臨時容器包含標題和 Part 1
    const part1Container = document.createElement('div')
    part1Container.style.backgroundColor = '#ffffff'
    part1Container.style.padding = '20px'
    part1Container.appendChild(headerElement.cloneNode(true))
    part1Container.appendChild(part1Element.cloneNode(true))
    document.body.appendChild(part1Container)

    const canvas1 = await html2canvas(part1Container, {
      scale: 2,
      useCORS: true,
      logging: false,
      backgroundColor: '#ffffff'
    })

    document.body.removeChild(part1Container)

    const imgHeight1 = (canvas1.height * imgWidth) / canvas1.width
    let heightLeft1 = imgHeight1
    let position = 10

    // 添加 Part 1 的頁面
    pdf.addImage(canvas1.toDataURL('image/png'), 'PNG', 10, position, imgWidth, imgHeight1)
    heightLeft1 -= pageHeight

    // Part 1 如果超過一頁
    while (heightLeft1 > 0) {
      position = heightLeft1 - imgHeight1 + 10
      pdf.addPage()
      pdf.addImage(canvas1.toDataURL('image/png'), 'PNG', 10, position, imgWidth, imgHeight1)
      heightLeft1 -= pageHeight
    }

    // Part 2: 生成異常偵測和統計部分（從新頁開始）
    ElMessage.info('正在生成 Part 2...')
    const part2Element = document.querySelector('#pdf-content .pdf-part-2')

    if (!part2Element) {
      throw new Error('找不到 Part 2 內容')
    }

    const canvas2 = await html2canvas(part2Element, {
      scale: 2,
      useCORS: true,
      logging: false,
      backgroundColor: '#ffffff'
    })

    const imgHeight2 = (canvas2.height * imgWidth) / canvas2.width
    let heightLeft2 = imgHeight2
    position = 10

    // 添加新頁開始 Part 2
    pdf.addPage()
    pdf.addImage(canvas2.toDataURL('image/png'), 'PNG', 10, position, imgWidth, imgHeight2)
    heightLeft2 -= pageHeight

    // Part 2 如果超過一頁
    while (heightLeft2 > 0) {
      position = heightLeft2 - imgHeight2 + 10
      pdf.addPage()
      pdf.addImage(canvas2.toDataURL('image/png'), 'PNG', 10, position, imgWidth, imgHeight2)
      heightLeft2 -= pageHeight
    }

    // 生成檔案名稱（使用 IP 和日期）
    const now = new Date()
    const dateStr = now.toISOString().slice(0, 19).replace(/:/g, '-').replace('T', '_')
    const filename = `AI安全分析報告_${results.value.ip}_${dateStr}.pdf`

    // 下載 PDF
    pdf.save(filename)

    ElMessage.success('PDF 報告下載成功')
  } catch (error) {
    console.error('PDF 生成失敗:', error)
    ElMessage.error('PDF 生成失敗：' + error.message)
  } finally {
    pdfGenerating.value = false
  }
}
</script>

<style scoped>
.ip-analysis {
  display: flex;
  flex-direction: column;
  gap: 20px;
  width: 100%;
  max-width: 100%;
  padding: 0;
}

.info-card,
.behavior-card,
.threat-card,
.stats-card,
.details-card {
  margin-top: 0;
  width: 100%;
}

.behavior-card {
  border-left: 4px solid #e6a23c;
}

.behavior-card .behaviors-section p {
  color: #606266;
  line-height: 1.6;
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

/* 自訂統計樣式 - 與 el-statistic 一致 */
.custom-statistic {
  text-align: center;
}

.custom-statistic .statistic-title {
  font-size: 14px;
  color: #909399;
  margin-bottom: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.custom-statistic .statistic-value {
  font-size: 28px;
  font-weight: 600;
  color: #303133;
  line-height: 1;
}

.custom-statistic .statistic-suffix {
  font-size: 16px;
  color: #909399;
  margin-left: 4px;
  font-weight: 400;
}

.threat-desc {
  margin-top: 16px;
}

.indicators-section,
.response-section,
.behaviors-section {
  margin-top: 20px;
  padding: 12px;
  background-color: #f5f7fa;
  border-radius: 4px;
}

.indicators-section h4,
.response-section h4,
.behaviors-section h4 {
  margin: 0 0 12px 0;
  color: #303133;
  font-size: 14px;
  font-weight: 600;
}

.indicators-section ul {
  margin: 0;
  padding-left: 24px;
}

.indicators-section li {
  margin: 6px 0;
  color: #606266;
  line-height: 1.6;
}

.stats-card :deep(.el-statistic__head) {
  font-size: 13px;
  color: #909399;
}

.stats-card :deep(.el-statistic__number) {
  font-size: 24px;
  font-weight: 600;
}

.details-card {
  margin-top: 20px;
}

:deep(.el-descriptions__label) {
  font-weight: 600;
}

:deep(.el-table) {
  font-size: 13px;
}

.llm-loading {
  padding: 40px 20px;
  text-align: center;
}

.progress-text {
  display: flex;
  justify-content: center;
  align-items: center;
  margin-top: 24px;
  font-size: 15px;
  color: #606266;
}

.llm-report {
  max-height: 600px;
  overflow-y: auto;
}

.report-content {
  line-height: 1.8;
  color: #303133;
}

.report-content :deep(h2) {
  color: #303133;
  font-size: 18px;
  margin-top: 24px;
  margin-bottom: 16px;
  border-bottom: 3px solid #409eff;
  padding-bottom: 8px;
  background: linear-gradient(to right, #ecf5ff, transparent);
  padding: 12px 16px 8px 16px;
  margin-left: -16px;
  margin-right: -16px;
  font-weight: 700;
}

.report-content :deep(h3) {
  color: #303133;
  font-size: 16px;
  margin-top: 20px;
  margin-bottom: 12px;
  font-weight: 700;
  border-left: 4px solid #e6a23c;
  padding-left: 12px;
  background-color: #fdf6ec;
  padding-top: 8px;
  padding-bottom: 8px;
}

.report-content :deep(ul) {
  margin-left: 0;
  margin-bottom: 16px;
  padding-left: 24px;
  background-color: #fafafa;
  padding-top: 12px;
  padding-bottom: 12px;
  border-radius: 4px;
  border-left: 3px solid #e4e7ed;
}

.report-content :deep(li) {
  margin: 10px 0;
  line-height: 1.8;
  color: #303133;
}

.report-content :deep(p) {
  margin: 12px 0;
  line-height: 1.8;
  color: #303133;
}

.report-content :deep(strong) {
  color: #e6a23c;
  font-weight: 600;
  background-color: #fdf6ec;
  padding: 2px 6px;
  border-radius: 3px;
}

.report-content :deep(code) {
  background-color: #f5f7fa;
  padding: 2px 6px;
  border-radius: 3px;
  font-family: 'Courier New', monospace;
  color: #e6a23c;
  border: 1px solid #e4e7ed;
}

.report-content :deep(blockquote) {
  border-left: 4px solid #409eff;
  padding-left: 16px;
  margin: 16px 0;
  background-color: #ecf5ff;
  padding: 12px 16px;
  border-radius: 4px;
  color: #606266;
}

.report-content :deep(table) {
  width: 100%;
  border-collapse: collapse;
  margin: 16px 0;
  background-color: #fff;
  border: 1px solid #e4e7ed;
  border-radius: 4px;
  overflow: hidden;
  table-layout: auto;
}

.report-content :deep(thead) {
  background: linear-gradient(to bottom, #f5f7fa, #e4e7ed);
}

.report-content :deep(th) {
  padding: 12px 16px;
  text-align: left;
  font-weight: 600;
  color: #303133;
  border-bottom: 2px solid #409eff;
  border-right: 1px solid #e4e7ed;
  white-space: nowrap;
  min-width: 80px;
}

.report-content :deep(th:last-child) {
  border-right: none;
}

.report-content :deep(td) {
  padding: 10px 16px;
  color: #606266;
  border-bottom: 1px solid #ebeef5;
  border-right: 1px solid #ebeef5;
  vertical-align: top;
  line-height: 1.6;
}

.report-content :deep(td:last-child) {
  border-right: none;
}

.report-content :deep(tbody tr:hover) {
  background-color: #f5f7fa;
}

.report-content :deep(tbody tr:last-child td) {
  border-bottom: none;
}

/* Part 1 特殊樣式 */
.pdf-part-1 .pdf-section {
  background-color: #fafbfc;
  padding: 20px;
  border-radius: 8px;
  border: 1px solid #e4e7ed;
}

.report-meta {
  text-align: right;
  margin-top: 10px;
}

.llm-error {
  padding: 20px;
}

.llm-loading {
  padding: 20px;
}

.report-header {
  text-align: center;
  margin-bottom: 20px;
}

.report-header h1 {
  margin: 0 0 16px 0;
}

.report-date {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 8px;
}

.dialog-footer {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}

/* PDF 內容樣式 */
.pdf-page-break {
  page-break-before: always;
  break-before: page;
  margin: 40px 0;
  border-top: 3px dashed #dcdfe6;
  padding-top: 40px;
}

.pdf-part-1,
.pdf-part-2 {
  margin-bottom: 40px;
}

.pdf-section {
  margin: 24px 0;
  page-break-inside: avoid;
}

.pdf-section h2 {
  font-size: 18px;
  margin-bottom: 16px;
  padding-bottom: 8px;
}

.method-explanation {
  line-height: 1.8;
  color: #303133;
  background-color: #fafbfc;
  padding: 20px;
  border-radius: 8px;
  border: 1px solid #e4e7ed;
}

.method-explanation p {
  margin: 12px 0;
}

.method-explanation ul {
  margin: 12px 0;
  padding-left: 24px;
  background-color: #fafafa;
  padding-top: 12px;
  padding-bottom: 12px;
  border-radius: 4px;
  border-left: 3px solid #e4e7ed;
}

.method-explanation li {
  margin: 10px 0;
  line-height: 1.8;
}

.method-explanation strong {
  color: #67c23a;
  font-weight: 600;
  background-color: #f0f9ff;
  padding: 2px 6px;
  border-radius: 3px;
}

.threat-summary,
.stats-summary {
  line-height: 1.8;
  font-size: 14px;
  background-color: #fafbfc;
  padding: 20px;
  border-radius: 8px;
  border: 1px solid #e4e7ed;
}

.threat-summary p,
.stats-summary p {
  margin: 10px 0;
  padding: 8px 12px;
  background-color: #ffffff;
  border-radius: 4px;
  border-left: 3px solid #409eff;
}

.threat-summary strong,
.stats-summary strong {
  color: #303133;
  font-weight: 600;
  background-color: #ecf5ff;
  padding: 2px 6px;
  border-radius: 3px;
}

.threat-summary ul,
.stats-summary ul {
  background-color: #fafafa;
  padding: 12px 12px 12px 36px;
  border-radius: 4px;
  border-left: 3px solid #e4e7ed;
  margin: 12px 0;
}

.threat-summary li,
.stats-summary li {
  margin: 8px 0;
  line-height: 1.8;
}

.pdf-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 12px;
  font-size: 13px;
}

.pdf-table th,
.pdf-table td {
  border: 1px solid #dcdfe6;
  padding: 8px 12px;
  text-align: left;
}

.pdf-table th {
  background-color: #f5f7fa;
  font-weight: 600;
  color: #303133;
}

.pdf-table tbody tr:nth-child(even) {
  background-color: #fafafa;
}

.pdf-table tbody tr:hover {
  background-color: #f0f9ff;
}

.pdf-table td:first-child {
  text-align: center;
  font-weight: 600;
  color: #909399;
}
</style>
