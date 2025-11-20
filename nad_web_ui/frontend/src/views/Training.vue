<template>
  <div class="training">
    <!-- 雙視角說明 -->
    <el-alert type="info" :closable="false" style="margin-bottom: 20px;">
      <template #title>
        🔍 雙視角異常偵測
      </template>
      <strong>By Src (來源 IP):</strong> 偵測掃描攻擊、DDoS 來源、惡意流量發送者 |
      <strong>By Dst (目標 IP):</strong> 偵測 DDoS 目標、被掃描主機、異常服務器
    </el-alert>

    <!-- 模式切換 Tabs -->
    <el-tabs v-model="activeMode" @tab-change="handleModeChange" class="mode-tabs">
      <!-- By Src Tab -->
      <el-tab-pane name="by_src">
        <template #label>
          <span style="font-size: 15px; display: flex; align-items: center; gap: 6px;">
            📤 來源 IP 視角 (By Src)
          </span>
        </template>

        <el-row :gutter="20">
          <!-- 模型資訊 - By Src -->
          <el-col :span="12">
            <el-card shadow="never">
              <template #header>
                <div style="display: flex; align-items: center; gap: 8px;">
                  <span>模型資訊 - By Src</span>
              <el-tooltip
                placement="right"
                raw-content
              >
                <template #content>
                  <div style="max-width: 500px; line-height: 1.8;">
                    <h3 style="color: #409EFF; margin: 0 0 12px 0; font-size: 16px;">🌲 Isolation Forest 異常偵測機制說明</h3>

                    <div style="margin-bottom: 16px; padding: 10px; background-color: #f0f9ff; border-left: 3px solid #409EFF; color: #303133;">
                      <strong>核心概念：</strong><br/>
                      一種基於樹狀結構的無監督式機器學習演算法，專門用於異常檢測。<br/>
                      原理是「異常點容易被隔離」—— 與正常點相比，異常點在特徵空間中較孤立，<br/>
                      因此需要較少次數的隨機分割就能被隔離出來。
                    </div>

                    <strong>🎯 偵測原理：</strong><br/>
                    • <strong>正常數據點：</strong>聚集在一起，需要很多次分割才能被隔離（路徑長）<br/>
                    • <strong>異常數據點：</strong>遠離正常群體，很快就被隔離（路徑短）<br/>
                    • <strong>異常分數：</strong>根據平均路徑長度計算，路徑越短分數越高<br/><br/>

                    <strong>📊 演算法步驟：</strong><br/>
                    1️⃣ 從訓練資料中隨機抽樣<br/>
                    2️⃣ 建立多棵隨機決策樹（Isolation Tree）<br/>
                    3️⃣ 計算每個數據點在所有樹中的平均路徑長度<br/>
                    4️⃣ 路徑長度短的點被判定為異常<br/><br/>

                    <h3 style="color: #67C23A; margin: 16px 0 12px 0; font-size: 16px;">🌳 Random Decision Tree（隨機決策樹）</h3>

                    <div style="margin-bottom: 16px; padding: 10px; background-color: #f0f9f0; border-left: 3px solid #67C23A; color: #303133;">
                      <strong>定義：</strong><br/>
                      Isolation Forest 的基本組成單元。不同於傳統決策樹，<br/>
                      這裡的樹使用<strong>隨機特徵</strong>和<strong>隨機分割點</strong>來建立，<br/>
                      目的是將數據點逐步隔離，而非分類。
                    </div>

                    <strong>🔧 建構方式：</strong><br/>
                    • <strong>隨機選擇特徵：</strong>從所有特徵中隨機挑選一個<br/>
                    • <strong>隨機選擇分割值：</strong>在該特徵的最大最小值間隨機選擇<br/>
                    • <strong>遞迴分割：</strong>持續分割直到每個點被隔離或達到樹深度上限<br/>
                    • <strong>無需標籤：</strong>訓練過程完全不需要標記異常/正常<br/><br/>

                    <strong>🌲 為什麼需要多棵樹（森林）？</strong><br/>
                    • <strong>降低隨機性：</strong>單棵樹的隨機分割可能不準確<br/>
                    • <strong>提高穩定性：</strong>多棵樹的平均結果更可靠<br/>
                    • <strong>增加覆蓋率：</strong>不同的樹在不同維度隔離異常點<br/>
                    • <strong>減少誤判：</strong>集成學習（Ensemble）降低偏差<br/><br/>

                    <div style="margin-top: 16px; padding: 10px; background-color: #fff7e6; border-left: 3px solid #E6A23C; color: #303133;">
                      <strong>💡 實際應用類比：</strong><br/>
                      就像用多個不同角度的標準來判斷一個人是否異常：<br/>
                      單一標準可能有偏見，但綜合多個獨立判斷，結果更準確可靠。
                    </div>

                    <div style="margin-top: 16px; padding: 8px; background-color: #fef0f0; border-left: 3px solid #F56C6C; color: #303133;">
                      <strong>⚡ 演算法優勢：</strong><br/>
                      ✓ 無需標記資料（無監督學習）<br/>
                      ✓ 訓練和預測速度快<br/>
                      ✓ 記憶體占用小<br/>
                      ✓ 對高維度資料效果好<br/>
                      ✓ 可處理大規模資料集
                    </div>
                  </div>
                </template>
                <el-icon style="cursor: help; color: #409EFF;">
                  <InfoFilled />
                </el-icon>
              </el-tooltip>
            </div>
          </template>

          <div v-if="trainingStore.configBySrc" class="model-info">
            <el-descriptions :column="1" border>
              <el-descriptions-item label="模型狀態">
                <el-tag :type="getStatusTagType(trainingStore.configBySrc.model_info?.status)">
                  {{ getModelStatusText(trainingStore.configBySrc.model_info?.status) }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="訓練日期" v-if="trainingStore.configBySrc.model_info?.trained_at">
                {{ formatTrainedDate(trainingStore.configBySrc.model_info.trained_at) }}
              </el-descriptions-item>
              <el-descriptions-item label="特徵數量">
                <span v-if="trainingStore.configBySrc.model_info?.n_features">
                  {{ trainingStore.configBySrc.model_info.n_features }}
                </span>
                <el-text v-else type="info">無法取得</el-text>
              </el-descriptions-item>
              <el-descriptions-item>
                <template #label>
                  <span>決策樹數量</span>
                  <el-tooltip
                    placement="top"
                    raw-content
                  >
                    <template #content>
                      <div style="max-width: 300px;">
                        用於訓練的決策樹總數<br/>
                        數量越多檢測越穩定但訓練時間越長
                      </div>
                    </template>
                    <el-icon style="margin-left: 4px; cursor: help;">
                      <InfoFilled />
                    </el-icon>
                  </el-tooltip>
                </template>
                <span v-if="trainingStore.configBySrc.model_info?.status === 'trained'">
                  {{ trainingStore.configBySrc.model_info.n_estimators }}
                </span>
                <span v-else>
                  {{ trainingStore.configBySrc.training_config?.n_estimators }}（配置值）
                </span>
              </el-descriptions-item>
              <el-descriptions-item>
                <template #label>
                  <span>污染率</span>
                  <el-tooltip
                    placement="top"
                    raw-content
                  >
                    <template #content>
                      <div style="max-width: 350px;">
                        <strong>定義：</strong>預期資料中異常比例的估計值<br/><br/>
                        <strong>作用：</strong>影響異常分數的判定閾值<br/>
                        • 0.05 (5%)：預期 5% 的流量是異常（常用值）<br/>
                        • 數值越高：判定越寬鬆，更多流量被標記為異常<br/>
                        • 數值越低：判定越嚴格，只有極端異常才會被標記<br/><br/>
                        <strong>建議：</strong>根據網路環境調整，一般設定 0.01-0.10
                      </div>
                    </template>
                    <el-icon style="margin-left: 4px; cursor: help;">
                      <InfoFilled />
                    </el-icon>
                  </el-tooltip>
                </template>
                <span v-if="trainingStore.configBySrc.model_info?.status === 'trained'">
                  {{ trainingStore.configBySrc.model_info.contamination }}
                </span>
                <span v-else>
                  {{ trainingStore.configBySrc.training_config?.contamination }}（配置值）
                </span>
              </el-descriptions-item>
            </el-descriptions>
          </div>
        </el-card>
      </el-col>

      <!-- 訓練配置 -->
      <el-col :span="12">
        <el-card shadow="never">
          <template #header>
            <span>訓練配置</span>
          </template>

          <el-form label-position="top">
            <!-- 使用兩欄布局 -->
            <el-row :gutter="16">
              <el-col :span="12">
                <el-form-item label="訓練資料天數">
                  <el-input-number
                    v-model="trainingDays"
                    :min="1"
                    :max="14"
                    style="width: 100%;"
                  />
                </el-form-item>
              </el-col>

              <el-col :span="12">
                <el-form-item>
                  <template #label>
                    <span>決策樹數量</span>
                    <el-tooltip placement="top" raw-content>
                      <template #content>
                        <div style="max-width: 300px;">
                          Isolation Forest 使用的決策樹總數<br/>
                          • 100-150：快速訓練<br/>
                          • 150-200：平衡效能（推薦）<br/>
                          • 200-300：最高準確度
                        </div>
                      </template>
                      <el-icon style="margin-left: 4px; cursor: help;">
                        <InfoFilled />
                      </el-icon>
                    </el-tooltip>
                  </template>
                  <el-input-number
                    v-model="nEstimators"
                    :min="50"
                    :max="300"
                    :step="10"
                    style="width: 100%;"
                  />
                </el-form-item>
              </el-col>
            </el-row>

            <el-row :gutter="16">
              <el-col :span="12">
                <el-form-item>
                  <template #label>
                    <span>污染率</span>
                    <el-tooltip placement="top" raw-content>
                      <template #content>
                        <div style="max-width: 300px;">
                          預期資料中異常比例<br/>
                          • 0.01-0.03：嚴格<br/>
                          • 0.05：平衡（推薦）<br/>
                          • 0.08-0.10：寬鬆
                        </div>
                      </template>
                      <el-icon style="margin-left: 4px; cursor: help;">
                        <InfoFilled />
                      </el-icon>
                    </el-tooltip>
                  </template>
                  <el-input-number
                    v-model="contamination"
                    :min="0.01"
                    :max="0.10"
                    :step="0.01"
                    :precision="2"
                    style="width: 100%;"
                  />
                </el-form-item>
              </el-col>

              <el-col :span="12">
                <el-form-item>
                  <template #label>
                    <span>異常偵測閾值</span>
                    <el-tooltip placement="top" raw-content>
                      <template #content>
                        <div style="max-width: 300px;">
                          控制即時偵測靈敏度<br/>
                          • 0.3-0.5：高靈敏度<br/>
                          • 0.6：平衡（推薦）<br/>
                          • 0.7-0.9：低靈敏度
                        </div>
                      </template>
                      <el-icon style="margin-left: 4px; cursor: help;">
                        <InfoFilled />
                      </el-icon>
                    </el-tooltip>
                  </template>
                  <el-input-number
                    v-model="anomalyThreshold"
                    :min="0.1"
                    :max="1.0"
                    :step="0.1"
                    :precision="1"
                    style="width: 100%;"
                  />
                </el-form-item>
              </el-col>
            </el-row>


            <!-- 特徵選擇按鈕 -->
            <el-form-item label="訓練特徵選擇">
              <el-button
                @click="openFeatureSelector('by_src')"
                :icon="Edit"
                style="width: 100%;"
              >
                自訂訓練特徵
              </el-button>
              <div style="font-size: 12px; color: #909399; margin-top: 4px;">
                {{ trainingStore.configBySrc?.model_info?.n_features || '...' }} 個特徵已選擇（含二值特徵閾值編輯）
              </div>
            </el-form-item>

            <!-- 操作按鈕 -->
            <el-divider style="margin: 16px 0;" />
            <el-row :gutter="12">
              <el-col :span="12">
                <el-button
                  @click="resetToDefaults"
                  :icon="RefreshLeft"
                  size="large"
                  style="width: 100%;"
                >
                  恢復預設值
                </el-button>
              </el-col>
              <el-col :span="12">
                <el-button
                  type="primary"
                  @click="handleStartTraining('by_src')"
                  :loading="trainingStore.trainingBySrc"
                  :icon="VideoPlay"
                  size="large"
                  style="width: 100%;"
                >
                  開始訓練 (By Src)
                </el-button>
              </el-col>
            </el-row>
          </el-form>
        </el-card>
      </el-col>
    </el-row>

    <!-- 訓練進度 - By Src -->
    <el-card v-if="trainingStore.trainingBySrc || trainingStore.progressBySrc.percent > 0" shadow="never" class="progress-card">
      <template #header>
        <span>訓練進度 - By Src</span>
      </template>

      <div class="progress-content">
        <el-progress
          :percentage="trainingStore.progressBySrc.percent"
          :status="trainingStore.progressBySrc.percent === 100 ? 'success' : undefined"
        />
        <p class="progress-message">{{ trainingStore.progressBySrc.message }}</p>
      </div>
    </el-card>
      </el-tab-pane>

      <!-- By Dst Tab - 完整複製 By Src 的內容並修改綁定 -->
      <el-tab-pane name="by_dst">
        <template #label>
          <span style="font-size: 15px; display: flex; align-items: center; gap: 6px;">
            📥 目標 IP 視角 (By Dst)
          </span>
        </template>

        <!-- 這裡需要複製整個 By Src 的內容，但使用 configByDst, progressByDst, trainingByDst -->
        <!-- 為了簡化，先添加一個佔位符 -->
        <el-row :gutter="20">
          <!-- 模型資訊 - By Dst -->
          <el-col :span="12">
            <el-card shadow="never">
              <template #header>
                <div style="display: flex; align-items: center; gap: 8px;">
                  <span>模型資訊 - By Dst</span>
              <el-tooltip
                placement="right"
                raw-content
              >
                <template #content>
                  <div style="max-width: 500px; line-height: 1.8;">
                    <h3 style="color: #409EFF; margin: 0 0 12px 0; font-size: 16px;">🌲 Isolation Forest 異常偵測機制說明</h3>

                    <div style="margin-bottom: 16px; padding: 10px; background-color: #f0f9ff; border-left: 3px solid #409EFF; color: #303133;">
                      <strong>核心概念：</strong><br/>
                      一種基於樹狀結構的無監督式機器學習演算法，專門用於異常檢測。<br/>
                      原理是「異常點容易被隔離」—— 與正常點相比，異常點在特徵空間中較孤立，<br/>
                      因此需要較少次數的隨機分割就能被隔離出來。
                    </div>

                    <strong>🎯 偵測原理：</strong><br/>
                    • <strong>正常數據點：</strong>聚集在一起，需要很多次分割才能被隔離（路徑長）<br/>
                    • <strong>異常數據點：</strong>遠離正常群體，很快就被隔離（路徑短）<br/>
                    • <strong>異常分數：</strong>根據平均路徑長度計算，路徑越短分數越高<br/><br/>

                    <strong>📊 演算法步驟：</strong><br/>
                    1️⃣ 從訓練資料中隨機抽樣<br/>
                    2️⃣ 建立多棵隨機決策樹（Isolation Tree）<br/>
                    3️⃣ 計算每個數據點在所有樹中的平均路徑長度<br/>
                    4️⃣ 路徑長度短的點被判定為異常<br/><br/>

                    <h3 style="color: #67C23A; margin: 16px 0 12px 0; font-size: 16px;">🌳 Random Decision Tree（隨機決策樹）</h3>

                    <div style="margin-bottom: 16px; padding: 10px; background-color: #f0f9f0; border-left: 3px solid #67C23A; color: #303133;">
                      <strong>定義：</strong><br/>
                      Isolation Forest 的基本組成單元。不同於傳統決策樹，<br/>
                      這裡的樹使用<strong>隨機特徵</strong>和<strong>隨機分割點</strong>來建立，<br/>
                      目的是將數據點逐步隔離，而非分類。
                    </div>

                    <strong>🔧 建構方式：</strong><br/>
                    • <strong>隨機選擇特徵：</strong>從所有特徵中隨機挑選一個<br/>
                    • <strong>隨機選擇分割值：</strong>在該特徵的最大最小值間隨機選擇<br/>
                    • <strong>遞迴分割：</strong>持續分割直到每個點被隔離或達到樹深度上限<br/>
                    • <strong>無需標籤：</strong>訓練過程完全不需要標記異常/正常<br/><br/>

                    <strong>🌲 為什麼需要多棵樹（森林）？</strong><br/>
                    • <strong>降低隨機性：</strong>單棵樹的隨機分割可能不準確<br/>
                    • <strong>提高穩定性：</strong>多棵樹的平均結果更可靠<br/>
                    • <strong>增加覆蓋率：</strong>不同的樹在不同維度隔離異常點<br/>
                    • <strong>減少誤判：</strong>集成學習（Ensemble）降低偏差<br/><br/>

                    <div style="margin-top: 16px; padding: 10px; background-color: #fff7e6; border-left: 3px solid #E6A23C; color: #303133;">
                      <strong>💡 實際應用類比：</strong><br/>
                      就像用多個不同角度的標準來判斷一個人是否異常：<br/>
                      單一標準可能有偏見，但綜合多個獨立判斷，結果更準確可靠。
                    </div>

                    <div style="margin-top: 16px; padding: 8px; background-color: #fef0f0; border-left: 3px solid #F56C6C; color: #303133;">
                      <strong>⚡ 演算法優勢：</strong><br/>
                      ✓ 無需標記資料（無監督學習）<br/>
                      ✓ 訓練和預測速度快<br/>
                      ✓ 記憶體占用小<br/>
                      ✓ 對高維度資料效果好<br/>
                      ✓ 可處理大規模資料集
                    </div>
                  </div>
                </template>
                <el-icon style="cursor: help; color: #409EFF;">
                  <InfoFilled />
                </el-icon>
              </el-tooltip>
            </div>
          </template>

          <div v-if="trainingStore.configByDst" class="model-info">
            <el-descriptions :column="1" border>
              <el-descriptions-item label="模型狀態">
                <el-tag :type="getStatusTagType(trainingStore.configByDst.model_info?.status)">
                  {{ getModelStatusText(trainingStore.configByDst.model_info?.status) }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="訓練日期" v-if="trainingStore.configByDst.model_info?.trained_at">
                {{ formatTrainedDate(trainingStore.configByDst.model_info.trained_at) }}
              </el-descriptions-item>
              <el-descriptions-item label="特徵數量">
                <span v-if="trainingStore.configByDst.model_info?.n_features">
                  {{ trainingStore.configByDst.model_info.n_features }}
                </span>
                <el-text v-else type="info">無法取得</el-text>
              </el-descriptions-item>
              <el-descriptions-item>
                <template #label>
                  <span>決策樹數量</span>
                  <el-tooltip
                    placement="top"
                    raw-content
                  >
                    <template #content>
                      <div style="max-width: 300px;">
                        用於訓練的決策樹總數<br/>
                        數量越多檢測越穩定但訓練時間越長
                      </div>
                    </template>
                    <el-icon style="margin-left: 4px; cursor: help;">
                      <InfoFilled />
                    </el-icon>
                  </el-tooltip>
                </template>
                <span v-if="trainingStore.configByDst.model_info?.status === 'trained'">
                  {{ trainingStore.configByDst.model_info.n_estimators }}
                </span>
                <span v-else>
                  {{ trainingStore.configByDst.training_config?.n_estimators }}（配置值）
                </span>
              </el-descriptions-item>
              <el-descriptions-item>
                <template #label>
                  <span>污染率</span>
                  <el-tooltip
                    placement="top"
                    raw-content
                  >
                    <template #content>
                      <div style="max-width: 350px;">
                        <strong>定義：</strong>預期資料中異常比例的估計值<br/><br/>
                        <strong>作用：</strong>影響異常分數的判定閾值<br/>
                        • 0.05 (5%)：預期 5% 的流量是異常（常用值）<br/>
                        • 數值越高：判定越寬鬆，更多流量被標記為異常<br/>
                        • 數值越低：判定越嚴格，只有極端異常才會被標記<br/><br/>
                        <strong>建議：</strong>根據網路環境調整，一般設定 0.01-0.10
                      </div>
                    </template>
                    <el-icon style="margin-left: 4px; cursor: help;">
                      <InfoFilled />
                    </el-icon>
                  </el-tooltip>
                </template>
                <span v-if="trainingStore.configByDst.model_info?.status === 'trained'">
                  {{ trainingStore.configByDst.model_info.contamination }}
                </span>
                <span v-else>
                  {{ trainingStore.configByDst.training_config?.contamination }}（配置值）
                </span>
              </el-descriptions-item>
            </el-descriptions>
          </div>
        </el-card>
      </el-col>

      <!-- 訓練配置 -->
      <el-col :span="12">
        <el-card shadow="never">
          <template #header>
            <span>訓練配置</span>
          </template>

          <el-form label-position="top">
            <!-- 使用兩欄布局 -->
            <el-row :gutter="16">
              <el-col :span="12">
                <el-form-item label="訓練資料天數">
                  <el-input-number
                    v-model="trainingDays"
                    :min="1"
                    :max="14"
                    style="width: 100%;"
                  />
                </el-form-item>
              </el-col>

              <el-col :span="12">
                <el-form-item>
                  <template #label>
                    <span>決策樹數量</span>
                    <el-tooltip placement="top" raw-content>
                      <template #content>
                        <div style="max-width: 300px;">
                          Isolation Forest 使用的決策樹總數<br/>
                          • 100-150：快速訓練<br/>
                          • 150-200：平衡效能（推薦）<br/>
                          • 200-300：最高準確度
                        </div>
                      </template>
                      <el-icon style="margin-left: 4px; cursor: help;">
                        <InfoFilled />
                      </el-icon>
                    </el-tooltip>
                  </template>
                  <el-input-number
                    v-model="nEstimators"
                    :min="50"
                    :max="300"
                    :step="10"
                    style="width: 100%;"
                  />
                </el-form-item>
              </el-col>
            </el-row>

            <el-row :gutter="16">
              <el-col :span="12">
                <el-form-item>
                  <template #label>
                    <span>污染率</span>
                    <el-tooltip placement="top" raw-content>
                      <template #content>
                        <div style="max-width: 300px;">
                          預期資料中異常比例<br/>
                          • 0.01-0.03：嚴格<br/>
                          • 0.05：平衡（推薦）<br/>
                          • 0.08-0.10：寬鬆
                        </div>
                      </template>
                      <el-icon style="margin-left: 4px; cursor: help;">
                        <InfoFilled />
                      </el-icon>
                    </el-tooltip>
                  </template>
                  <el-input-number
                    v-model="contamination"
                    :min="0.01"
                    :max="0.10"
                    :step="0.01"
                    :precision="2"
                    style="width: 100%;"
                  />
                </el-form-item>
              </el-col>

              <el-col :span="12">
                <el-form-item>
                  <template #label>
                    <span>異常偵測閾值</span>
                    <el-tooltip placement="top" raw-content>
                      <template #content>
                        <div style="max-width: 300px;">
                          控制即時偵測靈敏度<br/>
                          • 0.3-0.5：高靈敏度<br/>
                          • 0.6：平衡（推薦）<br/>
                          • 0.7-0.9：低靈敏度
                        </div>
                      </template>
                      <el-icon style="margin-left: 4px; cursor: help;">
                        <InfoFilled />
                      </el-icon>
                    </el-tooltip>
                  </template>
                  <el-input-number
                    v-model="anomalyThreshold"
                    :min="0.1"
                    :max="1.0"
                    :step="0.1"
                    :precision="1"
                    style="width: 100%;"
                  />
                </el-form-item>
              </el-col>
            </el-row>


            <!-- 特徵選擇按鈕 -->
            <el-form-item label="訓練特徵選擇">
              <el-button
                @click="openFeatureSelector('by_dst')"
                :icon="Edit"
                style="width: 100%;"
              >
                自訂訓練特徵
              </el-button>
              <div style="font-size: 12px; color: #909399; margin-top: 4px;">
                {{ trainingStore.configByDst?.model_info?.n_features || '...' }} 個特徵已選擇（含二值特徵閾值編輯）
              </div>
            </el-form-item>

            <!-- 操作按鈕 -->
            <el-divider style="margin: 16px 0;" />
            <el-row :gutter="12">
              <el-col :span="12">
                <el-button
                  @click="resetToDefaults"
                  :icon="RefreshLeft"
                  size="large"
                  style="width: 100%;"
                >
                  恢復預設值
                </el-button>
              </el-col>
              <el-col :span="12">
                <el-button
                  type="primary"
                  @click="handleStartTraining('by_dst')"
                  :loading="trainingStore.trainingByDst"
                  :icon="VideoPlay"
                  size="large"
                  style="width: 100%;"
                >
                  開始訓練 (By Dst)
                </el-button>
              </el-col>
            </el-row>
          </el-form>
        </el-card>
      </el-col>
    </el-row>

    <!-- 訓練進度 - By Dst -->
    <el-card v-if="trainingStore.trainingByDst || trainingStore.progressByDst.percent > 0" shadow="never" class="progress-card">
      <template #header>
        <span>訓練進度 - By Dst</span>
      </template>

      <div class="progress-content">
        <el-progress
          :percentage="trainingStore.progressByDst.percent"
          :status="trainingStore.progressByDst.percent === 100 ? 'success' : undefined"
        />
        <p class="progress-message">{{ trainingStore.progressByDst.message }}</p>
      </div>
    </el-card>
      
      </el-tab-pane>
    </el-tabs>

    <!-- 網段設備配置 -->
    <el-card shadow="never" class="device-mapping-card">
      <template #header>
        <div class="card-header">
          <span>
            網段設備配置
            <el-tooltip
              placement="top"
              raw-content
            >
              <template #content>
                <div style="max-width: 400px;">
                  此設定用於標示各網段的實際用途和設備類型<br/>
                  可協助系統在訓練模型時更精準地辨識不同設備的正常行為模式<br/><br/>
                  <strong>設定項目：</strong><br/>
                  • IP 網段：定義設備類型的 IP 範圍<br/>
                  • 特徵：描述該類型設備的網路行為特性<br/>
                  • 說明：設備類型的用途說明
                </div>
              </template>
              <el-icon style="margin-left: 4px; cursor: help;">
                <InfoFilled />
              </el-icon>
            </el-tooltip>
          </span>
          <div>
            <el-button
              size="small"
              type="primary"
              @click="openCreateDeviceTypeDialog"
              :icon="Plus"
            >
              新增設備類別
            </el-button>
            <el-button
              size="small"
              @click="refreshDeviceMapping"
              :icon="Refresh"
              :loading="deviceMappingLoading"
            >
              重新載入
            </el-button>
          </div>
        </div>
      </template>

      <!-- 重要提醒 -->
      <el-alert
        type="warning"
        :closable="false"
        style="margin-bottom: 16px;"
      >
        <template #title>
          重要提醒
        </template>
        新增、刪除或重命名設備類型後，需要<strong>重新訓練模型</strong>才能生效。<br/>
        設備類型變更會影響模型特徵編碼，舊模型將無法使用。
      </el-alert>

      <div v-if="deviceTypes" class="device-types-compact">
        <el-collapse accordion>
          <el-collapse-item
            v-for="(typeData, typeName) in deviceTypes"
            :key="typeName"
            :name="typeName"
          >
            <template #title>
              <div class="device-type-title">
                <div style="display: flex; align-items: center; gap: 8px; flex: 1;">
                  <span class="type-icon">{{ typeData.icon }}</span>
                  <strong>{{ typeData.display_name || getDeviceTypeName(typeName) }}</strong>
                  <el-tag size="small">
                    {{ typeData.ip_ranges ? typeData.ip_ranges.length : 0 }} 個網段
                  </el-tag>
                  <el-tag size="small" type="info" v-if="isProtectedType(typeName)">
                    預設
                  </el-tag>
                </div>
                <div style="display: flex; gap: 4px;" @click.stop>
                  <el-button
                    size="small"
                    @click="openEditDeviceTypeDialog(typeName)"
                    :icon="Edit"
                  >
                    編輯類別
                  </el-button>
                  <el-button
                    size="small"
                    type="danger"
                    @click="handleDeleteDeviceType(typeName)"
                    :icon="Delete"
                    :disabled="isProtectedType(typeName)"
                  >
                    刪除
                  </el-button>
                </div>
              </div>
            </template>

            <div class="device-type-content">
              <div class="description" style="margin-bottom: 12px;">
                <strong>說明：</strong>{{ typeData.description }}
              </div>

              <div class="ip-ranges-section">
                <strong>IP 網段：</strong>
                <div v-if="typeData.ip_ranges && typeData.ip_ranges.length > 0" class="range-list">
                  <el-tag
                    v-for="(range, idx) in typeData.ip_ranges"
                    :key="idx"
                    closable
                    @close="handleRemoveIpRange(typeName, range)"
                    style="margin: 4px;"
                  >
                    {{ range }}
                  </el-tag>
                </div>
                <el-text v-else type="info">尚無設定</el-text>
              </div>

              <div class="add-range-section" style="margin-top: 12px;">
                <el-input
                  v-model="newIpRanges[typeName]"
                  placeholder="例如: 192.168.1.0/24"
                  size="small"
                  style="width: 200px; margin-right: 8px;"
                  @keyup.enter="handleAddIpRange(typeName)"
                />
                <el-button
                  type="primary"
                  size="small"
                  @click="handleAddIpRange(typeName)"
                  :icon="Plus"
                >
                  新增網段
                </el-button>
                <el-button
                  size="small"
                  @click="openEditDeviceDialog(typeName)"
                  :icon="Edit"
                  style="margin-left: 8px;"
                >
                  編輯說明
                </el-button>
              </div>

              <div class="characteristics-section" style="margin-top: 12px;">
                <strong>特徵：</strong>
                <el-tag
                  v-for="(char, idx) in typeData.characteristics"
                  :key="idx"
                  type="info"
                  size="small"
                  style="margin: 4px;"
                >
                  {{ char }}
                </el-tag>
              </div>
            </div>
          </el-collapse-item>
        </el-collapse>
      </div>

      <div v-else style="text-align: center; padding: 20px; color: #909399;">
        載入中...
      </div>
    </el-card>

    <!-- Classifier 閾值配置 -->
    <el-card shadow="never" class="classifier-thresholds-card" style="margin-top: 20px;">
      <template #header>
        <div class="card-header">
          <span>
            🎯 Classifier 威脅分類閾值
            <el-tooltip
              placement="top"
              raw-content
            >
              <template #content>
                <div style="max-width: 400px;">
                  配置異常分類器的判斷閾值<br/><br/>
                  <strong>分類方法：</strong><br/>
                  • 規則閾值：基於預設條件判斷威脅類型<br/>
                  • ML模型（未來）：Random Forest + SHAP 解釋<br/><br/>
                  修改閾值後立即生效，無需重新訓練模型
                </div>
              </template>
              <el-icon style="margin-left: 4px; cursor: help;">
                <InfoFilled />
              </el-icon>
            </el-tooltip>
          </span>
          <div>
            <el-button
              size="small"
              type="primary"
              @click="openClassifierThresholdsDialog"
              :icon="Setting"
            >
              配置閾值
            </el-button>
            <el-button
              size="small"
              @click="loadClassifierThresholds"
              :icon="Refresh"
              :loading="classifierThresholdsLoading"
            >
              重新載入
            </el-button>
          </div>
        </div>
      </template>

      <el-alert
        type="info"
        :closable="false"
        style="margin-bottom: 16px;"
      >
        <template #title>
          當前分類方法
        </template>
        <strong>{{ classifierMethod === 'rule_based' ? '規則閾值' : 'ML 模型 (Random Forest + SHAP)' }}</strong>
        <span v-if="classifierMethod === 'ml_based'" style="margin-left: 8px;">
          （功能開發中）
        </span>
      </el-alert>

      <div v-if="classifierThresholds" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px;">
        <!-- Src 視角統計 -->
        <el-card shadow="never" style="border: 1px solid #ebeef5;">
          <template #header>
            <strong>📤 Src 視角威脅類型</strong>
          </template>
          <div style="display: flex; flex-direction: column; gap: 8px;">
            <div v-for="(config, key) in classifierThresholds.src_threats" :key="key" style="display: flex; justify-content: space-between; align-items: center;">
              <span>{{ config.name }}</span>
              <el-tag :type="config.enabled ? 'success' : 'info'" size="small">
                {{ config.enabled ? '啟用' : '停用' }}
              </el-tag>
            </div>
          </div>
        </el-card>

        <!-- Dst 視角統計 -->
        <el-card shadow="never" style="border: 1px solid #ebeef5;">
          <template #header>
            <strong>📥 Dst 視角威脅類型</strong>
          </template>
          <div style="display: flex; flex-direction: column; gap: 8px;">
            <div v-for="(config, key) in classifierThresholds.dst_threats" :key="key" style="display: flex; justify-content: space-between; align-items: center;">
              <span>{{ config.name }}</span>
              <el-tag :type="config.enabled ? 'success' : 'info'" size="small">
                {{ config.enabled ? '啟用' : '停用' }}
              </el-tag>
            </div>
          </div>
        </el-card>
      </div>

      <div v-else style="text-align: center; padding: 20px; color: #909399;">
        載入中...
      </div>
    </el-card>

    <!-- Classifier 閾值配置對話框 -->
    <el-dialog
      v-model="classifierThresholdsDialogVisible"
      title="Classifier 閾值配置"
      width="900px"
      :close-on-click-modal="false"
    >
      <div v-if="editingClassifierConfig" style="max-height: 600px; overflow-y: auto;">
        <!-- 分類方法選擇 -->
        <el-card shadow="never" style="margin-bottom: 16px; border: 1px solid #ebeef5;">
          <template #header>
            <strong>分類方法</strong>
          </template>
          <el-radio-group v-model="editingClassifierConfig.classifier_method.method" size="large">
            <el-radio label="rule_based">
              規則閾值（當前）
              <div style="font-size: 12px; color: #909399; margin-top: 4px;">
                基於預設條件判斷，可自訂閾值
              </div>
            </el-radio>
            <el-radio label="ml_based" disabled style="margin-top: 12px;">
              ML 模型（開發中）
              <div style="font-size: 12px; color: #909399; margin-top: 4px;">
                Random Forest + SHAP 解釋，需要訓練模型
              </div>
            </el-radio>
          </el-radio-group>
        </el-card>

        <!-- Src 視角威脅配置 -->
        <el-collapse v-model="activeThresholdPanels" accordion>
          <el-collapse-item name="src" title="📤 Src 視角威脅類型閾值">
            <div v-for="(config, key) in editingClassifierConfig.src_threats" :key="key" style="margin-bottom: 20px;">
              <el-card shadow="never" style="border: 1px solid #ebeef5;">
                <template #header>
                  <div style="display: flex; justify-content: space-between; align-items: center;">
                    <strong>{{ config.name }} ({{ key }})</strong>
                    <el-switch v-model="config.enabled" />
                  </div>
                </template>
                <el-form label-position="top" size="small">
                  <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px;">
                    <el-form-item v-for="(value, param) in config.thresholds" :key="param" :label="formatParamLabel(param)">
                      <el-input-number
                        v-model="config.thresholds[param]"
                        :min="0"
                        :step="getStep(param)"
                        :precision="getPrecision(param)"
                        style="width: 100%;"
                      />
                    </el-form-item>
                  </div>
                </el-form>
              </el-card>
            </div>
          </el-collapse-item>

          <!-- Dst 視角威脅配置 -->
          <el-collapse-item name="dst" title="📥 Dst 視角威脅類型閾值">
            <div v-for="(config, key) in editingClassifierConfig.dst_threats" :key="key" style="margin-bottom: 20px;">
              <el-card shadow="never" style="border: 1px solid #ebeef5;">
                <template #header>
                  <div style="display: flex; justify-content: space-between; align-items: center;">
                    <strong>{{ config.name }} ({{ key }})</strong>
                    <el-switch v-model="config.enabled" />
                  </div>
                </template>
                <el-form label-position="top" size="small">
                  <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px;">
                    <el-form-item v-for="(value, param) in config.thresholds" :key="param" :label="formatParamLabel(param)">
                      <el-input-number
                        v-model="config.thresholds[param]"
                        :min="0"
                        :step="getStep(param)"
                        :precision="getPrecision(param)"
                        style="width: 100%;"
                      />
                    </el-form-item>
                  </div>
                </el-form>
              </el-card>
            </div>
          </el-collapse-item>

          <!-- 全局配置 -->
          <el-collapse-item name="global" title="⚙️ 全局配置">
            <el-form label-position="top">
              <el-form-item label="備份時間（判斷正常高流量）">
                <el-checkbox-group v-model="editingClassifierConfig.global.backup_hours">
                  <el-checkbox v-for="hour in 24" :key="hour-1" :label="hour-1">
                    {{ (hour-1).toString().padStart(2, '0') }}:00
                  </el-checkbox>
                </el-checkbox-group>
              </el-form-item>
            </el-form>
          </el-collapse-item>
        </el-collapse>
      </div>

      <template #footer>
        <span class="dialog-footer">
          <el-button @click="classifierThresholdsDialogVisible = false">取消</el-button>
          <el-button @click="resetClassifierThresholds">重置為預設</el-button>
          <el-button
            type="primary"
            @click="saveClassifierThresholds"
            :loading="classifierThresholdsSaving"
          >
            儲存配置
          </el-button>
        </span>
      </template>
    </el-dialog>

    <!-- 新增/編輯設備類型對話框 -->
    <el-dialog
      v-model="deviceTypeDialogVisible"
      :title="isEditingDeviceType ? '編輯設備類別' : '新增設備類別'"
      width="600px"
    >
      <el-form label-position="top" v-if="deviceTypeFormData">
        <el-form-item label="類別 Key" :required="!isEditingDeviceType">
          <el-input
            v-model="deviceTypeFormData.type_key"
            placeholder="例如: database, web_server"
            :disabled="isEditingDeviceType"
          />
          <div class="form-item-tip">
            英文、數字、底線，用於程式識別（新增後不可修改）
          </div>
        </el-form-item>

        <el-form-item label="顯示名稱" required>
          <el-input
            v-model="deviceTypeFormData.display_name"
            placeholder="例如: 資料庫伺服器"
          />
        </el-form-item>

        <el-form-item label="圖示">
          <div style="display: flex; align-items: center; gap: 8px;">
            <el-input
              v-model="deviceTypeFormData.icon"
              placeholder="選擇或輸入 emoji"
              style="width: 120px;"
            />
            <div class="icon-picker">
              <el-button
                v-for="icon in commonIcons"
                :key="icon"
                size="small"
                @click="deviceTypeFormData.icon = icon"
                :type="deviceTypeFormData.icon === icon ? 'primary' : ''"
              >
                {{ icon }}
              </el-button>
            </div>
          </div>
        </el-form-item>

        <el-form-item label="說明">
          <el-input
            v-model="deviceTypeFormData.description"
            type="textarea"
            :rows="2"
            placeholder="設備類型的描述"
          />
        </el-form-item>

        <el-form-item label="特徵">
          <!-- 已選特徵 -->
          <div v-if="deviceTypeFormData.characteristics.length > 0" style="margin-bottom: 12px;">
            <div style="font-size: 12px; color: #909399; margin-bottom: 4px;">已選特徵：</div>
            <el-tag
              v-for="(char, idx) in deviceTypeFormData.characteristics"
              :key="idx"
              closable
              @close="deviceTypeFormData.characteristics.splice(idx, 1)"
              style="margin: 4px;"
              type="success"
            >
              {{ char }}
            </el-tag>
          </div>

          <!-- 預設特徵選擇 -->
          <div class="characteristics-selector">
            <div
              v-for="(category, key) in predefinedCharacteristics"
              :key="key"
              class="characteristic-category"
            >
              <div class="category-title">{{ category.name }}</div>
              <div class="characteristic-options">
                <el-checkbox
                  v-for="item in category.items"
                  :key="item"
                  :label="item"
                  :model-value="deviceTypeFormData.characteristics.includes(item)"
                  @change="toggleCharacteristic(item, $event)"
                  size="small"
                >
                  {{ item }}
                </el-checkbox>
              </div>
            </div>
          </div>

          <!-- 自訂特徵 -->
          <div style="margin-top: 12px;">
            <div style="font-size: 12px; color: #909399; margin-bottom: 4px;">自訂特徵：</div>
            <el-input
              v-model="newDeviceTypeCharacteristic"
              placeholder="輸入自訂特徵並按 Enter"
              style="width: 250px;"
              size="small"
              @keyup.enter="addDeviceTypeCharacteristic"
            >
              <template #append>
                <el-button @click="addDeviceTypeCharacteristic" :icon="Plus">新增</el-button>
              </template>
            </el-input>
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="deviceTypeDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="saveDeviceTypeChanges">存檔</el-button>
      </template>
    </el-dialog>

    <!-- 原編輯說明對話框（用於快速編輯） -->
    <el-dialog
      v-model="editDeviceDialogVisible"
      :title="`編輯設備說明：${currentEditDeviceType}`"
      width="600px"
    >
      <el-form label-position="top" v-if="editDeviceFormData">
        <el-form-item label="圖示">
          <el-input
            v-model="editDeviceFormData.icon"
            placeholder="輸入 emoji 圖示"
            maxlength="2"
            style="width: 100px;"
          />
        </el-form-item>
        <el-form-item label="說明">
          <el-input
            v-model="editDeviceFormData.description"
            type="textarea"
            :rows="2"
          />
        </el-form-item>
        <el-form-item label="特徵">
          <!-- 已選特徵 -->
          <div v-if="editDeviceFormData.characteristics.length > 0" style="margin-bottom: 12px;">
            <div style="font-size: 12px; color: #909399; margin-bottom: 4px;">已選特徵：</div>
            <el-tag
              v-for="(char, idx) in editDeviceFormData.characteristics"
              :key="idx"
              closable
              @close="removeDeviceCharacteristic(idx)"
              style="margin: 4px;"
              type="success"
            >
              {{ char }}
            </el-tag>
          </div>

          <!-- 預設特徵選擇 -->
          <div class="characteristics-selector">
            <div
              v-for="(category, key) in predefinedCharacteristics"
              :key="key"
              class="characteristic-category"
            >
              <div class="category-title">{{ category.name }}</div>
              <div class="characteristic-options">
                <el-checkbox
                  v-for="item in category.items"
                  :key="item"
                  :label="item"
                  :model-value="editDeviceFormData.characteristics.includes(item)"
                  @change="toggleEditCharacteristic(item, $event)"
                  size="small"
                >
                  {{ item }}
                </el-checkbox>
              </div>
            </div>
          </div>

          <!-- 自訂特徵 -->
          <div style="margin-top: 12px;">
            <div style="font-size: 12px; color: #909399; margin-bottom: 4px;">自訂特徵：</div>
            <el-input
              v-model="newDeviceCharacteristic"
              placeholder="輸入自訂特徵並按 Enter"
              style="width: 250px;"
              size="small"
              @keyup.enter="addDeviceCharacteristic"
            >
              <template #append>
                <el-button @click="addDeviceCharacteristic" :icon="Plus">新增</el-button>
              </template>
            </el-input>
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editDeviceDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="saveDeviceType">存檔</el-button>
      </template>
    </el-dialog>

    <!-- 特徵選擇器 -->
    <FeatureSelector
      v-model="featureSelectorVisible"
      :mode="currentMode"
      @saved="handleFeatureSaved"
    />
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useTrainingStore } from '@/stores/training'
import { VideoPlay, InfoFilled, RefreshLeft, Refresh, Plus, Edit, Delete, Setting } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import axios from 'axios'
import FeatureSelector from '@/components/FeatureSelector.vue'

const trainingStore = useTrainingStore()

// 預設值常數
const DEFAULT_VALUES = {
  trainingDays: 3,
  nEstimators: 150,
  contamination: 0.05,
  anomalyThreshold: 0.6
}

const trainingDays = ref(DEFAULT_VALUES.trainingDays)
const nEstimators = ref(DEFAULT_VALUES.nEstimators)
const contamination = ref(DEFAULT_VALUES.contamination)
const anomalyThreshold = ref(DEFAULT_VALUES.anomalyThreshold)

// 雙模式支援
const activeMode = ref('by_src')

// 特徵選擇器
const featureSelectorVisible = ref(false)
const currentMode = ref('by_src')

// 設備映射相關
const deviceMappingLoading = ref(false)
const deviceTypes = ref(null)
const newIpRanges = ref({})
const editDeviceDialogVisible = ref(false)
const currentEditDeviceType = ref('')
const editDeviceFormData = ref(null)
const newDeviceCharacteristic = ref('')

// 新增/編輯設備類型
const deviceTypeDialogVisible = ref(false)
const isEditingDeviceType = ref(false)
const deviceTypeFormData = ref(null)
const newDeviceTypeCharacteristic = ref('')

// 常用圖示
const commonIcons = ['🏭', '💻', '🛠️', '🌐', '🖥️', '📱', '🔧', '⚙️', '🗄️', '📡', '🌟', '📦']

// 預設類型（受保護）
const protectedTypes = ['server_farm', 'station', 'iot', 'external']

// Classifier 閾值配置相關
const classifierThresholds = ref(null)
const classifierThresholdsLoading = ref(false)
const classifierThresholdsDialogVisible = ref(false)
const classifierThresholdsSaving = ref(false)
const editingClassifierConfig = ref(null)
const activeThresholdPanels = ref('src')
const classifierMethod = ref('rule_based')

// 預設特徵標籤庫
const predefinedCharacteristics = {
  traffic: {
    name: '流量特徵',
    items: ['高入站流量', '高出站流量', '低流量', '中等流量', '小流量', '週期性流量']
  },
  connection: {
    name: '連線特徵',
    items: ['主動發起連線', '被動接受連線', '多並發連線', '持久連線', '短暫連線']
  },
  behavior: {
    name: '行為特徵',
    items: ['提供服務端口', '訪問外部服務', '週期性通信', '資料備份', '高磁碟 I/O', '特定協議']
  },
  security: {
    name: '安全特徵',
    items: ['需要人工審查', '預設分類', '受管控設備', '關鍵設備']
  }
}

const deviceTypeNameMap = {
  'server_farm': '服務器群',
  'station': '工作站',
  'iot': '物聯網設備',
  'external': '外部設備'
}

function getDeviceTypeName(type) {
  return deviceTypeNameMap[type] || type
}

function isProtectedType(type) {
  return protectedTypes.includes(type)
}

// 特徵選擇器相關函數
function openFeatureSelector(mode) {
  currentMode.value = mode
  featureSelectorVisible.value = true
}

function handleFeatureSaved() {
  ElMessage.success('特徵設定已更新')
  // 重新載入配置以更新特徵數量顯示
  trainingStore.loadConfig('by_src')
  trainingStore.loadConfig('by_dst')
}

function openCreateDeviceTypeDialog() {
  isEditingDeviceType.value = false
  deviceTypeFormData.value = {
    type_key: '',
    display_name: '',
    icon: '📦',
    description: '',
    characteristics: []
  }
  deviceTypeDialogVisible.value = true
}

function openEditDeviceTypeDialog(typeName) {
  isEditingDeviceType.value = true
  const typeData = deviceTypes.value[typeName]
  deviceTypeFormData.value = {
    type_key: typeName,
    display_name: typeData.display_name || getDeviceTypeName(typeName),
    icon: typeData.icon || '📦',
    description: typeData.description || '',
    characteristics: [...(typeData.characteristics || [])]
  }
  deviceTypeDialogVisible.value = true
}

function addDeviceTypeCharacteristic() {
  if (newDeviceTypeCharacteristic.value.trim()) {
    deviceTypeFormData.value.characteristics.push(newDeviceTypeCharacteristic.value.trim())
    newDeviceTypeCharacteristic.value = ''
  }
}

function toggleCharacteristic(item, checked) {
  if (!deviceTypeFormData.value) return

  if (checked) {
    if (!deviceTypeFormData.value.characteristics.includes(item)) {
      deviceTypeFormData.value.characteristics.push(item)
    }
  } else {
    const index = deviceTypeFormData.value.characteristics.indexOf(item)
    if (index > -1) {
      deviceTypeFormData.value.characteristics.splice(index, 1)
    }
  }
}

async function saveDeviceTypeChanges() {
  if (!deviceTypeFormData.value.type_key || !deviceTypeFormData.value.display_name) {
    ElMessage.warning('請填寫類別 Key 和顯示名稱')
    return
  }

  try {
    if (isEditingDeviceType.value) {
      // 編輯現有設備類型
      const response = await axios.put(`/api/device-mapping/${deviceTypeFormData.value.type_key}`, {
        display_name: deviceTypeFormData.value.display_name,
        description: deviceTypeFormData.value.description,
        characteristics: deviceTypeFormData.value.characteristics,
        icon: deviceTypeFormData.value.icon
      })

      if (response.data.status === 'success') {
        ElMessage.success('設備類別已更新')
        deviceTypeDialogVisible.value = false
        await fetchDeviceMapping()
      } else {
        ElMessage.error(response.data.error)
      }
    } else {
      // 新增設備類型
      const response = await axios.post('/api/device-mapping/types', {
        type_key: deviceTypeFormData.value.type_key,
        display_name: deviceTypeFormData.value.display_name,
        icon: deviceTypeFormData.value.icon,
        description: deviceTypeFormData.value.description,
        characteristics: deviceTypeFormData.value.characteristics
      })

      if (response.data.status === 'success') {
        ElMessage.success({
          message: response.data.message + ' - 請記得重新訓練模型以套用變更',
          duration: 5000
        })
        deviceTypeDialogVisible.value = false
        await fetchDeviceMapping()
      } else {
        ElMessage.error(response.data.error)
      }
    }
  } catch (error) {
    ElMessage.error('操作失敗：' + (error.response?.data?.error || error.message))
  }
}

async function handleDeleteDeviceType(typeName) {
  const typeData = deviceTypes.value[typeName]
  const ipCount = typeData.ip_ranges ? typeData.ip_ranges.length : 0

  try {
    await ElMessageBox.confirm(
      ipCount > 0
        ? `確定要刪除設備類別「${typeData.display_name || typeName}」嗎？\n此類別還有 ${ipCount} 個 IP 網段。`
        : `確定要刪除設備類別「${typeData.display_name || typeName}」嗎？`,
      '確認刪除',
      {
        confirmButtonText: '確定刪除',
        cancelButtonText: '取消',
        type: 'warning',
        dangerouslyUseHTMLString: true
      }
    )

    const response = await axios.delete(`/api/device-mapping/types/${typeName}`, {
      data: { force: ipCount > 0 }
    })

    if (response.data.status === 'success') {
      ElMessage.success({
        message: response.data.message + ' - 請記得重新訓練模型以套用變更',
        duration: 5000
      })
      await fetchDeviceMapping()
    } else {
      ElMessage.error(response.data.error)
    }
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('刪除失敗：' + (error.response?.data?.error || error.message))
    }
  }
}

async function fetchDeviceMapping() {
  deviceMappingLoading.value = true
  try {
    const response = await axios.get('/api/device-mapping')
    if (response.data.status === 'success') {
      deviceTypes.value = response.data.data.device_types
    } else {
      ElMessage.error(response.data.error || '載入網段設備配置失敗')
    }
  } catch (error) {
    ElMessage.error('載入網段設備配置時發生錯誤：' + error.message)
  } finally {
    deviceMappingLoading.value = false
  }
}

async function refreshDeviceMapping() {
  await fetchDeviceMapping()
  ElMessage.success('網段設備配置已重新載入')
}

async function handleAddIpRange(typeName) {
  const ipRange = newIpRanges.value[typeName]
  if (!ipRange) {
    ElMessage.warning('請輸入 IP 網段')
    return
  }

  try {
    const response = await axios.post(`/api/device-mapping/${typeName}/ip-ranges`, {
      ip_range: ipRange
    })
    if (response.data.status === 'success') {
      ElMessage.success(response.data.message)
      newIpRanges.value[typeName] = ''
      await fetchDeviceMapping()
    } else {
      ElMessage.error(response.data.error)
    }
  } catch (error) {
    ElMessage.error('新增失敗：' + (error.response?.data?.error || error.message))
  }
}

async function handleRemoveIpRange(typeName, ipRange) {
  try {
    await ElMessageBox.confirm(
      `確定要移除 IP 網段 ${ipRange} 嗎？`,
      '確認',
      {
        confirmButtonText: '確定',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )

    const response = await axios.delete(`/api/device-mapping/${typeName}/ip-ranges`, {
      data: { ip_range: ipRange }
    })

    if (response.data.status === 'success') {
      ElMessage.success(response.data.message)
      await fetchDeviceMapping()
    } else {
      ElMessage.error(response.data.error)
    }
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('移除失敗：' + (error.response?.data?.error || error.message))
    }
  }
}

function openEditDeviceDialog(typeName) {
  currentEditDeviceType.value = typeName
  editDeviceFormData.value = {
    icon: deviceTypes.value[typeName].icon || '📦',
    description: deviceTypes.value[typeName].description,
    characteristics: [...(deviceTypes.value[typeName].characteristics || [])]
  }
  editDeviceDialogVisible.value = true
}

function addDeviceCharacteristic() {
  if (newDeviceCharacteristic.value.trim()) {
    editDeviceFormData.value.characteristics.push(newDeviceCharacteristic.value.trim())
    newDeviceCharacteristic.value = ''
  }
}

function removeDeviceCharacteristic(idx) {
  editDeviceFormData.value.characteristics.splice(idx, 1)
}

function toggleEditCharacteristic(item, checked) {
  if (!editDeviceFormData.value) return

  if (checked) {
    if (!editDeviceFormData.value.characteristics.includes(item)) {
      editDeviceFormData.value.characteristics.push(item)
    }
  } else {
    const index = editDeviceFormData.value.characteristics.indexOf(item)
    if (index > -1) {
      editDeviceFormData.value.characteristics.splice(index, 1)
    }
  }
}

async function saveDeviceType() {
  try {
    const response = await axios.put(`/api/device-mapping/${currentEditDeviceType.value}`, {
      description: editDeviceFormData.value.description,
      characteristics: editDeviceFormData.value.characteristics,
      icon: editDeviceFormData.value.icon
    })

    if (response.data.status === 'success') {
      ElMessage.success('存檔成功')
      editDeviceDialogVisible.value = false
      await fetchDeviceMapping()
    } else {
      ElMessage.error(response.data.error)
    }
  } catch (error) {
    ElMessage.error('存檔失敗：' + (error.response?.data?.error || error.message))
  }
}

// ===== Classifier 閾值配置相關方法 =====

// 載入 Classifier 閾值配置
async function loadClassifierThresholds() {
  classifierThresholdsLoading.value = true
  try {
    const response = await axios.get('/api/classifier-thresholds')
    if (response.data.status === 'success') {
      classifierThresholds.value = response.data.config
      classifierMethod.value = response.data.config.classifier_method?.method || 'rule_based'
      ElMessage.success('載入成功')
    }
  } catch (error) {
    ElMessage.error('載入失敗：' + (error.response?.data?.error || error.message))
  } finally {
    classifierThresholdsLoading.value = false
  }
}

// 打開 Classifier 閾值配置對話框
function openClassifierThresholdsDialog() {
  if (!classifierThresholds.value) {
    ElMessage.warning('請先載入配置')
    return
  }
  // 深拷貝配置
  editingClassifierConfig.value = JSON.parse(JSON.stringify(classifierThresholds.value))
  classifierThresholdsDialogVisible.value = true
}

// 儲存 Classifier 閾值配置
async function saveClassifierThresholds() {
  classifierThresholdsSaving.value = true
  try {
    const response = await axios.put('/api/classifier-thresholds', {
      config: editingClassifierConfig.value
    })
    if (response.data.status === 'success') {
      classifierThresholds.value = JSON.parse(JSON.stringify(editingClassifierConfig.value))
      classifierMethod.value = editingClassifierConfig.value.classifier_method?.method || 'rule_based'
      classifierThresholdsDialogVisible.value = false
      ElMessage.success('配置已儲存')
    }
  } catch (error) {
    ElMessage.error('儲存失敗：' + (error.response?.data?.error || error.message))
  } finally {
    classifierThresholdsSaving.value = false
  }
}

// 重置為預設值
async function resetClassifierThresholds() {
  try {
    await ElMessageBox.confirm(
      '確定要重置為預設值嗎？這將覆蓋目前的所有閾值設定。',
      '警告',
      {
        confirmButtonText: '確定',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )

    classifierThresholdsSaving.value = true
    const response = await axios.post('/api/classifier-thresholds/reset')
    if (response.data.status === 'success') {
      classifierThresholds.value = response.data.config
      editingClassifierConfig.value = JSON.parse(JSON.stringify(response.data.config))
      classifierMethod.value = response.data.config.classifier_method?.method || 'rule_based'
      ElMessage.success('已重置為預設值')
    }
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('重置失敗：' + (error.response?.data?.error || error.message))
    }
  } finally {
    classifierThresholdsSaving.value = false
  }
}

// 格式化參數標籤
function formatParamLabel(param) {
  const labelMap = {
    'unique_dst_ports': '掃描埠數',
    'avg_bytes': '平均封包',
    'dst_port_diversity': '埠分散度',
    'unique_dsts': '目的地數',
    'dst_diversity': '目的地分散度',
    'flow_count': '連線數',
    'flow_rate': '連線速率',
    'total_bytes': '總流量',
    'byte_rate': '傳輸速率',
    'unique_srcs': '來源數',
    'unique_src_ports': '來源埠數',
    'flows_per_src': '每來源連線',
    'flow_count_min': '最小連線數',
    'flow_count_max': '最大連線數',
    'avg_bytes_min': '最小封包',
    'avg_bytes_max': '最大封包',
    'unique_dsts_min': '最小目的地',
    'unique_dsts_max': '最大目的地'
  }
  return labelMap[param] || param
}

// 取得輸入框步進值
function getStep(param) {
  if (param.includes('diversity') || param.includes('ratio')) {
    return 0.01
  } else if (param.includes('bytes') || param.includes('rate')) {
    return 1000
  } else {
    return 1
  }
}

// 取得輸入框精度
function getPrecision(param) {
  if (param.includes('diversity') || param.includes('ratio')) {
    return 2
  }
  return 0
}

onMounted(async () => {
  // 載入兩個模式的配置
  await trainingStore.fetchConfig()

  // 從配置中載入當前的參數值（優先使用 By Src）
  if (trainingStore.configBySrc?.training_config?.n_estimators) {
    nEstimators.value = trainingStore.configBySrc.training_config.n_estimators
  }
  if (trainingStore.configBySrc?.training_config?.contamination) {
    contamination.value = trainingStore.configBySrc.training_config.contamination
  }
  if (trainingStore.configBySrc?.training_config?.anomaly_threshold) {
    anomalyThreshold.value = trainingStore.configBySrc.training_config.anomaly_threshold
  }

  // 載入設備映射配置
  await fetchDeviceMapping()

  // 載入 Classifier 閾值配置
  await loadClassifierThresholds()
})

async function handleStartTraining(mode = 'by_src') {
  await trainingStore.startTraining({
    days: trainingDays.value,
    n_estimators: nEstimators.value,
    contamination: contamination.value,
    anomaly_threshold: anomalyThreshold.value,
    mode: mode
  })
}

function handleModeChange(mode) {
  console.log('切換到模式:', mode)
  activeMode.value = mode
}

function resetToDefaults() {
  trainingDays.value = DEFAULT_VALUES.trainingDays
  nEstimators.value = DEFAULT_VALUES.nEstimators
  contamination.value = DEFAULT_VALUES.contamination
  anomalyThreshold.value = DEFAULT_VALUES.anomalyThreshold
  excludeServers.value = DEFAULT_VALUES.excludeServers

  ElMessage.success({
    message: '已恢復為預設值：訓練天數 3 天、決策樹 150 棵、污染率 0.05、異常閾值 0.6',
    duration: 2000
  })
}

function getModelStatusText(status) {
  const statusMap = {
    'trained': '已訓練',
    'not_trained': '尚未訓練',
    'training': '訓練中',
    'file_exists_but_load_failed': '模型檔案損壞'
  }
  return statusMap[status] || status || '未知'
}

function getStatusTagType(status) {
  if (status === 'trained') return 'success'
  if (status === 'file_exists_but_load_failed') return 'danger'
  if (status === 'training') return 'info'
  return 'warning'
}

function formatTrainedDate(isoString) {
  if (!isoString) return 'N/A'
  const date = new Date(isoString)
  return date.toLocaleString('zh-TW', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  })
}
</script>

<style scoped>
.training {
  display: flex;
  flex-direction: column;
  gap: 20px;
  width: 100%;
  max-width: 100%;
}

.mode-tabs {
  margin-top: 10px;
}

.mode-tabs :deep(.el-tabs__item) {
  font-size: 15px;
  font-weight: 500;
  padding: 0 30px;
}

.mode-tabs :deep(.el-tabs__item.is-active) {
  color: #409EFF;
  font-weight: 600;
}

.model-info {
  padding: 10px 0;
}

.progress-card {
  margin-top: 20px;
  width: 100%;
}

.progress-content {
  padding: 20px;
}

.progress-message {
  margin-top: 12px;
  text-align: center;
  color: #606266;
}

.features-card {
  margin-top: 20px;
  width: 100%;
}

.features-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: 12px;
  padding: 10px 0;
}

.feature-tag {
  padding: 8px 12px;
  font-size: 13px;
  cursor: default;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-weight: 600;
}

.form-item-tip {
  margin-top: 8px;
  font-size: 12px;
  color: #909399;
  line-height: 1.5;
}

.device-mapping-card {
  margin-top: 20px;
  width: 100%;
}

.device-types-compact {
  padding: 10px 0;
}

.device-type-title {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
}

.type-icon {
  font-size: 18px;
}

.device-type-content {
  padding: 16px;
  background-color: #f5f7fa;
  border-radius: 4px;
}

.description {
  color: #606266;
  font-size: 14px;
}

.ip-ranges-section,
.characteristics-section {
  margin-top: 12px;
}

.range-list {
  display: flex;
  flex-wrap: wrap;
  margin-top: 8px;
}

.add-range-section {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}

.icon-picker {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  max-width: 400px;
}

.icon-picker .el-button {
  min-width: 32px;
  padding: 4px 8px;
  font-size: 18px;
}

.characteristics-selector {
  padding: 12px;
  background-color: #f5f7fa;
  border-radius: 4px;
  margin-top: 8px;
  margin-bottom: 12px;
}

.characteristic-category {
  margin-bottom: 16px;
}

.characteristic-category:last-child {
  margin-bottom: 0;
}

.category-title {
  font-size: 13px;
  font-weight: 600;
  color: #303133;
  margin-bottom: 8px;
  padding-bottom: 4px;
  border-bottom: 1px solid #dcdfe6;
}

.characteristic-options {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
}

.characteristic-options .el-checkbox {
  margin-right: 0;
}

.selected-characteristics {
  margin-bottom: 12px;
}

.selected-characteristics .el-tag {
  margin-right: 8px;
  margin-bottom: 8px;
}
</style>
