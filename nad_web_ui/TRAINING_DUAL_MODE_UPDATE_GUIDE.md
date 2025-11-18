# Training.vue 雙模式更新指南

## 概述
本指南說明如何更新 `frontend/src/views/Training.vue` 以支援雙模式（By Src / By Dst）訓練。

## 已完成的後端更新

✅ `backend/services/training_service.py` - 支援 `mode` 參數
✅ `backend/api/training.py` - API 接受 `mode` 參數
✅ `frontend/src/stores/training.js` - Store 支援雙模式狀態
✅ `frontend/src/services/api.js` - API 調用支援 `mode`

## 前端更新步驟

### 方案 1: 簡單更新（推薦）

在現有 Training.vue 的 `<script setup>` 部分添加：

```javascript
// 在現有的 ref 定義後添加
const activeMode = ref('by_src')

// 修改 onMounted
onMounted(async () => {
  // 載入兩個模式的配置
  await trainingStore.fetchConfig()  // 不帶參數會返回兩個模式

  // 從配置中載入當前的參數值
  if (trainingStore.configBySrc?.training_config?.n_estimators) {
    nEstimators.value = trainingStore.configBySrc.training_config.n_estimators
  }
  // ... 其他參數

  // 載入設備映射配置
  await fetchDeviceMapping()
})

// 修改 handleStartTraining
async function handleStartTraining() {
  await trainingStore.startTraining({
    days: trainingDays.value,
    n_estimators: nEstimators.value,
    contamination: contamination.value,
    exclude_servers: excludeServers.value,
    anomaly_threshold: anomalyThreshold.value,
    mode: activeMode.value  // 添加這行
  })
}
```

### 方案 2: 完整雙模式 UI（更複雜）

1. **添加 Tabs 切換**

在 `<template>` 開頭添加：

```vue
<template>
  <div class="training">
    <!-- 模式說明 -->
    <el-alert type="info" :closable="false" style="margin-bottom: 20px;">
      <strong>By Src:</strong> 偵測掃描、DDoS來源 |
      <strong>By Dst:</strong> 偵測DDoS目標、被掃描主機
    </el-alert>

    <!-- Tabs -->
    <el-tabs v-model="activeMode" @tab-change="handleModeChange">
      <el-tab-pane label="📤 By Src" name="by_src">
        <!-- 將現有的模型資訊、訓練配置放這裡 -->
      </el-tab-pane>
      <el-tab-pane label="📥 By Dst" name="by_dst">
        <!-- 複製模型資訊、訓練配置（使用 configByDst, progressByDst）-->
      </el-tab-pane>
    </el-tabs>

    <!-- 設備映射配置移到 Tabs 外面（共用）-->
  </div>
</template>
```

2. **更新數據綁定**

By Src tab:
- 使用 `trainingStore.configBySrc`
- 使用 `trainingStore.progressBySrc`
- 使用 `trainingStore.trainingBySrc`

By Dst tab:
- 使用 `trainingStore.configByDst`
- 使用 `trainingStore.progressByDst`
- 使用 `trainingStore.trainingByDst`

## 測試步驟

1. 啟動後端：
```bash
cd /home/kaisermac/nad_web_ui/backend
python app.py
```

2. 啟動前端：
```bash
cd /home/kaisermac/nad_web_ui/frontend
npm run dev
```

3. 訪問 http://192.168.10.25:5173/training

4. 測試功能：
   - [ ] 切換 By Src / By Dst tabs
   - [ ] 查看兩個模式的模型狀態
   - [ ] 開始 By Src 訓練
   - [ ] 開始 By Dst 訓練
   - [ ] 訓練進度顯示正確
   - [ ] 訓練完成後模型資訊更新

## API 端點測試

```bash
# 測試獲取配置（兩個模式）
curl http://localhost:5000/api/training/config

# 測試獲取 By Src 配置
curl http://localhost:5000/api/training/config?mode=by_src

# 測試獲取 By Dst 配置
curl http://localhost:5000/api/training/config?mode=by_dst

# 測試開始 By Dst 訓練
curl -X POST http://localhost:5000/api/training/start \
  -H "Content-Type: application/json" \
  -d '{"days": 3, "mode": "by_dst", "n_estimators": 150, "contamination": 0.05, "anomaly_threshold": 0.6}'
```

## 特徵差異

### By Src 模式
- 索引: `netflow_stats_5m`
- 群組欄位: `src_ip`
- 關鍵特徵: `unique_dsts`, `flow_count`, `total_bytes`
- 偵測目標: 掃描源、DDoS 攻擊源、惡意流量發送者

### By Dst 模式
- 索引: `netflow_stats_5m_by_dst`
- 群組欄位: `dst_ip`
- 關鍵特徵: `unique_srcs`, `flow_count`, `total_bytes`
- 偵測目標: DDoS 目標、被掃描主機、異常服務器

## 注意事項

1. 兩個模式的訓練互不影響，可以同時進行
2. 模型文件分別儲存：
   - By Src: `nad/models/isolation_forest.pkl`
   - By Dst: `nad/models/isolation_forest_by_dst.pkl`
3. 訓練配置參數（n_estimators, contamination）共用
4. 設備映射配置對兩個模式都有效
