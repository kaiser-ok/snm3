# 雙模式訓練 UI 實作總結

## 📋 概述

成功實作訓練網頁的雙模式支援，允許使用者分別訓練和管理 **By Src** 和 **By Dst** 兩種 Isolation Forest 模型。

## ✅ 已完成的更新

### 1. 後端服務層 (`/home/kaisermac/nad_web_ui/backend/services/training_service.py`)

**新增功能：**
- ✅ 導入 `IsolationForestByDst` 模型類別
- ✅ 新增 `_get_model_info_for_mode()` 方法：根據模式返回對應模型資訊
- ✅ 更新 `get_config()` 方法：支援 `mode` 參數
  - `mode='by_src'`: 僅返回 By Src 模型資訊
  - `mode='by_dst'`: 僅返回 By Dst 模型資訊
  - `mode=None`: 返回兩個模式的資訊（`models.by_src`, `models.by_dst`）
- ✅ 更新 `start_training()` 方法：接受 `mode` 參數
- ✅ 更新 `_train_worker()` 方法：
  - 根據 `mode` 選擇檢測器類型
  - 在訓練進度訊息中顯示模式描述

**關鍵代碼：**
```python
# 根據模式選擇檢測器
if mode == 'by_dst':
    detector = IsolationForestByDst(config)
else:
    detector = OptimizedIsolationForest(config)
```

### 2. 後端 API 層 (`/home/kaisermac/nad_web_ui/backend/api/training.py`)

**更新內容：**
- ✅ `GET /api/training/config`: 接受 `mode` query 參數
- ✅ `POST /api/training/start`: 接受 `mode` 參數並驗證
  - 驗證 `mode` 必須是 `'by_src'` 或 `'by_dst'`
  - 返回結果包含 `mode` 資訊

**API 使用範例：**
```bash
# 獲取兩個模式的配置
GET /api/training/config

# 獲取特定模式配置
GET /api/training/config?mode=by_src
GET /api/training/config?mode=by_dst

# 開始 By Dst 訓練
POST /api/training/start
{
  "days": 7,
  "mode": "by_dst",
  "n_estimators": 150,
  "contamination": 0.05
}
```

### 3. 前端 Store (`/home/kaisermac/nad_web_ui/frontend/src/stores/training.js`)

**新增狀態：**
```javascript
// 雙模式專用狀態
const configBySrc = ref(null)
const configByDst = ref(null)
const trainingJobBySrc = ref(null)
const trainingJobByDst = ref(null)
const progressBySrc = ref({ step: '', message: '', percent: 0 })
const progressByDst = ref({ step: '', message: '', percent: 0 })
const trainingBySrc = ref(false)
const trainingByDst = ref(false)
```

**更新方法：**
- ✅ `fetchConfig(mode)`: 支援模式參數，可獲取單一模式或兩者配置
- ✅ `startTraining(params)`: 根據 `params.mode` 更新對應狀態
- ✅ `connectSSE(jobId, mode)`: SSE 連接支援模式參數，分別更新進度

### 4. 前端 API 服務 (`/home/kaisermac/nad_web_ui/frontend/src/services/api.js`)

**更新內容：**
```javascript
export const trainingAPI = {
  // 支援模式參數
  getConfig(mode = null) {
    const params = mode ? { mode } : {}
    return api.get('/training/config', { params })
  },

  // startTraining 已支援 mode 參數（透過 POST body）
  startTraining(params) {
    return api.post('/training/start', params)
  }
}
```

### 5. 回填歷史數據工具 (`/home/kaisermac/snm_flow/backfill_historical_data.py`)

**已支援雙模式：**
```bash
# By Src 模式（預設）
python3 backfill_historical_data.py --execute --days 7

# By Dst 模式
python3 backfill_historical_data.py --execute --mode by_dst --days 7
```

## 📚 文檔

已創建以下文檔：

1. **`/home/kaisermac/nad_web_ui/TRAINING_DUAL_MODE_UPDATE_GUIDE.md`**
   - 前端 Training.vue 更新指南
   - 兩種實作方案（簡單更新 vs 完整雙模式 UI）
   - API 測試範例
   - 特徵差異說明

## 🔧 前端 UI 更新建議

### 方案 A: 最小化更新（快速實作）

只需在現有 `handleStartTraining()` 中添加 `mode` 參數：

```javascript
// 添加模式選擇器
const activeMode = ref('by_src')

async function handleStartTraining() {
  await trainingStore.startTraining({
    days: trainingDays.value,
    n_estimators: nEstimators.value,
    contamination: contamination.value,
    exclude_servers: excludeServers.value,
    anomaly_threshold: anomalyThreshold.value,
    mode: activeMode.value  // 新增
  })
}
```

### 方案 B: 完整雙模式 Tabs UI（推薦）

使用 `el-tabs` 切換兩個模式：

```vue
<el-tabs v-model="activeMode">
  <el-tab-pane label="📤 By Src" name="by_src">
    <!-- By Src 模型資訊、訓練配置 -->
  </el-tab-pane>
  <el-tab-pane label="📥 By Dst" name="by_dst">
    <!-- By Dst 模型資訊、訓練配置 -->
  </el-tab-pane>
</el-tabs>
```

## 🎯 兩種模式對比

| 特性 | By Src (來源 IP) | By Dst (目標 IP) |
|------|------------------|------------------|
| **ES 索引** | `netflow_stats_5m` | `netflow_stats_5m_by_dst` |
| **聚合欄位** | `src_ip` | `dst_ip` |
| **關鍵特徵** | `unique_dsts` (目標數量) | `unique_srcs` (來源數量) |
| **偵測目標** | 掃描源、DDoS攻擊源 | DDoS目標、被掃描主機 |
| **模型文件** | `nad/models/isolation_forest.pkl` | `nad/models/isolation_forest_by_dst.pkl` |
| **訓練腳本** | `train_model.py` | `train_isolation_forest_by_dst.py` |

## 📁 檔案變更列表

### 後端
- ✅ `/home/kaisermac/nad_web_ui/backend/services/training_service.py`
- ✅ `/home/kaisermac/nad_web_ui/backend/api/training.py`

### 前端
- ✅ `/home/kaisermac/nad_web_ui/frontend/src/stores/training.js`
- ✅ `/home/kaisermac/nad_web_ui/frontend/src/services/api.js`
- ⏳ `/home/kaisermac/nad_web_ui/frontend/src/views/Training.vue` (需要手動更新)

### 工具
- ✅ `/home/kaisermac/snm_flow/backfill_historical_data.py`

### 文檔
- ✅ `/home/kaisermac/nad_web_ui/TRAINING_DUAL_MODE_UPDATE_GUIDE.md`
- ✅ `/home/kaisermac/snm_flow/DUAL_MODE_TRAINING_UI_IMPLEMENTATION.md`

## 🧪 測試步驟

### 1. 後端測試

```bash
# 啟動後端
cd /home/kaisermac/nad_web_ui/backend
python app.py

# 測試 API
curl http://localhost:5000/api/training/config
curl http://localhost:5000/api/training/config?mode=by_src
curl http://localhost:5000/api/training/config?mode=by_dst
```

### 2. 前端測試

```bash
# 啟動前端
cd /home/kaisermac/nad_web_ui/frontend
npm run dev

# 訪問 http://192.168.10.25:5173/training
```

### 3. 功能測試清單

- [ ] 查看 By Src 模型狀態
- [ ] 查看 By Dst 模型狀態
- [ ] 開始 By Src 訓練
- [ ] 開始 By Dst 訓練
- [ ] 訓練進度實時更新
- [ ] 訓練完成後模型資訊更新
- [ ] 兩個模式可以獨立訓練

## 🚀 下一步

1. **更新 Training.vue UI** (參考 `TRAINING_DUAL_MODE_UPDATE_GUIDE.md`)
2. **測試雙模式訓練流程**
3. **確認兩個模型文件正確儲存**
4. **驗證實時偵測是否使用兩個模型**

## 💡 使用建議

1. **初次使用**：先訓練 By Src 模型（已有數據且常用）
2. **回填數據**：使用 `backfill_historical_data.py --mode by_dst` 回填 By Dst 數據
3. **訓練 By Dst**：有足夠歷史數據後訓練 By Dst 模型
4. **雙模式偵測**：兩個模型互補，提供更全面的異常偵測

## 📞 支援

相關文檔：
- `/home/kaisermac/snm_flow/DUAL_ISOLATION_FOREST_PROPOSAL.md` - 雙模式設計提案
- `/home/kaisermac/snm_flow/ISOLATION_FOREST_DUAL_PERSPECTIVE_GUIDE.md` - 實作指南
- `/home/kaisermac/nad_web_ui/TRAINING_DUAL_MODE_UPDATE_GUIDE.md` - UI 更新指南
