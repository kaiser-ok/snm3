# IP 分析時間參數功能實作總結

## 功能說明

實現了在 IP 分析功能中支援不同的時間範圍和 Top N 參數設定，使得：

1. **從 Top 10 異常 IP 進行分析**：使用 24 小時時間範圍，顯示前 20 筆 IP 和 Port
2. **從特定 Time Bucket 進行分析**：使用 10 分鐘時間範圍，顯示前 10 筆 IP 和 Port

## 修改內容

### 後端修改

#### 1. `backend/services/analysis_service.py`

**修改點 1: `analyze_ip` 方法增加 `top_n` 參數**
```python
def analyze_ip(self, ip: str, start_time: str = None, end_time: str = None,
               hours: int = 24, top_n: int = 10) -> Dict:
```
- 新增 `top_n` 參數，預設為 10
- 用於控制返回的 Top IP 和 Port 數量

**修改點 2: `_get_details_from_raw` 方法支援動態 Top N**
```python
def _get_details_from_raw(self, ip: str, start_time: str, end_time: str, top_n: int = 10) -> Dict:
```
- 修改 Elasticsearch 查詢中的 `size` 參數，從固定值改為使用 `top_n`
- 同時應用於目的地 IP 和目的 Port 的查詢

#### 2. `backend/api/analysis.py`

**修改點: `/api/analysis/ip` 端點接受並驗證 `top_n` 參數**
```python
top_n = data.get('top_n', 10)  # 預設 10

# 驗證 top_n
if not (1 <= top_n <= 50):  # 最多 50 筆
    return jsonify({
        'status': 'error',
        'error': 'top_n must be between 1 and 50'
    }), 400
```

### 前端修改

#### 1. `frontend/src/views/Dashboard.vue`

**修改點 1: 新增兩個不同的分析函數**

```javascript
// 從 Top 10 異常 IP 列表分析 (24 小時)
function analyzeIP(ip) {
  router.push({
    name: 'IPAnalysis',
    query: {
      ip,
      hours: 24,  // 24 小時分析
      top_n: 20   // 顯示前 20 筆
    }
  })
}

// 從特定時間段分析 (10 分鐘)
function analyzeIPFromBucket(ip, timeBucket) {
  router.push({
    name: 'IPAnalysis',
    query: {
      ip,
      hours: 0.167,  // 10 分鐘 = 10/60 小時
      top_n: 10,     // 顯示前 10 筆
      time_bucket: timeBucket  // 傳遞時間段資訊
    }
  })
}
```

**修改點 2: 更新 selected bucket 中的按鈕呼叫**
```vue
<el-button
  size="small"
  @click="analyzeIPFromBucket(row.src_ip, selectedBucket.time_bucket)"
>
  詳細分析
</el-button>
```

#### 2. `frontend/src/views/IPAnalysis.vue`

**修改點 1: 新增狀態變數**
```javascript
const topN = ref(10)  // Top N 參數
const timeBucket = ref(null)  // 時間段資訊
```

**修改點 2: 從 URL query 讀取參數**
```javascript
onMounted(() => {
  if (route.query.ip) {
    ipAddress.value = route.query.ip

    if (route.query.hours) {
      hours.value = parseFloat(route.query.hours)
    }

    if (route.query.top_n) {
      topN.value = parseInt(route.query.top_n)
    }

    if (route.query.time_bucket) {
      timeBucket.value = route.query.time_bucket
    }

    handleAnalyze()
  }
})
```

**修改點 3: API 呼叫時傳遞 `top_n`**
```javascript
const { data } = await analysisAPI.analyzeIP({
  ip: ipAddress.value,
  hours: hours.value,
  top_n: topN.value  // 傳遞 top_n 參數
})
```

**修改點 4: UI 顯示時間區段和 Top N 資訊**
```vue
<el-descriptions :column="3" border>
  <!-- 原有欄位 -->
  <el-descriptions-item label="時間範圍">
    {{ results.time_range?.duration_hours?.toFixed(1) }} 小時
    <el-tag v-if="timeBucket" type="info" size="small">
      特定時段分析
    </el-tag>
  </el-descriptions-item>

  <!-- 新增欄位 -->
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

  <el-descriptions-item label="Top N 設定">
    顯示前 {{ topN }} 筆資料
  </el-descriptions-item>
</el-descriptions>
```

**修改點 5: 更新標題顯示 Top N**
```vue
<!-- Top 通訊目的地 -->
Top 通訊目的地 (前 {{ topN }} 名)

<!-- Top 目的埠號分佈 -->
Top 目的埠號分佈 (前 {{ topN }} 名)
```

**修改點 6: 新增格式化函數**
```javascript
// 格式化時間段
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

// 格式化日期時間
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
```

## 使用流程

### 流程 1: 從 Top 10 異常 IP 分析

1. 使用者在 Dashboard 查看過去 24 小時的異常檢測結果
2. 點擊「Top 10 異常 IP」表格中某個 IP 的「詳細分析」按鈕
3. 系統跳轉到 IP 分析頁面，參數：
   - `hours=24`（24 小時）
   - `top_n=20`（顯示前 20 筆）
4. IP 分析頁面顯示：
   - 分析時間範圍：24.0 小時
   - Top N 設定：顯示前 20 筆資料
   - Top 20 通訊目的地
   - Top 20 目的埠號

### 流程 2: 從特定 Time Bucket 分析

1. 使用者在 Dashboard 點擊柱狀圖的某個時間段
2. 展開該時段的異常 IP 列表
3. 點擊某個 IP 的「詳細分析」按鈕
4. 系統跳轉到 IP 分析頁面，參數：
   - `hours=0.167`（10 分鐘）
   - `top_n=10`（顯示前 10 筆）
   - `time_bucket=2025-11-16T10:05:00.000Z`（該時段的時間戳）
5. IP 分析頁面顯示：
   - 分析時間範圍：0.2 小時（含「特定時段分析」標籤）
   - 分析時段：2025/11/16 10:05:00
   - Top N 設定：顯示前 10 筆資料
   - Top 10 通訊目的地
   - Top 10 目的埠號

## API 參數規格

### POST `/api/analysis/ip`

**Request Body:**
```json
{
  "ip": "192.168.10.135",
  "hours": 24,           // 選填，預設 24（可以是小數，如 0.167 表示 10 分鐘）
  "top_n": 20,           // 選填，預設 10，範圍 1-50
  "start_time": null,    // 選填，ISO 格式
  "end_time": null       // 選填，ISO 格式
}
```

**Response:**
```json
{
  "status": "success",
  "ip": "192.168.10.135",
  "time_range": {
    "start": "2025-11-15T10:00:00.000Z",
    "end": "2025-11-16T10:00:00.000Z",
    "duration_hours": 24.0
  },
  "details": {
    "top_destinations": [
      // 最多 top_n 筆
    ],
    "port_distribution": {
      // 最多 top_n 筆
    }
  }
}
```

## 測試方法

### 手動測試

1. 啟動後端：`cd backend && python3 app.py`
2. 啟動前端：`cd frontend && npm run dev`
3. 訪問 Dashboard
4. 執行異常檢測
5. 測試兩種分析路徑：
   - 從 Top 10 異常 IP 的「詳細分析」
   - 從特定時段的「詳細分析」
6. 觀察 IP 分析頁面是否正確顯示時間範圍和 Top N

### 自動測試腳本

執行 `./test_time_params.sh` 測試後端 API：

```bash
cd /home/kaisermac/nad_web_ui
./test_time_params.sh
```

測試項目：
1. 24 小時分析，Top 20
2. 10 分鐘分析，Top 10
3. top_n 參數驗證（測試邊界值）

## 注意事項

1. **小數時間支援**：`hours` 參數支援小數，例如 `0.167` 表示 10 分鐘
2. **Top N 限制**：後端限制 `top_n` 在 1-50 之間，防止查詢過大數據集
3. **時間段顯示**：如果是從 time bucket 進入，會額外顯示「分析時段」資訊
4. **相容性**：未傳遞 `top_n` 參數時使用預設值 10，保持向後相容

## 檔案清單

### 修改的檔案
- `backend/services/analysis_service.py`
- `backend/api/analysis.py`
- `frontend/src/views/Dashboard.vue`
- `frontend/src/views/IPAnalysis.vue`

### 新增的檔案
- `test_time_params.sh` - 測試腳本
- `FEATURE_TIME_PARAMS.md` - 本文件
