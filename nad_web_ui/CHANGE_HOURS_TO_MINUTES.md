# 將時間參數從小時改為分鐘

## 修改原因

1. **避免小數問題**：10 分鐘 = 0.167 小時，使用小數容易出錯且不直觀
2. **更精確的控制**：分鐘作為單位更適合短時間範圍的分析
3. **參數驗證簡化**：整數驗證比小數驗證更清晰
4. **用戶體驗**：「10 分鐘」比「0.167 小時」更易理解

## 修改內容

### 1. 後端 API (`backend/api/analysis.py`)

**修改前：**
```python
hours = data.get('hours', 24)

if not (0.167 <= hours <= 168):
    return jsonify({
        'status': 'error',
        'error': 'hours must be between 0.167 (10 minutes) and 168 (7 days)'
    }), 400

service.analyze_ip(..., hours=hours, ...)
```

**修改後：**
```python
minutes = data.get('minutes', 1440)  # 預設 24 小時 = 1440 分鐘

if not (5 <= minutes <= 10080):  # 5 分鐘 ~ 7 天
    return jsonify({
        'status': 'error',
        'error': 'minutes must be between 5 and 10080 (7 days)'
    }), 400

service.analyze_ip(..., minutes=minutes, ...)
```

### 2. 後端 Service (`backend/services/analysis_service.py`)

**修改前：**
```python
def analyze_ip(self, ip: str, ..., hours: int = 24, ...):
    if not start_time:
        start_dt = end_dt - timedelta(hours=hours)

    return {
        'time_range': {
            'duration_hours': (end_dt - start_dt).total_seconds() / 3600
        }
    }
```

**修改後：**
```python
def analyze_ip(self, ip: str, ..., minutes: int = 1440, ...):
    if not start_time:
        start_dt = end_dt - timedelta(minutes=minutes)

    duration_seconds = (end_dt - start_dt).total_seconds()
    return {
        'time_range': {
            'duration_minutes': duration_seconds / 60,
            'duration_hours': duration_seconds / 3600  # 保留向後相容
        }
    }
```

### 3. 前端 Dashboard (`frontend/src/views/Dashboard.vue`)

**修改前：**
```javascript
// Top 10 異常 IP
function analyzeIP(ip) {
  router.push({
    query: {
      ip,
      hours: 24,
      top_n: 20
    }
  })
}

// 特定時段
function analyzeIPFromBucket(ip, timeBucket) {
  router.push({
    query: {
      ip,
      hours: 0.167,  // 10 分鐘
      top_n: 10
    }
  })
}
```

**修改後：**
```javascript
// Top 10 異常 IP
function analyzeIP(ip) {
  router.push({
    query: {
      ip,
      minutes: 1440,  // 24 小時
      top_n: 20
    }
  })
}

// 特定時段
function analyzeIPFromBucket(ip, timeBucket) {
  router.push({
    query: {
      ip,
      minutes: 10,  // 10 分鐘
      top_n: 10
    }
  })
}
```

### 4. 前端 IP 分析頁面 (`frontend/src/views/IPAnalysis.vue`)

**a. 狀態變數**
```javascript
// 修改前
const hours = ref(1)

// 修改後
const minutes = ref(60)  // 預設 60 分鐘 = 1 小時
```

**b. URL 參數讀取**
```javascript
// 修改前
if (route.query.hours) {
  hours.value = parseFloat(route.query.hours)
}

// 修改後
if (route.query.minutes) {
  minutes.value = parseInt(route.query.minutes)
}
```

**c. API 呼叫**
```javascript
// 修改前
analysisAPI.analyzeIP({
  ip: ipAddress.value,
  hours: hours.value,
  top_n: topN.value
})

// 修改後
analysisAPI.analyzeIP({
  ip: ipAddress.value,
  minutes: minutes.value,
  top_n: topN.value
})
```

**d. 時間範圍選擇器**
```vue
<!-- 修改前 -->
<el-select v-model="hours">
  <el-option label="1 小時" :value="1" />
  <el-option label="3 小時" :value="3" />
  <el-option label="24 小時" :value="24" />
</el-select>

<!-- 修改後 -->
<el-select v-model="minutes">
  <el-option label="10 分鐘" :value="10" />
  <el-option label="30 分鐘" :value="30" />
  <el-option label="1 小時" :value="60" />
  <el-option label="3 小時" :value="180" />
  <el-option label="6 小時" :value="360" />
  <el-option label="12 小時" :value="720" />
  <el-option label="24 小時" :value="1440" />
  <el-option label="48 小時" :value="2880" />
</el-select>
```

**e. 新增時間格式化函數**
```javascript
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
```

**f. UI 顯示**
```vue
<!-- 修改前 -->
<el-descriptions-item label="時間範圍">
  {{ results.time_range?.duration_hours?.toFixed(1) }} 小時
</el-descriptions-item>

<!-- 修改後 -->
<el-descriptions-item label="時間範圍">
  {{ formatDuration(results.time_range?.duration_minutes) }}
</el-descriptions-item>
```

### 5. 修復 El-Statistic 錯誤

**問題：**
```
Invalid prop: type check failed for prop "value".
Expected Number | Object, got String with value "1.11 GB"
```

**解決方案：**
將 `formatBytes()` 返回的字符串改用自定義樣式顯示：

```vue
<!-- 修改前 -->
<el-statistic title="總位元組" :value="formatBytes(results.summary?.total_bytes || 0)" />

<!-- 修改後 -->
<div class="custom-statistic">
  <div class="statistic-title">總位元組</div>
  <div class="statistic-value">{{ formatBytes(results.summary?.total_bytes || 0) }}</div>
</div>
```

## 參數範圍

| 參數 | 最小值 | 最大值 | 說明 |
|------|--------|--------|------|
| minutes | 5 | 10080 | 5 分鐘 ~ 7 天 |

## 常用時間對照表

| 時間 | 分鐘數 |
|------|--------|
| 10 分鐘 | 10 |
| 30 分鐘 | 30 |
| 1 小時 | 60 |
| 3 小時 | 180 |
| 6 小時 | 360 |
| 12 小時 | 720 |
| 24 小時 | 1440 |
| 48 小時 | 2880 |
| 7 天 | 10080 |

## API 範例

### 請求

```bash
curl -X POST http://localhost:5000/api/analysis/ip \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.10.135",
    "minutes": 10,
    "top_n": 10
  }'
```

### 響應

```json
{
  "status": "success",
  "ip": "192.168.10.135",
  "time_range": {
    "start": "2025-11-16T10:00:00.000Z",
    "end": "2025-11-16T10:10:00.000Z",
    "duration_minutes": 10.0,
    "duration_hours": 0.167
  },
  "details": {
    "top_destinations": [...],
    "port_distribution": {...}
  }
}
```

## 向後相容性

- 後端 API 仍返回 `duration_hours` 欄位，確保舊版前端不會中斷
- 新增 `duration_minutes` 欄位供新版使用
- 建議所有客戶端遷移到使用 `minutes` 參數

## 測試

### 後端測試

```bash
# 測試 10 分鐘
curl -X POST http://localhost:5000/api/analysis/ip \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.10.135", "minutes": 10, "top_n": 10}'

# 測試 24 小時
curl -X POST http://localhost:5000/api/analysis/ip \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.10.135", "minutes": 1440, "top_n": 20}'

# 測試參數驗證（應該失敗）
curl -X POST http://localhost:5000/api/analysis/ip \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.10.135", "minutes": 3, "top_n": 10}'
# 預期: {"error": "minutes must be between 5 and 10080 (7 days)", "status": "error"}
```

### 前端測試

1. 從 Dashboard 點擊 Top 10 異常 IP 的「詳細分析」
   - 應該看到 URL: `?ip=x.x.x.x&minutes=1440&top_n=20`
   - 時間範圍應顯示：「1.0 天」或「24.0 小時」

2. 從 Dashboard 點擊柱狀圖某時段，再點擊「詳細分析」
   - 應該看到 URL: `?ip=x.x.x.x&minutes=10&top_n=10`
   - 時間範圍應顯示：「10 分鐘」

3. 在 IP 分析頁面手動選擇不同時間範圍
   - 選擇「10 分鐘」→ 應正常分析
   - 選擇「24 小時」→ 應正常分析

## 影響的檔案

**後端：**
- `backend/api/analysis.py`
- `backend/services/analysis_service.py`

**前端：**
- `frontend/src/views/Dashboard.vue`
- `frontend/src/views/IPAnalysis.vue`

**文檔：**
- `CHANGE_HOURS_TO_MINUTES.md`（本文件）

## 建置驗證

```bash
cd frontend
npm run build
# ✓ built in 37.14s
```

建置成功，無錯誤。
