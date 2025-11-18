# 修改記錄 - 修正 IP 分析時間範圍計算

**日期**: 2025-11-17
**修改者**: Claude Code
**問題描述**: 從異常 IP 清單跳轉到 IP 分析頁面時，時間範圍總是從「現在」往回推算，而非使用異常發生的實際時間區段

---

## 🐛 問題說明

### 修改前的行為
當使用者從 Dashboard 的特定時間段（例如：2025-11-17 10:05 的 5 分鐘區間）點擊某個異常 IP 的「詳細分析」時：

- **分析起始時間**: 2025-11-17 11:50（現在 - 10 分鐘）
- **分析結束時間**: 2025-11-17 12:00（現在）

這導致分析的時間範圍與異常實際發生的時間不一致！

### 預期行為
應該使用異常實際發生的時間區段：
- **分析起始時間**: 2025-11-17 10:05:00
- **分析結束時間**: 2025-11-17 10:10:00（+5 分鐘）

---

## 🔧 修改內容

### 1. Dashboard.vue - 傳遞實際時間範圍

**檔案**: `/home/kaisermac/nad_web_ui/frontend/src/views/Dashboard.vue`

#### 修改位置：`analyzeIPFromBucket()` 函數 (Line 502-519)

**修改前**:
```javascript
function analyzeIPFromBucket(ip, timeBucket) {
  router.push({
    name: 'IPAnalysis',
    query: {
      ip,
      minutes: 10,  // 10 分鐘
      time_bucket: timeBucket
    }
  })
}
```

**修改後**:
```javascript
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
```

**說明**:
- 從 `timeBucket` 計算實際的 5 分鐘時間範圍
- 傳遞 `start_time` 和 `end_time` 而非 `minutes`
- 保留 `time_bucket` 用於頁面顯示

---

### 2. IPAnalysis.vue - 接收並使用實際時間範圍

**檔案**: `/home/kaisermac/nad_web_ui/frontend/src/views/IPAnalysis.vue`

#### 修改 1：新增狀態變數 (Line 770-777)

**修改前**:
```javascript
const ipAddress = ref('')
const minutes = ref(60)  // 改為分鐘，預設 60 分鐘 = 1 小時
const topN = ref(10)  // Top N 參數
const loading = ref(false)
const results = ref(null)
const timeBucket = ref(null)  // 儲存時間段資訊（如果從 bucket 進來）
```

**修改後**:
```javascript
const ipAddress = ref('')
const minutes = ref(60)  // 改為分鐘，預設 60 分鐘 = 1 小時
const startTime = ref(null)  // 分析開始時間（從 Dashboard 傳來）
const endTime = ref(null)    // 分析結束時間（從 Dashboard 傳來）
const topN = ref(10)  // Top N 參數
const loading = ref(false)
const results = ref(null)
const timeBucket = ref(null)  // 儲存時間段資訊（如果從 bucket 進來）
```

---

#### 修改 2：onMounted 接收時間參數 (Line 799-827)

**修改前**:
```javascript
onMounted(() => {
  if (route.query.ip) {
    ipAddress.value = route.query.ip

    if (route.query.minutes) {
      minutes.value = parseInt(route.query.minutes)
    }

    if (route.query.top_n) {
      topN.value = parseInt(route.query.top_n)
    } else {
      topN.value = null
    }

    if (route.query.time_bucket) {
      timeBucket.value = route.query.time_bucket
    }

    handleAnalyze()
  }
})
```

**修改後**:
```javascript
onMounted(() => {
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

    if (route.query.top_n) {
      topN.value = parseInt(route.query.top_n)
    } else {
      topN.value = null
    }

    if (route.query.time_bucket) {
      timeBucket.value = route.query.time_bucket
    }

    handleAnalyze()
  }
})
```

**說明**:
- 優先接收 `start_time` 和 `end_time`（從特定時間段跳轉）
- 其次使用 `minutes`（從 Top 10 跳轉或手動輸入）

---

#### 修改 3：handleAnalyze 使用時間參數 (Line 837-863)

**修改前**:
```javascript
async function handleAnalyze() {
  if (!ipAddress.value) {
    ElMessage.warning('請輸入 IP 地址')
    return
  }

  loading.value = true
  try {
    const requestData = {
      ip: ipAddress.value,
      minutes: minutes.value
    }

    if (topN.value !== null) {
      requestData.top_n = topN.value
    }

    const { data } = await analysisAPI.analyzeIP(requestData)
    // ...
  }
}
```

**修改後**:
```javascript
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

    if (topN.value !== null) {
      requestData.top_n = topN.value
    }

    const { data } = await analysisAPI.analyzeIP(requestData)
    // ...
  }
}
```

**說明**:
- 優先傳遞 `start_time` 和 `end_time`
- 如果沒有具體時間，則使用 `minutes`

---

#### 修改 4：watch 清除具體時間 (Line 829-838)

**修改前**:
```javascript
watch(minutes, (newMinutes) => {
  if (ipAddress.value && results.value) {
    handleAnalyze()
  }
})
```

**修改後**:
```javascript
watch(minutes, (newMinutes) => {
  if (ipAddress.value && results.value) {
    // 當使用者手動改變時間範圍，清除具體的開始/結束時間
    startTime.value = null
    endTime.value = null
    handleAnalyze()
  }
})
```

**說明**:
- 當使用者手動改變時間範圍下拉選單時，清除具體的開始/結束時間
- 改用 `minutes` 重新計算（從現在往回推算）

---

## 📊 影響範圍

### 受影響的功能
1. ✅ **從特定時間段跳轉** - 現在使用實際時間範圍
   - URL 範例: `?ip=192.168.10.160&start_time=2025-11-17T10:05:00.000Z&end_time=2025-11-17T10:10:00.000Z&time_bucket=2025-11-17T10:05:00.000Z`

### 不受影響的功能
- ❌ **從 Top 10 異常 IP 跳轉** - 仍使用 `minutes` 參數（從現在往回推 24 小時）
  - URL 範例: `?ip=192.168.10.160&minutes=1440`

- ❌ **手動輸入 IP 分析** - 仍使用下拉選單的時間範圍

---

## ✅ 修改後的行為

### 場景 1：從特定時間段（2025-11-17 10:05）跳轉

**URL**:
```
http://192.168.10.25:5173/analysis?ip=192.168.10.160
  &start_time=2025-11-17T10:05:00.000Z
  &end_time=2025-11-17T10:10:00.000Z
  &time_bucket=2025-11-17T10:05:00.000Z
```

**基本資訊顯示**:
- **時間段**: 2025-11-17 10:05:00
- **分析起始**: 2025-11-17 10:05:00 ✅（使用實際時間）
- **分析結束**: 2025-11-17 10:10:00 ✅（使用實際時間）

---

### 場景 2：從 Top 10 異常 IP 跳轉

**URL**:
```
http://192.168.10.25:5173/analysis?ip=192.168.10.160&minutes=1440
```

**基本資訊顯示**:
- **分析起始**: 2025-11-17 10:00:00（現在 - 24 小時）
- **分析結束**: 2025-11-17 11:00:00（現在）

---

### 場景 3：使用者手動改變時間範圍

當使用者從特定時間段跳轉後，手動改變時間範圍下拉選單：
1. `startTime` 和 `endTime` 被清除
2. 改用 `minutes` 重新計算（從現在往回推算）
3. 重新執行分析

---

## 🧪 測試建議

### 測試步驟 1：從特定時間段跳轉
1. 前往 Dashboard
2. 點擊時間軸中的某個 bar（例如：10:05）
3. 在彈出的該時段異常列表中，點擊任一 IP 的「詳細分析」
4. **驗證**：
   - ✅ URL 包含 `start_time` 和 `end_time` 參數
   - ✅ 「分析起始」時間 = 該時段的開始時間（10:05:00）
   - ✅ 「分析結束」時間 = 該時段的結束時間（10:10:00）
   - ✅ 「時間段」顯示正確的時間

### 測試步驟 2：從 Top 10 跳轉
1. 前往 Dashboard
2. 點擊 Top 10 異常 IP 列表中任一 IP 的「詳細分析」
3. **驗證**：
   - ✅ URL 包含 `minutes=1440` 參數
   - ✅ URL **不包含** `start_time` 和 `end_time`
   - ✅ 「分析起始」和「分析結束」時間是從現在往回推 24 小時

### 測試步驟 3：手動改變時間範圍
1. 從特定時間段跳轉到 IP 分析頁面
2. 手動改變時間範圍下拉選單（例如：從 10 分鐘改為 1 小時）
3. **驗證**：
   - ✅ 分析自動重新執行
   - ✅ 「分析起始」和「分析結束」時間改為從現在往回推 1 小時
   - ✅ 資料更新正確

---

## 🔗 相關檔案

- **Dashboard**: `/home/kaisermac/nad_web_ui/frontend/src/views/Dashboard.vue`
- **IP 分析頁面**: `/home/kaisermac/nad_web_ui/frontend/src/views/IPAnalysis.vue`
- **後端 API**: `/home/kaisermac/nad_web_ui/backend/api/analysis.py` (已支援 start_time/end_time)
- **後端服務**: `/home/kaisermac/nad_web_ui/backend/services/analysis_service.py`

---

## 💡 技術細節

### 時間計算邏輯
```javascript
// Dashboard.vue - 計算 5 分鐘時間範圍
const startTime = new Date(timeBucket)  // "2025-11-17T10:05:00.000Z"
const endTime = new Date(startTime.getTime() + 5 * 60 * 1000)  // +5 分鐘
```

### 後端 API 支援
後端 `analysis.py` 已經支援兩種模式：
1. **具體時間模式**: 傳遞 `start_time` 和 `end_time`
2. **相對時間模式**: 傳遞 `minutes`（從現在往回推算）

當兩種參數都存在時，優先使用具體時間。

---

**修改完成時間**: 2025-11-17
**狀態**: ✅ 已完成，待測試
