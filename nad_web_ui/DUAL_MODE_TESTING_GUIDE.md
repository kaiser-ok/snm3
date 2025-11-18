# 雙模式訓練 UI 測試指南

## ✅ 已完成的實作

### 後端 ✅
- ✅ `backend/services/training_service.py` - 支援雙模式
- ✅ `backend/api/training.py` - API 支援 mode 參數
- ✅ `frontend/src/stores/training.js` - Store 支援雙模式狀態
- ✅ `frontend/src/services/api.js` - API 調用支援 mode

### 前端 ✅
- ✅ `frontend/src/views/Training.vue` - 完整雙模式 Tabs UI
  - ✅ 雙視角說明卡片
  - ✅ By Src Tab（來源 IP 視角）
  - ✅ By Dst Tab（目標 IP 視角）
  - ✅ 獨立的模型資訊顯示
  - ✅ 獨立的訓練配置
  - ✅ 獨立的訓練進度追蹤
  - ✅ 共用的設備映射配置

## 🚀 啟動測試

### 1. 啟動後端
```bash
cd /home/kaisermac/nad_web_ui/backend
python app.py
```

應該看到：
```
* Running on http://127.0.0.1:5000
* Running on http://192.168.10.25:5000
```

### 2. 啟動前端
```bash
cd /home/kaisermac/nad_web_ui/frontend
npm run dev
```

應該看到：
```
VITE v5.x.x  ready in xxx ms

➜  Local:   http://localhost:5173/
➜  Network: http://192.168.10.25:5173/
```

### 3. 訪問測試頁面
打開瀏覽器訪問：
```
http://192.168.10.25:5173/training
```

## 📋 測試清單

### 基本 UI 測試

- [ ] **雙視角說明顯示**
  - [ ] 看到藍色 info alert "雙視角異常偵測"
  - [ ] 說明文字清楚易懂

- [ ] **Tabs 切換**
  - [ ] 看到兩個 Tab：📤 來源 IP 視角 (By Src) 和 📥 目標 IP 視角 (By Dst)
  - [ ] 點擊可以切換 Tab
  - [ ] 切換時控制台顯示 "切換到模式: by_src/by_dst"

### By Src Tab 測試

- [ ] **模型資訊卡片**
  - [ ] 標題顯示 "模型資訊 - By Src"
  - [ ] 顯示模型狀態（已訓練/尚未訓練）
  - [ ] 如果已訓練，顯示訓練日期
  - [ ] 顯示特徵數量
  - [ ] 顯示決策樹數量
  - [ ] 顯示污染率

- [ ] **訓練配置卡片**
  - [ ] 訓練資料天數輸入框（1-14天）
  - [ ] 決策樹數量輸入框（50-300）
  - [ ] 污染率輸入框（0.01-0.10）
  - [ ] 異常偵測閾值輸入框（0.1-1.0）
  - [ ] 排除伺服器回應流量開關
  - [ ] "恢復預設值" 按鈕
  - [ ] "開始訓練 (By Src)" 按鈕

- [ ] **開始訓練**
  - [ ] 點擊 "開始訓練 (By Src)"
  - [ ] 按鈕變成 loading 狀態
  - [ ] 顯示訓練進度卡片
  - [ ] 進度條正常更新（0% → 100%）
  - [ ] 進度訊息顯示正確（包含 "By Src"）
  - [ ] 訓練完成後顯示成功訊息
  - [ ] 模型資訊自動更新

### By Dst Tab 測試

- [ ] **模型資訊卡片**
  - [ ] 標題顯示 "模型資訊 - By Dst"
  - [ ] 顯示模型狀態
  - [ ] 獨立於 By Src 的狀態

- [ ] **訓練配置卡片**
  - [ ] 所有配置項目正常顯示
  - [ ] "開始訓練 (By Dst)" 按鈕

- [ ] **開始訓練**
  - [ ] 點擊 "開始訓練 (By Dst)"
  - [ ] 訓練進度獨立顯示
  - [ ] 進度訊息包含 "By Dst"
  - [ ] 訓練完成後模型資訊更新

### 雙模式同時測試

- [ ] **切換 Tab 時狀態保持**
  - [ ] 在 By Src 開始訓練
  - [ ] 切換到 By Dst Tab
  - [ ] 切回 By Src Tab
  - [ ] By Src 的訓練進度仍然顯示

- [ ] **獨立訓練進度**
  - [ ] By Src 訓練時，By Dst 可以獨立操作
  - [ ] By Dst 訓練時，By Src 可以獨立操作

### 設備映射配置測試

- [ ] **共用配置**
  - [ ] 設備映射配置在 Tabs 外面（所有模式共用）
  - [ ] 新增/編輯/刪除設備類別正常運作
  - [ ] 新增/移除 IP 網段正常運作

## 🧪 API 測試

### 測試 GET 配置

```bash
# 獲取所有模式配置
curl http://localhost:5000/api/training/config | jq

# 應該返回：
# {
#   "status": "success",
#   "models": {
#     "by_src": { ... },
#     "by_dst": { ... }
#   }
# }

# 獲取 By Src 配置
curl http://localhost:5000/api/training/config?mode=by_src | jq

# 獲取 By Dst 配置
curl http://localhost:5000/api/training/config?mode=by_dst | jq
```

### 測試開始訓練

```bash
# 開始 By Src 訓練
curl -X POST http://localhost:5000/api/training/start \
  -H "Content-Type: application/json" \
  -d '{
    "days": 3,
    "mode": "by_src",
    "n_estimators": 150,
    "contamination": 0.05,
    "anomaly_threshold": 0.6
  }' | jq

# 開始 By Dst 訓練
curl -X POST http://localhost:5000/api/training/start \
  -H "Content-Type: application/json" \
  -d '{
    "days": 3,
    "mode": "by_dst",
    "n_estimators": 150,
    "contamination": 0.05,
    "anomaly_threshold": 0.6
  }' | jq
```

## 🐛 常見問題排查

### 問題 1: 模型狀態顯示 "尚未訓練"
**檢查：**
- Elasticsearch 是否有對應索引的數據
  - By Src: `netflow_stats_5m`
  - By Dst: `netflow_stats_5m_by_dst`
- 模型文件是否存在：
  - By Src: `/home/kaisermac/snm_flow/nad/models/isolation_forest.pkl`
  - By Dst: `/home/kaisermac/snm_flow/nad/models/isolation_forest_by_dst.pkl`

### 問題 2: By Dst 無數據
**解決：**
```bash
# 回填 By Dst 歷史數據
cd /home/kaisermac/snm_flow
python3 backfill_historical_data.py --execute --mode by_dst --days 7
```

### 問題 3: 訓練失敗
**檢查：**
1. 後端控制台錯誤訊息
2. 瀏覽器開發者工具 Console
3. Network tab 中的 API 回應

### 問題 4: 進度不更新
**檢查：**
1. SSE 連接是否成功（Network tab）
2. 後端是否正常發送事件
3. 瀏覽器是否支援 EventSource

## 📊 預期結果

### By Src 模型
- **特徵數量**: 16
- **關鍵特徵**: `unique_dsts`, `flow_count`, `total_bytes`
- **偵測目標**: 掃描攻擊、DDoS 來源、惡意流量發送者

### By Dst 模型
- **特徵數量**: 16
- **關鍵特徵**: `unique_srcs`, `flow_count`, `total_bytes`
- **偵測目標**: DDoS 目標、被掃描主機、異常服務器

## ✨ 成功標準

- ✅ 可以切換兩個 Tab
- ✅ 每個 Tab 顯示獨立的模型狀態
- ✅ 可以分別訓練兩個模型
- ✅ 訓練進度獨立追蹤
- ✅ 訓練完成後模型資訊正確更新
- ✅ 兩個模型可以同時存在並使用

## 📝 測試報告模板

```markdown
## 測試日期: YYYY-MM-DD
## 測試人員:

### 環境
- 前端版本:
- 後端版本:
- Elasticsearch 版本:

### 測試結果
- [ ] By Src Tab 顯示正常
- [ ] By Dst Tab 顯示正常
- [ ] Tab 切換功能正常
- [ ] By Src 訓練成功
- [ ] By Dst 訓練成功
- [ ] 進度追蹤正常
- [ ] 模型資訊更新正確

### 問題記錄
1.
2.

### 建議改進
1.
2.
```

## 🎯 下一步

測試成功後：
1. 訓練兩個模型
2. 整合到實時偵測系統
3. 驗證雙視角異常偵測效果
4. 收集使用者回饋
5. 優化 UI/UX
