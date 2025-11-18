# NAD Web UI

網路異常檢測系統 (Network Anomaly Detection) 的 Web 管理介面

## 專案狀態

### ✅ 後端 (Backend) - 已完成

位置：`/home/kaisermac/nad_web_ui/backend/`

Flask 後端已完全實作，包含：

- ✅ 異常檢測 API
- ✅ 模型訓練 API (含 SSE 即時進度)
- ✅ IP 分析 API
- ✅ 完整的服務層架構
- ✅ 錯誤處理和日誌
- ✅ CORS 支援

### ⏳ 前端 (Frontend) - 待實作

位置：`/home/kaisermac/nad_web_ui/frontend/` (待創建)

計劃使用：
- Vue.js 3 + Vite
- Element Plus UI 元件庫
- ECharts 圖表庫
- Pinia 狀態管理

## 快速開始

### 後端啟動

```bash
cd /home/kaisermac/nad_web_ui/backend

# 方法 1: 使用啟動腳本（推薦）
./start.sh

# 方法 2: 手動啟動
python3 app.py
```

預設運行在：`http://localhost:5000`

### API 測試

```bash
# 運行測試腳本
cd /home/kaisermac/nad_web_ui/backend
./test_api.sh

# 或手動測試
curl http://localhost:5000/api/health
```

## 專案結構

```
nad_web_ui/
├── backend/                    # Flask 後端 (已完成)
│   ├── app.py                 # 主應用
│   ├── config.py              # 配置
│   ├── requirements.txt       # Python 依賴
│   ├── .env.example          # 環境變數範例
│   ├── start.sh              # 啟動腳本
│   ├── test_api.sh           # API 測試
│   ├── README.md             # 後端文檔
│   ├── api/                  # API 端點
│   │   ├── detection.py      # 檢測 API
│   │   ├── training.py       # 訓練 API
│   │   └── analysis.py       # 分析 API
│   └── services/             # 業務邏輯
│       ├── detector_service.py
│       ├── training_service.py
│       └── analysis_service.py
│
└── frontend/                  # Vue.js 前端 (待實作)
    └── (待創建)
```

## 核心功能

### 1. 即時異常檢測

**API 端點：** `POST /api/detection/run`

```bash
curl -X POST http://localhost:5000/api/detection/run \
  -H "Content-Type: application/json" \
  -d '{"minutes": 60}'
```

功能：
- 分析最近 N 分鐘的網路流量
- 按 5 分鐘時間 bucket 分組異常
- 包含設備類型、威脅分類、嚴重性

### 2. 模型訓練

**API 端點：** `POST /api/training/start`

```bash
curl -X POST http://localhost:5000/api/training/start \
  -H "Content-Type: application/json" \
  -d '{"days": 3, "exclude_servers": false}'
```

功能：
- 背景執行模型訓練
- SSE 即時進度串流
- 訓練配置管理

### 3. IP 詳細分析

**API 端點：** `POST /api/analysis/ip`

```bash
curl -X POST http://localhost:5000/api/analysis/ip \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.10.135", "hours": 24}'
```

功能：
- Top 目的地統計
- 埠號/協議分布
- 流量時間軸
- 歷史基準比較

## API 文檔

### 檢測 API

| 端點 | 方法 | 說明 |
|------|------|------|
| `/api/detection/status` | GET | 獲取模型狀態 |
| `/api/detection/run` | POST | 執行異常檢測 |
| `/api/detection/results/<job_id>` | GET | 獲取檢測結果 |
| `/api/detection/stats?days=7` | GET | 獲取統計資訊 |

### 訓練 API

| 端點 | 方法 | 說明 |
|------|------|------|
| `/api/training/config` | GET | 獲取訓練配置 |
| `/api/training/config` | PUT | 更新配置 |
| `/api/training/start` | POST | 開始訓練 |
| `/api/training/status/<job_id>` | GET | SSE 進度串流 |
| `/api/training/history` | GET | 訓練歷史 |

### 分析 API

| 端點 | 方法 | 說明 |
|------|------|------|
| `/api/analysis/ip` | POST | 分析特定 IP |
| `/api/analysis/top-talkers?minutes=60` | GET | Top 流量 IP |

## 訓練配置參數

可調整的訓練參數：

| 參數 | 範圍 | 默認值 | 說明 |
|------|------|-------|------|
| `contamination` | 0.01 - 0.10 | 0.05 | 異常比例 (5%) |
| `n_estimators` | 50 - 300 | 150 | 決策樹數量 |
| `max_samples` | 256 - 2048 | 512 | 每棵樹的樣本數 |
| `max_features` | 0.5 - 1.0 | 0.8 | 特徵使用比例 |

## 下一步 - 前端開發

### 待實作頁面

1. **Dashboard (儀表板)**
   - 時間範圍選擇器
   - 執行檢測按鈕
   - 時間 bucket 柱狀圖 (12 buckets × 5 min)
   - 異常 IP 列表（可展開）

2. **Training (訓練管理)**
   - 當前模型資訊卡片
   - 訓練參數配置表單
   - 訓練進度條 (SSE 即時更新)
   - 訓練歷史記錄

3. **IP Analysis (IP 分析)**
   - IP 搜尋表單
   - 摘要統計卡片
   - Top 目的地表格
   - 埠號/協議分布圓餅圖
   - 流量時間軸折線圖

### 前端技術棧

- **框架：** Vue.js 3 + Vite
- **UI 元件：** Element Plus
- **圖表：** ECharts
- **狀態管理：** Pinia
- **HTTP 客戶端：** Axios
- **路由：** Vue Router

### 初始化前端

```bash
cd /home/kaisermac/nad_web_ui/frontend
npm create vite@latest . -- --template vue
npm install vue-router pinia axios element-plus echarts
```

## 系統需求

### 後端

- Python 3.9+
- Elasticsearch 7.17.x
- 訪問 `/home/kaisermac/snm_flow/nad` 模組

### 前端

- Node.js 18+
- npm 9+

## 開發模式

### 後端 (Port 5000)

```bash
cd backend
python3 app.py
```

### 前端 (Port 5173，待實作)

```bash
cd frontend
npm run dev
```

### API 代理

前端開發時，Vite 會將 `/api/*` 請求代理到 `http://localhost:5000`

配置在 `frontend/vite.config.js`:

```javascript
export default defineConfig({
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true
      }
    }
  }
})
```

## 生產部署

### 後端

使用 Systemd + Gunicorn + Nginx

詳見：`backend/README.md`

### 前端

```bash
cd frontend
npm run build
# 輸出到 dist/ 目錄
# 使用 Nginx 提供靜態文件
```

## 疑難排解

### 後端問題

查看詳細文檔：`backend/README.md`

常見問題：
- NAD 模組導入失敗 → 檢查 `NAD_BASE_PATH` 環境變數
- ES 連線失敗 → 檢查 `ES_HOST` 和 Elasticsearch 服務狀態

### API 測試

使用測試腳本：

```bash
cd backend
./test_api.sh
```

## 貢獻指南

### 添加新 API

1. 在 `backend/services/` 創建服務類
2. 在 `backend/api/` 創建 Blueprint
3. 在 `backend/app.py` 註冊 Blueprint
4. 更新文檔

### 添加新前端頁面

1. 在 `frontend/src/views/` 創建頁面元件
2. 在 `frontend/src/router/` 添加路由
3. 在 `frontend/src/stores/` 創建狀態管理
4. 更新導航選單

## 授權

內部專案 - 僅供授權使用者使用

## 聯絡資訊

如有問題或需要支援，請聯絡系統管理員。
