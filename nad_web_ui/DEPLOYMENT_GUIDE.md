# NAD Web UI - 部署與使用指南

## 🎉 專案已完成！

完整的 Web UI 已成功建立，包含前端和後端所有功能。

---

## 📁 專案結構

```
/home/kaisermac/nad_web_ui/
├── backend/          ✅ Flask 後端（完整實作）
│   ├── api/         # API 端點
│   ├── services/    # 業務邏輯
│   ├── app.py       # 主應用
│   └── ...
└── frontend/         ✅ Vue.js 前端（完整實作）
    ├── src/
    │   ├── views/      # 頁面（Dashboard, Training, IPAnalysis）
    │   ├── stores/     # Pinia stores
    │   ├── services/   # API 服務
    │   ├── router/     # 路由
    │   └── App.vue     # 主應用
    └── ...
```

---

## 🚀 快速啟動

### 1. 啟動後端

```bash
# 方法 1：直接啟動
cd /home/kaisermac/nad_web_ui/backend
python3 app.py

# 方法 2：使用啟動腳本
./start.sh
```

後端將運行在：**http://localhost:5000**

### 2. 啟動前端

```bash
cd /home/kaisermac/nad_web_ui/frontend
npm run dev
```

前端將運行在：**http://localhost:5173**

### 3. 訪問應用

打開瀏覽器訪問：**http://localhost:5173**

---

## 📊 功能清單

### ✅ 異常檢測（Dashboard）

**功能：**
- 選擇時間範圍（15/30/60/120 分鐘）
- 一鍵執行異常檢測
- 按 5 分鐘 bucket 分組顯示結果
- 可展開查看每個 bucket 的異常 IP 詳情
- 顯示設備類型圖標（🖥️💻📡🌐）
- 異常分數、置信度、威脅分類
- 點擊 IP 可跳轉到詳細分析

**使用流程：**
1. 選擇時間範圍
2. 點擊"執行檢測"
3. 等待檢測完成
4. 查看分組結果
5. 展開 bucket 查看異常 IP
6. 點擊"詳細分析"跳轉到 IP 分析頁面

---

### ✅ 模型訓練（Training）

**功能：**
- 查看當前模型資訊（特徵數、樹數量、狀態）
- 設置訓練參數（天數、是否排除伺服器）
- 一鍵開始訓練
- **即時顯示訓練進度**（透過 SSE）
- 訓練完成自動更新模型資訊

**使用流程：**
1. 查看當前模型狀態
2. 設置訓練天數（1-14 天）
3. 選擇是否排除伺服器流量
4. 點擊"開始訓練"
5. 觀察即時進度條
6. 等待訓練完成

**注意：** 訓練可能需要數分鐘，請耐心等待。

---

### ✅ IP 分析（IP Analysis）

**功能：**
- 輸入 IP 地址進行深入分析
- 選擇分析時間範圍（1-168 小時）
- 顯示統計摘要（總流量、位元組、目的地、埠號）
- Top 目的地列表
- 設備類型標識

**使用流程：**
1. 輸入 IP 地址（可從 Dashboard 點擊跳轉自動填入）
2. 選擇分析時間範圍
3. 點擊"分析"
4. 查看詳細統計資訊

---

## 🔧 API 端點

後端提供以下 API（已自動配置代理）：

| 端點 | 方法 | 功能 |
|------|------|------|
| `/api/detection/status` | GET | 模型狀態 |
| `/api/detection/run` | POST | 執行檢測 |
| `/api/detection/results/{job_id}` | GET | 獲取結果 |
| `/api/training/config` | GET/PUT | 訓練配置 |
| `/api/training/start` | POST | 開始訓練 |
| `/api/training/status/{job_id}` | GET (SSE) | 訓練進度 |
| `/api/analysis/ip` | POST | IP 分析 |

---

## 🛠️ 技術棧

### 後端
- **Flask 3.x** - Web 框架
- **Elasticsearch 7.17** - 數據存儲
- **scikit-learn** - 機器學習
- **SSE** - 即時進度推送

### 前端
- **Vue 3** - 前端框架
- **Vite** - 建構工具
- **Element Plus** - UI 元件庫
- **Pinia** - 狀態管理
- **Vue Router** - 路由
- **Axios** - HTTP 客戶端
- **ECharts** - 圖表庫（可擴展）

---

## 📝 開發模式

### 熱重載

前後端都支持熱重載，修改代碼後會自動刷新：

- **後端：** Flask debug 模式自動重載
- **前端：** Vite HMR 熱模塊替換

### API 代理

前端開發時，`/api/*` 請求會自動代理到後端 `http://localhost:5000`

配置位於：`frontend/vite.config.js`

---

## 🔒 生產部署

### 後端部署

使用 Gunicorn + Systemd：

```bash
cd /home/kaisermac/nad_web_ui/backend
gunicorn --bind 0.0.0.0:5000 --workers 4 app:app
```

詳細部署步驟請參閱：`backend/README.md`

### 前端部署

建構靜態文件：

```bash
cd /home/kaisermac/nad_web_ui/frontend
npm run build
```

輸出到 `dist/` 目錄，使用 Nginx 提供服務。

Nginx 配置範例：

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    root /home/kaisermac/nad_web_ui/frontend/dist;
    index index.html;
    
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    location /api/ {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
    }
}
```

---

## 🐛 故障排解

### 後端問題

**端口被占用：**
```bash
# 更換端口
export BACKEND_PORT=5001
python3 app.py
```

**NAD 模組導入失敗：**
```bash
# 檢查環境變數
cat backend/.env
# 確保 NAD_BASE_PATH 正確
```

### 前端問題

**無法連接後端：**
- 確認後端已啟動在 5000 端口
- 檢查瀏覽器控制台的網路請求
- 確認 Vite 代理配置正確

**頁面空白：**
- 打開瀏覽器開發者工具查看錯誤
- 檢查前端日誌：`/tmp/frontend.log`

---

## 📈 擴展建議

目前實作了核心功能，未來可擴展：

1. **Dashboard 圖表** - 使用 ECharts 添加時間 bucket 柱狀圖
2. **IP Analysis 圖表** - 埠號分布圓餅圖、流量時間軸
3. **訓練歷史** - 顯示過往訓練記錄
4. **用戶認證** - 添加登入功能
5. **實時監控** - WebSocket 實時更新異常
6. **導出功能** - 導出報表為 CSV/PDF

---

## 📚 相關文檔

- **總覽：** `/home/kaisermac/nad_web_ui/README.md`
- **後端：** `/home/kaisermac/nad_web_ui/backend/README.md`
- **後端快速啟動：** `/home/kaisermac/nad_web_ui/backend/QUICKSTART.md`

---

## ✅ 已完成項目清單

- [x] Flask 後端 API（檢測、訓練、分析）
- [x] SSE 即時訓練進度
- [x] Vue.js 前端應用框架
- [x] Pinia 狀態管理
- [x] Vue Router 路由
- [x] Element Plus UI 整合
- [x] Dashboard 頁面（異常檢測）
- [x] Training 頁面（模型訓練）
- [x] IP Analysis 頁面（IP 分析）
- [x] API 服務層封裝
- [x] 前後端代理配置
- [x] 頁面導航和布局
- [x] 錯誤處理和用戶提示

---

## 🎯 使用建議

1. **首次使用：**
   - 先訪問 Training 頁面確認模型已訓練
   - 如未訓練，執行一次訓練（建議 3-7 天）
   
2. **日常使用：**
   - Dashboard 執行檢測查看異常
   - 點擊異常 IP 進行詳細分析
   - 定期重新訓練模型（每週一次）

3. **性能優化：**
   - 檢測時間範圍不要超過 120 分鐘
   - 訓練天數建議 3-7 天
   - IP 分析時間範圍建議 24-72 小時

---

**祝您使用愉快！** 🎉

如有問題，請查閱相關文檔或聯繫系統管理員。
