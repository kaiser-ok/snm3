# NAD Web UI - Backend

網路異常檢測系統的 Flask 後端服務

## 功能特性

- ✅ 異常檢測 API (即時檢測、結果查詢、統計)
- ✅ 模型訓練 API (配置管理、訓練執行、進度追蹤)
- ✅ IP 分析 API (詳細分析、Top Talkers)
- ✅ SSE 支援 (訓練進度即時串流)
- ✅ CORS 支援 (跨域請求)

## 系統需求

- Python 3.9+
- Elasticsearch 7.17.x
- 存取 `/home/kaisermac/snm_flow/nad` 模組的權限

## 快速開始

### 1. 創建虛擬環境

```bash
cd /home/kaisermac/nad_web_ui/backend
python3 -m venv venv
source venv/bin/activate
```

### 2. 安裝依賴

```bash
pip install -r requirements.txt
```

### 3. 配置環境變數

```bash
# 複製範例配置
cp .env.example .env

# 編輯 .env 文件
nano .env
```

必要的環境變數：

```env
ES_HOST=http://localhost:9200
NAD_BASE_PATH=/home/kaisermac/snm_flow
NAD_CONFIG_PATH=/home/kaisermac/snm_flow/nad/config.yaml
NAD_MODELS_PATH=/home/kaisermac/snm_flow/nad/models
```

### 4. 啟動開發伺服器

```bash
python3 app.py
```

伺服器將在 `http://0.0.0.0:5000` 啟動

### 5. 測試 API

```bash
# 健康檢查
curl http://localhost:5000/api/health

# 獲取模型狀態
curl http://localhost:5000/api/detection/status

# 執行檢測
curl -X POST http://localhost:5000/api/detection/run \
  -H "Content-Type: application/json" \
  -d '{"minutes": 60}'
```

## API 端點

### 檢測 API

| 端點 | 方法 | 說明 |
|------|------|------|
| `/api/detection/status` | GET | 獲取模型狀態 |
| `/api/detection/run` | POST | 執行異常檢測 |
| `/api/detection/results/<job_id>` | GET | 獲取檢測結果 |
| `/api/detection/stats` | GET | 獲取異常統計 |

### 訓練 API

| 端點 | 方法 | 說明 |
|------|------|------|
| `/api/training/config` | GET | 獲取訓練配置 |
| `/api/training/config` | PUT | 更新訓練配置 |
| `/api/training/start` | POST | 開始訓練 |
| `/api/training/status/<job_id>` | GET | 訓練進度 (SSE) |
| `/api/training/history` | GET | 訓練歷史 |

### 分析 API

| 端點 | 方法 | 說明 |
|------|------|------|
| `/api/analysis/ip` | POST | 分析特定 IP |
| `/api/analysis/top-talkers` | GET | Top 流量 IP |

## 專案結構

```
backend/
├── app.py                  # Flask 應用主程式
├── config.py               # 配置管理
├── requirements.txt        # Python 依賴
├── .env.example           # 環境變數範例
├── api/                   # API 端點
│   ├── detection.py       # 檢測 API
│   ├── training.py        # 訓練 API
│   └── analysis.py        # 分析 API
└── services/              # 業務邏輯
    ├── detector_service.py    # 檢測服務
    ├── training_service.py    # 訓練服務
    └── analysis_service.py    # 分析服務
```

## 開發指南

### 添加新 API 端點

1. 在 `api/` 目錄創建新的 Blueprint
2. 在 `services/` 目錄創建對應的服務類
3. 在 `app.py` 中註冊 Blueprint

### 錯誤處理

所有 API 響應使用統一格式：

成功：
```json
{
  "status": "success",
  "data": { ... }
}
```

錯誤：
```json
{
  "status": "error",
  "error": "錯誤訊息"
}
```

### 日誌

日誌文件位於 `../logs/backend.log`

查看日誌：
```bash
tail -f ../logs/backend.log
```

## 生產部署

### 使用 Gunicorn

```bash
gunicorn --bind 0.0.0.0:5000 \
         --workers 4 \
         --timeout 300 \
         --access-logfile ../logs/access.log \
         --error-logfile ../logs/error.log \
         app:app
```

### 使用 Systemd

創建服務文件 `/etc/systemd/system/nad-web-backend.service`:

```ini
[Unit]
Description=NAD Web UI Backend
After=network.target elasticsearch.service

[Service]
Type=notify
User=kaisermac
WorkingDirectory=/home/kaisermac/nad_web_ui/backend
Environment="PATH=/home/kaisermac/nad_web_ui/backend/venv/bin"
ExecStart=/home/kaisermac/nad_web_ui/backend/venv/bin/gunicorn \
    --bind 127.0.0.1:5000 \
    --workers 4 \
    --timeout 300 \
    app:app

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

啟動服務：

```bash
sudo systemctl enable nad-web-backend
sudo systemctl start nad-web-backend
sudo systemctl status nad-web-backend
```

## 疑難排解

### 問題：無法導入 nad 模組

**解決方案：**
- 確認 `NAD_BASE_PATH` 環境變數正確設置
- 確認 `/home/kaisermac/snm_flow/nad` 目錄存在
- 檢查檔案權限

### 問題：Elasticsearch 連線失敗

**解決方案：**
- 檢查 `ES_HOST` 環境變數
- 確認 Elasticsearch 服務正在運行：`systemctl status elasticsearch`
- 測試連線：`curl http://localhost:9200`

### 問題：訓練任務停滯

**解決方案：**
- 檢查後端日誌：`tail -f ../logs/backend.log`
- 確認有足夠的記憶體和磁碟空間
- 減少訓練天數參數

## 安全注意事項

- 🔒 預設配置僅綁定到 `0.0.0.0`，適合內網使用
- 🔒 生產環境請綁定到 `127.0.0.1` 並使用 Nginx 反向代理
- 🔒 不要將 `.env` 文件提交到版本控制
- 🔒 定期更新依賴套件

## 授權

內部專案 - 僅供授權使用者使用
