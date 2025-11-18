# 訓練頁面 500 錯誤問題解決

## 問題描述

訓練頁面出現以下錯誤：
```
GET /api/training/config 500 (Internal Server Error)
GET /api/detection/status 500 (Internal Server Error)
```

前端控制台顯示：
```
API Request: GET /training/config
GET http://192.168.10.25:5173/api/training/config 500 (Internal Server Error)
```

## 根本原因

**後端服務未運行**

前端開發伺服器（Vite）會將 `/api/*` 請求代理到 `http://localhost:5000`，但如果後端服務沒有運行，代理會失敗並返回 500 錯誤。

## 解決方法

### 1. 啟動後端服務

```bash
cd /home/kaisermac/nad_web_ui/backend
python3 app.py
```

後端服務會在 `http://localhost:5000` 上運行。

### 2. 驗證後端運行狀態

```bash
# 檢查進程
ps aux | grep "python.*app.py"

# 測試健康檢查
curl http://localhost:5000/api/health
```

預期輸出：
```json
{
  "service": "NAD Web UI Backend",
  "status": "healthy",
  "version": "1.0.0"
}
```

### 3. 重新刷新前端頁面

後端運行後，刷新瀏覽器頁面，訓練頁面應該能正常載入。

## 完整開發流程

### 啟動開發環境

**終端 1 - 後端：**
```bash
cd /home/kaisermac/nad_web_ui/backend
python3 app.py
```

**終端 2 - 前端：**
```bash
cd /home/kaisermac/nad_web_ui/frontend
npm run dev
```

然後訪問：`http://localhost:5173`

## 生產部署

生產環境中，使用 Gunicorn 運行後端：

```bash
cd /home/kaisermac/nad_web_ui/backend
gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 300 app:app
```

或使用 systemd 服務：

```bash
sudo systemctl start nad-web-backend
sudo systemctl status nad-web-backend
```

## 常見錯誤排查

### 1. 後端無法啟動

**檢查依賴：**
```bash
cd backend
pip install -r requirements.txt
```

**檢查環境變數：**
```bash
# 確認 .env 文件存在
ls -la backend/.env

# 檢查關鍵配置
cat backend/.env | grep -E "ES_HOST|NAD_BASE_PATH"
```

### 2. Elasticsearch 連接失敗

```bash
# 檢查 ES 服務狀態
sudo systemctl status elasticsearch

# 測試 ES 連接
curl http://localhost:9200
```

### 3. NAD 模組路徑問題

確認 NAD 模組路徑正確：
```bash
ls -la /home/kaisermac/snm_flow/nad
```

應該看到：
- `ml/` 目錄
- `device_classifier.py`
- `config.yaml`

## 錯誤訊息解讀

| 錯誤 | 原因 | 解決 |
|------|------|------|
| `500 Internal Server Error` | 後端未運行或崩潰 | 啟動後端服務 |
| `Connection refused` | 後端連接被拒絕 | 檢查後端端口是否正確 |
| `CORS error` | 跨域請求被阻擋 | 檢查後端 CORS 設定 |
| `404 Not Found` | API 路由不存在 | 檢查 API 路徑是否正確 |

## 正常運行的指標

### 後端

```bash
# 健康檢查
$ curl http://localhost:5000/api/health
{"service":"NAD Web UI Backend","status":"healthy","version":"1.0.0"}

# 檢測狀態
$ curl http://localhost:5000/api/detection/status
{"status":"success",...}

# 訓練配置
$ curl http://localhost:5000/api/training/config
{"status":"success",...}
```

### 前端

瀏覽器控制台應該看到：
```
API Request: GET /detection/status
API Request: GET /training/config
```

無 500 錯誤。

## 預防措施

### 1. 使用啟動腳本

創建 `start-dev.sh`：
```bash
#!/bin/bash
# 啟動開發環境

# 啟動後端
cd /home/kaisermac/nad_web_ui/backend
python3 app.py &
BACKEND_PID=$!

# 等待後端啟動
sleep 3

# 啟動前端
cd /home/kaisermac/nad_web_ui/frontend
npm run dev

# Ctrl+C 時清理
trap "kill $BACKEND_PID" EXIT
```

### 2. 健康檢查腳本

創建 `check-services.sh`：
```bash
#!/bin/bash

echo "檢查後端服務..."
if curl -s http://localhost:5000/api/health > /dev/null; then
    echo "✓ 後端正常運行"
else
    echo "✗ 後端未運行"
    exit 1
fi

echo "檢查 Elasticsearch..."
if curl -s http://localhost:9200 > /dev/null; then
    echo "✓ Elasticsearch 正常運行"
else
    echo "✗ Elasticsearch 未運行"
    exit 1
fi

echo "所有服務正常！"
```

## 總結

訓練頁面的 500 錯誤是因為後端服務未運行。啟動後端服務後問題即解決。

**快速修復：**
```bash
cd /home/kaisermac/nad_web_ui/backend && python3 app.py
```

然後刷新瀏覽器頁面。
