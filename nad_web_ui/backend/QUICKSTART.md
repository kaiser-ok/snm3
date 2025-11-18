# 快速啟動指南

## ✅ 問題已解決

您遇到的 `ModuleNotFoundError: No module named 'flask'` 問題已修復！

## 🚀 如何啟動後端

### 方法 1：直接啟動（推薦）

由於系統已安裝所需的 Python 套件，可以直接運行：

```bash
cd /home/kaisermac/nad_web_ui/backend
python3 app.py
```

後端將在 `http://localhost:5000` 啟動

### 方法 2：使用不同埠號

如果 5000 埠被占用：

```bash
export BACKEND_PORT=5001
python3 app.py
```

### 方法 3：背景執行

```bash
nohup python3 app.py > /tmp/backend.log 2>&1 &

# 查看日誌
tail -f /tmp/backend.log

# 停止
pkill -f "python3 app.py"
```

## ✅ 測試 API

```bash
# 健康檢查
curl http://localhost:5000/api/health

# 模型狀態
curl http://localhost:5000/api/detection/status

# 訓練配置
curl http://localhost:5000/api/training/config
```

## 📦 已安裝的套件

系統已安裝：
- ✅ Flask 3.1.2
- ✅ Flask-CORS 6.0.1
- ✅ elasticsearch 7.17.6
- ✅ numpy 1.26.4
- ✅ PyYAML
- ✅ python-dotenv
- ✅ scikit-learn (系統已有)

## 🔧 故障排除

### 埠號被占用

錯誤：`Address already in use`

解決方案：
```bash
# 查看占用程序
lsof -i :5000

# 或使用不同埠號
export BACKEND_PORT=5001
python3 app.py
```

### NAD 模組導入失敗

確保環境變數正確：
```bash
# 檢查 .env 文件
cat .env

# 應包含：
# NAD_BASE_PATH=/home/kaisermac/snm_flow
# NAD_CONFIG_PATH=/home/kaisermac/snm_flow/nad/config.yaml
```

### Elasticsearch 連線失敗

```bash
# 檢查 ES 服務
systemctl status elasticsearch

# 測試連線
curl http://localhost:9200
```

## 📊 可用的 API 端點

| 端點 | 方法 | 說明 |
|------|------|------|
| `/api/health` | GET | 健康檢查 |
| `/api/detection/status` | GET | 模型狀態 |
| `/api/detection/run` | POST | 執行檢測 |
| `/api/detection/results/<job_id>` | GET | 獲取結果 |
| `/api/training/config` | GET | 訓練配置 |
| `/api/training/start` | POST | 開始訓練 |
| `/api/analysis/ip` | POST | IP 分析 |

## 下一步

後端已就緒！現在可以：

1. 測試 API 端點
2. 開始開發前端 Vue.js 應用
3. 整合前後端

詳細文檔請參閱 `README.md`
