# NAD Web UI 服務管理

## 系統服務狀態

所有服務已配置為開機自動啟動，由 systemd 管理。

### 1. Backend API 服務

**服務名稱：** `nad-web-backend.service`

**管理命令：**
```bash
# 查看狀態
sudo systemctl status nad-web-backend.service

# 啟動服務
sudo systemctl start nad-web-backend.service

# 停止服務
sudo systemctl stop nad-web-backend.service

# 重啟服務
sudo systemctl restart nad-web-backend.service

# 查看日誌
sudo journalctl -u nad-web-backend.service -f
```

**服務信息：**
- 端口：5000
- 工作目錄：`/home/kaisermac/snm_flow/nad_web_ui/backend`
- 日誌文件：`/home/kaisermac/snm_flow/nad_web_ui/backend/backend.log`
- 自動重啟：是（失敗後 10 秒重啟）

---

### 2. Frontend 服務

**服務名稱：** `nad-web-frontend.service`

**管理命令：**
```bash
# 查看狀態
sudo systemctl status nad-web-frontend.service

# 啟動服務
sudo systemctl start nad-web-frontend.service

# 停止服務
sudo systemctl stop nad-web-frontend.service

# 重啟服務
sudo systemctl restart nad-web-frontend.service

# 查看日誌
sudo journalctl -u nad-web-frontend.service -f
```

**服務信息：**
- 端口：5173
- 工作目錄：`/home/kaisermac/snm_flow/nad_web_ui/frontend`
- 日誌文件：`/home/kaisermac/snm_flow/nad_web_ui/frontend/frontend.log`
- 自動重啟：是（失敗後 10 秒重啟）

---

### 3. Realtime Anomaly Detection 服務

**服務名稱：** `nad-realtime-detection.service`

**管理命令：**
```bash
# 查看狀態
sudo systemctl status nad-realtime-detection.service

# 啟動服務
sudo systemctl start nad-realtime-detection.service

# 停止服務
sudo systemctl stop nad-realtime-detection.service

# 重啟服務
sudo systemctl restart nad-realtime-detection.service

# 查看日誌
sudo journalctl -u nad-realtime-detection.service -f
# 或直接查看日誌文件
tail -f /home/kaisermac/snm_flow/detection.log
```

**服務信息：**
- 工作目錄：`/home/kaisermac/snm_flow`
- 日誌文件：`/home/kaisermac/snm_flow/detection.log`
- 檢測間隔：600 秒（10 分鐘）
- 分析範圍：最近 10 分鐘
- 自動重啟：是（失敗後 30 秒重啟）

---

## 一鍵管理所有服務

### 啟動所有服務
```bash
sudo systemctl start nad-web-backend.service nad-web-frontend.service nad-realtime-detection.service
```

### 停止所有服務
```bash
sudo systemctl stop nad-web-backend.service nad-web-frontend.service nad-realtime-detection.service
```

### 重啟所有服務
```bash
sudo systemctl restart nad-web-backend.service nad-web-frontend.service nad-realtime-detection.service
```

### 查看所有服務狀態
```bash
sudo systemctl status nad-web-backend.service nad-web-frontend.service nad-realtime-detection.service
```

---

## 開機自動啟動

所有服務已設置為開機自動啟動。

**查看自啟動狀態：**
```bash
systemctl is-enabled nad-web-backend.service
systemctl is-enabled nad-web-frontend.service
systemctl is-enabled nad-realtime-detection.service
```

**禁用自啟動（如需要）：**
```bash
sudo systemctl disable nad-web-backend.service
sudo systemctl disable nad-web-frontend.service
sudo systemctl disable nad-realtime-detection.service
```

**重新啟用自啟動：**
```bash
sudo systemctl enable nad-web-backend.service
sudo systemctl enable nad-web-frontend.service
sudo systemctl enable nad-realtime-detection.service
```

---

## 服務配置文件位置

- `/etc/systemd/system/nad-web-backend.service`
- `/etc/systemd/system/nad-web-frontend.service`
- `/etc/systemd/system/nad-realtime-detection.service`

**修改配置後需要重新載入：**
```bash
sudo systemctl daemon-reload
sudo systemctl restart <service-name>
```

---

## 常見問題排查

### 服務無法啟動

1. 查看詳細錯誤日誌：
```bash
sudo journalctl -u <service-name> -n 50
```

2. 檢查服務配置：
```bash
sudo systemctl cat <service-name>
```

3. 檢查進程是否佔用端口：
```bash
ss -tlnp | grep -E ":5000|:5173"
```

### 服務運行但無法訪問

1. 檢查防火牆設置
2. 確認 Elasticsearch 服務運行正常：`sudo systemctl status elasticsearch`
3. 查看應用日誌文件

---

## 訪問地址

- **Backend API:** http://192.168.10.25:5000
- **Frontend UI:** http://192.168.10.25:5173

## 健康檢查

```bash
# Backend 健康檢查
curl http://localhost:5000/api/health

# Frontend 健康檢查
curl -I http://localhost:5173
```
