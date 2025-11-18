# 設備映射配置功能說明

## 功能概述

設備映射配置功能允許管理員透過 Web UI 管理網路設備的 IP 分類，系統會根據配置將不同的 IP 網段分類為不同的設備類型（服務器群、工作站、IoT 設備、外部設備）。

## 功能特點

### 1. **設備類型管理**

系統支援四種設備類型：

- **🏭 服務器群 (server_farm)**
  - 提供各種服務的伺服器
  - 特徵：高入站流量、多並發連線、提供服務端口

- **💻 工作站 (station)**
  - 工作站、PC、筆電、iPad 等終端設備
  - 特徵：主動發起連線、低到中等流量、訪問外部服務

- **🛠️ 物聯網設備 (iot)**
  - IoT 設備、傳感器、攝像頭等
  - 特徵：周期性通信、小流量、特定協議

- **🌐 外部設備 (external)**
  - 外部 IP 或未分類的內部 IP
  - 特徵：預設分類、需要人工審查

### 2. **IP 網段管理**

每個設備類型可以配置多個 IP 網段（CIDR 格式）：

- **新增網段**：輸入 CIDR 格式的 IP 網段（例如：192.168.1.0/24）
- **刪除網段**：點擊標籤上的 ✕ 即可移除
- **自動驗證**：系統會驗證 IP 網段格式的正確性

### 3. **設備類型編輯**

可以編輯每個設備類型的：

- **說明**：設備類型的描述文字
- **特徵**：設備的行為特徵（可新增/刪除）

### 4. **特殊設備標記**

針對特定 IP 進行標記，例如：

- **DNS 伺服器**：8.8.8.8、168.95.1.1
- **關鍵伺服器**：重要的生產伺服器 IP
- 可自訂分類名稱和對應的 IP 列表

## 使用方式

### 訪問設備映射頁面

1. 啟動服務後，訪問 http://localhost:5173
2. 點擊左側導航欄的「設備映射配置」

### 管理 IP 網段

#### 新增 IP 網段

1. 在對應設備類型的卡片中找到「新增網段」輸入框
2. 輸入 CIDR 格式的 IP 網段（例如：192.168.100.0/24）
3. 點擊「新增網段」按鈕或按 Enter 鍵

#### 刪除 IP 網段

1. 找到要刪除的網段標籤
2. 點擊標籤上的 ✕ 圖示
3. 確認刪除操作

### 編輯設備類型

1. 點擊設備類型卡片右上角的「編輯」按鈕
2. 修改說明或特徵
3. 點擊「保存」按鈕

### 管理特殊設備

#### 新增特殊設備

1. 在「特殊設備標記」區塊點擊「新增特殊設備」
2. 輸入分類名稱（例如：dns_servers）
3. 選擇設備類型
4. 輸入 IP 地址列表（每行一個）
5. 點擊「保存」

#### 編輯特殊設備

1. 在特殊設備表格中找到要編輯的項目
2. 點擊「編輯」按鈕
3. 修改配置後點擊「保存」

## 後端 API

### 端點列表

| 方法 | 路徑 | 說明 |
|------|------|------|
| GET | `/api/device-mapping` | 獲取設備映射配置 |
| PUT | `/api/device-mapping/<device_type>` | 更新設備類型配置 |
| POST | `/api/device-mapping/<device_type>/ip-ranges` | 添加 IP 網段 |
| DELETE | `/api/device-mapping/<device_type>/ip-ranges` | 刪除 IP 網段 |
| PUT | `/api/device-mapping/special/<category>` | 更新特殊設備 |

### 範例請求

#### 獲取配置

```bash
curl http://localhost:5000/api/device-mapping
```

#### 添加 IP 網段

```bash
curl -X POST http://localhost:5000/api/device-mapping/station/ip-ranges \
  -H "Content-Type: application/json" \
  -d '{"ip_range": "192.168.100.0/24"}'
```

#### 更新設備類型

```bash
curl -X PUT http://localhost:5000/api/device-mapping/station \
  -H "Content-Type: application/json" \
  -d '{
    "description": "工作站設備（更新）",
    "characteristics": ["主動連線", "中等流量"]
  }'
```

#### 更新特殊設備

```bash
curl -X PUT http://localhost:5000/api/device-mapping/special/dns_servers \
  -H "Content-Type: application/json" \
  -d '{
    "device_type": "external",
    "ips": ["8.8.8.8", "1.1.1.1"]
  }'
```

## 配置檔案

設備映射配置儲存在：
```
/home/kaisermac/snm_flow/nad/device_mapping.yaml
```

### 配置檔案結構

```yaml
device_types:
  server_farm:
    description: "服務器群，提供各種服務"
    ip_ranges:
      - 192.168.10.0/24
      - 192.168.20.0/24
    characteristics:
      - 高入站流量
      - 多並發連線

  station:
    description: "工作站、PC、筆電"
    ip_ranges:
      - 192.168.50.0/24
    characteristics:
      - 主動發起連線

special_devices:
  dns_servers:
    device_type: external
    ips:
      - 8.8.8.8
      - 168.95.1.1
```

## 自動備份

每次修改配置時，系統會自動創建備份檔案：
```
device_mapping.yaml.backup.YYYYMMDD_HHMMSS
```

## 測試

運行測試腳本以驗證 API 功能：

```bash
cd /home/kaisermac/nad_web_ui/backend
./test_device_mapping_api.sh
```

## 注意事項

1. **IP 網段格式**：必須使用 CIDR 格式（例如：192.168.1.0/24）
2. **網段重複**：系統會檢查同一設備類型中是否已存在相同網段
3. **自動備份**：每次修改都會自動備份原配置檔案
4. **權限要求**：需要對配置檔案有寫入權限

## 整合說明

設備映射配置會被 NAD 異常檢測系統使用：

1. **設備分類**：在異常檢測結果中顯示設備類型圖示
2. **分析優化**：根據設備類型調整異常檢測策略
3. **報告生成**：在報告中按設備類型分組顯示異常

## 故障排除

### 問題：無法載入配置

**原因**：配置檔案路徑錯誤或權限不足

**解決方案**：
```bash
# 檢查檔案是否存在
ls -l /home/kaisermac/snm_flow/nad/device_mapping.yaml

# 檢查權限
chmod 644 /home/kaisermac/snm_flow/nad/device_mapping.yaml
```

### 問題：無法保存配置

**原因**：寫入權限不足

**解決方案**：
```bash
# 確保目錄有寫入權限
chmod 755 /home/kaisermac/snm_flow/nad
```

### 問題：IP 網段格式錯誤

**原因**：輸入的不是有效的 CIDR 格式

**解決方案**：確保格式為 `X.X.X.X/XX`，例如：
- ✅ 正確：192.168.1.0/24
- ❌ 錯誤：192.168.1.0
- ❌ 錯誤：192.168.1.0/24/25

## 未來增強計劃

- [ ] IP 地址範圍驗證（檢查是否重疊）
- [ ] 批量匯入 IP 網段（CSV 檔案上傳）
- [ ] 設備映射視覺化圖表
- [ ] IP 地址查詢工具（檢查某個 IP 屬於哪個設備類型）
- [ ] 配置版本控制和回滾功能
