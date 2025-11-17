# Transform 通訊埠聚合改進報告

## 📋 改進目的

解決 Windows AD 伺服器（192.168.10.135）被誤報為異常的問題。

### 問題分析

**AD 伺服器行為特徵：**
- 源通訊埠：53 (DNS), 389 (LDAP) - 固定服務埠
- 目的通訊埠：49152-65535 - 客戶端隨機埠
- 服務對象：67 個內網客戶端
- 這是**正常的伺服器回應行為**

**舊系統問題：**
- 只追蹤 `unique_ports`（目的通訊埠）
- 無法區分：
  - ❌ 惡意掃描：隨機源埠 → 多個目的埠（很多目標）
  - ✅ 伺服器回應：固定源埠 → 多個目的埠（客戶端隨機埠）

---

## 🔧 改進方案

### 方案 3: 改進 Transform 聚合（已實施）

在 Elasticsearch Transform 中分別聚合源通訊埠和目的通訊埠統計。

---

## ✅ 實施步驟

### Step 1: 停止並刪除舊 Transform

```bash
curl -X POST "http://localhost:9200/_transform/netflow_production/_stop?wait_for_completion=true"
curl -X DELETE "http://localhost:9200/_transform/netflow_production"
```

**狀態：** ✅ 完成

---

### Step 2: 創建改進的 Transform 配置

**新增的聚合欄位：**

```json
"aggregations": {
  "unique_src_ports": {
    "cardinality": {
      "field": "L4_SRC_PORT",
      "precision_threshold": 1000
    }
  },
  "unique_dst_ports": {
    "cardinality": {
      "field": "L4_DST_PORT",
      "precision_threshold": 1000
    }
  }
}
```

**執行：**
```bash
curl -X PUT "http://localhost:9200/_transform/netflow_production" \
  -H 'Content-Type: application/json' \
  -d @/tmp/transform_config_improved.json

curl -X POST "http://localhost:9200/_transform/netflow_production/_start"
```

**狀態：** ✅ 完成

**驗證：**
```bash
curl -s "http://localhost:9200/netflow_stats_5m/_search?size=1&sort=time_bucket:desc" | python3 -m json.tool
```

**結果：**
```json
{
  "src_ip": "1.168.173.126",
  "unique_src_ports": 3.0,      // ✅ 新欄位
  "unique_dst_ports": 1.0,      // ✅ 新欄位
  "flow_count": 10,
  "time_bucket": "2025-11-12T19:35:00.000Z"
}
```

---

### Step 3: 更新 feature_engineer.py

**新增特徵：**

#### 基礎特徵（9 個）
- `unique_src_ports` - 不同源通訊埠數量（新增）
- `unique_dst_ports` - 不同目的通訊埠數量（新增）

#### 衍生特徵（5 個）
- `src_port_diversity` = unique_src_ports / flow_count（新增）
- `dst_port_diversity` = unique_dst_ports / flow_count（新增）

#### 改進的伺服器檢測邏輯

**舊邏輯（有誤）：**
```python
is_likely_server_response = (
    port_diversity > 0.5 and      # 通訊埠分散（但不知道是源還是目的）
    unique_dsts < 5               # ❌ AD 伺服器有 67 個目的地
)
```

**新邏輯（正確）：**
```python
is_likely_server_response = (
    src_port_diversity < 0.1 and      # ✅ 源通訊埠集中（固定服務埠）
    dst_port_diversity > 0.3 and      # ✅ 目的通訊埠分散（客戶端隨機埠）
    unique_src_ports <= 10 and        # ✅ 源通訊埠數量少（DNS=53, LDAP=389）
    flow_count > 100 and              # ✅ 連線數足夠多
    avg_bytes < 50000                 # ✅ 平均流量不大
)
```

**檔案：** `nad/ml/feature_engineer.py`
**狀態：** ✅ 完成

---

### Step 4: 更新 config.yaml

**修改特徵配置：**

```yaml
features:
  basic:
    - unique_src_ports           # 新增
    - unique_dst_ports           # 新增

  derived:
    - src_port_diversity         # 新增
    - dst_port_diversity         # 新增

  binary:
    - is_likely_server_response  # src_port_diversity < 0.1 && dst_port_diversity > 0.3
```

**檔案：** `nad/config.yaml`
**狀態：** ✅ 完成

---

## 📊 當前狀態

### Transform 運行狀況

```bash
# 檢查狀態
curl -s "http://localhost:9200/_transform/netflow_production/_stats" | python3 -m json.tool
```

**結果：**
- ✅ 狀態：started（運行中）
- ✅ 已處理：40,948 筆文檔
- ✅ 已寫入：965 筆聚合記錄
- ⏱️ 待處理：5,772 筆操作

### 新資料覆蓋範圍

```bash
# 查詢有新欄位的記錄數
curl -s "http://localhost:9200/netflow_stats_5m/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"exists":{"field":"unique_src_ports"}}}'
```

**結果：**
- 📊 有新欄位的記錄：1,579 筆
- ⏰ 時間範圍：2025-11-12 19:25 - 19:35（約 10 分鐘）
- 🔄 預計每 5 分鐘新增 ~150-200 筆

### 訓練資料需求

| 項目 | 最少需求 | 建議需求 | 當前狀態 |
|------|---------|---------|---------|
| **記錄數** | 1,000 筆 | 10,000 筆 | 1,579 筆 ✅ |
| **時間跨度** | 1 小時 | 24 小時 | 10 分鐘 ⚠️ |
| **IP 多樣性** | 100 個 | 500+ 個 | 檢查中 |

**建議：** 等待 2-4 小時後再進行訓練，以獲得更穩定的模型。

---

## 🚀 下一步操作

### 選項 1: 立即測試（小範圍驗證）

適用於快速驗證改進是否有效：

```bash
# 使用最近的資料訓練（僅用於測試）
python3 train_isolation_forest.py --hours 1 --evaluate

# 檢測最近 10 分鐘
python3 realtime_detection.py --minutes 10 --exclude-servers

# 驗證 AD 伺服器
python3 verify_anomaly.py --ip 192.168.10.135 --minutes 10
```

**優點：** 快速驗證
**缺點：** 模型不穩定，可能結果不準確

---

### 選項 2: 等待足夠資料（推薦）

等待 Transform 累積足夠的資料：

```bash
# 每小時檢查一次資料量
watch -n 3600 'curl -s "http://localhost:9200/netflow_stats_5m/_count?q=unique_src_ports:*" | python3 -m json.tool'

# 當記錄數 > 10,000 時，進行完整訓練
python3 train_isolation_forest.py --days 1 --evaluate --exclude-servers

# 實時檢測
python3 realtime_detection.py --minutes 30 --exclude-servers

# 驗證 AD 伺服器
python3 verify_anomaly.py --ip 192.168.10.135 --minutes 30
```

**預計等待時間：**
- 1 小時：~1,800-2,400 筆（可以初步測試）
- 4 小時：~7,200-9,600 筆（可以訓練）
- 24 小時：~43,200-57,600 筆（理想狀態）

---

## 📈 監控命令

### 檢查 Transform 進度

```bash
# 1. 檢查 Transform 狀態
curl -s "http://localhost:9200/_transform/netflow_production/_stats" | \
  python3 -c "import sys,json;d=json.load(sys.stdin);s=d['transforms'][0]['stats'];print(f\"已處理: {s['documents_processed']:,} | 已寫入: {s['documents_indexed']:,} | 待處理: {d['transforms'][0]['checkpointing'].get('operations_behind', 0):,}\")"

# 2. 檢查新資料數量
curl -s "http://localhost:9200/netflow_stats_5m/_count?q=unique_src_ports:*" | \
  python3 -c "import sys,json;print(f\"有新欄位的記錄: {json.load(sys.stdin)['count']:,} 筆\")"

# 3. 檢查時間覆蓋範圍
curl -s "http://localhost:9200/netflow_stats_5m/_search" -H 'Content-Type: application/json' -d '
{
  "size":0,
  "query":{"exists":{"field":"unique_src_ports"}},
  "aggs":{
    "min_time":{"min":{"field":"time_bucket"}},
    "max_time":{"max":{"field":"time_bucket"}}
  }
}' | python3 -c "import sys,json;from datetime import datetime;d=json.load(sys.stdin);a=d['aggregations'];print(f\"最早: {datetime.fromtimestamp(a['min_time']['value']/1000)}\");print(f\"最新: {datetime.fromtimestamp(a['max_time']['value']/1000)}\")"
```

### 一鍵監控腳本

創建 `monitor_transform.sh`：

```bash
#!/bin/bash
echo "======================================"
echo "Transform 監控 - $(date)"
echo "======================================"
echo ""

# Transform 狀態
echo "📊 Transform 狀態:"
curl -s "http://localhost:9200/_transform/netflow_production/_stats" | \
  python3 -c "import sys,json;d=json.load(sys.stdin);t=d['transforms'][0];s=t['stats'];c=t['checkpointing'];print(f\"  狀態: {t['state']}\");print(f\"  已處理: {s['documents_processed']:,} 筆\");print(f\"  已寫入: {s['documents_indexed']:,} 筆\");print(f\"  待處理: {c.get('operations_behind', 0):,} 筆\")"
echo ""

# 新資料統計
echo "📈 新資料統計:"
NEW_COUNT=$(curl -s "http://localhost:9200/netflow_stats_5m/_count?q=unique_src_ports:*" | python3 -c "import sys,json;print(json.load(sys.stdin)['count'])")
TOTAL_COUNT=$(curl -s "http://localhost:9200/netflow_stats_5m/_count" | python3 -c "import sys,json;print(json.load(sys.stdin)['count'])")
PERCENTAGE=$(python3 -c "print(f'{($NEW_COUNT/$TOTAL_COUNT*100):.2f}')" 2>/dev/null || echo "0")
echo "  有新欄位: $NEW_COUNT 筆"
echo "  總記錄數: $TOTAL_COUNT 筆"
echo "  覆蓋率: ${PERCENTAGE}%"
echo ""

# 時間範圍
echo "⏰ 時間範圍:"
curl -s "http://localhost:9200/netflow_stats_5m/_search" -H 'Content-Type: application/json' -d '{"size":0,"query":{"exists":{"field":"unique_src_ports"}},"aggs":{"min_time":{"min":{"field":"time_bucket"}},"max_time":{"max":{"field":"time_bucket"}}}}' | \
  python3 -c "import sys,json;from datetime import datetime;d=json.load(sys.stdin);a=d['aggregations'];print(f\"  最早: {datetime.fromtimestamp(a['min_time']['value']/1000)}\");print(f\"  最新: {datetime.fromtimestamp(a['max_time']['value']/1000)}\")"
echo ""

# 建議
if [ $NEW_COUNT -lt 1000 ]; then
  echo "💡 建議: 資料量不足，建議等待"
elif [ $NEW_COUNT -lt 10000 ]; then
  echo "💡 建議: 可以進行初步測試（python3 train_isolation_forest.py --hours 1）"
else
  echo "💡 建議: 資料充足，可以進行完整訓練（python3 train_isolation_forest.py --days 1）"
fi
echo ""
```

使用：
```bash
chmod +x monitor_transform.sh
./monitor_transform.sh

# 或每 10 分鐘自動監控
watch -n 600 ./monitor_transform.sh
```

---

## 🎯 預期改進效果

### AD 伺服器 (192.168.10.135) 檢測結果

**改進前：**
```
🚨 異常檢測結果:
  - unique_ports: 6119（高）
  - port_diversity: 0.89（高）
  - 判斷: 通訊埠掃描 ❌ 誤報
```

**改進後（預期）：**
```
✅ 正常服務檢測結果:
  - unique_src_ports: 2（DNS=53, LDAP=389）
  - unique_dst_ports: 6119（客戶端隨機埠）
  - src_port_diversity: 0.0003（低 ✅）
  - dst_port_diversity: 0.89（高 ✅）
  - is_likely_server_response: 1 ✅
  - 判斷: 伺服器回應流量（正常）
```

### 其他改進

1. **DNS 伺服器（如 8.8.8.8）**
   - 源埠：53
   - 目的埠：隨機
   - 結果：正確識別為伺服器回應 ✅

2. **Web 伺服器**
   - 源埠：80, 443
   - 目的埠：隨機
   - 結果：正確識別為伺服器回應 ✅

3. **真實掃描行為**
   - 源埠：隨機
   - 目的埠：多個（22, 80, 443, 3389...）
   - 結果：仍然正確識別為掃描 ✅

---

## 📚 相關文檔

- `TERMINOLOGY.md` - 術語對照表
- `ISOLATION_FOREST_GUIDE.md` - Isolation Forest 使用指南
- `ANOMALY_VERIFICATION_GUIDE.md` - 異常驗證指南
- `nad/config.yaml` - 系統配置
- `nad/ml/feature_engineer.py` - 特徵工程

---

## 🔄 回滾方案

如果改進後效果不佳，可以回滾：

```bash
# 1. 停止新 Transform
curl -X POST "http://localhost:9200/_transform/netflow_production/_stop"
curl -X DELETE "http://localhost:9200/_transform/netflow_production"

# 2. 恢復舊配置
curl -X PUT "http://localhost:9200/_transform/netflow_production" \
  -H 'Content-Type: application/json' \
  -d @/tmp/transform_config.json  # 舊配置備份

curl -X POST "http://localhost:9200/_transform/netflow_production/_start"

# 3. 恢復 feature_engineer.py（使用 git 或手動）
git checkout nad/ml/feature_engineer.py

# 4. 恢復 config.yaml
git checkout nad/config.yaml

# 5. 重新訓練舊模型
python3 train_isolation_forest.py --days 7
```

---

**實施日期：** 2025-11-12
**實施人員：** Claude Code
**狀態：** ✅ Transform 已啟動，等待資料累積
**下次檢查：** 2 小時後（或執行 `./monitor_transform.sh` 檢查）
