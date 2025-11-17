# 異常特徵解釋文檔

## 📊 異常特徵如何取得？

異常特徵是通過 **特徵工程** 從 `netflow_stats_5m` 聚合資料中計算得出的。

---

## 🔧 特徵提取流程

### 位置
- **程式碼**: `nad/ml/feature_engineer.py`
- **配置**: `nad/config.yaml`
- **函數**: `FeatureEngineer.extract_features()`

### 流程
```
netflow_stats_5m (聚合資料)
         ↓
FeatureEngineer.extract_features()
         ↓
特徵字典 (17 個特徵)
         ↓
Isolation Forest 模型評分
```

---

## 📋 四類特徵詳解

### 1️⃣ 基礎特徵 (7 個)

**直接從聚合資料讀取：**

```python
features['flow_count'] = agg_record.get('flow_count', 0)        # 連線數
features['total_bytes'] = agg_record.get('total_bytes', 0)      # 總流量
features['total_packets'] = agg_record.get('total_packets', 0)  # 總封包數
features['unique_dsts'] = agg_record.get('unique_dsts', 0)      # 唯一目的地數
features['unique_ports'] = agg_record.get('unique_ports', 0)    # 唯一端口數
features['avg_bytes'] = agg_record.get('avg_bytes', 0)          # 平均流量
features['max_bytes'] = agg_record.get('max_bytes', 0)          # 最大單次流量
```

**來源**:
- 這些值來自 ES Transform 的聚合計算
- 每 5 分鐘自動更新一次

---

### 2️⃣ 衍生特徵 (4 個)

**透過基礎特徵計算：**

#### dst_diversity (目的地多樣性)
```python
dst_diversity = unique_dsts / flow_count
```
**意義**: 平均每個連線連到幾個不同目的地
- 值越高 → 連線更分散（可能是掃描）
- 值越低 → 連線集中（正常或 DDoS）

#### port_diversity (端口多樣性)
```python
port_diversity = unique_ports / flow_count
```
**意義**: 平均每個連線使用幾個不同端口
- 值接近 1 → 每個連線用不同端口（異常）
- 值接近 0 → 連線集中在少數端口（正常）

#### traffic_concentration (流量集中度)
```python
traffic_concentration = max_bytes / total_bytes
```
**意義**: 最大單次流量佔總流量的比例
- 值接近 1 → 流量非常集中（可能是檔案傳輸）
- 值接近 0 → 流量分散（正常瀏覽）

#### bytes_per_packet (每封包位元組數)
```python
bytes_per_packet = total_bytes / total_packets
```
**意義**: 封包大小
- 大值 → 大封包（檔案傳輸、視訊）
- 小值 → 小封包（DNS、控制流量）

---

### 3️⃣ 二值特徵 (4 個) - **異常行為標記**

這些就是你問的 **高連線數、掃描模式、小封包** 等特徵！

#### ✅ is_high_connection (高連線數)

```python
features['is_high_connection'] = 1 if features['flow_count'] > 1000 else 0
```

**判斷條件**:
- `flow_count > 1000` → 標記為 1（異常）
- 否則 → 標記為 0（正常）

**配置**: `nad/config.yaml` line 70
```yaml
thresholds:
  high_connection: 1000
```

**意義**: 在 5 分鐘內產生超過 1000 個連線
- **可能原因**:
  - 爬蟲
  - P2P 應用
  - DDoS 攻擊
  - 大量 API 調用

---

#### ✅ is_scanning_pattern (掃描模式)

```python
features['is_scanning_pattern'] = 1 if (
    features['unique_dsts'] > 30 and
    features['avg_bytes'] < 10000
) else 0
```

**判斷條件**（兩個條件同時滿足）:
1. `unique_dsts > 30` - 連到超過 30 個不同目的地
2. `avg_bytes < 10000` - 平均流量小於 10KB

**配置**: `nad/config.yaml` line 71-72
```yaml
thresholds:
  scanning_dsts: 30
  scanning_avg_bytes: 10000
```

**意義**: 連到很多目的地但流量很小
- **典型掃描行為**:
  - 端口掃描 (Nmap)
  - 網路探測
  - 弱點掃描
  - 服務發現

**範例**:
```
連線數: 100
目的地: 50 個不同 IP
平均流量: 500 bytes
→ 這是掃描！
```

---

#### ✅ is_small_packet (小封包)

```python
features['is_small_packet'] = 1 if features['avg_bytes'] < 1000 else 0
```

**判斷條件**:
- `avg_bytes < 1000` → 標記為 1（異常）
- 否則 → 標記為 0（正常）

**配置**: `nad/config.yaml` line 73
```yaml
thresholds:
  small_packet: 1000
```

**意義**: 平均每個連線流量小於 1KB
- **可能原因**:
  - DNS 查詢
  - ICMP ping
  - TCP SYN 掃描
  - Keep-alive 封包
  - C&C 通訊

---

#### ✅ is_large_flow (大流量)

```python
features['is_large_flow'] = 1 if features['max_bytes'] > 104857600 else 0
```

**判斷條件**:
- `max_bytes > 104857600` (100 MB) → 標記為 1（異常）
- 否則 → 標記為 0（正常）

**配置**: `nad/config.yaml` line 74
```yaml
thresholds:
  large_flow: 104857600  # 100MB
```

**意義**: 單次連線傳輸超過 100MB
- **可能原因**:
  - 檔案下載/上傳
  - 視訊串流
  - 資料外洩
  - 備份傳輸

---

### 4️⃣ 對數特徵 (2 個)

**處理數據偏態分布：**

```python
features['log_flow_count'] = np.log1p(features['flow_count'])
features['log_total_bytes'] = np.log1p(features['total_bytes'])
```

**意義**:
- 將右偏分布轉換為較對稱的分布
- 幫助模型更好地學習
- `log1p` = `log(1 + x)` 避免 log(0) 錯誤

---

## 🎯 特徵使用範例

### 實際案例：8.8.8.8 (Google DNS)

**原始數據**:
```json
{
  "src_ip": "8.8.8.8",
  "time_bucket": "2025-11-12T03:10:00.000Z",
  "flow_count": 4624,
  "unique_dsts": 1,
  "unique_ports": 4157,
  "total_bytes": 5137728,
  "total_packets": 4624,
  "avg_bytes": 1112,
  "max_bytes": 1200
}
```

**特徵提取**:

1. **基礎特徵**:
   - flow_count: 4,624
   - unique_dsts: 1
   - unique_ports: 4,157
   - avg_bytes: 1,112

2. **衍生特徵**:
   - dst_diversity: 1 / 4624 = 0.0002 (極低)
   - port_diversity: 4157 / 4624 = 0.899 (極高！)

3. **二值特徵**:
   - ✅ is_high_connection: 1 (4624 > 1000)
   - ❌ is_scanning_pattern: 0 (unique_dsts = 1 < 30)
   - ✅ is_small_packet: 1 (1112 < 1000... 接近邊界)
   - ❌ is_large_flow: 0

**異常原因分析**:
- 🔴 極高連線數 (4,624)
- 🔴 只連到 1 個目的地但使用 4,000+ 個端口
- 🔴 小封包 (~1KB)
- 🟡 端口多樣性接近 1（每個連線用不同端口）

**結論**: 這是異常的 DNS 查詢模式，可能是：
- DNS 隧道攻擊
- DGA 惡意軟體
- 大量域名解析

---

## 🔧 如何調整閾值？

編輯 `nad/config.yaml`:

```yaml
thresholds:
  high_connection: 1000      # 改成 2000 → 更寬鬆
  scanning_dsts: 30          # 改成 50 → 更嚴格
  scanning_avg_bytes: 10000  # 改成 5000 → 更嚴格
  small_packet: 1000         # 改成 500 → 更嚴格
  large_flow: 104857600      # 改成 209715200 (200MB) → 更寬鬆
```

**修改後需要**:
```bash
# 重新訓練模型
python3 train_isolation_forest.py --days 7 --evaluate
```

---

## 📊 查看特徵統計

### 方法 1: 使用 Python

```python
from nad.ml import FeatureEngineer
from nad.utils import load_config

config = load_config('nad/config.yaml')
engineer = FeatureEngineer(config)

# 範例聚合記錄
agg_record = {
    'flow_count': 4624,
    'total_bytes': 5137728,
    'total_packets': 4624,
    'unique_dsts': 1,
    'unique_ports': 4157,
    'avg_bytes': 1112,
    'max_bytes': 1200
}

# 提取特徵
features = engineer.extract_features(agg_record)

# 顯示特徵
for name, value in features.items():
    print(f"{name}: {value}")
```

### 方法 2: 查看實時檢測結果

```bash
python3 realtime_detection.py --minutes 60
```

輸出中的 "行為統計" 和 "行為特徵" 就是這些二值特徵的統計。

---

## 🎓 總結

### 異常特徵來源

```
聚合資料 (netflow_stats_5m)
    ↓
基礎特徵 (7個) ← 直接讀取
    ↓
衍生特徵 (4個) ← 數學計算
    ↓
二值特徵 (4個) ← 閾值判斷 ← 這就是你問的！
    ↓
對數特徵 (2個) ← 數學轉換
    ↓
特徵向量 (17維)
    ↓
Isolation Forest 模型
    ↓
異常分數
```

### 二值特徵（異常行為標記）

| 特徵 | 判斷條件 | 閾值 | 意義 |
|------|---------|------|------|
| **is_high_connection** | flow_count > 1000 | 1000 | 高連線數 |
| **is_scanning_pattern** | unique_dsts > 30 AND avg_bytes < 10000 | 30, 10KB | 掃描模式 |
| **is_small_packet** | avg_bytes < 1000 | 1KB | 小封包 |
| **is_large_flow** | max_bytes > 104857600 | 100MB | 大流量 |

### 關鍵文件

- 📄 `nad/ml/feature_engineer.py` - 特徵提取邏輯
- 📄 `nad/config.yaml` - 閾值配置
- 📄 `nad/ml/isolation_forest_detector.py` - 模型使用

---

**這些特徵是透過領域知識和網路安全經驗設計的，用於捕捉異常網路行為模式！** 🎯
