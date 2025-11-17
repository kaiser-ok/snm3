# 專案結構深入分析：Isolation Forest 異常檢測系統

## 目錄
1. [項目概述](#項目概述)
2. [核心模組架構](#核心模組架構)
3. [Isolation Forest 實作位置](#isolation-forest-實作位置)
4. [Classify 功能實作](#classify-功能實作)
5. [特徵值完整流程](#特徵值完整流程)
6. [資料流程圖](#資料流程圖)
7. [文件路徑速查表](#文件路徑速查表)

---

## 項目概述

### 系統目標
基於 Elasticsearch 中的聚合網路流量數據 (netflow_stats_5m)，使用 Isolation Forest 進行無監督異常檢測，並通過規則型分類器判斷異常類型。

### 核心特性
- **數據來源**: netflow_stats_5m（5分鐘聚合索引）
- **檢測方式**: Isolation Forest（無監督ML）
- **分類方式**: 規則型分類器（基於特徵閾值）
- **特徵數量**: 18個特徵向量
- **模型覆蓋率**: 99.57%
- **實時性**: < 5秒推論延遲

---

## 核心模組架構

```
snm_flow/
│
├── nad/                                    # 核心異常檢測模組
│   │
│   ├── config.yaml                         # 全局配置文件
│   ├── device_mapping.yaml                 # 設備類型映射
│   │
│   ├── ml/                                 # 機器學習模組
│   │   ├── __init__.py                     # 模組入口
│   │   ├── feature_engineer.py             # 特徵工程器 ⭐ 特徵提取
│   │   ├── isolation_forest_detector.py    # IF檢測器 ⭐ 異常檢測
│   │   └── anomaly_classifier.py           # 異常分類器 ⭐ 威脅分類
│   │
│   ├── utils/
│   │   ├── __init__.py
│   │   └── config_loader.py                # 配置加載工具
│   │
│   ├── device_classifier.py                # 設備類型分類
│   ├── anomaly_logger.py                   # 異常日誌記錄
│   │
│   └── models/                             # 訓練模型存儲目錄
│       ├── isolation_forest.pkl            # IF模型（pickle）
│       └── scaler.pkl                      # 特徵標準化器
│
├── train_isolation_forest.py               # 訓練腳本入口
├── realtime_detection.py                   # 實時檢測腳本入口
├── verify_anomaly.py                       # 異常驗證工具
└── optimize_classifier_thresholds.py       # 分類器優化工具
```

---

## Isolation Forest 實作位置

### 文件: `/home/kaisermac/snm_flow/nad/ml/isolation_forest_detector.py`

#### 核心類: `OptimizedIsolationForest`

**主要方法:**

##### 1. 訓練方法
```python
def train_on_aggregated_data(self, days: int = 7, exclude_servers: bool = False)
```
- 從 Elasticsearch 獲取過去 N 天的聚合數據
- 調用 FeatureEngineer 提取特徵
- 使用 StandardScaler 標準化特徵
- 訓練 scikit-learn 的 IsolationForest 模型
- 保存模型和 scaler 到 pkl 文件

**實作位置**: 第 70-155 行

**關鍵步驟**:
1. `_fetch_training_data()` - 從ES獲取數據（第157-199行）
2. `extract_features_batch()` - 特徵提取（使用FeatureEngineer）
3. `scaler.fit_transform()` - 特徵標準化
4. `IsolationForest(**config).fit()` - 模型訓練
5. `_save_model()` - 模型序列化（第340-348行）

##### 2. 預測方法
```python
def predict_realtime(self, recent_minutes: int = 10) -> List[Dict]
def predict_batch(self, records: List[Dict]) -> List[Dict]
```
- 加載已訓練的模型
- 對新數據進行特徵提取和標準化
- 生成異常預測和分數
- 轉換為置信度（Sigmoid映射）

**實作位置**:
- `predict_realtime()`: 第201-248行
- `predict_batch()`: 第250-308行
- `_predict_batch()`: 第265-308行（核心邏輯）

##### 3. 模型配置
```python
self.model_config = {
    'contamination': 0.05,        # 預期異常比例 5%
    'n_estimators': 150,          # 隔離樹數量
    'max_samples': 512,           # 每棵樹的樣本數
    'max_features': 0.8,          # 每棵樹的特徵比例
    'random_state': 42,           # 隨機種子
    'n_jobs': -1                  # 使用所有CPU核心
}
```

#### 模型文件位置
```python
self.model_path = 'nad/models/isolation_forest.pkl'
self.scaler_path = 'nad/models/scaler.pkl'
```

#### 異常分數到置信度的轉換
```python
def _score_to_confidence(self, score: float) -> float
```
- 使用 Sigmoid 函數進行平滑映射
- 參數: midpoint=0.60, steepness=20
- 公式: `1 / (1 + exp(-20 * (score - 0.60)))`
- 輸出範圍: [0, 1]

實作位置: 第310-338行

---

## Classify 功能實作

### 文件: `/home/kaisermac/snm_flow/nad/ml/anomaly_classifier.py`

#### 核心類: `AnomalyClassifier`

**主要方法:**

##### 1. 分類入口方法
```python
def classify(self, features: Dict, context: Dict = None) -> Dict
```
- 輸入: 特徵字典 + 上下文信息
- 輸出: 分類結果字典（類別、置信度、建議等）
- 位置: 第218-329行

**分類流程邏輯** (按優先級順序):

1. **埠掃描 (PORT_SCAN)** - `_is_port_scan()`
   - 條件: unique_dst_ports > 100 AND avg_bytes < 5000 AND dst_port_diversity > 0.5
   - 威脅級別: HIGH / P0

2. **網路掃描 (NETWORK_SCAN)** - `_is_network_scan()`
   - 條件: unique_dsts > 50 AND dst_diversity > 0.3 AND flow_count > 1000
   - 威脅級別: HIGH / P0

3. **DNS隧道 (DNS_TUNNELING)** - `_is_dns_tunneling()`
   - 條件: flow_count > 1000 AND unique_dst_ports <= 2 AND avg_bytes < 1000
   - 威脅級別: HIGH / P0

4. **DDoS攻擊 (DDOS)** - `_is_ddos()`
   - 條件: flow_count > 10000 AND avg_bytes < 500 AND unique_dsts < 20
   - 威脅級別: CRITICAL / P0

5. **數據外洩 (DATA_EXFILTRATION)** - `_is_data_exfiltration()`
   - 條件: total_bytes > 1GB AND unique_dsts <= 5 AND dst_diversity < 0.1 AND 有外部IP
   - 威脅級別: CRITICAL / P0

6. **C&C通訊 (C2_COMMUNICATION)** - `_is_c2_communication()`
   - 條件: unique_dsts == 1 AND 100 < flow_count < 1000 AND 1KB < avg_bytes < 100KB
   - 威脅級別: CRITICAL / P0

7. **正常高流量 (NORMAL_HIGH_TRAFFIC)** - `_is_normal_high_traffic()`
   - 條件: 大流量 BUT 目標是內網IP 或 服務器回應 或 備份時間
   - 威脅級別: LOW / P3

8. **未知異常 (UNKNOWN)** - 默認分類
   - 威脅級別: MEDIUM / P2

##### 2. 置信度計算方法

每個威脅類型都有對應的置信度計算函數:

```python
def _calculate_port_scan_confidence(self, features: Dict) -> float
def _calculate_network_scan_confidence(self, features: Dict) -> float
def _calculate_dns_tunneling_confidence(self, features: Dict) -> float
def _calculate_ddos_confidence(self, features: Dict) -> float
def _calculate_exfil_confidence(self, features: Dict, dst_ips: List) -> float
def _calculate_c2_confidence(self, features: Dict) -> float
def _calculate_normal_confidence(self, features: Dict, dst_ips: List, timestamp) -> float
```

位置: 第465-605行

**置信度計算策略**:
- 基礎置信度 (0.5 - 0.7)
- 根據特徵強度增加置信度 (+0.05 ~ +0.3)
- 最終置信度 capped at 0.85 - 0.99

##### 3. 判斷輔助方法
位置: 第333-439行

```python
def _is_internal_ip(self, ip: str) -> bool
def _create_classification(self, class_name: str, confidence: float, ...) -> Dict
def _generate_indicators(self, class_name: str, features: Dict, context: Dict) -> List
```

#### 威脅類別定義

**常量: `THREAT_CLASSES` (第24-182行)**

8個威脅類別，每個包含:
- name: 中文名稱
- name_en: 英文名稱
- severity: 嚴重級別 (CRITICAL/HIGH/MEDIUM/LOW)
- priority: 優先級 (P0/P1/P2/P3)
- description: 威脅描述
- indicators: 指標列表
- response: 響應建議
- auto_action: 自動化行動

#### 分類輸出格式

```python
{
    'class': 'PORT_SCAN',                  # 威脅類別代碼
    'class_name': '埠掃描',                 # 中文名稱
    'class_name_en': 'Port Scanning',      # 英文名稱
    'confidence': 0.92,                    # 置信度 [0-1]
    'severity': 'HIGH',                    # 嚴重級別
    'priority': 'P0',                      # 優先級
    'description': '探測大量埠，尋找漏洞',   # 描述
    'indicators': [                        # 關鍵指標
        '掃描 500 個不同埠',
        '平均封包 2000 bytes',
        '埠分散度 0.85'
    ],
    'response': [                          # 響應建議
        '立即隔離主機',
        '檢查主機是否被入侵',
        ...
    ],
    'auto_action': 'ISOLATE'               # 自動化行動
}
```

---

## 特徵值完整流程

### 文件: `/home/kaisermac/snm_flow/nad/ml/feature_engineer.py`

#### 核心類: `FeatureEngineer`

**關鍵方法:**

##### 1. 特徵名稱定義
```python
def _build_feature_names(self)
```
位置: 第31-71行

**18個特徵**（按順序）:

**基礎特徵 (9個)** - 直接從聚合數據讀取:
```python
1. flow_count           # 連線數
2. total_bytes          # 總流量（字節）
3. total_packets        # 總封包數
4. unique_dsts          # 唯一目的地IP數
5. unique_src_ports     # 唯一源端口數
6. unique_dst_ports     # 唯一目的端口數
7. avg_bytes            # 平均字節數
8. max_bytes            # 最大單次流量
```

來源: `netflow_stats_5m` 聚合索引

**衍生特徵 (5個)** - 基於基礎特徵計算:
```python
9. dst_diversity        = unique_dsts / flow_count
10. src_port_diversity   = unique_src_ports / flow_count
11. dst_port_diversity   = unique_dst_ports / flow_count
12. traffic_concentration = max_bytes / total_bytes
13. bytes_per_packet     = total_bytes / total_packets
```

**二值特徵 (5個)** - 異常行為標記:
```python
14. is_high_connection       # flow_count > threshold['high_connection']
15. is_scanning_pattern      # unique_dsts > 30 AND avg_bytes < 2200
16. is_small_packet          # avg_bytes < threshold['small_packet']
17. is_large_flow            # max_bytes > threshold['large_flow']
18. is_likely_server_response # 服務器回應流量判斷
```

**對數變換特徵 (2個)** - 處理偏態分布:
```python
19. log_flow_count   = np.log1p(flow_count)
20. log_total_bytes  = np.log1p(total_bytes)
```

**設備類型特徵 (1個)** - 源IP設備分類:
```python
21. device_type      # 0=服務器, 1=工作站, 2=IoT, 3=外部
```

**總計: 21個特徵** (配置中定義為17+device_type)

##### 2. 單筆特徵提取
```python
def extract_features(self, agg_record: Dict) -> Dict
```
位置: 第73-145行

**輸入**: 單筆聚合記錄
```json
{
    "src_ip": "192.168.1.100",
    "time_bucket": "2025-11-17T10:00:00Z",
    "flow_count": 500,
    "total_bytes": 524288000,
    "total_packets": 1000,
    "unique_dsts": 50,
    "unique_src_ports": 100,
    "unique_dst_ports": 80,
    "avg_bytes": 512000,
    "max_bytes": 1048576
}
```

**輸出**: 特徵字典
```python
{
    'flow_count': 500,
    'total_bytes': 524288000,
    ...(全部18個特徵)...
    'is_scanning_pattern': 0,
    'log_flow_count': 6.217,
    'device_type': 1
}
```

**特徵計算邏輯**:
- 基礎特徵: 直接 `record.get(feature_name, 0)`
- 衍生特徵: 四則運算（避免除零）
- 二值特徵: 閾值判斷（使用 `config.thresholds`）
- 對數特徵: `np.log1p()` 計算
- 設備特徵: `device_classifier.get_device_type_code(src_ip)`

##### 3. 批量特徵提取
```python
def extract_features_batch(self, agg_records: List[Dict]) -> np.ndarray
```
位置: 第147-165行

**輸入**: N筆聚合記錄

**輸出**: NumPy數組，形狀 (N, 21)

**實現**: 循環調用 `extract_features()` 然後組裝成矩陣

##### 4. 特徵標準化
```python
# 在 OptimizedIsolationForest 中
X_scaled = self.scaler.fit_transform(X)  # 訓練時
X_scaled = self.scaler.transform(X)      # 預測時
```

使用 sklearn 的 `StandardScaler`:
- 訓練: 計算均值和標準差，進行標準化
- 預測: 使用訓練時的統計量進行標準化

#### 特徵配置文件
**位置**: `/home/kaisermac/snm_flow/nad/config.yaml` (第7-33行)

```yaml
features:
  basic:
    - flow_count
    - total_bytes
    - total_packets
    - unique_dsts
    - unique_src_ports
    - unique_dst_ports
    - avg_bytes
    - max_bytes
  
  derived:
    - dst_diversity
    - src_port_diversity
    - dst_port_diversity
    - traffic_concentration
    - bytes_per_packet
  
  binary:
    - is_high_connection
    - is_scanning_pattern
    - is_small_packet
    - is_large_flow
    - is_likely_server_response
  
  log_transform:
    - log_flow_count
    - log_total_bytes
  
  device_type:
    - device_type
```

#### 特徵閾值配置
**位置**: `/home/kaisermac/snm_flow/nad/config.yaml` (第60-65行)

```yaml
thresholds:
  high_connection: 352           # 改自原始1000
  scanning_dsts: 3               # 改自原始30
  scanning_avg_bytes: 2200       # 改自原始10000
  small_packet: 456              # 改自原始1000
  large_flow: 7914975            # 改自原始104857600
```

---

## 資料流程圖

### 訓練流程

```
開始: train_isolation_forest.py
  │
  ├─> 加載配置 (load_config)
  │     ↓
  │   nad/config.yaml
  │
  ├─> 創建 OptimizedIsolationForest 實例
  │     ↓
  │   初始化 FeatureEngineer
  │
  ├─> train_on_aggregated_data(days=7)
  │     │
  │     ├─> _fetch_training_data(7)
  │     │     ↓
  │     │   Elasticsearch (netflow_stats_5m)
  │     │     ↓
  │     │   List[Dict] - N筆聚合記錄
  │     │
  │     ├─> extract_features_batch(records)  [FeatureEngineer]
  │     │     ↓
  │     │   extract_features(record) for each record
  │     │     ↓
  │     │   NumPy Array (N, 21)
  │     │
  │     ├─> scaler.fit_transform(X)
  │     │     ↓
  │     │   NumPy Array - 標準化 (N, 21)
  │     │
  │     ├─> IsolationForest.fit(X_scaled)
  │     │     ↓
  │     │   訓練完成
  │     │
  │     └─> _save_model()
  │           ↓
  │         isolation_forest.pkl
  │         scaler.pkl
  │
  └─> 結束: 模型保存完成
```

### 預測流程

```
開始: realtime_detection.py
  │
  ├─> 加載配置 (load_config)
  │
  ├─> 創建 OptimizedIsolationForest 實例
  │     │
  │     └─> _load_model()
  │           ├─> isolation_forest.pkl
  │           └─> scaler.pkl
  │
  ├─> predict_realtime(recent_minutes=10)
  │     │
  │     ├─> 查詢 Elasticsearch (最近10分鐘)
  │     │     ↓
  │     │   netflow_stats_5m
  │     │     ↓
  │     │   List[Dict] - M筆記錄
  │     │
  │     └─> _predict_batch(records)
  │           │
  │           ├─> extract_features_batch(records)  [FeatureEngineer]
  │           │     ↓
  │           │   NumPy Array (M, 21)
  │           │
  │           ├─> scaler.transform(X)
  │           │     ↓
  │           │   NumPy Array - 標準化 (M, 21)
  │           │
  │           ├─> model.predict(X_scaled)
  │           │     ↓
  │           │   預測結果 [-1 = 異常, 1 = 正常]
  │           │
  │           ├─> model.score_samples(X_scaled)
  │           │     ↓
  │           │   異常分數 (越低越異常)
  │           │
  │           ├─> _score_to_confidence(score)
  │           │     ↓
  │           │   置信度 [0-1]
  │           │
  │           └─> 組裝結果字典
  │                 {
  │                   src_ip: ...,
  │                   anomaly_score: ...,
  │                   confidence: ...,
  │                   features: {...},
  │                   ...
  │                 }
  │
  ├─> analyze_anomalies(anomalies)
  │     │
  │     ├─> 創建 AnomalyClassifier 實例
  │     │
  │     └─> classify(features, context)
  │           │
  │           ├─> _is_port_scan() ✓/✗
  │           ├─> _is_network_scan() ✓/✗
  │           ├─> _is_dns_tunneling() ✓/✗
  │           ├─> _is_ddos() ✓/✗
  │           ├─> _is_data_exfiltration() ✓/✗
  │           ├─> _is_c2_communication() ✓/✗
  │           ├─> _is_normal_high_traffic() ✓/✗
  │           └─> UNKNOWN (默認)
  │                 ↓
  │           _create_classification(class_name, confidence)
  │                 ↓
  │           分類結果字典
  │
  ├─> AnomalyLogger.log_anomalies()
  │     │
  │     └─> Elasticsearch (anomaly_detection-*)
  │
  └─> 結束: 打印結果
```

### 完整資料流向圖

```
┌─────────────────────────────────────────────────────────────┐
│          Elasticsearch - netflow_stats_5m 聚合索引          │
│  (聚合的網路流量數據：連線數、流量、目的地等)                  │
└──────────────────────────┬──────────────────────────────────┘
                           │
                 (5分鐘時間窗口的記錄)
                           │
           ┌───────────────▼──────────────┐
           │  FeatureEngineer             │
           │  extract_features_batch()    │
           │  extract_features()          │
           └───────────┬──────────────────┘
                       │
        (9 基礎 + 5衍生 + 5二值 + 2對數 + 1設備 = 21維)
                       │
           ┌───────────▼──────────────────┐
           │  StandardScaler              │
           │  fit_transform() / transform()│
           └───────────┬──────────────────┘
                       │
            (均值=0, 標準差=1的標準化特徵)
                       │
    ┌──────────────────┼──────────────────┐
    │                  │                  │
    ▼                  │                  │
訓練階段             │              預測階段
    │                  │                  │
    ├─> IsolationForest│                  │
    │    fit()         │      ┌──────────▼────────────┐
    │         │        │      │ IsolationForest       │
    │         │        │      │ predict()             │
    │         │        │      │ score_samples()       │
    │         ▼        │      └──────────┬────────────┘
    │   isolation_     │                  │
    │   forest.pkl     │        (異常分數, 預測值)
    │                  │                  │
    └──────────────────┤                  │
                       │                  │
                       │      ┌──────────▼────────────┐
                       │      │ _score_to_confidence()│
                       │      │ (Sigmoid轉換)         │
                       │      └──────────┬────────────┘
                       │                  │
                       │        (置信度 [0-1])
                       │                  │
                       │      ┌──────────▼────────────┐
                       │      │ AnomalyClassifier     │
                       │      │ classify()            │
                       │      │ (規則型分類)          │
                       │      └──────────┬────────────┘
                       │                  │
                       │   ┌──────────────┼──────────────┐
                       │   │ 判斷條件:                   │
                       │   │ - _is_port_scan()          │
                       │   │ - _is_network_scan()       │
                       │   │ - _is_dns_tunneling()      │
                       │   │ - _is_ddos()               │
                       │   │ - _is_data_exfiltration()  │
                       │   │ - _is_c2_communication()   │
                       │   │ - _is_normal_high_traffic()│
                       │   │ - UNKNOWN                  │
                       │   └──────────────┬──────────────┘
                       │                  │
                       │      ┌──────────▼────────────┐
                       │      │ _calculate_*_confidence()
                       │      │ (置信度計算)            │
                       │      └──────────┬────────────┘
                       │                  │
                       │      ┌──────────▼────────────┐
                       │      │ _create_classification()
                       │      │ 返回分類結果           │
                       │      └──────────┬────────────┘
                       │                  │
                       └──────────────────┼────────────────────┐
                                          │                    │
                            ┌─────────────▼────────────┐        │
                            │ AnomalyLogger.log()      │        │
                            │ 寫入 ES                  │        │
                            └──────────────────────────┘        │
                                                                │
                                    ┌───────────────────────────┘
                                    │
                            ┌───────▼──────────────┐
                            │ 異常結果輸出:         │
                            │ - 異常IP列表         │
                            │ - 異常分數           │
                            │ - 置信度             │
                            │ - 威脅類別           │
                            │ - 建議行動           │
                            └──────────────────────┘
```

---

## 文件路徑速查表

### 核心ML模組

| 功能 | 文件路徑 | 主要類/函數 | 行號 |
|------|---------|-----------|------|
| **Isolation Forest實現** | `/home/kaisermac/snm_flow/nad/ml/isolation_forest_detector.py` | `OptimizedIsolationForest` | 20-444 |
| 訓練方法 | 同上 | `train_on_aggregated_data()` | 70-155 |
| 實時預測 | 同上 | `predict_realtime()` | 201-248 |
| 批量預測 | 同上 | `predict_batch()` / `_predict_batch()` | 250-308 |
| 模型加載/保存 | 同上 | `_load_model()` / `_save_model()` | 350-362 |
| 分數轉換 | 同上 | `_score_to_confidence()` | 310-338 |
| | | | |
| **特徵工程** | `/home/kaisermac/snm_flow/nad/ml/feature_engineer.py` | `FeatureEngineer` | 15-305 |
| 單筆提取 | 同上 | `extract_features()` | 73-145 |
| 批量提取 | 同上 | `extract_features_batch()` | 147-165 |
| 特徵定義 | 同上 | `_build_feature_names()` | 31-71 |
| 時間序列 | 同上 | `extract_time_series_features()` | 179-250 |
| | | | |
| **異常分類** | `/home/kaisermac/snm_flow/nad/ml/anomaly_classifier.py` | `AnomalyClassifier` | 185-720 |
| 分類主方法 | 同上 | `classify()` | 218-329 |
| 埠掃描判斷 | 同上 | `_is_port_scan()` | 333-347 |
| 網路掃描判斷 | 同上 | `_is_network_scan()` | 349-366 |
| DNS隧道判斷 | 同上 | `_is_dns_tunneling()` | 368-385 |
| DDoS判斷 | 同上 | `_is_ddos()` | 387-401 |
| 數據外洩判斷 | 同上 | `_is_data_exfiltration()` | 403-422 |
| C&C判斷 | 同上 | `_is_c2_communication()` | 424-439 |
| 正常高流量判斷 | 同上 | `_is_normal_high_traffic()` | 441-463 |
| 威脅類別定義 | 同上 | `THREAT_CLASSES` 常量 | 24-182 |

### 配置文件

| 功能 | 文件路徑 | 內容 |
|------|---------|------|
| 主配置 | `/home/kaisermac/snm_flow/nad/config.yaml` | ES連接、模型參數、特徵列表、閾值 |
| 設備映射 | `/home/kaisermac/snm_flow/nad/device_mapping.yaml` | IP範圍到設備類型映射 |
| 配置加載器 | `/home/kaisermac/snm_flow/nad/utils/config_loader.py` | `Config` 類、`load_config()` 函數 |

### 訓練和推論腳本

| 功能 | 文件路徑 | 入口函數 |
|------|---------|---------|
| 訓練入口 | `/home/kaisermac/snm_flow/train_isolation_forest.py` | `main()` |
| 實時檢測 | `/home/kaisermac/snm_flow/realtime_detection.py` | `main()` |
| 異常驗證 | `/home/kaisermac/snm_flow/verify_anomaly.py` | `AnomalyVerifier` 類 |
| 分類優化 | `/home/kaisermac/snm_flow/optimize_classifier_thresholds.py` | 調優工具 |

### 模型存儲

| 類型 | 路徑 | 格式 |
|------|------|------|
| IF模型 | `/home/kaisermac/snm_flow/nad/models/isolation_forest.pkl` | Pickle |
| 特徵Scaler | `/home/kaisermac/snm_flow/nad/models/scaler.pkl` | Pickle |

### 文檔

| 主題 | 文件路徑 |
|------|---------|
| Isolation Forest指南 | `/home/kaisermac/snm_flow/ISOLATION_FOREST_GUIDE.md` |
| 特徵詳解 | `/home/kaisermac/snm_flow/ANOMALY_FEATURES_EXPLAINED.md` |
| 分類指南 | `/home/kaisermac/snm_flow/ANOMALY_CLASSIFICATION_GUIDE.md` |
| 快速開始 | `/home/kaisermac/snm_flow/ISOLATION_FOREST_QUICKSTART.md` |

---

## 關鍵概念速查

### 特徵向量維度

| 類別 | 特徵名 | 數量 | 來源 |
|------|--------|------|------|
| 基礎 | flow_count, total_bytes, ... | 9 | netflow_stats_5m |
| 衍生 | dst_diversity, bytes_per_packet, ... | 5 | 四則運算 |
| 二值 | is_high_connection, is_scanning_pattern, ... | 5 | 閾值判斷 |
| 對數 | log_flow_count, log_total_bytes | 2 | np.log1p() |
| 設備 | device_type | 1 | IP分類 |
| **總計** | | **21** | |

### Isolation Forest 參數

| 參數 | 值 | 說明 |
|------|-----|------|
| contamination | 0.05 | 預期異常比例(5%) |
| n_estimators | 150 | 隔離樹數量 |
| max_samples | 512 | 每棵樹的樣本數 |
| max_features | 0.8 | 每棵樹的特徵比例(80%) |
| random_state | 42 | 隨機種子(可重現) |
| n_jobs | -1 | 使用所有CPU核心並行 |

### 異常分數轉置信度

```
異常分數 (IF的score_samples輸出)
     │
     ├─> 負值越大 → 異常越明顯
     │
     ├─> 取反 (-score)
     │     │
     │     ├─> 得到正分數
     │     │
     │     └─> 範圍 [0, ∞)
     │
     ├─> Sigmoid轉換
     │     │
     │     ├─> 公式: 1 / (1 + exp(-20 * (x - 0.60)))
     │     │
     │     └─> 輸出: [0, 1]
     │
     └─> 置信度 [0, 1]
```

### 分類優先級順序

```
1. 埠掃描 (PORT_SCAN)
   ↓
2. 網路掃描 (NETWORK_SCAN)
   ↓
3. DNS隧道 (DNS_TUNNELING)
   ↓
4. DDoS攻擊 (DDOS)
   ↓
5. 數據外洩 (DATA_EXFILTRATION)
   ↓
6. C&C通訊 (C2_COMMUNICATION)
   ↓
7. 正常高流量 (NORMAL_HIGH_TRAFFIC)
   ↓
8. 未知異常 (UNKNOWN) [默認]
```

(優先級高的條件若符合，則使用該分類，不再檢查後續條件)

---

## 使用示例

### 訓練模型

```bash
cd /home/kaisermac/snm_flow
python3 train_isolation_forest.py --days 7 --evaluate
```

### 實時檢測

```bash
python3 realtime_detection.py --minutes 10
```

### 異常驗證

```bash
python3 verify_anomaly.py <IP地址>
```

### Python代碼使用

```python
from nad.utils import load_config
from nad.ml import OptimizedIsolationForest
from nad.ml.anomaly_classifier import AnomalyClassifier

# 加載配置
config = load_config('nad/config.yaml')

# 創建檢測器
detector = OptimizedIsolationForest(config)

# 加載已訓練的模型
detector._load_model()

# 進行實時預測
anomalies = detector.predict_realtime(recent_minutes=10)

# 對每個異常進行分類
classifier = AnomalyClassifier()
for anomaly in anomalies[:5]:
    classification = classifier.classify(
        features=anomaly['features'],
        context={
            'timestamp': datetime.now(),
            'src_ip': anomaly['src_ip'],
            'anomaly_score': anomaly['anomaly_score']
        }
    )
    print(f"{anomaly['src_ip']} → {classification['class_name']}")
```

---

**生成時間**: 2025-11-17
**系統**: Isolation Forest 異常檢測系統
**覆蓋率**: 99.57%

