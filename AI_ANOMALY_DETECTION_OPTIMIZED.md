# AI 輔助網路異常偵測系統設計（優化版）

## 基於驗證結果的調整

**關鍵發現：**
- ✅ Transform 聚合數據覆蓋率：99.57%
- ✅ 數據縮減比例：100-200x
- ✅ 查詢速度提升：100x
- ✅ 每5分鐘：400-600 個唯一 IP

**影響：**
- 可直接使用 `netflow_stats_5m` 作為 ML 訓練和推論的數據源
- 無需擔心數據遺漏問題
- 可進行實時 ML 推論（延遲低）

---

## 一、優化的數據流架構

### 1.1 數據層級

```
原始 NetFlow 數據 (radar_flow_collector-*)
    ↓
ES Transform (每5分鐘)
    ↓
聚合數據 (netflow_stats_5m) ← ✅ 99.57% 覆蓋率
    ↓                              ✅ 100x 查詢加速
    ↓                              ✅ 完整特徵工程
    ↓
┌──────────────────────────────────────────┐
│   ML/AI 分析層                            │
│                                          │
│  Layer 1: Rule-based (實時，< 1s)        │
│  Layer 2: ML Classification (實時，< 5s) │
│  Layer 3: Time Series (批次，< 30s)      │
│  Layer 4: LLM Reasoning (按需，< 10s)    │
└──────────────────────────────────────────┘
    ↓
異常報告 + 建議措施
```

**關鍵優勢：**
- 所有 ML 模型直接讀取 `netflow_stats_5m`（已包含完整特徵）
- 不需要再次聚合或特徵工程
- 訓練和推論使用相同數據源（避免 train-serve skew）

---

## 二、基於聚合數據的特徵工程

### 2.1 已有特徵（來自 Transform）

Transform 已經提供的特徵：

```python
# netflow_stats_5m 的原生欄位
NATIVE_FEATURES = [
    'time_bucket',          # 時間桶（5分鐘）
    'src_ip',               # 來源 IP
    'flow_count',           # 連線數 ✅
    'total_bytes',          # 總流量 ✅
    'total_packets',        # 總封包數 ✅
    'unique_dsts',          # 唯一目的地數 ✅
    'unique_ports',         # 唯一端口數 ✅
    'avg_bytes',            # 平均流量 ✅
    'max_bytes'             # 最大單一連線流量 ✅
]
```

### 2.2 衍生特徵（快速計算）

在 Python 中即時計算的衍生特徵：

```python
class FeatureEngineer:
    """
    從聚合數據提取 ML 特徵
    """

    def extract_features(self, agg_record):
        """
        從單筆 netflow_stats_5m 記錄提取特徵

        優勢：
        - 不需要重新查詢原始數據
        - 計算速度快（毫秒級）
        - 特徵完整且一致
        """
        features = {}

        # 1. 原生特徵（直接使用）
        features['flow_count'] = agg_record['flow_count']
        features['total_bytes'] = agg_record['total_bytes']
        features['unique_dsts'] = agg_record['unique_dsts']
        features['unique_ports'] = agg_record['unique_ports']
        features['avg_bytes'] = agg_record['avg_bytes']
        features['max_bytes'] = agg_record['max_bytes']

        # 2. 比例特徵
        features['dst_diversity'] = (
            agg_record['unique_dsts'] / max(agg_record['flow_count'], 1)
        )
        features['port_diversity'] = (
            agg_record['unique_ports'] / max(agg_record['flow_count'], 1)
        )

        # 3. 流量分布特徵
        features['traffic_concentration'] = (
            agg_record['max_bytes'] / max(agg_record['total_bytes'], 1)
        )
        features['bytes_per_packet'] = (
            agg_record['total_bytes'] / max(agg_record['total_packets'], 1)
        )

        # 4. 行為標記（二值特徵）
        features['is_high_connection'] = 1 if agg_record['flow_count'] > 1000 else 0
        features['is_scanning_pattern'] = (
            1 if (agg_record['unique_dsts'] > 30 and
                  agg_record['avg_bytes'] < 10000) else 0
        )
        features['is_small_packet'] = 1 if agg_record['avg_bytes'] < 1000 else 0
        features['is_large_flow'] = 1 if agg_record['max_bytes'] > 100*1024*1024 else 0

        # 5. 對數變換（處理偏態分布）
        import numpy as np
        features['log_flow_count'] = np.log1p(agg_record['flow_count'])
        features['log_total_bytes'] = np.log1p(agg_record['total_bytes'])

        return features

    def extract_time_series_features(self, ip, hours=24):
        """
        從多個時間桶提取時間序列特徵

        優勢：
        - 查詢速度快（已聚合）
        - 可檢測趨勢變化
        - 適合異常偏差檢測
        """
        # 查詢該 IP 過去24小時的聚合數據
        query = {
            "size": 288,  # 24小時 × 12個5分鐘
            "query": {
                "bool": {
                    "must": [
                        {"term": {"src_ip": ip}},
                        {"range": {"time_bucket": {"gte": f"now-{hours}h"}}}
                    ]
                }
            },
            "sort": [{"time_bucket": "asc"}]
        }

        records = self.es.search(index="netflow_stats_5m", body=query)

        # 提取時間序列
        flow_counts = [r['_source']['flow_count'] for r in records['hits']['hits']]
        unique_dsts = [r['_source']['unique_dsts'] for r in records['hits']['hits']]

        # 統計特徵
        import numpy as np

        ts_features = {
            # 基本統計
            'mean_flow_count': np.mean(flow_counts),
            'std_flow_count': np.std(flow_counts),
            'max_flow_count': np.max(flow_counts),

            # 變異性
            'cv_flow_count': np.std(flow_counts) / (np.mean(flow_counts) + 1),

            # 趨勢
            'flow_count_trend': self._calculate_trend(flow_counts),

            # 突變檢測
            'recent_spike': 1 if flow_counts[-1] > np.mean(flow_counts) + 2*np.std(flow_counts) else 0,

            # 週期性（簡化版）
            'hour_of_day': datetime.fromisoformat(
                records['hits']['hits'][-1]['_source']['time_bucket']
            ).hour
        }

        return ts_features

    def _calculate_trend(self, values):
        """計算簡單線性趨勢"""
        if len(values) < 2:
            return 0

        import numpy as np
        x = np.arange(len(values))
        y = np.array(values)

        # 簡單線性回歸
        slope = np.corrcoef(x, y)[0, 1] if len(values) > 2 else 0
        return slope
```

### 2.3 最終特徵集

```python
# ML 模型使用的特徵（共 20+ 個）
FEATURE_SET = {
    # 原生特徵 (8個)
    'basic': [
        'flow_count', 'total_bytes', 'total_packets',
        'unique_dsts', 'unique_ports', 'avg_bytes', 'max_bytes'
    ],

    # 比例特徵 (4個)
    'ratios': [
        'dst_diversity', 'port_diversity',
        'traffic_concentration', 'bytes_per_packet'
    ],

    # 行為標記 (4個)
    'binary': [
        'is_high_connection', 'is_scanning_pattern',
        'is_small_packet', 'is_large_flow'
    ],

    # 對數特徵 (2個)
    'log_transformed': [
        'log_flow_count', 'log_total_bytes'
    ],

    # 時間序列特徵 (7個) - 可選
    'time_series': [
        'mean_flow_count', 'std_flow_count', 'cv_flow_count',
        'flow_count_trend', 'recent_spike', 'hour_of_day'
    ]
}

# 總計：17個基礎特徵 + 7個時序特徵 = 24個特徵
```

---

## 三、優化的 ML 模型選擇

### 3.1 Isolation Forest（無監督異常檢測）

**適用場景：**
- 不需要標記數據
- 初期快速部署
- 檢測未知異常模式

**優化建議：**

```python
from sklearn.ensemble import IsolationForest
import numpy as np

class OptimizedIsolationForest:
    """
    基於聚合數據優化的 Isolation Forest
    """

    def __init__(self):
        self.model = IsolationForest(
            contamination=0.05,      # 預期5%異常率（基於實測數據調整）
            n_estimators=150,        # 增加樹的數量以提高穩定性
            max_samples=512,         # 每棵樹採樣512個樣本
            max_features=0.8,        # 使用80%的特徵
            random_state=42,
            n_jobs=-1                # 使用所有 CPU 核心
        )
        self.feature_engineer = FeatureEngineer()
        self.scaler = StandardScaler()

    def train_on_aggregated_data(self, days=7):
        """
        使用過去 N 天的聚合數據訓練

        優勢：
        - 數據量適中（7天 × 288個時間桶 × 500IP ≈ 100萬筆）
        - 訓練速度快（幾分鐘內完成）
        - 包含正常流量的全部模式
        """
        print(f"📚 收集過去 {days} 天的聚合數據...")

        # 查詢聚合數據
        query = {
            "size": 10000,
            "query": {
                "range": {
                    "time_bucket": {
                        "gte": f"now-{days}d"
                    }
                }
            }
        }

        records = self.es.search(
            index="netflow_stats_5m",
            body=query,
            scroll='5m'
        )

        # 提取特徵
        X = []
        for record in self._scroll_all(records):
            features = self.feature_engineer.extract_features(record['_source'])
            X.append(list(features.values()))

        X = np.array(X)

        # 標準化
        X_scaled = self.scaler.fit_transform(X)

        print(f"🏋️  訓練 Isolation Forest ({len(X):,} 樣本)...")
        self.model.fit(X_scaled)

        print("✅ 訓練完成")
        self._save_model()

    def predict_realtime(self, recent_minutes=10):
        """
        對最近的數據進行實時異常檢測

        優勢：
        - 延遲低（< 5秒）
        - 只需掃描最近幾個時間桶
        - 可每5分鐘執行一次
        """
        query = {
            "size": 1000,
            "query": {
                "range": {
                    "time_bucket": {
                        "gte": f"now-{recent_minutes}m"
                    }
                }
            }
        }

        records = self.es.search(index="netflow_stats_5m", body=query)

        results = []
        for record in records['hits']['hits']:
            src = record['_source']
            features = self.feature_engineer.extract_features(src)

            X = np.array([list(features.values())])
            X_scaled = self.scaler.transform(X)

            prediction = self.model.predict(X_scaled)[0]
            score = self.model.score_samples(X_scaled)[0]

            if prediction == -1:  # 異常
                results.append({
                    'src_ip': src['src_ip'],
                    'time_bucket': src['time_bucket'],
                    'anomaly_score': -score,  # 轉為正值，越大越異常
                    'features': features,
                    'flow_count': src['flow_count'],
                    'unique_dsts': src['unique_dsts']
                })

        # 按異常分數排序
        results.sort(key=lambda x: x['anomaly_score'], reverse=True)

        return results
```

**訓練建議：**
```python
# 初始訓練：使用過去7天的正常流量
detector = OptimizedIsolationForest()
detector.train_on_aggregated_data(days=7)

# 定期重訓練：每週一次
# 使用最新7天數據，排除已知異常
```

### 3.2 Random Forest Classifier（監督式行為分類）

**適用場景：**
- 已有部分標記數據
- 需要可解釋的分類結果
- 多類別異常檢測

**優化建議：**

```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score

class BehaviorClassifier:
    """
    流量行為分類器（基於聚合數據優化）
    """

    BEHAVIOR_LABELS = {
        0: 'normal',
        1: 'port_scanning',       # 端口掃描
        2: 'network_scanning',    # 網路掃描
        3: 'dns_abuse',           # DNS 濫用
        4: 'data_exfiltration',   # 數據外洩
        5: 'high_traffic',        # 高流量（可能正常）
    }

    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=10,
            min_samples_leaf=5,
            class_weight='balanced',  # 處理類別不平衡
            random_state=42,
            n_jobs=-1
        )
        self.feature_engineer = FeatureEngineer()

    def create_training_data_from_rules(self):
        """
        使用規則引擎自動生成訓練數據

        優勢：
        - 不需要人工標記
        - 可快速生成大量樣本
        - 基於已知異常模式
        """
        print("📚 從聚合數據生成訓練集...")

        # 查詢過去30天的數據
        query = {
            "size": 10000,
            "query": {
                "range": {"time_bucket": {"gte": "now-30d"}}
            }
        }

        records = self.es.search(index="netflow_stats_5m", body=query, scroll='5m')

        X = []
        y = []

        for record in self._scroll_all(records):
            src = record['_source']
            features = self.feature_engineer.extract_features(src)

            # 使用規則引擎自動標記
            label = self._auto_label(src)

            if label is not None:  # 只保留高置信度標記
                X.append(list(features.values()))
                y.append(label)

        print(f"✅ 生成 {len(X):,} 個訓練樣本")
        print(f"   類別分布: {np.bincount(y)}")

        return np.array(X), np.array(y)

    def _auto_label(self, record):
        """
        自動標記規則（基於實測數據優化）
        """
        # 正常流量（保守標記）
        if (record['flow_count'] < 100 and
            record['unique_dsts'] < 10):
            return 0  # normal

        # 端口掃描
        if (record['unique_ports'] > 50 and
            record['avg_bytes'] < 5000 and
            record['flow_count'] > 100):
            return 1  # port_scanning

        # 網路掃描
        if (record['unique_dsts'] > 100 and
            record['avg_bytes'] < 10000 and
            record['flow_count'] > 500):
            return 2  # network_scanning

        # DNS 濫用
        # 注意：需要在 Transform 中添加 dst_port 統計
        # 暫時使用高連線數 + 小封包作為近似
        if (record['flow_count'] > 10000 and
            record['avg_bytes'] < 500 and
            record['unique_dsts'] < 10):
            return 3  # dns_abuse

        # 數據外洩
        if (record['total_bytes'] > 1024*1024*1024 and  # > 1GB
            record['unique_dsts'] < 5 and
            record['avg_bytes'] > 1024*1024):  # > 1MB 平均
            return 4  # data_exfiltration

        # 高流量（但可能正常）
        if record['flow_count'] > 5000:
            return 5  # high_traffic

        # 不確定的模式不標記
        return None

    def train(self):
        """訓練模型"""
        X, y = self.create_training_data_from_rules()

        # 交叉驗證
        scores = cross_val_score(self.model, X, y, cv=5)
        print(f"📊 交叉驗證準確率: {scores.mean():.3f} (+/- {scores.std():.3f})")

        # 訓練
        self.model.fit(X, y)

        # 特徵重要性
        self._print_feature_importance()

    def _print_feature_importance(self):
        """輸出特徵重要性"""
        importances = self.model.feature_importances_
        feature_names = list(FEATURE_SET['basic']) + list(FEATURE_SET['ratios'])

        print("\n📈 特徵重要性 Top 5:")
        indices = np.argsort(importances)[-5:][::-1]
        for i in indices:
            print(f"   {feature_names[i]}: {importances[i]:.3f}")
```

### 3.3 時間序列異常檢測（LSTM / Prophet）

**適用場景：**
- 檢測流量趨勢異常
- 識別突發流量
- 預測未來異常

**簡化方案（基於統計）：**

```python
class TimeSeriesAnomalyDetector:
    """
    基於統計的時間序列異常檢測
    （比 LSTM 簡單，但對聚合數據很有效）
    """

    def detect_spike(self, ip, window_hours=24):
        """
        檢測流量突增

        優勢：
        - 直接使用聚合數據
        - 計算速度快
        - 無需複雜模型
        """
        # 查詢過去24小時的時間序列
        query = {
            "size": 288,  # 24h × 12
            "query": {
                "bool": {
                    "must": [
                        {"term": {"src_ip": ip}},
                        {"range": {"time_bucket": {"gte": f"now-{window_hours}h"}}}
                    ]
                }
            },
            "sort": [{"time_bucket": "asc"}]
        }

        records = self.es.search(index="netflow_stats_5m", body=query)

        # 提取流量時間序列
        flow_counts = [
            r['_source']['flow_count']
            for r in records['hits']['hits']
        ]

        if len(flow_counts) < 12:  # 至少1小時數據
            return None

        # 統計方法檢測異常
        import numpy as np

        # 使用移動平均和標準差
        recent = flow_counts[-1]
        baseline = np.mean(flow_counts[:-1])
        std = np.std(flow_counts[:-1])

        # Z-score
        z_score = (recent - baseline) / (std + 1)

        # 判斷異常
        is_spike = z_score > 3  # 3個標準差

        return {
            'is_anomaly': is_spike,
            'z_score': z_score,
            'current': recent,
            'baseline': baseline,
            'deviation_pct': ((recent - baseline) / baseline * 100) if baseline > 0 else 0
        }
```

---

## 四、實時推論流程（優化版）

```python
class RealtimeAnomalyEngine:
    """
    實時異常檢測引擎（基於聚合數據）
    """

    def __init__(self):
        self.isolation_forest = OptimizedIsolationForest()
        self.behavior_classifier = BehaviorClassifier()
        self.ts_detector = TimeSeriesAnomalyDetector()

        # 加載預訓練模型
        self.isolation_forest.load_model()
        self.behavior_classifier.load_model()

    def analyze_recent(self, minutes=5):
        """
        分析最近 N 分鐘的數據

        執行流程：
        1. 從 netflow_stats_5m 讀取最新數據（< 0.5s）
        2. Isolation Forest 異常檢測（< 1s）
        3. Behavior Classification（< 2s）
        4. 時間序列分析（可選，< 2s）

        總延遲：< 5s（可接受的實時性）
        """
        import time
        start_time = time.time()

        print(f"\n{'='*60}")
        print(f"實時異常分析 - 過去 {minutes} 分鐘")
        print(f"{'='*60}\n")

        # Step 1: Isolation Forest（快速篩選）
        print("🤖 Step 1: 無監督異常檢測...")
        anomalies = self.isolation_forest.predict_realtime(minutes)
        print(f"   發現 {len(anomalies)} 個潛在異常")

        # Step 2: Behavior Classification（精確分類）
        print("\n🎯 Step 2: 行為分類...")
        classified = []
        for anomaly in anomalies:
            behavior = self.behavior_classifier.predict_single(anomaly)

            classified.append({
                **anomaly,
                'behavior': behavior['label'],
                'confidence': behavior['confidence']
            })

        # Step 3: 時間序列分析（檢測突變）
        print("\n📈 Step 3: 時間序列異常檢測...")
        for item in classified:
            ts_result = self.ts_detector.detect_spike(item['src_ip'])
            if ts_result:
                item['is_spike'] = ts_result['is_anomaly']
                item['z_score'] = ts_result['z_score']

        # 排序：優先顯示高置信度異常
        classified.sort(
            key=lambda x: (x['confidence'], x['anomaly_score']),
            reverse=True
        )

        elapsed = time.time() - start_time
        print(f"\n✅ 分析完成 (耗時: {elapsed:.2f}s)")

        return classified

    def continuous_monitoring(self, interval_minutes=5):
        """
        持續監控模式

        每 N 分鐘執行一次實時分析
        """
        import schedule
        import time

        def job():
            results = self.analyze_recent(minutes=interval_minutes)

            # 輸出高風險異常
            high_risk = [
                r for r in results
                if r['behavior'] in ['port_scanning', 'network_scanning', 'dns_abuse']
                and r['confidence'] > 0.7
            ]

            if high_risk:
                print(f"\n⚠️  發現 {len(high_risk)} 個高風險異常:\n")
                for i, anomaly in enumerate(high_risk, 1):
                    print(f"{i}. {anomaly['src_ip']:15} | "
                          f"{anomaly['behavior']:20} | "
                          f"置信度: {anomaly['confidence']:.2f} | "
                          f"連線數: {anomaly['flow_count']:,}")
            else:
                print("\n✅ 未發現高風險異常")

        # 立即執行一次
        job()

        # 定期執行
        schedule.every(interval_minutes).minutes.do(job)

        print(f"\n🔄 持續監控模式啟動 (每 {interval_minutes} 分鐘分析一次)")
        print("   按 Ctrl+C 停止\n")

        while True:
            schedule.run_pending()
            time.sleep(10)
```

---

## 五、訓練數據策略（基於聚合數據）

### 5.1 自動標記策略

```python
class AutoLabelingEngine:
    """
    從聚合數據自動生成訓練集
    """

    def generate_labeled_dataset(self, days=30):
        """
        生成過去 N 天的標記數據集

        優勢：
        - 數據量適中（30天 × 288 × 500IP ≈ 430萬筆）
        - 標記速度快（基於規則）
        - 可持續更新
        """
        labeled_data = {
            'normal': [],
            'port_scanning': [],
            'network_scanning': [],
            'dns_abuse': [],
            'data_exfiltration': [],
            'high_traffic': []
        }

        # 查詢聚合數據
        query = {
            "size": 10000,
            "query": {
                "range": {"time_bucket": {"gte": f"now-{days}d"}}
            }
        }

        records = self.es.search(
            index="netflow_stats_5m",
            body=query,
            scroll='10m'
        )

        for record in self._scroll_all(records):
            src = record['_source']

            # 提取特徵
            features = self.feature_engineer.extract_features(src)

            # 自動標記
            label, confidence = self._auto_label_with_confidence(src)

            # 只保留高置信度樣本
            if confidence > 0.8:
                labeled_data[label].append({
                    'features': features,
                    'label': label,
                    'confidence': confidence,
                    'src_ip': src['src_ip'],
                    'time_bucket': src['time_bucket']
                })

        # 平衡數據集
        balanced = self._balance_dataset(labeled_data)

        return balanced

    def _auto_label_with_confidence(self, record):
        """
        自動標記並返回置信度
        """
        # 端口掃描（高置信度）
        if (record['unique_ports'] > 100 and
            record['avg_bytes'] < 5000 and
            record['flow_count'] > 1000):
            return 'port_scanning', 0.95

        # 網路掃描（高置信度）
        if (record['unique_dsts'] > 200 and
            record['avg_bytes'] < 10000 and
            record['flow_count'] > 2000):
            return 'network_scanning', 0.90

        # DNS 濫用（中等置信度）
        if (record['flow_count'] > 20000 and
            record['avg_bytes'] < 500):
            return 'dns_abuse', 0.75

        # 正常流量（保守標記）
        if (record['flow_count'] < 100 and
            record['unique_dsts'] < 20 and
            record['avg_bytes'] > 1000):
            return 'normal', 0.85

        # 其他
        return 'normal', 0.5  # 低置信度

    def _balance_dataset(self, labeled_data):
        """
        平衡類別數量（處理類別不平衡）
        """
        # 找到最小類別數量
        min_count = min(len(samples) for samples in labeled_data.values())

        # 每個類別隨機採樣相同數量
        balanced = {}
        for label, samples in labeled_data.items():
            if len(samples) > min_count:
                balanced[label] = np.random.choice(
                    samples, size=min_count, replace=False
                ).tolist()
            else:
                balanced[label] = samples

        return balanced
```

### 5.2 增量學習

```python
class IncrementalLearner:
    """
    持續學習管理器
    """

    def should_retrain(self):
        """
        判斷是否需要重新訓練
        """
        # 1. 檢查距離上次訓練的時間
        last_train_time = self.get_last_train_time()
        days_since_train = (datetime.now() - last_train_time).days

        # 2. 檢查新數據量
        new_data_count = self.count_new_labeled_data()

        # 3. 檢查模型性能
        recent_accuracy = self.evaluate_recent_performance()

        # 重訓練條件
        return (
            days_since_train >= 7 or          # 每週重訓練
            new_data_count >= 10000 or        # 有足夠新數據
            recent_accuracy < 0.85            # 性能下降
        )

    def incremental_update(self):
        """
        增量更新模型
        """
        print("🔄 開始增量更新...")

        # 1. 收集新數據
        new_data = self.collect_recent_data(days=7)

        # 2. 自動標記
        labeled = self.auto_label(new_data)

        # 3. 與舊數據合併
        full_dataset = self.merge_with_historical(labeled)

        # 4. 重新訓練
        self.retrain_models(full_dataset)

        # 5. 驗證性能
        self.validate_and_save()

        print("✅ 增量更新完成")
```

---

## 六、成本與性能優化

### 6.1 LLM 使用策略（優化版）

```python
class SmartLLMReasoner:
    """
    智能 LLM 推論器（成本優化）
    """

    def __init__(self, api_key, budget_per_day=50):
        self.llm = anthropic.Anthropic(api_key=api_key)
        self.budget = budget_per_day
        self.cost_tracker = DailyCostTracker()

    def analyze_if_worth(self, anomaly):
        """
        只對值得分析的案例使用 LLM
        """
        # 條件 1: 高風險
        is_high_risk = anomaly['behavior'] in [
            'port_scanning', 'network_scanning', 'data_exfiltration'
        ]

        # 條件 2: ML 分類不確定
        is_uncertain = anomaly['confidence'] < 0.75

        # 條件 3: 首次發現
        is_first_time = self.is_first_occurrence(anomaly['src_ip'], anomaly['behavior'])

        # 條件 4: 預算充足
        has_budget = self.cost_tracker.remaining_budget() > 0

        # 只有滿足所有條件才使用 LLM
        if is_high_risk and (is_uncertain or is_first_time) and has_budget:
            return self._llm_deep_analysis(anomaly)
        else:
            return self._rule_based_analysis(anomaly)

    def batch_analyze(self, anomalies):
        """
        批次分析（節省 API 調用）
        """
        # 將相似異常分組
        groups = self._group_similar_anomalies(anomalies)

        results = []
        for group in groups:
            # 每組只分析一個代表
            representative = group[0]
            analysis = self._llm_deep_analysis(representative)

            # 結論套用到整組
            for anomaly in group:
                results.append({
                    **anomaly,
                    'ai_analysis': analysis,
                    'note': f'基於相似案例推論 (組大小: {len(group)})'
                })

        return results

    def _group_similar_anomalies(self, anomalies):
        """
        將相似異常分組
        """
        from sklearn.cluster import DBSCAN
        import numpy as np

        # 提取特徵向量
        X = np.array([
            [
                a['flow_count'],
                a['unique_dsts'],
                a['avg_bytes']
            ]
            for a in anomalies
        ])

        # 聚類
        clustering = DBSCAN(eps=0.3, min_samples=2).fit(X)

        # 分組
        groups = {}
        for i, label in enumerate(clustering.labels_):
            if label not in groups:
                groups[label] = []
            groups[label].append(anomalies[i])

        return list(groups.values())
```

### 6.2 性能基準測試

```python
# 基於聚合數據的性能基準

PERFORMANCE_BENCHMARKS = {
    'data_loading': {
        'raw_index_query': '15-30s',          # 查詢原始數據
        'aggregated_index_query': '0.1-0.5s', # 查詢聚合數據 ✅
        'speedup': '100x'
    },

    'feature_extraction': {
        'from_raw': '10-20s',                 # 從原始數據聚合
        'from_aggregated': '0.01-0.05s',      # 從聚合數據提取 ✅
        'speedup': '200-400x'
    },

    'ml_inference': {
        'isolation_forest': '< 1s',           # 1000個樣本
        'random_forest': '< 2s',              # 1000個樣本
        'time_series_stats': '< 2s',          # 單個 IP
    },

    'total_realtime_analysis': {
        'target': '< 5s',                      # 目標延遲
        'typical': '3-4s',                     # 典型情況
        'worst_case': '< 10s'                  # 最壞情況
    }
}
```

---

## 七、完整實作範例

### 7.1 快速啟動腳本

```python
#!/usr/bin/env python3
# quick_start_ml_detection.py

"""
基於聚合數據的 ML 異常檢測 - 快速啟動

步驟：
1. 訓練 Isolation Forest（使用過去7天數據）
2. 訓練 Behavior Classifier（使用自動標記數據）
3. 執行實時檢測
"""

from nad.ml.optimized_isolation_forest import OptimizedIsolationForest
from nad.ml.behavior_classifier import BehaviorClassifier
from nad.core.realtime_engine import RealtimeAnomalyEngine

def main():
    print("="*60)
    print("ML 異常檢測系統 - 初始化")
    print("="*60)

    # Step 1: 訓練 Isolation Forest
    print("\n📚 Step 1: 訓練無監督異常檢測模型...")
    iso_forest = OptimizedIsolationForest()
    iso_forest.train_on_aggregated_data(days=7)

    # Step 2: 訓練 Behavior Classifier
    print("\n🎯 Step 2: 訓練行為分類器...")
    classifier = BehaviorClassifier()
    classifier.train()

    # Step 3: 啟動實時監控
    print("\n🚀 Step 3: 啟動實時監控...")
    engine = RealtimeAnomalyEngine()

    # 選擇模式
    mode = input("\n選擇運行模式:\n1. 單次分析\n2. 持續監控\n請選擇 (1/2): ")

    if mode == '1':
        results = engine.analyze_recent(minutes=10)
        print(f"\n發現 {len(results)} 個異常")
    else:
        engine.continuous_monitoring(interval_minutes=5)

if __name__ == "__main__":
    main()
```

---

## 八、總結與建議

### 基於 99.57% 覆蓋率的關鍵優勢

1. **數據質量保證**
   - ✅ 幾乎不遺漏 IP
   - ✅ 特徵完整且一致
   - ✅ 無需擔心數據偏差

2. **訓練效率提升**
   - ✅ 數據量適中（100萬筆 vs 40億筆）
   - ✅ 訓練時間短（分鐘級 vs 小時級）
   - ✅ 可頻繁重訓練

3. **推論延遲降低**
   - ✅ 實時檢測 < 5秒
   - ✅ 可每5分鐘執行
   - ✅ 支持持續監控

4. **成本大幅降低**
   - ✅ ES 查詢成本降低 100x
   - ✅ CPU/內存使用降低
   - ✅ LLM 調用次數可控

### 推薦實作路徑

**Week 1-2: 基礎 ML**
- ✅ 實作 Isolation Forest（基於聚合數據）
- ✅ 驗證性能和準確率
- ✅ 整合到定期分析

**Week 3-4: 行為分類**
- ✅ 自動生成訓練數據
- ✅ 訓練 Random Forest Classifier
- ✅ 優化特徵工程

**Week 5-6: 高級功能**
- ✅ 時間序列異常檢測
- ✅ LLM 深度分析（可選）
- ✅ 持續學習機制

**持續改進**
- ✅ 收集反饋
- ✅ 每週重訓練
- ✅ 性能監控

### 關鍵成功因素

1. **充分利用聚合數據**
   - 所有 ML 模型直接讀取 `netflow_stats_5m`
   - 特徵工程簡化且高效
   - 訓練和推論數據一致

2. **分層檢測策略**
   - Layer 1: 規則（快速篩選）
   - Layer 2: ML（精確分類）
   - Layer 3: LLM（深度分析）

3. **成本控制**
   - 優先使用本地 ML
   - LLM 僅用於高價值案例
   - 批次處理相似異常

4. **持續學習**
   - 自動標記新數據
   - 定期重訓練模型
   - 整合人工反饋

---

**文檔版本:** 2.0（優化版）
**更新日期:** 2025-11-11
**基於:** Transform 覆蓋率驗證結果（99.57%）
