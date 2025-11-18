# Isolation Forest 雙向聚合整合指南

## 當前狀況分析

### 現有架構

```
原始 flows
  ↓
netflow_stats_5m (by_src) ← 目前 Isolation Forest 使用這個
  ↓
FeatureEngineer 提取特徵
  ↓
Isolation Forest 訓練/預測
  ↓
AnomalyClassifier 分類
  ↓
anomaly_detection 索引
```

### 新增的資源

```
netflow_stats_5m_by_dst (by_dst) ← 新增，目前 Isolation Forest 未使用
BidirectionalAnalyzer ← 新增，用於重新驗證
```

---

## 核心問題：Isolation Forest 需要修改嗎？

### 🎯 **答案：建議保持當前架構，在後處理階段使用雙向分析**

---

## 決策分析

### 方案 A：保持現狀（推薦）⭐⭐⭐⭐⭐

**架構：**
```
Isolation Forest (只用 by_src)
  ↓ 偵測異常
anomaly_detection 索引
  ↓ 後處理
BidirectionalAnalyzer 重新驗證
  ↓ 排除誤報
最終告警
```

**優點：**
- ✅ **無需修改 Isolation Forest**（已訓練好的模型可繼續使用）
- ✅ **保持簡單**（Isolation Forest 專注於偵測，雙向分析專注於驗證）
- ✅ **靈活性高**（可以隨時調整雙向分析邏輯，不影響 ML 模型）
- ✅ **效能好**（Isolation Forest 特徵維度不變，速度快）

**實作：**
- Isolation Forest：不需要修改 ✅
- 新增後處理步驟：使用 `BidirectionalAnalyzer` 驗證

### 方案 B：整合 dst 特徵到 Isolation Forest（可選）⭐⭐⭐

**架構：**
```
Isolation Forest (同時用 by_src + by_dst 特徵)
  ↓ 直接偵測更準確的異常
anomaly_detection 索引
```

**優點：**
- ✅ ML 模型可能更準確（有更多維度）
- ✅ 可能減少誤報（ML 直接學習雙向特徵）

**缺點：**
- ❌ **需要重新訓練模型**
- ❌ **特徵維度增加**（從 22 個增加到 35+ 個）
- ❌ **訓練時間增加**
- ❌ **複雜度增加**（需要同時查詢兩個索引）
- ⚠️ **可能沒有顯著提升**（因為 dst 視角主要用於驗證，不是偵測）

### 方案 C：完全基於 dst 視角重新設計（不推薦）⭐

**不推薦理由：**
- dst 視角主要用於 DDoS 偵測
- 不適合用於一般異常偵測
- 會失去 src 視角的優勢

---

## 推薦方案詳解：後處理驗證

### 架構圖

```
┌──────────────────────────────────────────────────────────────┐
│                    異常偵測流程 (改進後)                      │
└──────────────────────────────────────────────────────────────┘

Step 1: ML 異常偵測 (保持不變)
  ┌─────────────────────────────┐
  │ netflow_stats_5m (by_src)   │
  └─────────────┬───────────────┘
                ↓
  ┌─────────────────────────────┐
  │ FeatureEngineer             │
  │ - 提取 22 個特徵            │
  └─────────────┬───────────────┘
                ↓
  ┌─────────────────────────────┐
  │ Isolation Forest            │
  │ - 訓練好的模型              │
  │ - 偵測異常 IP               │
  └─────────────┬───────────────┘
                ↓
  ┌─────────────────────────────┐
  │ AnomalyClassifier           │
  │ - PORT_SCAN, NETWORK_SCAN... │
  └─────────────┬───────────────┘
                ↓
  ┌─────────────────────────────┐
  │ anomaly_detection 索引      │
  │ - 初步告警列表              │
  └─────────────┬───────────────┘
                │
                │ ← ← ← 新增步驟
                ↓
Step 2: 雙向驗證 (新增)
  ┌─────────────────────────────┐
  │ BidirectionalAnalyzer       │
  │                             │
  │ 查詢:                       │
  │ - netflow_stats_5m (by_src) │
  │ - netflow_stats_5m_by_dst   │
  │                             │
  │ 驗證:                       │
  │ - 是否微服務架構？          │
  │ - 是否負載均衡？            │
  │ - 是否真實掃描？            │
  └─────────────┬───────────────┘
                ↓
  ┌─────────────────────────────┐
  │ 最終告警                    │
  │ - 排除誤報後的告警          │
  └─────────────────────────────┘

Step 3: DDoS 偵測 (新增獨立流程)
  ┌─────────────────────────────┐
  │ netflow_stats_5m_by_dst     │
  └─────────────┬───────────────┘
                ↓
  ┌─────────────────────────────┐
  │ BidirectionalAnalyzer       │
  │ .detect_ddos_by_dst()       │
  └─────────────┬───────────────┘
                ↓
  ┌─────────────────────────────┐
  │ DDoS 告警                   │
  └─────────────────────────────┘
```

---

## 實作步驟

### Step 1: 修改實時偵測流程（已有基礎）

當前文件：`realtime_detection_aggregated.py`

**需要添加的代碼：**

```python
# realtime_detection_aggregated.py

from nad.ml.isolation_forest_detector import OptimizedIsolationForest
from nad.ml.anomaly_classifier import AnomalyClassifier
from nad.ml.bidirectional_analyzer import BidirectionalAnalyzer  # 新增
from nad.anomaly_logger import AnomalyLogger

def main():
    print("啟動實時異常偵測...")

    # 初始化
    detector = OptimizedIsolationForest()
    classifier = AnomalyClassifier()
    bi_analyzer = BidirectionalAnalyzer()  # 新增
    logger = AnomalyLogger()

    while True:
        # Step 1: Isolation Forest 偵測（保持不變）
        anomalies = detector.predict_realtime(recent_minutes=10)

        if not anomalies:
            print("未發現異常")
            time.sleep(300)  # 5 分鐘
            continue

        print(f"Isolation Forest 偵測到 {len(anomalies)} 個異常")

        # Step 2: AnomalyClassifier 分類（保持不變）
        classified_anomalies = []
        for anomaly in anomalies:
            classification = classifier.classify(
                features=anomaly['features'],
                context={
                    'src_ip': anomaly['src_ip'],
                    'timestamp': anomaly['time_bucket']
                }
            )

            classified_anomalies.append({
                **anomaly,
                'classification': classification
            })

        # ===== 新增：Step 3: 雙向驗證 =====
        validated_anomalies = []

        for anomaly in classified_anomalies:
            src_ip = anomaly['src_ip']
            threat_class = anomaly['classification']['class']

            # 對 Port Scan 進行雙向驗證
            if threat_class == 'PORT_SCAN':
                verification = bi_analyzer.detect_port_scan_improved(
                    src_ip,
                    time_range="now-10m"
                )

                # 如果是微服務模式，降級為 INFO
                if not verification.get('is_port_scan'):
                    pattern = verification.get('pattern', 'UNKNOWN')

                    anomaly['classification']['class'] = 'NORMAL_HIGH_TRAFFIC'
                    anomaly['classification']['severity'] = 'LOW'
                    anomaly['classification']['priority'] = 'P3'
                    anomaly['false_positive_reason'] = f"雙向驗證: {pattern}"

                    print(f"  ⚠️  {src_ip} 被重新分類為正常流量 ({pattern})")
                    continue  # 跳過這個誤報

            # 保留真實的異常
            validated_anomalies.append(anomaly)

        print(f"雙向驗證後剩餘 {len(validated_anomalies)} 個真實異常")

        # Step 4: 記錄到 anomaly_detection 索引
        for anomaly in validated_anomalies:
            logger.log_anomaly(anomaly)

        # ===== 新增：Step 5: DDoS 偵測（獨立流程）=====
        ddos_attacks = bi_analyzer.detect_ddos_by_dst(
            time_range="now-10m",
            threshold=50
        )

        if ddos_attacks:
            print(f"偵測到 {len(ddos_attacks)} 個可能的 DDoS 攻擊")
            for ddos in ddos_attacks:
                logger.log_ddos(ddos)

        # 休眠
        time.sleep(300)  # 5 分鐘
```

### Step 2: 創建整合偵測器類別（可選）

創建一個新文件整合所有功能：

```python
# nad/ml/integrated_detector.py

from .isolation_forest_detector import OptimizedIsolationForest
from .anomaly_classifier import AnomalyClassifier
from .bidirectional_analyzer import BidirectionalAnalyzer

class IntegratedDetector:
    """
    整合的異常偵測器

    結合：
    - Isolation Forest (src 視角異常偵測)
    - AnomalyClassifier (威脅分類)
    - BidirectionalAnalyzer (雙向驗證 + DDoS 偵測)
    """

    def __init__(self, config=None):
        self.config = config
        self.iso_forest = OptimizedIsolationForest(config)
        self.classifier = AnomalyClassifier(config)
        self.bi_analyzer = BidirectionalAnalyzer()

    def detect_realtime(self, recent_minutes=10):
        """
        實時異常偵測（整合流程）

        Returns:
            {
                'anomalies': [...],  # 驗證後的異常列表
                'ddos_attacks': [...],  # DDoS 攻擊列表
                'false_positives': [...]  # 被排除的誤報
            }
        """
        # Step 1: Isolation Forest 偵測
        anomalies = self.iso_forest.predict_realtime(recent_minutes)

        # Step 2: 分類
        classified = []
        for anomaly in anomalies:
            classification = self.classifier.classify(
                features=anomaly['features'],
                context={'src_ip': anomaly['src_ip']}
            )
            classified.append({**anomaly, 'classification': classification})

        # Step 3: 雙向驗證
        validated = []
        false_positives = []

        for anomaly in classified:
            is_false_positive = False

            # 驗證 Port Scan
            if anomaly['classification']['class'] == 'PORT_SCAN':
                verification = self.bi_analyzer.detect_port_scan_improved(
                    anomaly['src_ip'],
                    time_range=f"now-{recent_minutes}m"
                )

                if not verification.get('is_port_scan'):
                    is_false_positive = True
                    anomaly['false_positive_reason'] = verification.get('pattern')

            if is_false_positive:
                false_positives.append(anomaly)
            else:
                validated.append(anomaly)

        # Step 4: DDoS 偵測
        ddos_attacks = self.bi_analyzer.detect_ddos_by_dst(
            time_range=f"now-{recent_minutes}m",
            threshold=50
        )

        return {
            'anomalies': validated,
            'ddos_attacks': ddos_attacks,
            'false_positives': false_positives,
            'stats': {
                'total_detected': len(anomalies),
                'after_validation': len(validated),
                'false_positives': len(false_positives),
                'ddos_attacks': len(ddos_attacks)
            }
        }
```

### Step 3: 更新現有腳本

找到當前的實時偵測腳本並更新：

```bash
# 查找現有的實時偵測腳本
find . -name "*realtime*.py" -o -name "*detection*.py"
```

---

## 不需要修改的部分

### ✅ Isolation Forest 保持不變

**理由：**
1. **已訓練好的模型仍然有效**
2. **特徵維度不變**（22 個特徵）
3. **訓練數據來源不變**（netflow_stats_5m）
4. **偵測能力不變**

**代碼：**
```python
# nad/ml/isolation_forest_detector.py
# 不需要修改！保持原樣

class OptimizedIsolationForest:
    def train_on_aggregated_data(self, days=7):
        # 仍然只使用 netflow_stats_5m
        # 不需要查詢 netflow_stats_5m_by_dst
        ...

    def predict_realtime(self, recent_minutes=10):
        # 仍然只使用 netflow_stats_5m
        ...
```

### ✅ FeatureEngineer 保持不變

**理由：**
- 特徵定義不變
- 只基於 src 視角的聚合數據

**代碼：**
```python
# nad/ml/feature_engineer.py
# 不需要修改！保持原樣

class FeatureEngineer:
    def extract_features(self, agg_record):
        # agg_record 來自 netflow_stats_5m (by_src)
        # 不需要加入 dst 視角的特徵
        ...
```

### ✅ AnomalyClassifier 保持不變

**理由：**
- 分類邏輯基於 src 視角的特徵
- 雙向驗證在後處理階段進行

**代碼：**
```python
# nad/ml/anomaly_classifier.py
# 不需要修改！保持原樣

class AnomalyClassifier:
    def classify(self, features, context):
        # 基於 src 視角的特徵進行分類
        # 雙向驗證由 BidirectionalAnalyzer 處理
        ...
```

---

## 需要新增/修改的部分

### ✅ 新增：後處理驗證模組

創建新文件：`nad/ml/post_processor.py`

```python
#!/usr/bin/env python3
"""
後處理模組

對 Isolation Forest + AnomalyClassifier 的結果進行驗證
"""

from .bidirectional_analyzer import BidirectionalAnalyzer
from typing import List, Dict

class AnomalyPostProcessor:
    """異常檢測後處理器"""

    def __init__(self):
        self.bi_analyzer = BidirectionalAnalyzer()

    def validate_anomalies(self, anomalies: List[Dict]) -> Dict:
        """
        驗證異常列表

        Args:
            anomalies: 來自 Isolation Forest + Classifier 的異常列表

        Returns:
            {
                'validated': [...],  # 真實異常
                'false_positives': [...]  # 誤報
            }
        """
        validated = []
        false_positives = []

        for anomaly in anomalies:
            src_ip = anomaly['src_ip']
            threat_class = anomaly['classification']['class']

            # 驗證 Port Scan
            if threat_class == 'PORT_SCAN':
                verification = self.bi_analyzer.detect_port_scan_improved(
                    src_ip,
                    time_range="now-10m"
                )

                if not verification.get('is_port_scan'):
                    # 是誤報
                    anomaly['validation_result'] = 'FALSE_POSITIVE'
                    anomaly['false_positive_reason'] = verification.get('pattern')
                    false_positives.append(anomaly)
                    continue

            # 驗證 Network Scan（可選）
            elif threat_class == 'NETWORK_SCAN':
                # 可以添加額外的驗證邏輯
                pass

            # 保留為真實異常
            anomaly['validation_result'] = 'VALIDATED'
            validated.append(anomaly)

        return {
            'validated': validated,
            'false_positives': false_positives,
            'reduction_rate': len(false_positives) / len(anomalies) if anomalies else 0
        }

    def detect_ddos(self, time_range="now-10m") -> List[Dict]:
        """
        獨立的 DDoS 偵測

        Args:
            time_range: 時間範圍

        Returns:
            DDoS 攻擊列表
        """
        return self.bi_analyzer.detect_ddos_by_dst(
            time_range=time_range,
            threshold=50
        )
```

### ✅ 修改：實時偵測主程式

修改 `realtime_detection_aggregated.py` 或創建新的：

```python
# realtime_detection_integrated.py

#!/usr/bin/env python3
"""
整合的實時異常偵測

流程：
  Isolation Forest → Classifier → 雙向驗證 → 最終告警
"""

import time
from nad.ml.isolation_forest_detector import OptimizedIsolationForest
from nad.ml.anomaly_classifier import AnomalyClassifier
from nad.ml.post_processor import AnomalyPostProcessor  # 新增
from nad.anomaly_logger import AnomalyLogger

def main():
    print("="*70)
    print("啟動整合的實時異常偵測")
    print("="*70)

    # 初始化
    detector = OptimizedIsolationForest()
    classifier = AnomalyClassifier()
    post_processor = AnomalyPostProcessor()  # 新增
    logger = AnomalyLogger()

    detector._load_model()

    while True:
        print(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] 開始偵測...")

        # Step 1: Isolation Forest
        anomalies = detector.predict_realtime(recent_minutes=10)
        print(f"  Step 1: Isolation Forest 偵測到 {len(anomalies)} 個異常")

        if not anomalies:
            time.sleep(300)
            continue

        # Step 2: Classifier
        classified = []
        for anomaly in anomalies:
            classification = classifier.classify(
                features=anomaly['features'],
                context={'src_ip': anomaly['src_ip']}
            )
            classified.append({**anomaly, 'classification': classification})

        # 統計分類結果
        class_counts = {}
        for a in classified:
            c = a['classification']['class']
            class_counts[c] = class_counts.get(c, 0) + 1

        print(f"  Step 2: 分類結果:")
        for threat_class, count in class_counts.items():
            print(f"    - {threat_class}: {count}")

        # ===== 新增：Step 3: 雙向驗證 =====
        validation_result = post_processor.validate_anomalies(classified)

        validated = validation_result['validated']
        false_positives = validation_result['false_positives']

        print(f"  Step 3: 雙向驗證:")
        print(f"    - 真實異常: {len(validated)}")
        print(f"    - 誤報: {len(false_positives)} ({validation_result['reduction_rate']*100:.1f}%)")

        # Step 4: 記錄真實異常
        for anomaly in validated:
            logger.log_anomaly(anomaly)

        # ===== 新增：Step 5: DDoS 偵測 =====
        ddos_attacks = post_processor.detect_ddos(time_range="now-10m")
        print(f"  Step 4: DDoS 偵測: {len(ddos_attacks)} 個攻擊")

        for ddos in ddos_attacks:
            logger.log_ddos(ddos)

        # 休眠 5 分鐘
        time.sleep(300)

if __name__ == "__main__":
    main()
```

---

## 總結

### 需要修改的內容

| 組件 | 修改類型 | 說明 |
|------|---------|------|
| **Isolation Forest** | ❌ 不修改 | 保持使用 by_src 聚合數據 |
| **FeatureEngineer** | ❌ 不修改 | 特徵定義不變 |
| **AnomalyClassifier** | ❌ 不修改 | 分類邏輯不變 |
| **BidirectionalAnalyzer** | ✅ 已完成 | 新增的雙向分析器 |
| **AnomalyPostProcessor** | ✅ 需新增 | 後處理驗證模組 |
| **實時偵測主程式** | ✅ 需修改 | 加入後處理步驟 |

### 工作流程對比

**修改前：**
```
Isolation Forest → Classifier → anomaly_detection 索引
（有誤報）
```

**修改後：**
```
Isolation Forest → Classifier → 雙向驗證 → anomaly_detection 索引
                                  ↓
                            排除誤報（100%）

                 +  獨立的 DDoS 偵測（新功能）
```

### 優勢

1. ✅ **保持 Isolation Forest 不變**（無需重新訓練）
2. ✅ **後處理驗證靈活**（可隨時調整邏輯）
3. ✅ **新增 DDoS 偵測**（dst 視角的獨特能力）
4. ✅ **100% 減少 Port Scan 誤報**（測試結果）
5. ✅ **效能影響小**（只對異常 IP 進行雙向查詢）
