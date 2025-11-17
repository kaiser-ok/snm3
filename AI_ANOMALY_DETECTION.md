# AI 輔助網路異常偵測系統設計

## 概述

將類似本次分析的 **AI 推論能力**整合到自動化異常偵測系統中，實現：
1. 自動化模式識別
2. 智能異常分類
3. 根因分析推論
4. 行為關聯分析
5. 風險評估與建議

---

## 一、AI 推論機制設計

### 1.1 多層次推論架構

```
原始流量數據
    ↓
┌─────────────────────────────────────────┐
│  Layer 1: 規則引擎 (Rule-based)          │
│  - 明確的閾值檢測                         │
│  - 已知攻擊模式匹配                       │
│  - 速度快、準確率高                       │
└─────────────────┬───────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│  Layer 2: 統計異常檢測 (Statistical)     │
│  - Isolation Forest (孤立森林)           │
│  - Z-Score / IQR 異常檢測                │
│  - 時間序列異常 (ARIMA, Prophet)         │
└─────────────────┬───────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│  Layer 3: 機器學習分類 (ML Classification)│
│  - 行為分類器 (掃描/DDoS/正常/...)       │
│  - 隨機森林 / XGBoost                    │
│  - 神經網路分類器                         │
└─────────────────┬───────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│  Layer 4: LLM 智能分析 (AI Reasoning)    │
│  - 根因分析推論                          │
│  - 關聯事件分析                          │
│  - 自然語言報告生成                       │
│  - 修復建議生成                          │
└─────────────────────────────────────────┘
```

---

## 二、具體實作方案

### 方案 A: 輕量級 ML 模型 (推薦優先實作)

**優點:**
- 可離線運行
- 低延遲 (<100ms)
- 可解釋性強
- 不需外部 API

#### 2.1 Isolation Forest 異常檢測

```python
# nad/ml/isolation_forest_detector.py

from sklearn.ensemble import IsolationForest
import numpy as np
import pickle
import os

class IsolationForestDetector:
    """
    使用 Isolation Forest 進行無監督異常檢測
    """

    def __init__(self, model_path='models/isolation_forest.pkl'):
        self.model = None
        self.model_path = model_path
        self.feature_names = [
            'connections_per_hour',
            'unique_destinations',
            'unique_ports',
            'avg_bytes_per_connection',
            'total_bytes',
            'tcp_ratio',
            'udp_ratio',
            'connection_rate',
            'port_diversity',
            'dst_ip_entropy'
        ]

    def train(self, training_data, contamination=0.1):
        """
        訓練模型

        Args:
            training_data: 正常流量的特徵數據
            contamination: 預期異常比例 (0.1 = 10%)
        """
        X = self._extract_features(training_data)

        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto'
        )

        self.model.fit(X)
        self._save_model()

        return self

    def predict(self, flow_data):
        """
        預測是否異常

        Returns:
            anomaly_scores: -1 為異常, 1 為正常
            confidence: 異常置信度 (0-1)
        """
        if not self.model:
            self._load_model()

        X = self._extract_features(flow_data)
        predictions = self.model.predict(X)

        # 獲取異常分數 (越負越異常)
        scores = self.model.score_samples(X)

        # 轉換為 0-1 的置信度
        confidence = self._normalize_scores(scores)

        results = []
        for i, (pred, conf, data) in enumerate(zip(predictions, confidence, flow_data)):
            results.append({
                'is_anomaly': pred == -1,
                'confidence': conf,
                'anomaly_score': scores[i],
                'src_ip': data.get('src_ip'),
                'features': dict(zip(self.feature_names, X[i]))
            })

        return results

    def _extract_features(self, flow_data):
        """
        從流量數據提取特徵向量
        """
        features = []

        for record in flow_data:
            feature_vector = [
                record.get('connection_count', 0),
                record.get('unique_destinations', 0),
                record.get('unique_ports', 0),
                record.get('avg_bytes_per_connection', 0),
                record.get('total_bytes', 0),
                record.get('tcp_ratio', 0),
                record.get('udp_ratio', 0),
                record.get('connection_rate', 0),
                self._calculate_port_diversity(record),
                self._calculate_entropy(record.get('destination_ips', []))
            ]
            features.append(feature_vector)

        return np.array(features)

    def _calculate_port_diversity(self, record):
        """計算端口多樣性"""
        unique_ports = record.get('unique_ports', 0)
        total_connections = record.get('connection_count', 1)
        return unique_ports / total_connections if total_connections > 0 else 0

    def _calculate_entropy(self, ip_list):
        """計算 IP 分布的熵值"""
        if not ip_list:
            return 0

        from collections import Counter
        import math

        counts = Counter(ip_list)
        total = len(ip_list)
        entropy = -sum(
            (count/total) * math.log2(count/total)
            for count in counts.values()
        )
        return entropy

    def _normalize_scores(self, scores):
        """
        將異常分數正規化為 0-1 的置信度
        """
        # Isolation Forest 分數通常在 -0.5 到 0.5 之間
        # 越負越異常
        normalized = []
        for score in scores:
            # 轉換為 0-1，0 為正常，1 為高度異常
            confidence = max(0, min(1, (-score + 0.25) * 2))
            normalized.append(confidence)
        return normalized

    def _save_model(self):
        """保存模型"""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)

    def _load_model(self):
        """加載模型"""
        if os.path.exists(self.model_path):
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
        else:
            raise FileNotFoundError(f"模型文件不存在: {self.model_path}")
```

#### 2.2 行為分類器

```python
# nad/ml/behavior_classifier.py

from sklearn.ensemble import RandomForestClassifier
import numpy as np

class BehaviorClassifier:
    """
    流量行為分類器
    分類: 正常、掃描、DDoS、數據外洩、DNS濫用
    """

    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            random_state=42
        )
        self.behavior_labels = {
            0: 'normal',
            1: 'port_scanning',
            2: 'network_scanning',
            3: 'ddos',
            4: 'data_exfiltration',
            5: 'dns_abuse',
            6: 'brute_force'
        }

    def train(self, labeled_data):
        """
        使用標記數據訓練

        labeled_data: [
            {
                'features': {...},
                'label': 'port_scanning'
            },
            ...
        ]
        """
        X = []
        y = []

        label_to_int = {v: k for k, v in self.behavior_labels.items()}

        for record in labeled_data:
            features = self._extract_features(record['features'])
            label = label_to_int[record['label']]
            X.append(features)
            y.append(label)

        self.model.fit(np.array(X), np.array(y))

    def predict(self, flow_data):
        """
        預測流量行為類型
        """
        results = []

        for record in flow_data:
            features = self._extract_features(record)
            prediction = self.model.predict([features])[0]
            probabilities = self.model.predict_proba([features])[0]

            behavior = self.behavior_labels[prediction]
            confidence = probabilities[prediction]

            # 獲取特徵重要性
            feature_importance = self._get_top_features(features)

            results.append({
                'src_ip': record.get('src_ip'),
                'behavior': behavior,
                'confidence': confidence,
                'all_probabilities': {
                    self.behavior_labels[i]: prob
                    for i, prob in enumerate(probabilities)
                },
                'key_indicators': feature_importance
            })

        return results

    def _extract_features(self, record):
        """提取分類特徵"""
        return [
            record.get('connection_count', 0),
            record.get('unique_destinations', 0),
            record.get('unique_ports', 0),
            record.get('avg_bytes_per_connection', 0),
            record.get('connection_rate', 0),
            record.get('tcp_ratio', 0),
            record.get('udp_ratio', 0),
            # 衍生特徵
            record.get('unique_destinations', 0) / max(record.get('connection_count', 1), 1),  # 目標多樣性
            record.get('unique_ports', 0) / max(record.get('connection_count', 1), 1),  # 端口多樣性
            1 if record.get('avg_bytes_per_connection', 0) < 1000 else 0,  # 小封包標記
            1 if record.get('dns_query_count', 0) > 1000 else 0,  # DNS 密集標記
        ]

    def _get_top_features(self, features):
        """獲取最重要的特徵"""
        feature_names = [
            'connection_count',
            'unique_destinations',
            'unique_ports',
            'avg_bytes',
            'connection_rate',
            'tcp_ratio',
            'udp_ratio',
            'dest_diversity',
            'port_diversity',
            'is_small_packet',
            'is_dns_heavy'
        ]

        importances = self.model.feature_importances_
        indices = np.argsort(importances)[-3:]  # Top 3

        return [
            {
                'feature': feature_names[i],
                'value': features[i],
                'importance': importances[i]
            }
            for i in indices
        ]
```

---

### 方案 B: LLM 智能推論 (進階)

**優點:**
- 強大的推論能力
- 自然語言報告
- 關聯分析
- 持續學習

**使用場景:**
- 複雜異常的根因分析
- 生成可讀的分析報告
- 提供修復建議

#### 2.3 LLM 推論引擎

```python
# nad/ai/llm_reasoner.py

import anthropic
import json
from typing import Dict, List

class LLMReasoner:
    """
    使用 LLM 進行智能推論和分析
    """

    def __init__(self, api_key=None):
        self.client = anthropic.Anthropic(api_key=api_key) if api_key else None
        self.use_local_llm = not api_key  # 如果沒有 API key，使用本地規則

    def analyze_anomaly(self, anomaly_data: Dict, context: Dict) -> Dict:
        """
        深度分析異常事件

        Args:
            anomaly_data: 異常數據
            context: 上下文信息 (設備資訊、歷史數據等)

        Returns:
            分析結果包含: 根因、建議、風險評估
        """
        if self.use_local_llm:
            return self._rule_based_analysis(anomaly_data, context)

        # 構建提示詞
        prompt = self._build_analysis_prompt(anomaly_data, context)

        # 調用 LLM
        response = self.client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=2000,
            temperature=0.3,
            system=self._get_system_prompt(),
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        # 解析回應
        analysis = self._parse_llm_response(response.content[0].text)

        return analysis

    def _build_analysis_prompt(self, anomaly_data: Dict, context: Dict) -> str:
        """
        構建 LLM 分析提示詞
        """
        prompt = f"""
請分析以下網路異常事件：

## 異常數據
IP 地址: {anomaly_data.get('src_ip')}
設備名稱: {context.get('device_name', '未知')}
設備類型: {context.get('device_type', '未知')}

異常指標:
- 連線數: {anomaly_data.get('connection_count', 0):,}
- 唯一目的地: {anomaly_data.get('unique_destinations', 0)}
- 唯一端口: {anomaly_data.get('unique_ports', 0)}
- 平均每連線流量: {anomaly_data.get('avg_bytes_per_connection', 0):.2f} bytes
- 總流量: {anomaly_data.get('total_bytes', 0) / 1024 / 1024:.2f} MB

協定分布:
- TCP: {anomaly_data.get('tcp_ratio', 0) * 100:.1f}%
- UDP: {anomaly_data.get('udp_ratio', 0) * 100:.1f}%

主要目的端口: {anomaly_data.get('top_ports', [])}

異常分類: {anomaly_data.get('behavior_classification', '未知')}
異常評分: {anomaly_data.get('anomaly_score', 0)}/100

## 歷史對比
過去7天平均連線數: {context.get('baseline_connections', 0):,}
偏差: {context.get('deviation_percentage', 0):.1f}%

## 請提供以下分析:

1. **根因分析**: 造成此異常的最可能原因是什麼？
2. **行為判斷**: 這是惡意行為、配置錯誤、還是正常業務行為？
3. **風險評估**: 風險等級 (低/中/高/嚴重) 及理由
4. **關聯分析**: 是否與其他異常事件相關？
5. **建議措施**: 具體的調查步驟和修復建議

請以 JSON 格式回覆，包含以下欄位:
{{
  "root_cause": "...",
  "behavior_type": "malicious|misconfiguration|normal",
  "risk_level": "low|medium|high|critical",
  "risk_reasoning": "...",
  "correlations": ["..."],
  "recommendations": [
    {{
      "priority": "immediate|high|medium|low",
      "action": "...",
      "reason": "..."
    }}
  ],
  "additional_investigation": ["..."]
}}
"""
        return prompt

    def _get_system_prompt(self) -> str:
        """
        系統提示詞
        """
        return """你是一位資深的網路安全分析專家，專精於：
1. 網路流量分析
2. 異常行為偵測
3. 資安事件調查
4. 根因分析

你的任務是分析 NetFlow 數據中的異常事件，提供專業的判斷和建議。

分析原則:
- 基於數據和事實進行推論
- 考慮多種可能性，但指出最可能的原因
- 提供可執行的具體建議
- 評估風險時保持客觀
- 使用專業但清晰的語言

已知的異常模式:
- 端口掃描: 高連線數、多目的地、小流量
- 網路掃描: 極多目的地、小流量、快速連線
- DDoS: 極高連線數、單一或少數目的地
- 數據外洩: 大量數據傳輸到外部 IP
- DNS 濫用: 大量 DNS 查詢 (可能是 DNS 隧道)
- 暴力破解: 多次連線到認證端口 (22, 3389, 等)
"""

    def _parse_llm_response(self, response_text: str) -> Dict:
        """
        解析 LLM 回應
        """
        try:
            # 嘗試提取 JSON
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            json_str = response_text[start:end]
            return json.loads(json_str)
        except:
            # 如果無法解析，返回原始文本
            return {
                "root_cause": "分析失敗",
                "raw_response": response_text
            }

    def _rule_based_analysis(self, anomaly_data: Dict, context: Dict) -> Dict:
        """
        基於規則的分析 (備用方案)
        """
        behavior = anomaly_data.get('behavior_classification', 'unknown')
        connections = anomaly_data.get('connection_count', 0)
        unique_dsts = anomaly_data.get('unique_destinations', 0)
        avg_bytes = anomaly_data.get('avg_bytes_per_connection', 0)

        # 簡單規則推論
        if behavior == 'port_scanning':
            root_cause = "設備正在進行端口掃描，可能是安全掃描工具或惡意軟體"
            risk_level = "high"
            behavior_type = "malicious" if context.get('device_type') != 'security_scanner' else "normal"

        elif behavior == 'dns_abuse':
            root_cause = "DNS 查詢頻率異常，可能是 DNS 配置錯誤或 DNS 隧道攻擊"
            risk_level = "high"
            behavior_type = "misconfiguration"

        else:
            root_cause = "流量模式異常，需進一步調查"
            risk_level = "medium"
            behavior_type = "unknown"

        return {
            "root_cause": root_cause,
            "behavior_type": behavior_type,
            "risk_level": risk_level,
            "risk_reasoning": f"基於規則引擎分析",
            "recommendations": [
                {
                    "priority": "high",
                    "action": f"調查 {anomaly_data.get('src_ip')} 的異常行為",
                    "reason": root_cause
                }
            ]
        }

    def generate_report(self, analysis_results: List[Dict]) -> str:
        """
        生成自然語言分析報告
        """
        if self.use_local_llm:
            return self._template_based_report(analysis_results)

        # 構建提示詞
        prompt = f"""
根據以下異常分析結果，生成一份專業的網路安全分析報告:

{json.dumps(analysis_results, indent=2, ensure_ascii=False)}

報告要求:
1. 執行摘要 (100字內)
2. 關鍵發現 (3-5點)
3. 風險評估
4. 建議措施 (按優先級排序)
5. 結論

使用 Markdown 格式，語氣專業但易懂。
"""

        response = self.client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=3000,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

    def _template_based_report(self, results: List[Dict]) -> str:
        """
        基於模板的報告生成
        """
        critical_count = len([r for r in results if r.get('risk_level') == 'critical'])
        high_count = len([r for r in results if r.get('risk_level') == 'high'])

        report = f"""
# 網路異常分析報告

## 執行摘要
發現 {len(results)} 個異常事件，其中 {critical_count} 個嚴重、{high_count} 個高風險。

## 關鍵發現
"""
        for i, result in enumerate(results[:5], 1):
            report += f"\n{i}. {result.get('root_cause', '未知異常')}"

        return report
```

---

## 三、整合到定期分析流程

### 3.1 增強的分析引擎

```python
# nad/core/enhanced_engine.py

from nad.ml.isolation_forest_detector import IsolationForestDetector
from nad.ml.behavior_classifier import BehaviorClassifier
from nad.ai.llm_reasoner import LLMReasoner

class EnhancedAnalysisEngine:
    """
    AI 增強的分析引擎
    """

    def __init__(self, config):
        self.config = config

        # 傳統組件
        self.es_client = ElasticSearchClient(config)
        self.mysql_client = MySQLClient(config)
        self.analyzer = TrafficAnalyzer()

        # ML/AI 組件
        self.anomaly_detector = IsolationForestDetector()
        self.behavior_classifier = BehaviorClassifier()
        self.llm_reasoner = LLMReasoner(api_key=config.get('anthropic_api_key'))

        # 基準線
        self.baseline_manager = BaselineManager()

    def analyze(self, timeframe='1h'):
        """
        完整的 AI 增強分析流程
        """
        print("🔍 Step 1: 收集數據...")
        traffic_data = self._fetch_aggregated_data(timeframe)

        print("📊 Step 2: 統計分析...")
        statistics = self.analyzer.analyze(traffic_data)

        print("🤖 Step 3: ML 異常檢測...")
        ml_anomalies = self.anomaly_detector.predict(traffic_data)

        print("🎯 Step 4: 行為分類...")
        behaviors = self.behavior_classifier.predict(
            [a for a in ml_anomalies if a['is_anomaly']]
        )

        print("🧠 Step 5: AI 深度分析...")
        ai_insights = self._ai_deep_analysis(behaviors)

        print("📝 Step 6: 生成報告...")
        report = self._generate_enhanced_report(
            statistics, ml_anomalies, behaviors, ai_insights
        )

        return {
            'statistics': statistics,
            'ml_anomalies': ml_anomalies,
            'behaviors': behaviors,
            'ai_insights': ai_insights,
            'report': report
        }

    def _ai_deep_analysis(self, behaviors):
        """
        對高風險異常進行 AI 深度分析
        """
        insights = []

        # 只對高風險異常進行 LLM 分析 (節省成本)
        high_risk_behaviors = [
            b for b in behaviors
            if b['behavior'] in ['port_scanning', 'ddos', 'data_exfiltration']
            and b['confidence'] > 0.7
        ]

        for behavior in high_risk_behaviors:
            # 獲取上下文信息
            context = self._get_context(behavior['src_ip'])

            # LLM 分析
            insight = self.llm_reasoner.analyze_anomaly(behavior, context)

            insights.append({
                'src_ip': behavior['src_ip'],
                'behavior': behavior['behavior'],
                'ai_analysis': insight
            })

        return insights

    def _get_context(self, ip):
        """
        獲取 IP 的上下文信息
        """
        # 從 MySQL 獲取設備信息
        device_info = self.mysql_client.get_device_by_ip(ip)

        # 從基準線獲取歷史數據
        baseline = self.baseline_manager.get_baseline(ip)

        return {
            'device_name': device_info.get('Name'),
            'device_type': device_info.get('Type'),
            'baseline_connections': baseline.get('avg_connections'),
            'deviation_percentage': self._calculate_deviation(ip, baseline)
        }
```

### 3.2 定期執行腳本

```python
#!/usr/bin/env python3
# scripts/ai_periodic_analysis.py

import schedule
import time
from nad.core.enhanced_engine import EnhancedAnalysisEngine
from nad.utils.config import load_config

def run_analysis():
    """
    執行 AI 增強分析
    """
    config = load_config()
    engine = EnhancedAnalysisEngine(config)

    print(f"\n{'='*60}")
    print(f"開始分析: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    # 執行分析
    result = engine.analyze(timeframe='1h')

    # 保存報告
    report_path = f"reports/ai_analysis_{time.strftime('%Y%m%d_%H%M%S')}.md"
    with open(report_path, 'w') as f:
        f.write(result['report'])

    print(f"\n✅ 分析完成，報告已保存: {report_path}\n")

    # 如果有嚴重異常，發送通知 (可選)
    critical_anomalies = [
        a for a in result['ai_insights']
        if a['ai_analysis'].get('risk_level') == 'critical'
    ]

    if critical_anomalies:
        send_alert(critical_anomalies)

def send_alert(anomalies):
    """
    發送告警 (可選)
    """
    # 實作告警邏輯
    pass

if __name__ == "__main__":
    # 每小時執行一次
    schedule.every(1).hours.do(run_analysis)

    # 立即執行一次
    run_analysis()

    # 持續運行
    while True:
        schedule.run_pending()
        time.sleep(60)
```

---

## 四、訓練數據準備

### 4.1 標記數據生成

```python
# scripts/generate_training_data.py

def generate_labeled_dataset():
    """
    從歷史數據生成標記訓練集
    """

    # 1. 從已知良好時段採樣正常流量
    normal_samples = sample_normal_traffic(
        date_range=('2025-11-01', '2025-11-10'),
        hours=(9, 18),  # 工作時間
        exclude_ips=['192.168.10.135']  # 排除已知異常
    )

    # 2. 從已知事件標記異常流量
    labeled_anomalies = [
        {
            'ip': '192.168.10.135',
            'date': '2025-11-11',
            'label': 'port_scanning',
            'confidence': 1.0
        },
        {
            'ip': '192.168.20.56',
            'date': '2025-11-11',
            'label': 'dns_abuse',
            'confidence': 1.0
        }
    ]

    # 3. 合成異常樣本 (可選)
    synthetic_anomalies = generate_synthetic_anomalies()

    # 4. 組合並保存
    dataset = {
        'normal': normal_samples,
        'anomalies': labeled_anomalies + synthetic_anomalies
    }

    save_dataset(dataset, 'training_data/labeled_flows.json')
```

### 4.2 自動化標記

```python
def auto_label_with_confidence():
    """
    使用規則引擎自動標記，並設定置信度
    """
    unlabeled_data = load_historical_data()

    auto_labeled = []
    for record in unlabeled_data:
        label, confidence = apply_labeling_rules(record)

        if confidence > 0.8:  # 只保留高置信度標記
            auto_labeled.append({
                'features': record,
                'label': label,
                'confidence': confidence,
                'method': 'auto_rule_based'
            })

    return auto_labeled

def apply_labeling_rules(record):
    """
    規則引擎標記
    """
    if (record['unique_dests'] > 100 and
        record['avg_bytes'] < 5000 and
        record['connections'] > 1000):
        return 'network_scanning', 0.95

    if (record['dst_port_53_ratio'] > 0.8 and
        record['connections'] > 10000):
        return 'dns_abuse', 0.90

    if record['connections'] < 100:
        return 'normal', 0.85

    return 'unknown', 0.5
```

---

## 五、持續學習機制

### 5.1 模型更新策略

```python
class ModelUpdateManager:
    """
    管理 ML 模型的持續學習
    """

    def __init__(self):
        self.update_frequency = 'weekly'  # 每週更新
        self.min_new_samples = 1000  # 最少新樣本數

    def should_update(self):
        """
        判斷是否需要更新模型
        """
        last_update = self.get_last_update_time()
        new_samples_count = self.count_new_labeled_samples()

        time_elapsed = datetime.now() - last_update

        return (
            time_elapsed > timedelta(days=7) and
            new_samples_count >= self.min_new_samples
        )

    def update_models(self):
        """
        重新訓練模型
        """
        print("📚 收集訓練數據...")
        training_data = self.collect_training_data()

        print("🏋️ 訓練 Isolation Forest...")
        self.train_isolation_forest(training_data['normal'])

        print("🎯 訓練行為分類器...")
        self.train_behavior_classifier(training_data['labeled'])

        print("✅ 模型更新完成")
        self.save_update_timestamp()

    def collect_training_data(self):
        """
        收集訓練數據
        """
        return {
            'normal': load_normal_samples(),
            'labeled': load_labeled_samples()
        }
```

### 5.2 人工反饋循環

```python
def incorporate_human_feedback():
    """
    整合人工反饋改進模型
    """

    # 1. 收集分析師反饋
    feedback = load_analyst_feedback()
    # Format: {'prediction_id': 'xxx', 'actual_label': 'yyy', 'notes': '...'}

    # 2. 更新標記數據
    for fb in feedback:
        update_label(fb['prediction_id'], fb['actual_label'])

    # 3. 識別誤報模式
    false_positives = identify_false_positive_patterns(feedback)

    # 4. 調整規則或重訓練
    if len(false_positives) > 10:
        adjust_detection_rules(false_positives)
        retrain_models()
```

---

## 六、成本與效能考量

### 6.1 LLM API 成本優化

```python
class CostOptimizedLLMReasoner(LLMReasoner):
    """
    成本優化的 LLM 推論器
    """

    def __init__(self, api_key, budget_per_hour=10):
        super().__init__(api_key)
        self.budget_per_hour = budget_per_hour
        self.cost_tracker = CostTracker()

    def analyze_anomaly(self, anomaly_data, context):
        """
        帶成本控制的分析
        """
        # 1. 先用本地規則快速評估
        quick_assessment = self._rule_based_analysis(anomaly_data, context)

        # 2. 只對高風險且模糊的案例使用 LLM
        if (quick_assessment['risk_level'] in ['high', 'critical'] and
            self._is_ambiguous(anomaly_data)):

            # 3. 檢查預算
            if self.cost_tracker.can_afford_query():
                return super().analyze_anomaly(anomaly_data, context)
            else:
                return quick_assessment  # 預算用完，降級到規則引擎

        return quick_assessment

    def _is_ambiguous(self, data):
        """
        判斷是否為模糊案例，需要 LLM 分析
        """
        # 例如: 行為分類置信度低於 0.7
        return data.get('classification_confidence', 1.0) < 0.7
```

### 6.2 批次處理策略

```python
def batch_llm_analysis(anomalies):
    """
    批次處理多個異常，節省成本
    """
    # 將相似異常分組
    grouped = group_similar_anomalies(anomalies)

    results = []
    for group in grouped:
        # 對每組只分析一個代表性樣本
        representative = group[0]
        analysis = llm_reasoner.analyze_anomaly(representative)

        # 將結論套用到整組
        for anomaly in group:
            results.append({
                'anomaly': anomaly,
                'analysis': analysis,
                'note': f'基於相似案例推論 (群組大小: {len(group)})'
            })

    return results
```

---

## 七、總結與建議

### 推薦實作路徑:

#### Phase 1 (Week 1-2): 基礎 ML
✅ 實作 Isolation Forest 異常檢測
✅ 建立初始訓練數據集
✅ 整合到定期分析流程

#### Phase 2 (Week 3-4): 行為分類
✅ 訓練行為分類器
✅ 標記歷史數據
✅ 調優模型參數

#### Phase 3 (Week 5-6): LLM 增強
✅ 整合 LLM 深度分析 (可選)
✅ 成本優化策略
✅ 自然語言報告生成

#### Phase 4 (持續): 改進循環
✅ 收集反饋
✅ 持續訓練
✅ 模型版本管理

### 關鍵優勢:

🎯 **準確率提升**: ML 可識別規則難以描述的模式
🚀 **效率提升**: 自動化分析，減少人工工作量
🧠 **深度洞察**: LLM 提供根因分析和建議
📈 **持續改進**: 從反饋中學習，越用越準

---

**文檔版本:** 1.0
**更新日期:** 2025-11-11
