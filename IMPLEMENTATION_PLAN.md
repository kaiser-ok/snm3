# NetFlow 異常分析工具 - 實作計劃 (精簡版)

## 專案名稱: NetFlow Anomaly Detector (NAD)

**版本:** 1.0.0
**語言:** Python 3.8+
**重點:** 異常檢測 + 健康度評估 (不含告警功能)

---

## 一、核心功能清單

### ✅ 必須實作
1. **流量數據收集** - 從 ElasticSearch 查詢 NetFlow
2. **設備資訊關聯** - 從 MySQL 查詢設備資訊
3. **異常檢測** - 根據規則檢測異常行為
4. **健康度評估** - 評估網路整體健康狀態
5. **報告生成** - 生成 Markdown/HTML/JSON 報告
6. **CLI 工具** - 命令列介面

### ❌ 暫不實作
- ~~告警系統~~
- ~~通知機制 (Email, Webhook)~~
- ~~即時監控模式~~
- ~~Web UI~~

---

## 二、健康度評估系統設計

### 2.1 健康度評分模型

健康度採用 **0-100 分制**，綜合考量多個維度：

```python
health_score_calculation:
  base_score: 100

  # 扣分因素
  deductions:
    # 異常事件扣分
    critical_anomalies:
      weight: -30 per_event
      max_deduction: -60

    high_anomalies:
      weight: -15 per_event
      max_deduction: -45

    medium_anomalies:
      weight: -5 per_event
      max_deduction: -20

    # 流量健康度扣分
    traffic_health:
      excessive_traffic:
        threshold: 200%_of_baseline
        deduction: -10

      low_traffic:
        threshold: 50%_of_baseline
        deduction: -5

    # 連線健康度扣分
    connection_health:
      excessive_connections:
        threshold: 150%_of_baseline
        deduction: -10

      connection_errors:
        high_rst_rate: -5
        high_timeout_rate: -5

    # 協定健康度扣分
    protocol_health:
      unusual_protocol_ratio:
        threshold: 10%
        deduction: -5

  # 健康等級
  health_levels:
    excellent: 90-100    # 優秀 - 綠色
    good: 75-89          # 良好 - 淺綠
    fair: 60-74          # 普通 - 黃色
    poor: 40-59          # 不佳 - 橙色
    critical: 0-39       # 危急 - 紅色
```

### 2.2 健康度維度

#### A. 流量健康度 (Traffic Health)
```yaml
traffic_health_metrics:
  - name: volume_stability
    description: 流量穩定性
    calculation: |
      與基準線比較，偏差在 ±50% 內為健康

  - name: distribution_balance
    description: 流量分布均衡度
    calculation: |
      Top 10 IP 不應佔總流量超過 80%

  - name: protocol_diversity
    description: 協定多樣性正常
    calculation: |
      TCP/UDP 比例在正常範圍 (60-90% TCP)
```

#### B. 連線健康度 (Connection Health)
```yaml
connection_health_metrics:
  - name: connection_rate
    description: 連線速率正常
    healthy_range: "10-100 connections/sec"

  - name: connection_distribution
    description: 連線分布合理
    calculation: |
      無單一 IP 佔用超過 30% 連線數

  - name: connection_quality
    description: 連線品質良好
    indicators:
      - rst_rate < 5%
      - timeout_rate < 3%
```

#### C. 行為健康度 (Behavior Health)
```yaml
behavior_health_metrics:
  - name: no_scanning_activity
    description: 無掃描行為
    criteria: |
      無 IP 連線到 >50 個不同目的地且流量極小

  - name: normal_dns_usage
    description: DNS 使用正常
    criteria: |
      每小時 DNS 查詢 < 10,000 次/IP

  - name: no_data_exfiltration
    description: 無異常數據外傳
    criteria: |
      無單一連線超過 500MB 到外部 IP
```

#### D. 設備健康度 (Device Health)
```yaml
device_health_metrics:
  - name: registered_devices
    description: 設備已註冊
    calculation: |
      活躍 IP 中有設備記錄的比例

  - name: no_rogue_devices
    description: 無異常設備
    criteria: |
      無未註冊設備產生大量流量
```

### 2.3 健康度報告格式

```
╔══════════════════════════════════════════════════════════════╗
║              網路健康度評估報告                               ║
║              2025-11-11 14:00:00                             ║
╚══════════════════════════════════════════════════════════════╝

🏥 整體健康度評分: 65/100  [普通]

  ███████████████░░░░░░░░░  65%

┌──────────────────────────────────────────────────────────────┐
│ 健康度分析                                                    │
├──────────────────────────────────────────────────────────────┤
│ ✅ 流量健康度:        85/100  [良好]                         │
│    - 流量穩定性:      ✓ 正常                                 │
│    - 分布均衡度:      ✓ 均衡                                 │
│    - 協定多樣性:      ✓ 正常                                 │
│                                                               │
│ ⚠️  連線健康度:        60/100  [普通]                        │
│    - 連線速率:        ⚠️  偏高 (142 conn/sec)               │
│    - 連線分布:        ⚠️  不均衡 (Top IP 佔 28%)            │
│    - 連線品質:        ✓ 良好                                 │
│                                                               │
│ 🔴 行為健康度:        35/100  [危急]                         │
│    - 掃描活動:        ✗ 發現 28 個掃描 IP                    │
│    - DNS 使用:        ✗ 2 個 IP 異常 DNS 查詢               │
│    - 數據外傳:        ✓ 正常                                 │
│                                                               │
│ ✅ 設備健康度:        90/100  [優秀]                         │
│    - 設備註冊率:      ✓ 95% 已註冊                          │
│    - 異常設備:        ✓ 無                                   │
└──────────────────────────────────────────────────────────────┘

📉 扣分詳情:
  - 發現 2 個嚴重異常   -30 分
  - 發現 5 個高風險異常  -15 分
  - 發現 28 個掃描行為   -20 分 (上限)
  - 連線分布不均衡      -10 分

💡 改善建議:
  1. [緊急] 立即調查 192.168.10.135 (AD Server) 的掃描行為
  2. [緊急] 檢查 192.168.20.56 的 DNS 查詢風暴
  3. [建議] 優化連線分布，分散負載
  4. [建議] 建立基準線以提高檢測準確度
```

---

## 三、目錄結構 (精簡版)

```
netflow-anomaly-detector/
├── README.md
├── requirements.txt
├── setup.py
├── config/
│   ├── config.yaml              # 主配置
│   ├── rules.yaml               # 檢測規則
│   └── health_criteria.yaml     # 健康度標準
├── nad/
│   ├── __init__.py
│   ├── cli.py                   # CLI 入口
│   ├── core/
│   │   ├── __init__.py
│   │   ├── engine.py            # 分析引擎
│   │   ├── analyzer.py          # 流量分析器
│   │   ├── detector.py          # 異常檢測器
│   │   ├── health.py            # 健康度評估器 [新增]
│   │   └── baseline.py          # 基準線管理器 [新增]
│   ├── datasources/
│   │   ├── __init__.py
│   │   ├── elasticsearch.py
│   │   ├── mysql.py
│   │   └── cache.py
│   ├── models/
│   │   ├── __init__.py
│   │   ├── traffic.py
│   │   ├── device.py
│   │   ├── anomaly.py
│   │   └── health.py            # 健康度數據模型 [新增]
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── generator.py
│   │   ├── templates/
│   │   │   ├── markdown.jinja2
│   │   │   └── html.jinja2
│   │   └── formatters.py
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── engine.py
│   │   └── evaluator.py
│   └── utils/
│       ├── __init__.py
│       ├── config.py
│       ├── logger.py
│       └── helpers.py
└── tests/
    └── test_*.py
```

---

## 四、健康度配置文件

### health_criteria.yaml

```yaml
# 健康度評估標準配置
version: "1.0"

# 基礎分數
base_score: 100

# 異常事件扣分規則
anomaly_deductions:
  critical:
    score_per_event: -30
    max_deduction: -60
    description: "嚴重異常，如掃描行為、數據外洩"

  high:
    score_per_event: -15
    max_deduction: -45
    description: "高風險異常，如異常高連線數"

  medium:
    score_per_event: -5
    max_deduction: -20
    description: "中等異常，如連線數偏高"

  low:
    score_per_event: -2
    max_deduction: -10
    description: "低風險異常"

# 流量健康度標準
traffic_health:
  weight: 0.25  # 佔總健康度 25%

  metrics:
    volume_stability:
      weight: 0.4
      thresholds:
        healthy: [-30, 30]      # 與基準線 ±30% 為健康
        fair: [-50, 50]
        poor: [-100, 100]       # 超過此範圍為不健康

    distribution_balance:
      weight: 0.3
      thresholds:
        healthy_top10_ratio: 0.6    # Top 10 IP < 60% 為健康
        fair_top10_ratio: 0.8
        poor_top10_ratio: 0.9

    protocol_ratio:
      weight: 0.3
      thresholds:
        healthy_tcp_ratio: [0.6, 0.9]  # TCP 佔 60-90%
        healthy_udp_ratio: [0.1, 0.4]   # UDP 佔 10-40%

# 連線健康度標準
connection_health:
  weight: 0.25

  metrics:
    connection_rate:
      weight: 0.4
      thresholds:
        healthy: [10, 100]      # 每秒 10-100 連線為健康
        fair: [5, 150]
        poor: [0, 200]

    connection_distribution:
      weight: 0.3
      thresholds:
        healthy_top_ip_ratio: 0.2   # 單一 IP < 20% 連線
        fair_top_ip_ratio: 0.3
        poor_top_ip_ratio: 0.5

    connection_quality:
      weight: 0.3
      thresholds:
        healthy_rst_rate: 0.05      # RST 率 < 5%
        healthy_timeout_rate: 0.03  # 超時率 < 3%

# 行為健康度標準
behavior_health:
  weight: 0.30

  metrics:
    no_scanning:
      weight: 0.4
      deduction_per_scanner: -3

    dns_usage:
      weight: 0.3
      thresholds:
        healthy_queries_per_hour: 5000
        warning_queries_per_hour: 10000
        critical_queries_per_hour: 50000

    data_transfer:
      weight: 0.3
      thresholds:
        single_flow_warning: 104857600    # 100MB
        single_flow_critical: 524288000   # 500MB

# 設備健康度標準
device_health:
  weight: 0.20

  metrics:
    registration_rate:
      weight: 0.6
      thresholds:
        healthy_rate: 0.9       # 90% IP 已註冊
        fair_rate: 0.7
        poor_rate: 0.5

    rogue_devices:
      weight: 0.4
      deduction_per_rogue: -5
      rogue_traffic_threshold: 10485760  # 10MB

# 健康等級定義
health_levels:
  excellent:
    range: [90, 100]
    label: "優秀"
    color: "green"
    emoji: "✅"

  good:
    range: [75, 89]
    label: "良好"
    color: "lightgreen"
    emoji: "✅"

  fair:
    range: [60, 74]
    label: "普通"
    color: "yellow"
    emoji: "⚠️"

  poor:
    range: [40, 59]
    label: "不佳"
    color: "orange"
    emoji: "⚠️"

  critical:
    range: [0, 39]
    label: "危急"
    color: "red"
    emoji: "🔴"

# 基準線配置
baseline:
  enabled: true
  duration: 7d              # 使用過去7天數據建立基準線
  update_interval: 1d       # 每天更新
  storage: "./data/baseline.json"

  metrics:
    - total_traffic
    - total_connections
    - connection_rate
    - top_protocols
    - avg_flow_size
```

---

## 五、核心類別實作範例

### 5.1 HealthAssessor (健康度評估器)

```python
# nad/core/health.py

from typing import Dict, List
from nad.models.health import HealthScore, HealthMetrics
from nad.models.anomaly import Anomaly
from nad.models.traffic import TrafficStatistics
from nad.utils.config import Config


class HealthAssessor:
    """
    網路健康度評估器
    """

    def __init__(self, config: Config):
        self.config = config
        self.criteria = config.health_criteria
        self.baseline_manager = None  # 可選的基準線管理器

    def assess(
        self,
        statistics: TrafficStatistics,
        anomalies: List[Anomaly],
        baseline: Dict = None
    ) -> HealthScore:
        """
        評估網路健康度

        Args:
            statistics: 流量統計數據
            anomalies: 檢測到的異常列表
            baseline: 基準線數據 (可選)

        Returns:
            HealthScore: 健康度評分對象
        """
        health_score = HealthScore(base_score=100)

        # 1. 基於異常事件扣分
        anomaly_deduction = self._assess_anomalies(anomalies)
        health_score.add_deduction("異常事件", anomaly_deduction)

        # 2. 流量健康度評估
        traffic_health = self._assess_traffic_health(statistics, baseline)
        health_score.add_component("流量健康度", traffic_health)

        # 3. 連線健康度評估
        connection_health = self._assess_connection_health(statistics, baseline)
        health_score.add_component("連線健康度", connection_health)

        # 4. 行為健康度評估
        behavior_health = self._assess_behavior_health(statistics, anomalies)
        health_score.add_component("行為健康度", behavior_health)

        # 5. 設備健康度評估
        device_health = self._assess_device_health(statistics)
        health_score.add_component("設備健康度", device_health)

        # 計算最終分數
        health_score.calculate_final_score()

        return health_score

    def _assess_anomalies(self, anomalies: List[Anomaly]) -> int:
        """評估異常事件的扣分"""
        deduction = 0
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }

        for anomaly in anomalies:
            severity_counts[anomaly.severity] += 1

        # 根據配置計算扣分
        for severity, count in severity_counts.items():
            if count > 0:
                rule = self.criteria.anomaly_deductions[severity]
                score_deduction = min(
                    count * rule['score_per_event'],
                    rule['max_deduction']
                )
                deduction += score_deduction

        return deduction

    def _assess_traffic_health(
        self,
        stats: TrafficStatistics,
        baseline: Dict
    ) -> HealthMetrics:
        """評估流量健康度"""
        metrics = HealthMetrics(name="流量健康度")

        # 1. 流量穩定性
        if baseline:
            volume_deviation = self._calculate_deviation(
                stats.total_bytes,
                baseline.get('avg_traffic', stats.total_bytes)
            )
            volume_score = self._score_by_threshold(
                volume_deviation,
                self.criteria.traffic_health.metrics.volume_stability.thresholds
            )
            metrics.add_metric("流量穩定性", volume_score)

        # 2. 分布均衡度
        top10_ratio = self._calculate_top10_traffic_ratio(stats)
        balance_score = 100 if top10_ratio < 0.6 else \
                       80 if top10_ratio < 0.8 else 50
        metrics.add_metric("分布均衡度", balance_score)

        # 3. 協定比例
        tcp_ratio = stats.protocol_distribution.get('TCP', 0) / stats.total_bytes
        protocol_score = 100 if 0.6 <= tcp_ratio <= 0.9 else 70
        metrics.add_metric("協定多樣性", protocol_score)

        return metrics

    def _assess_connection_health(
        self,
        stats: TrafficStatistics,
        baseline: Dict
    ) -> HealthMetrics:
        """評估連線健康度"""
        metrics = HealthMetrics(name="連線健康度")

        # 1. 連線速率
        conn_rate = stats.total_flows / 3600  # 假設1小時分析
        rate_score = 100 if 10 <= conn_rate <= 100 else \
                    70 if 5 <= conn_rate <= 150 else 40
        metrics.add_metric("連線速率", rate_score)

        # 2. 連線分布
        top_ip_ratio = self._calculate_top_ip_connection_ratio(stats)
        dist_score = 100 if top_ip_ratio < 0.2 else \
                    70 if top_ip_ratio < 0.3 else 40
        metrics.add_metric("連線分布", dist_score)

        # 3. 連線品質 (如果有 RST/超時數據)
        metrics.add_metric("連線品質", 90)  # 暫時固定

        return metrics

    def _assess_behavior_health(
        self,
        stats: TrafficStatistics,
        anomalies: List[Anomaly]
    ) -> HealthMetrics:
        """評估行為健康度"""
        metrics = HealthMetrics(name="行為健康度")

        # 1. 掃描活動檢查
        scanning_count = len([a for a in anomalies if a.category == 'scanning'])
        scan_score = max(0, 100 - scanning_count * 3)
        metrics.add_metric("掃描活動", scan_score)

        # 2. DNS 使用檢查
        dns_anomalies = len([a for a in anomalies if 'dns' in a.name.lower()])
        dns_score = max(0, 100 - dns_anomalies * 10)
        metrics.add_metric("DNS使用", dns_score)

        # 3. 數據傳輸檢查
        large_flows = len([a for a in anomalies if a.category == 'traffic'])
        transfer_score = max(0, 100 - large_flows * 5)
        metrics.add_metric("數據外傳", transfer_score)

        return metrics

    def _assess_device_health(self, stats: TrafficStatistics) -> HealthMetrics:
        """評估設備健康度"""
        metrics = HealthMetrics(name="設備健康度")

        # 1. 設備註冊率
        if hasattr(stats, 'device_registration_rate'):
            reg_rate = stats.device_registration_rate
            reg_score = 100 if reg_rate >= 0.9 else \
                       80 if reg_rate >= 0.7 else 50
            metrics.add_metric("設備註冊率", reg_score)
        else:
            metrics.add_metric("設備註冊率", 85)  # 預設

        # 2. 異常設備檢查
        metrics.add_metric("異常設備", 100)  # 暫時固定

        return metrics

    # 輔助方法
    def _calculate_deviation(self, current: float, baseline: float) -> float:
        """計算偏差百分比"""
        if baseline == 0:
            return 0
        return ((current - baseline) / baseline) * 100

    def _score_by_threshold(self, value: float, thresholds: Dict) -> int:
        """根據閾值評分"""
        if thresholds['healthy'][0] <= value <= thresholds['healthy'][1]:
            return 100
        elif thresholds['fair'][0] <= value <= thresholds['fair'][1]:
            return 70
        else:
            return 40

    def _calculate_top10_traffic_ratio(self, stats: TrafficStatistics) -> float:
        """計算Top 10 IP的流量佔比"""
        if not stats.top_src_ips or stats.total_bytes == 0:
            return 0
        top10_traffic = sum(ip['bytes'] for ip in stats.top_src_ips[:10])
        return top10_traffic / stats.total_bytes

    def _calculate_top_ip_connection_ratio(self, stats: TrafficStatistics) -> float:
        """計算最大連線數IP的佔比"""
        if not stats.ip_behaviors or stats.total_flows == 0:
            return 0
        max_connections = max(
            behavior['connection_count']
            for behavior in stats.ip_behaviors.values()
        )
        return max_connections / stats.total_flows
```

### 5.2 健康度數據模型

```python
# nad/models/health.py

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class HealthMetrics:
    """健康度指標"""
    name: str
    metrics: Dict[str, float] = field(default_factory=dict)
    score: float = 0.0

    def add_metric(self, name: str, score: float):
        """添加指標"""
        self.metrics[name] = score

    def calculate_score(self):
        """計算平均分數"""
        if self.metrics:
            self.score = sum(self.metrics.values()) / len(self.metrics)
        return self.score


@dataclass
class HealthScore:
    """健康度評分"""
    base_score: float = 100.0
    components: Dict[str, HealthMetrics] = field(default_factory=dict)
    deductions: Dict[str, float] = field(default_factory=dict)
    final_score: float = 0.0
    level: str = ""
    label: str = ""

    def add_component(self, name: str, metrics: HealthMetrics):
        """添加健康度組件"""
        metrics.calculate_score()
        self.components[name] = metrics

    def add_deduction(self, reason: str, amount: float):
        """添加扣分"""
        self.deductions[reason] = amount

    def calculate_final_score(self):
        """計算最終分數"""
        # 從基礎分數開始
        score = self.base_score

        # 扣除異常事件分數
        for deduction in self.deductions.values():
            score += deduction  # deduction 已經是負數

        # 根據各組件權重計算
        # 這裡簡化為平均分數
        if self.components:
            component_avg = sum(
                comp.score for comp in self.components.values()
            ) / len(self.components)
            # 組件分數影響最終分數的 50%
            score = score * 0.5 + component_avg * 0.5

        # 確保分數在 0-100 之間
        self.final_score = max(0, min(100, score))

        # 確定健康等級
        self._determine_level()

        return self.final_score

    def _determine_level(self):
        """確定健康等級"""
        score = self.final_score
        if score >= 90:
            self.level = "excellent"
            self.label = "優秀"
        elif score >= 75:
            self.level = "good"
            self.label = "良好"
        elif score >= 60:
            self.level = "fair"
            self.label = "普通"
        elif score >= 40:
            self.level = "poor"
            self.label = "不佳"
        else:
            self.level = "critical"
            self.label = "危急"
```

---

## 六、CLI 使用範例

```bash
# 基本分析 (包含健康度評估)
nad analyze

# 分析並生成報告
nad analyze --report --format html

# 只看健康度
nad health

# 建立基準線
nad baseline create --duration 7d

# 與基準線比較
nad analyze --compare-baseline

# 深度分析特定IP
nad analyze-ip 192.168.10.135 --health
```

---

## 七、實作優先級

### Phase 1: MVP (Week 1-2)
- [x] 基礎數據收集 (ES + MySQL)
- [x] 簡單異常檢測 (掃描、高流量、高連線數)
- [x] 健康度評估基礎框架
- [x] Markdown 報告生成

### Phase 2: 完善功能 (Week 3-4)
- [ ] 規則引擎
- [ ] 完整的健康度評估
- [ ] 基準線功能
- [ ] HTML 報告
- [ ] CLI 完整命令

### Phase 3: 優化 (Week 5-6)
- [ ] 快取機制
- [ ] 性能優化
- [ ] 單元測試
- [ ] 文檔完善

---

**更新日期:** 2025-11-11
