# 進階功能提案

## 您的三個改進建議

### A. 四種進階 Pattern 識別

在 `BidirectionalAnalyzer` 加入更精細的模式分類：

1. **MICROSERVICE_PATTERN**（已實作）
   - 當前：微服務架構
   - 特徵：多個目標，每個目標固定少量端口

2. **SINGLE_TARGET_PATTERN**（新增）
   - True Vertical Port Scan
   - 特徵：對單一目標掃描大量端口
   - 範例：Attacker → Target:1-65535

3. **BROADCAST_PATTERN**（新增）
   - Horizontal Scan
   - 特徵：掃描多個目標的相同端口
   - 範例：Attacker → 100 hosts:port 22

4. **REVERSE_SCAN_PATTERN**（新增）
   - Destination 被大量掃描
   - 特徵：一個 dst_ip 收到對多個 ports 的探測
   - 範例：多個 src → Target:ports 1-1000

---

### B. Baseline 驗證（行為基準線）

建立每個 IP 的正常行為基準，偵測異常偏離：

**概念：**
```python
# 學習階段（7-30天）
baseline_192_168_10_135 = {
    "unique_dst_ports": {
        "mean": 2.5,
        "std": 1.2,
        "max": 5
    },
    "unique_dsts": {
        "mean": 50,
        "std": 10,
        "max": 70
    },
    "avg_bytes": {
        "mean": 1200,
        "std": 300
    }
}

# 偵測階段
current = {
    "unique_dst_ports": 200  # ← 異常！平常只有 2-5
}

if current["unique_dst_ports"] > baseline["unique_dst_ports"]["max"] * 10:
    alert("行為異常偏離基準線")
```

---

### C. On-Demand Pair 聚合

不使用 Transform 持續聚合，改用按需查詢：

**優點：**
- 減少索引量（不需要 `netflow_stats_5m_by_pair`）
- 只在偵測到異常時才查詢
- 效能更高（只查詢特定 IP）

**概念：**
```python
def query_pair_on_demand(src_ip, dst_ip, time_range):
    """按需查詢特定 pair 的統計"""
    # 直接查詢原始 flows
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"term": {"IPV4_SRC_ADDR": src_ip}},
                    {"term": {"IPV4_DST_ADDR": dst_ip}},
                    {"range": {"FLOW_START_MILLISECONDS": {"gte": time_range}}}
                ]
            }
        },
        "aggs": {
            "unique_dst_ports": {"cardinality": {"field": "L4_DST_PORT"}},
            "flow_count": {"value_count": {"field": "IPV4_SRC_ADDR"}},
            "total_bytes": {"sum": {"field": "IN_BYTES"}},
            ...
        }
    }

    # 實時聚合（無需預先建立 Transform）
    result = es.search(index="radar_flow_collector-*", body=query)
    return result['aggregations']
```

---

## 實作計劃

### 階段 1：四種 Pattern 識別（立即實作）

修改 `BidirectionalAnalyzer` 增加：

```python
class BidirectionalAnalyzer:

    def detect_port_scan_improved(self, src_ip, time_range):
        """改進版，返回具體的 pattern"""

        src_data = self._get_src_perspective(src_ip, time_range)

        # 1. Single Target Pattern（針對性掃描）
        if self._is_single_target_scan(src_data):
            return {
                'is_port_scan': True,
                'pattern': 'SINGLE_TARGET_PATTERN',
                'scan_type': 'VERTICAL_SCAN',
                'confidence': 0.95,
                'details': {...}
            }

        # 2. Broadcast Pattern（水平掃描）
        if self._is_broadcast_scan(src_data):
            return {
                'is_port_scan': True,
                'pattern': 'BROADCAST_PATTERN',
                'scan_type': 'HORIZONTAL_SCAN',
                'confidence': 0.90,
                'details': {...}
            }

        # 3. Microservice Pattern（正常）
        if self._is_microservice_pattern(src_data):
            return {
                'is_port_scan': False,
                'pattern': 'MICROSERVICE_PATTERN',
                'confidence': 0.85,
                'details': {...}
            }

        # 4. 查詢 dst 視角（Reverse Scan）
        dst_data = self._get_dst_perspective_for_targets(src_data)
        if self._is_reverse_scan_pattern(dst_data):
            return {
                'is_port_scan': True,
                'pattern': 'REVERSE_SCAN_PATTERN',
                'confidence': 0.80,
                'details': {...}
            }

    def _is_single_target_scan(self, src_data):
        """針對單一目標的掃描"""
        return (
            src_data['unique_dsts'] <= 3 and          # 目標很少
            src_data['unique_dst_ports'] > 100 and    # 掃描很多端口
            src_data['avg_bytes'] < 5000              # 小封包
        )

    def _is_broadcast_scan(self, src_data):
        """水平掃描（多目標，相同端口）"""
        return (
            src_data['unique_dsts'] > 50 and          # 很多目標
            src_data['unique_dst_ports'] / src_data['unique_dsts'] < 3 and  # 平均每個目標少量端口
            src_data['avg_bytes'] < 5000
        )

    def _is_reverse_scan_pattern(self, dst_data_list):
        """檢查是否有目標被大量掃描端口"""
        for dst in dst_data_list:
            if dst['unique_src_ports'] > 100:  # 被從很多不同的 src ports 掃描
                return True
        return False
```

### 階段 2：Baseline 驗證（中期實作）

創建新模組 `baseline_manager.py`：

```python
class BaselineManager:
    """管理每個 IP 的行為基準線"""

    def __init__(self, es_host, learning_days=7):
        self.es_host = es_host
        self.learning_days = learning_days
        self.baselines = {}  # IP → baseline

    def learn_baseline(self, src_ip):
        """學習某個 IP 的基準線"""
        # 查詢過去 7-30 天的數據
        historical_data = self._query_historical(src_ip, days=self.learning_days)

        # 計算統計
        baseline = {
            'src_ip': src_ip,
            'unique_dst_ports': {
                'mean': np.mean([d['unique_dst_ports'] for d in historical_data]),
                'std': np.std([d['unique_dst_ports'] for d in historical_data]),
                'max': np.max([d['unique_dst_ports'] for d in historical_data]),
                'p95': np.percentile([d['unique_dst_ports'] for d in historical_data], 95)
            },
            'unique_dsts': {...},
            'flow_count': {...},
            'avg_bytes': {...},
            'last_updated': datetime.now()
        }

        self.baselines[src_ip] = baseline
        return baseline

    def check_deviation(self, src_ip, current_data):
        """檢查當前行為是否偏離基準線"""
        if src_ip not in self.baselines:
            self.learn_baseline(src_ip)

        baseline = self.baselines[src_ip]

        deviations = {}

        # 檢查 unique_dst_ports
        current_ports = current_data['unique_dst_ports']
        baseline_max = baseline['unique_dst_ports']['max']
        baseline_mean = baseline['unique_dst_ports']['mean']

        if current_ports > baseline_max * 5:  # 超過基準 5 倍
            deviations['unique_dst_ports'] = {
                'current': current_ports,
                'baseline_max': baseline_max,
                'baseline_mean': baseline_mean,
                'deviation_ratio': current_ports / baseline_mean,
                'severity': 'CRITICAL'
            }

        # 檢查其他指標...

        return {
            'has_deviation': len(deviations) > 0,
            'deviations': deviations,
            'baseline': baseline
        }
```

### 階段 3：On-Demand Pair 聚合（優化實作）

創建新模組 `on_demand_aggregator.py`：

```python
class OnDemandAggregator:
    """按需聚合，不使用 Transform"""

    def __init__(self, es_host):
        self.es_host = es_host
        self.es = Elasticsearch([es_host])

    def query_pair(self, src_ip, dst_ip, time_range="now-5m"):
        """
        按需查詢特定 pair 的統計

        優點：
        - 不需要預先建立 Transform
        - 只在需要時才查詢
        - 減少儲存成本
        """
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"IPV4_SRC_ADDR": src_ip}},
                        {"term": {"IPV4_DST_ADDR": dst_ip}},
                        {"range": {"FLOW_START_MILLISECONDS": {"gte": time_range}}}
                    ]
                }
            },
            "aggs": {
                "unique_dst_ports": {
                    "cardinality": {"field": "L4_DST_PORT", "precision_threshold": 1000}
                },
                "unique_src_ports": {
                    "cardinality": {"field": "L4_SRC_PORT", "precision_threshold": 1000}
                },
                "flow_count": {"value_count": {"field": "IPV4_SRC_ADDR"}},
                "total_bytes": {"sum": {"field": "IN_BYTES"}},
                "total_packets": {"sum": {"field": "IN_PKTS"}},
                "avg_bytes": {"avg": {"field": "IN_BYTES"}},
                "max_bytes": {"max": {"field": "IN_BYTES"}}
            }
        }

        result = self.es.search(index="radar_flow_collector-*", body=query)
        aggs = result['aggregations']

        return {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'unique_dst_ports': aggs['unique_dst_ports']['value'],
            'unique_src_ports': aggs['unique_src_ports']['value'],
            'flow_count': aggs['flow_count']['value'],
            'total_bytes': aggs['total_bytes']['value'],
            'avg_bytes': aggs['avg_bytes']['value'],
            'max_bytes': aggs['max_bytes']['value']
        }

    def query_all_pairs_for_src(self, src_ip, time_range="now-5m"):
        """
        查詢某個 src_ip 的所有 pairs

        使用 composite aggregation 一次性獲取所有 dst
        """
        all_pairs = []
        after_key = None

        while True:
            query = {
                "size": 0,
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"IPV4_SRC_ADDR": src_ip}},
                            {"range": {"FLOW_START_MILLISECONDS": {"gte": time_range}}}
                        ]
                    }
                },
                "aggs": {
                    "pairs": {
                        "composite": {
                            "size": 100,
                            "sources": [
                                {"dst_ip": {"terms": {"field": "IPV4_DST_ADDR"}}}
                            ]
                        },
                        "aggs": {
                            "unique_dst_ports": {"cardinality": {"field": "L4_DST_PORT"}},
                            "flow_count": {"value_count": {"field": "IPV4_SRC_ADDR"}},
                            "total_bytes": {"sum": {"field": "IN_BYTES"}},
                            "avg_bytes": {"avg": {"field": "IN_BYTES"}}
                        }
                    }
                }
            }

            if after_key:
                query['aggs']['pairs']['composite']['after'] = after_key

            result = self.es.search(index="radar_flow_collector-*", body=query)
            buckets = result['aggregations']['pairs']['buckets']

            for bucket in buckets:
                all_pairs.append({
                    'src_ip': src_ip,
                    'dst_ip': bucket['key']['dst_ip'],
                    'unique_dst_ports': bucket['unique_dst_ports']['value'],
                    'flow_count': bucket['flow_count']['value'],
                    'total_bytes': bucket['total_bytes']['value'],
                    'avg_bytes': bucket['avg_bytes']['value']
                })

            if 'after_key' in result['aggregations']['pairs']:
                after_key = result['aggregations']['pairs']['after_key']
            else:
                break

        return all_pairs
```

---

## 效能對比

### Transform vs On-Demand

| 方案 | 儲存成本 | 查詢速度 | 靈活性 | 推薦場景 |
|------|---------|----------|--------|----------|
| **Transform (by_pair)** | 高（持續聚合）| 快（預先聚合）| 低 | 需要頻繁查詢 pair 數據 |
| **On-Demand** | 低（按需查詢）| 中（實時聚合）| 高 | 只在偵測到異常時查詢 |

### 建議：混合策略

```python
def analyze_suspicious_ip(src_ip):
    # Step 1: 使用 by_src 快速判斷
    src_data = query_by_src(src_ip)

    if not is_suspicious(src_data):
        return "正常"

    # Step 2: 異常 IP，使用 on-demand 查詢 pairs
    pairs = on_demand_aggregator.query_all_pairs_for_src(src_ip)

    # Step 3: 精確分析每個 pair
    for pair in pairs:
        if pair['unique_dst_ports'] > 100:
            return "Port Scan"

    return "微服務"
```

---

## 總結

### 建議實作優先順序

1. **立即實作：四種 Pattern 識別** ⭐⭐⭐⭐⭐
   - 成本低，效益高
   - 顯著提升偵測準確度

2. **中期實作：On-Demand Pair 聚合** ⭐⭐⭐⭐
   - 減少儲存成本
   - 保持查詢靈活性

3. **長期實作：Baseline 驗證** ⭐⭐⭐
   - 需要較長學習期
   - 維護成本較高
   - 但能偵測微妙的行為變化

您希望我立即實作哪個功能？
