# Src+Dst Pair Aggregation 方案建議

## 決策矩陣

| 方案 | 數據量 | 查詢速度 | 偵測準確度 | 實作複雜度 | 推薦度 |
|------|--------|----------|-----------|-----------|--------|
| **A. 不建立 pair** | ✅ 低 | ✅ 快 | ⚠️ 良好 | ✅ 簡單 | ⭐⭐⭐ 短期 |
| **B. 有限 pair** | ⚠️ 中 | ⚠️ 中 | ✅ 優秀 | ⚠️ 中等 | ⭐⭐⭐⭐⭐ 長期 |
| **C. 全量 pair** | ❌ 高 | ❌ 慢 | ✅ 完美 | ❌ 複雜 | ⭐ 不推薦 |

---

## 推薦：混合方案

### 架構設計

```
┌─────────────────────────────────────────────────────────┐
│                   異常偵測流程                           │
└─────────────────────────────────────────────────────────┘

Level 1: 快速篩選 (< 100ms)
  ├─ by_src 聚合 (674 docs/5min)
  ├─ by_dst 聚合 (674 docs/5min)
  └─ 識別可疑 IP

              ↓ 發現異常

Level 2: 重點分析 (< 500ms)
  ├─ by_pair 聚合 (只對異常流量，~1000 docs/5min)
  └─ 精確判斷每個 pair 的行為

              ↓ 需要詳細調查

Level 3: 深度調查 (按需查詢)
  ├─ 原始 flows (25000 docs/5min)
  └─ 完整的封包級分析
```

### 實作步驟

#### Step 1: 建立「有限 pair」聚合

創建一個只聚合**重要 pairs** 的 transform：

```json
PUT /_transform/netflow_by_pair_selective
{
  "source": {
    "index": ["radar_flow_collector-*"],
    "query": {
      "bool": {
        "must": [
          {"range": {"FLOW_START_MILLISECONDS": {"gte": "now-10m"}}}
        ],
        "should": [
          // 規則 1: 高連線數 pairs（可能是掃描或攻擊）
          {
            "script": {
              "script": """
                def count = doc['IPV4_SRC_ADDR'].value + '_' + doc['IPV4_DST_ADDR'].value;
                // 這裡簡化，實際需要在 aggregation 階段計算
              """
            }
          },

          // 規則 2: 外部連線（重點監控）
          {
            "bool": {
              "must_not": [
                {"prefix": {"IPV4_DST_ADDR": "192.168"}},
                {"prefix": {"IPV4_DST_ADDR": "10."}},
                {"prefix": {"IPV4_DST_ADDR": "172.16"}},
                {"prefix": {"IPV4_DST_ADDR": "172.17"}},
                {"prefix": {"IPV4_DST_ADDR": "172.18"}},
                {"prefix": {"IPV4_DST_ADDR": "172.19"}},
                {"prefix": {"IPV4_DST_ADDR": "172.20"}},
                {"prefix": {"IPV4_DST_ADDR": "172.21"}},
                {"prefix": {"IPV4_DST_ADDR": "172.22"}},
                {"prefix": {"IPV4_DST_ADDR": "172.23"}},
                {"prefix": {"IPV4_DST_ADDR": "172.24"}},
                {"prefix": {"IPV4_DST_ADDR": "172.25"}},
                {"prefix": {"IPV4_DST_ADDR": "172.26"}},
                {"prefix": {"IPV4_DST_ADDR": "172.27"}},
                {"prefix": {"IPV4_DST_ADDR": "172.28"}},
                {"prefix": {"IPV4_DST_ADDR": "172.29"}},
                {"prefix": {"IPV4_DST_ADDR": "172.30"}},
                {"prefix": {"IPV4_DST_ADDR": "172.31"}}
              ]
            }
          },

          // 規則 3: 大流量 pairs
          {"range": {"IN_BYTES": {"gte": 1000000}}}  // > 1MB
        ],
        "minimum_should_match": 1
      }
    }
  },
  "dest": {
    "index": "netflow_stats_5m_by_pair"
  },
  "frequency": "5m",
  "sync": {
    "time": {
      "field": "FLOW_START_MILLISECONDS",
      "delay": "60s"
    }
  },
  "pivot": {
    "group_by": {
      "time_bucket": {
        "date_histogram": {
          "field": "FLOW_START_MILLISECONDS",
          "fixed_interval": "5m"
        }
      },
      "src_ip": {
        "terms": {"field": "IPV4_SRC_ADDR"}
      },
      "dst_ip": {
        "terms": {"field": "IPV4_DST_ADDR"}
      }
    },
    "aggregations": {
      "total_bytes": {"sum": {"field": "IN_BYTES"}},
      "total_packets": {"sum": {"field": "IN_PKTS"}},
      "flow_count": {"value_count": {"field": "IPV4_SRC_ADDR"}},
      "unique_dst_ports": {
        "cardinality": {
          "field": "L4_DST_PORT",
          "precision_threshold": 1000
        }
      },
      "unique_src_ports": {
        "cardinality": {
          "field": "L4_SRC_PORT",
          "precision_threshold": 1000
        }
      },
      "avg_bytes": {"avg": {"field": "IN_BYTES"}},
      "max_bytes": {"max": {"field": "IN_BYTES"}},
      "min_bytes": {"min": {"field": "IN_BYTES"}},

      // 新增：方向性指標
      "avg_packet_size": {
        "bucket_script": {
          "buckets_path": {
            "bytes": "total_bytes",
            "packets": "total_packets"
          },
          "script": "params.bytes / params.packets"
        }
      }
    }
  }
}
```

#### Step 2: 更新偵測邏輯

```python
# nad/ml/bidirectional_analyzer.py

class BidirectionalAnalyzer:
    def __init__(self, es_host="http://localhost:9200"):
        self.es_host = es_host
        self.src_index = f"{es_host}/netflow_stats_5m/_search"
        self.dst_index = f"{es_host}/netflow_stats_5m_by_dst/_search"
        self.pair_index = f"{es_host}/netflow_stats_5m_by_pair/_search"  # 新增

    def detect_port_scan_precise(self, src_ip: str, time_range: str = "now-5m") -> Dict:
        """
        使用 pair 聚合的精確 Port Scan 偵測
        """
        # 1. 查詢該 src_ip 的所有 pairs
        query = {
            "size": 1000,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"src_ip": src_ip}},
                        {"range": {"time_bucket": {"gte": time_range}}}
                    ]
                }
            }
        }

        response = requests.post(self.pair_index, json=query,
                                headers={'Content-Type': 'application/json'})
        data = response.json()

        pairs = data.get('hits', {}).get('hits', [])

        # 2. 分析每個 pair 的端口使用情況
        for pair_hit in pairs:
            pair = pair_hit['_source']
            dst_ip = pair['dst_ip']
            unique_dst_ports = pair.get('unique_dst_ports', 0)
            flow_count = pair.get('flow_count', 0)
            avg_bytes = pair.get('avg_bytes', 0)

            # 針對單一目標的 Port Scan
            if (unique_dst_ports > 100 and      # 對這個目標掃描 100+ 端口
                avg_bytes < 5000 and            # 小封包
                flow_count > 50):               # 連線數多

                return {
                    'is_port_scan': True,
                    'scan_type': 'TARGETED_PORT_SCAN',
                    'confidence': 0.95,
                    'target': dst_ip,
                    'scanned_ports': unique_dst_ports,
                    'flow_count': flow_count,
                    'evidence': 'Pair-level analysis shows port scanning behavior'
                }

        # 3. 檢查是否是微服務模式
        if self._is_microservice_by_pairs(pairs):
            return {
                'is_port_scan': False,
                'pattern': 'MICROSERVICE',
                'confidence': 0.90,
                'pairs_analyzed': len(pairs),
                'evidence': 'Each pair uses only 1-3 fixed ports (microservice pattern)'
            }

        return {'is_port_scan': False}

    def _is_microservice_by_pairs(self, pairs: List[Dict]) -> bool:
        """
        基於 pair 數據判斷是否是微服務模式

        特徵：
        - 每個 pair 只用 1-3 個端口
        - 所有 pairs 都是內部 IP
        - 有實際數據傳輸
        """
        if len(pairs) < 5:
            return False

        fixed_port_pairs = 0
        internal_pairs = 0

        for pair_hit in pairs:
            pair = pair_hit['_source']
            dst_ip = pair['dst_ip']
            unique_dst_ports = pair.get('unique_dst_ports', 0)
            avg_bytes = pair.get('avg_bytes', 0)

            # 固定少量端口
            if unique_dst_ports <= 3 and avg_bytes > 500:
                fixed_port_pairs += 1

            # 內部 IP
            if self._is_internal_ip(dst_ip):
                internal_pairs += 1

        # 80%+ 的 pairs 符合微服務特徵
        return (fixed_port_pairs >= len(pairs) * 0.8 and
                internal_pairs >= len(pairs) * 0.8)

    def verify_bidirectional_traffic(self, src_ip: str, dst_ip: str,
                                     time_range: str = "now-5m") -> Dict:
        """
        驗證 src-dst 之間是否有雙向流量（新功能）

        用途：
        - 區分掃描（單向）vs 真實通訊（雙向）
        - C2 通訊偵測（雙向但模式異常）
        """
        # 查詢 A→B
        pair_AB = self._query_pair(src_ip, dst_ip, time_range)

        # 查詢 B→A
        pair_BA = self._query_pair(dst_ip, src_ip, time_range)

        if not pair_AB:
            return {'has_traffic': False}

        if not pair_BA:
            return {
                'has_traffic': True,
                'is_bidirectional': False,
                'direction': 'unidirectional',
                'warning': 'Only outbound traffic detected (possible scan)'
            }

        # 計算雙向比率
        bytes_AB = pair_AB.get('total_bytes', 0)
        bytes_BA = pair_BA.get('total_bytes', 0)

        if bytes_AB > 0:
            bidirectional_ratio = bytes_BA / bytes_AB
        else:
            bidirectional_ratio = 0

        return {
            'has_traffic': True,
            'is_bidirectional': True,
            'bytes_sent': bytes_AB,
            'bytes_received': bytes_BA,
            'bidirectional_ratio': bidirectional_ratio,
            'flows_AB': pair_AB.get('flow_count', 0),
            'flows_BA': pair_BA.get('flow_count', 0),
            'pattern': self._classify_bidirectional_pattern(
                bytes_AB, bytes_BA,
                pair_AB.get('flow_count', 0),
                pair_BA.get('flow_count', 0)
            )
        }

    def _query_pair(self, src_ip: str, dst_ip: str, time_range: str) -> Optional[Dict]:
        """查詢特定 src-dst pair 的數據"""
        query = {
            "size": 1,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"src_ip": src_ip}},
                        {"term": {"dst_ip": dst_ip}},
                        {"range": {"time_bucket": {"gte": time_range}}}
                    ]
                }
            },
            "sort": [{"time_bucket": "desc"}]
        }

        response = requests.post(self.pair_index, json=query,
                                headers={'Content-Type': 'application/json'})
        data = response.json()

        hits = data.get('hits', {}).get('hits', [])
        if hits:
            return hits[0]['_source']
        return None

    def _classify_bidirectional_pattern(self, bytes_AB, bytes_BA,
                                        flows_AB, flows_BA) -> str:
        """分類雙向流量模式"""
        if bytes_BA == 0:
            return "UNIDIRECTIONAL_SCAN"

        ratio = bytes_BA / bytes_AB if bytes_AB > 0 else 0

        if 0.3 < ratio < 3:  # 雙向流量相對平衡
            return "NORMAL_COMMUNICATION"
        elif ratio < 0.1:  # 回應很少
            return "POSSIBLE_SCAN_WITH_RESPONSE"
        elif ratio > 10:  # 主要是接收
            return "SERVER_RESPONSE_DOMINANT"
        else:
            return "ASYMMETRIC_COMMUNICATION"
```

---

## 預期效果

### 數據量對比

| 索引 | 文檔數/5min | 壓縮率 | 用途 |
|------|------------|--------|------|
| 原始 flows | 25,000 | 0% | 基準 |
| by_src | 674 | 97% | 快速篩選 |
| by_dst | 674 | 97% | DDoS 偵測 |
| **by_pair (有限)** | **~2,000** | **92%** | 精確分析 |
| by_pair (全量) | ~10,000 | 60% | ❌ 不推薦 |

### 查詢性能

| 操作 | 無 Pair | 有限 Pair | 全量 Pair |
|------|---------|-----------|-----------|
| Level 1 篩選 | 50ms | 50ms | 50ms |
| Level 2 精確分析 | ❌ 需查詢原始 | **100ms** ✅ | 500ms |
| Level 3 深度調查 | 5000ms | 5000ms | 5000ms |

### 偵測改進

| 場景 | 無 Pair | 有 Pair |
|------|---------|---------|
| 微服務誤報 | ✅ 已解決 | ✅ 更精確 |
| 針對性 Port Scan | ⚠️ 推測 | ✅ **精確判斷** |
| 雙向流量驗證 | ❌ 無法 | ✅ **可精確驗證** |
| C2 通訊偵測 | ⚠️ 困難 | ✅ **容易** |
| 橫向移動追蹤 | ⚠️ 困難 | ✅ **清晰** |

---

## 實作決策

### 立即實作（Phase 1）

✅ **保持當前架構**
- by_src + by_dst 已經解決了 100% 的誤報
- 數據量可控，查詢快速
- 足以應對大部分場景

### 下一步（Phase 2）- 如果需要更高精確度

⭐ **建立「有限 pair」聚合**
- 只聚合：外部連線 + 高流量 + 異常模式
- 預期數據量：~2,000 docs/5min（8% 的原始量）
- 用途：
  1. 精確的 Port Scan 判斷
  2. 雙向流量驗證
  3. C2 通訊偵測
  4. 橫向移動追蹤

### 不推薦（除非特殊需求）

❌ **全量 pair 聚合**
- 數據量太大（~10,000 docs/5min）
- 查詢變慢
- 性價比低

---

## 結論

### 建議：分階段實作

**現在：**
- 使用 by_src + by_dst（已完成）
- 解決了 Port Scan 誤報問題
- 新增了 DDoS 偵測能力

**未來（如有需要）：**
- 實作「有限 pair」聚合
- 條件觸發：只對可疑流量建立 pair
- 提供精確的 pair-level 分析能力

**查詢策略：**
```
大部分情況 → by_src/by_dst (快速)
需要精確判斷 → by_pair (中速)
深度調查 → 原始 flows (慢速)
```

這樣既保持了性能，又提供了精確分析能力。
