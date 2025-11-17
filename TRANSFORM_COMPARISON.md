# Transform 配置比較與問題分析

## 當前 Transform (netflow_basic_stats) 配置

```json
{
  "id": "netflow_basic_stats",
  "source": {
    "index": ["radar_flow_collector-*"],
    "query": {
      "match_all": {}  // ⚠️ 問題1: 會掃描所有歷史數據！
    }
  },
  "dest": {
    "index": "netflow_stats_5m"
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
        "terms": {
          "field": "IPV4_SRC_ADDR"  // ⚠️ 問題2: 沒有 size 限制
        }
      }
    },
    "aggregations": {
      "total_bytes": {"sum": {"field": "IN_BYTES"}},
      "total_packets": {"sum": {"field": "IN_PKTS"}},
      "flow_count": {"value_count": {"field": "IPV4_SRC_ADDR"}},
      "unique_dsts": {"cardinality": {"field": "IPV4_DST_ADDR"}},
      "unique_ports": {"cardinality": {"field": "L4_DST_PORT"}},
      "avg_bytes": {"avg": {"field": "IN_BYTES"}}
    }
  }
}
```

## 建議的 Transform 配置

```json
{
  "id": "netflow_production",
  "source": {
    "index": ["radar_flow_collector-*"],
    "query": {
      "range": {
        "FLOW_START_MILLISECONDS": {
          "gte": "now-10m"  // ✅ 只處理最近10分鐘
        }
      }
    }
  },
  "dest": {
    "index": "netflow_stats_5m"
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
        "terms": {
          "field": "IPV4_SRC_ADDR",
          "size": 10000  // ✅ 限制每個時間桶最多10000個IP
        }
      }
    },
    "aggregations": {
      "total_bytes": {"sum": {"field": "IN_BYTES"}},
      "total_packets": {"sum": {"field": "IN_PKTS"}},
      "flow_count": {"value_count": {"field": "IPV4_SRC_ADDR"}},
      "unique_dsts": {
        "cardinality": {
          "field": "IPV4_DST_ADDR",
          "precision_threshold": 3000  // ✅ 優化 cardinality 效能
        }
      },
      "unique_ports": {
        "cardinality": {
          "field": "L4_DST_PORT",
          "precision_threshold": 1000
        }
      },
      "avg_bytes": {"avg": {"field": "IN_BYTES"}},
      "max_bytes": {"max": {"field": "IN_BYTES"}}  // ✅ 新增最大值
    }
  },
  "settings": {
    "max_page_search_size": 5000  // ✅ 控制每批處理大小
  }
}
```

---

## 主要差異分析

### 差異 1: Query 範圍 ⚠️⚠️⚠️ 最關鍵

| 配置 | 當前 | 建議 |
|------|------|------|
| Query | `match_all: {}` | `gte: "now-10m"` |
| **影響** | 掃描**所有歷史索引** | 只處理最近10分鐘 |
| **數據量** | ~14億筆（所有歷史） | ~28萬筆（10分鐘） |
| **首次執行時間** | **幾小時到幾天** | **幾秒到幾分鐘** |

**當前狀態:**
```
operations_behind: 1,399,148,423  (13.9億操作待處理)

預估時間:
  假設 ES 每秒處理 10,000 筆
  → 1,399,148,423 / 10,000 = 139,914 秒
  → 約 38.9 小時 = 1.6 天！
```

**這就是為什麼 Transform 看起來"沒有啟動"的原因！**
- 它其實已經啟動了
- 但正在緩慢地掃描所有歷史數據
- 進度太慢以至於看起來像是卡住

---

### 差異 2: Terms Aggregation Size

| 配置 | 當前 | 建議 |
|------|------|------|
| src_ip size | 未設定（預設10） | 10000 |
| **影響** | 每個時間桶只記錄前10個IP | 記錄前10000個IP |

**當前問題:**
```
假設5分鐘內有 5000 個活躍 IP
→ 但 Transform 只會記錄前 10 個
→ 其他 4990 個 IP 的數據會丟失！
```

---

### 差異 3: Cardinality Precision

| 配置 | 當前 | 建議 |
|------|------|------|
| unique_dsts | 預設精度（3000） | 顯式設定 3000 |
| unique_ports | 預設精度（3000） | 顯式設定 1000 |
| **影響** | 預設可能不夠精確 | 明確控制精度和效能 |

---

### 差異 4: Settings

| 配置 | 當前 | 建議 |
|------|------|------|
| max_page_search_size | 未設定（預設500） | 5000 |
| **影響** | 每批處理500筆 | 每批處理5000筆（更快） |

---

## 當前 Transform 的問題

### 問題 1: 正在掃描所有歷史數據 🔴

**證據:**
```json
{
  "state": "indexing",
  "operations_behind": 1,399,148,423,
  "documents_processed": 0,
  "documents_indexed": 0
}
```

**解讀:**
- `state: indexing` → 正在執行
- `operations_behind: 13.9億` → 需要處理13.9億個操作
- `documents_processed: 0` → 但還沒處理任何文檔
- **原因**: 正在初始化，計算需要處理的總量

**預估:**
```
您的歷史數據:
  - 約 26 個索引 (2025.10.17 - 2025.11.11)
  - 每個索引約 4000萬筆
  - 總計: 26 × 40,000,000 = 1,040,000,000 筆 (10.4億)

Transform 顯示 13.9億操作，合理（包含內部操作）

處理時間預估:
  - 假設 ES 每秒處理 5,000 筆
  - 1,040,000,000 / 5,000 = 208,000 秒
  - 約 57.8 小時 = 2.4 天
```

---

### 問題 2: Terms Aggregation 會丟失數據 🔴

**當前配置:**
```json
"src_ip": {
  "terms": {
    "field": "IPV4_SRC_ADDR"  // 沒有 size，預設 = 10
  }
}
```

**影響:**
```
每個 5分鐘時間桶:
  - 實際有 5000 個活躍 IP
  - Transform 只記錄前 10 個（按文檔數排序）
  - 丟失 4990 個 IP 的數據！

結果:
  → 聚合結果不完整
  → 異常偵測會漏掉大部分 IP
```

**修復:**
```json
"src_ip": {
  "terms": {
    "field": "IPV4_SRC_ADDR",
    "size": 10000  // 記錄前 10000 個 IP
  }
}
```

---

## 解決方案

### 方案 A: 停止並重新配置 (推薦) ✅

```bash
# 1. 停止當前 Transform
curl -X POST "http://localhost:9200/_transform/netflow_basic_stats/_stop?force=true&wait_for_completion=true"

# 2. 刪除當前 Transform
curl -X DELETE "http://localhost:9200/_transform/netflow_basic_stats"

# 3. 刪除目標索引（重新開始）
curl -X DELETE "http://localhost:9200/netflow_stats_5m"

# 4. 創建優化的 Transform
curl -X PUT "http://localhost:9200/_transform/netflow_production" \
  -H 'Content-Type: application/json' -d'
{
  "source": {
    "index": ["radar_flow_collector-*"],
    "query": {
      "range": {
        "FLOW_START_MILLISECONDS": {
          "gte": "now-10m"
        }
      }
    }
  },
  "dest": {
    "index": "netflow_stats_5m"
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
        "terms": {
          "field": "IPV4_SRC_ADDR",
          "size": 10000
        }
      }
    },
    "aggregations": {
      "total_bytes": {"sum": {"field": "IN_BYTES"}},
      "total_packets": {"sum": {"field": "IN_PKTS"}},
      "flow_count": {"value_count": {"field": "IPV4_SRC_ADDR"}},
      "unique_dsts": {
        "cardinality": {
          "field": "IPV4_DST_ADDR",
          "precision_threshold": 3000
        }
      },
      "unique_ports": {
        "cardinality": {
          "field": "L4_DST_PORT",
          "precision_threshold": 1000
        }
      },
      "avg_bytes": {"avg": {"field": "IN_BYTES"}},
      "max_bytes": {"max": {"field": "IN_BYTES"}}
    }
  },
  "settings": {
    "max_page_search_size": 5000
  }
}'

# 5. 啟動新 Transform
curl -X POST "http://localhost:9200/_transform/netflow_production/_start"
```

**優點:**
- ✅ 幾分鐘內完成首次執行
- ✅ 只處理未來的新數據
- ✅ 不會丟失數據
- ✅ 效能最佳

---

### 方案 B: 等待當前 Transform 完成 (不推薦) ❌

**時間成本:**
- 需要等待 2-3 天
- 期間會持續消耗 ES 資源
- 可能影響其他查詢效能

**數據完整性:**
- 因為沒有設定 `size`，大部分 IP 數據會丟失
- 需要重新配置並重跑

**結論: 不建議**

---

### 方案 C: 修改當前 Transform 的 Query (折衷)

```bash
# 1. 停止 Transform
curl -X POST "http://localhost:9200/_transform/netflow_basic_stats/_stop?force=true"

# 2. 更新配置
curl -X POST "http://localhost:9200/_transform/netflow_basic_stats/_update" \
  -H 'Content-Type: application/json' -d'
{
  "source": {
    "query": {
      "range": {
        "FLOW_START_MILLISECONDS": {
          "gte": "now-1h"
        }
      }
    }
  }
}'

# 3. 重啟
curl -X POST "http://localhost:9200/_transform/netflow_basic_stats/_start"
```

**問題:**
- ⚠️ 仍然缺少 `size` 參數，會丟失數據
- ⚠️ 無法修改 `pivot` 配置（需要重建）

---

## 建議執行步驟

### 立即行動 (方案 A)

```bash
# Step 1: 停止並刪除當前 Transform
curl -X POST "http://localhost:9200/_transform/netflow_basic_stats/_stop?force=true"
sleep 5
curl -X DELETE "http://localhost:9200/_transform/netflow_basic_stats"
curl -X DELETE "http://localhost:9200/netflow_stats_5m"

# Step 2: 創建優化的 Transform (使用上面的完整配置)

# Step 3: 啟動並驗證
curl -X POST "http://localhost:9200/_transform/netflow_production/_start"
sleep 10
curl -s "http://localhost:9200/_transform/netflow_production/_stats" | python3 -m json.tool
```

**預期結果:**
```
首次執行:
  - 處理約 28萬筆（10分鐘數據）
  - 完成時間: 30秒 - 2分鐘
  - 寫入約 1000-3000 筆聚合數據

後續運行:
  - 每5分鐘處理約 14萬筆
  - 完成時間: 10-30秒
```

---

## 總結

### 當前 Transform 的問題

1. 🔴 **正在掃描所有歷史數據** (13.9億操作)
   - 需要 2-3 天才能完成
   - 消耗大量 ES 資源

2. 🔴 **Terms aggregation 缺少 size**
   - 每個時間桶只記錄前10個IP
   - 大部分數據會丟失

3. 🟡 **缺少效能優化設定**
   - 沒有 `max_page_search_size`
   - 沒有 cardinality `precision_threshold`

### 推薦做法

**✅ 停止當前 Transform → 創建優化版本 → 只處理未來數據**

**時間投入:** 10-15 分鐘
**效果:** 立即可用，效能最佳，數據完整

需要我幫您執行這些步驟嗎？
