# ElasticSearch Transform 運作模式詳解

## 核心問題：Transform 會處理歷史數據嗎？

**答案：取決於配置模式**

---

## 一、Transform 的兩種模式

### Mode 1: Batch Mode (批次模式)
- ✅ **會處理歷史數據**
- 一次性執行完就停止
- 適合一次性聚合歷史資料

### Mode 2: Continuous Mode (持續模式)
- ⚠️ **預設只處理新數據**
- 持續運行，自動處理新增數據
- 但可配置初次啟動時處理歷史數據

---

## 二、詳細說明

### 2.1 沒有 `sync` 參數 = Batch Mode

```json
PUT _transform/netflow_batch
{
  "source": {
    "index": "radar_flow_collector-*"
    // 沒有時間範圍限制 = 處理所有歷史數據
  },
  "dest": {
    "index": "netflow_stats_5m"
  },
  "pivot": {
    "group_by": {...},
    "aggregations": {...}
  },
  "frequency": "5m"  // 每5分鐘檢查一次
}
```

**行為:**
1. 啟動時掃描**所有符合的索引** (`radar_flow_collector-*`)
2. 處理**所有歷史數據**（可能是幾千萬、幾億筆）
3. 每5分鐘檢查一次是否有新數據
4. 如果沒有新數據，就等待
5. 如果有新數據，聚合後寫入目標索引

**問題:**
- ⚠️ 首次啟動會掃描**所有歷史索引**
- ⚠️ 如果數據量大（如您的 4000萬/天），首次可能要跑很久
- ⚠️ 每次檢查都要掃描所有數據，效率低

---

### 2.2 有 `sync` 參數 = Continuous Mode (推薦)

```json
PUT _transform/netflow_continuous
{
  "source": {
    "index": "radar_flow_collector-*",
    "query": {
      "range": {
        "FLOW_START_MILLISECONDS": {
          "gte": "now-7d"  // ⭐ 重點：只處理過去7天
        }
      }
    }
  },
  "dest": {
    "index": "netflow_stats_5m"
  },
  "pivot": {...},
  "frequency": "5m",
  "sync": {  // ⭐ 關鍵：啟用持續模式
    "time": {
      "field": "FLOW_START_MILLISECONDS",
      "delay": "60s"  // 延遲60秒以確保數據完整
    }
  }
}
```

**行為:**
1. **首次啟動**:
   - 掃描 `query` 範圍內的數據（這裡是過去7天）
   - 處理這些數據並寫入目標索引

2. **後續運行**:
   - 每5分鐘檢查一次
   - **只處理新增的數據**（通過 checkpoint 機制追蹤）
   - 增量更新目標索引

**優點:**
- ✅ 首次啟動只處理指定範圍（如過去7天）
- ✅ 後續只處理增量數據，高效
- ✅ 自動追蹤進度（checkpoint）
- ✅ 故障恢復時從斷點繼續

---

## 三、Checkpoint 機制

### 3.1 什麼是 Checkpoint？

Transform 會記錄處理進度：

```json
{
  "checkpoint": 5,
  "last_search_time": "2025-11-11T12:00:00Z",
  "documents_processed": 1500000
}
```

### 3.2 工作原理

```
Time: 12:00 - Transform 啟動
  └─ 處理 11:55-12:00 的數據
  └─ 設置 checkpoint: time = 12:00

Time: 12:05 - Transform 再次執行
  └─ 從 checkpoint 12:00 開始
  └─ 只查詢 12:00 之後的新數據
  └─ 更新 checkpoint: time = 12:05

Time: 12:10 - Transform 再次執行
  └─ 從 checkpoint 12:05 開始
  └─ 只處理增量數據
```

**關鍵:**
- ✅ 不會重複處理舊數據
- ✅ 只處理 checkpoint 之後的新數據
- ✅ 如果中斷，重啟後從 checkpoint 繼續

---

## 四、針對您的場景的配置建議

### 場景 1: 只想處理未來的新數據（推薦）

```json
PUT _transform/netflow_realtime
{
  "source": {
    "index": "radar_flow_collector-*",
    "query": {
      "range": {
        "FLOW_START_MILLISECONDS": {
          "gte": "now-10m"  // ⭐ 只處理最近10分鐘
        }
      }
    }
  },
  "dest": {
    "index": "netflow_stats_5m"
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
      }
    },
    "aggregations": {
      "total_bytes": {"sum": {"field": "IN_BYTES"}},
      "flow_count": {"value_count": {"field": "IPV4_SRC_ADDR"}},
      "unique_dsts": {"cardinality": {"field": "IPV4_DST_ADDR"}}
    }
  },
  "frequency": "5m",
  "sync": {
    "time": {
      "field": "FLOW_START_MILLISECONDS",
      "delay": "60s"
    }
  }
}
```

**結果:**
- ✅ 啟動時只處理最近10分鐘數據（輕量）
- ✅ 之後每5分鐘只處理新增的5分鐘數據
- ✅ 不會回頭處理歷史數據

---

### 場景 2: 需要回填過去7天的數據

```json
PUT _transform/netflow_with_history
{
  "source": {
    "index": "radar_flow_collector-*",
    "query": {
      "range": {
        "FLOW_START_MILLISECONDS": {
          "gte": "now-7d"  // ⭐ 首次啟動處理過去7天
        }
      }
    }
  },
  "dest": {
    "index": "netflow_stats_5m"
  },
  "pivot": {...},
  "frequency": "5m",
  "sync": {
    "time": {
      "field": "FLOW_START_MILLISECONDS",
      "delay": "60s"
    }
  }
}
```

**首次啟動:**
```
檢查所有索引:
  radar_flow_collector-2025.11.04 ✓ (在範圍內)
  radar_flow_collector-2025.11.05 ✓
  ...
  radar_flow_collector-2025.11.11 ✓

處理過去7天的數據:
  預計數據量: 7天 × 4000萬 = 2.8億筆
  處理時間: 視 ES 效能，可能需要 30分鐘 - 2小時
```

**後續運行:**
```
每5分鐘:
  只處理新增的數據（約 140萬筆）
  處理時間: 數秒
```

---

### 場景 3: 分批處理歷史數據（安全方式）

如果要處理大量歷史數據，建議分批：

#### Step 1: 處理第一天

```json
PUT _transform/netflow_history_day1
{
  "source": {
    "index": "radar_flow_collector-2025.11.04",  // ⭐ 指定單一索引
    "query": {
      "match_all": {}
    }
  },
  "dest": {
    "index": "netflow_stats_5m"
  },
  "pivot": {...}
  // ⭐ 沒有 sync，一次性處理
}
```

#### Step 2: 處理第二天

```json
PUT _transform/netflow_history_day2
{
  "source": {
    "index": "radar_flow_collector-2025.11.05",
    ...
  }
  ...
}
```

#### Step 3: 啟動即時處理

```json
PUT _transform/netflow_realtime
{
  "source": {
    "index": "radar_flow_collector-*",
    "query": {
      "range": {
        "FLOW_START_MILLISECONDS": {
          "gte": "now-10m"  // 從現在開始
        }
      }
    }
  },
  ...
  "sync": {...}  // 持續模式
}
```

---

## 五、檢查 Transform 狀態

### 5.1 查看 Transform 進度

```bash
GET _transform/netflow_continuous/_stats
```

**回應範例:**

```json
{
  "transforms": [{
    "id": "netflow_continuous",
    "state": "started",
    "stats": {
      "pages_processed": 150,
      "documents_processed": 43703944,  // ⭐ 已處理文檔數
      "documents_indexed": 285000,       // ⭐ 寫入目標索引數
      "trigger_count": 288,              // 執行次數
      "index_time_in_ms": 45000,
      "search_time_in_ms": 120000,
      "processing_time_in_ms": 165000,
      "index_total": 285000,
      "search_total": 43703944
    },
    "checkpointing": {
      "last": {
        "checkpoint": 288,
        "timestamp_millis": 1699708800000,  // ⭐ 最後處理到的時間
        "time_upper_bound_millis": 1699708800000
      },
      "next": {
        "checkpoint": 289,
        "position": {
          "indexer_position": {...}
        }
      }
    }
  }]
}
```

**重點欄位:**
- `documents_processed`: 從原始索引讀取了多少文檔
- `documents_indexed`: 寫入目標索引多少文檔
- `checkpoint`: 當前處理進度
- `timestamp_millis`: 最後處理到的時間點

### 5.2 查看是否還在處理歷史數據

```bash
# 如果正在處理大量歷史數據
GET _transform/netflow_continuous/_stats

# 觀察:
# - documents_processed 持續快速增長 → 還在掃描歷史數據
# - documents_processed 緩慢增長 → 只處理新數據
```

---

## 六、實際測試範例

讓我用您的數據測試：

### 測試 1: 檢查現有數據量

```bash
# 過去7天的總文檔數
GET radar_flow_collector-2025.11.*/_count
```

假設結果:
```json
{
  "count": 280000000  // 2.8億筆 (7天)
}
```

### 測試 2: 創建只處理新數據的 Transform

```bash
PUT _transform/netflow_test
{
  "source": {
    "index": "radar_flow_collector-*",
    "query": {
      "range": {
        "FLOW_START_MILLISECONDS": {
          "gte": "now-5m"  // ⭐ 測試：只處理最近5分鐘
        }
      }
    }
  },
  "dest": {
    "index": "netflow_stats_test"
  },
  "pivot": {
    "group_by": {
      "src_ip": {"terms": {"field": "IPV4_SRC_ADDR"}}
    },
    "aggregations": {
      "flow_count": {"value_count": {"field": "IPV4_SRC_ADDR"}}
    }
  },
  "frequency": "1m",  // 測試用：每1分鐘
  "sync": {
    "time": {
      "field": "FLOW_START_MILLISECONDS",
      "delay": "30s"
    }
  }
}

POST _transform/netflow_test/_start
```

### 測試 3: 觀察處理情況

```bash
# 等待 1 分鐘後查看
GET _transform/netflow_test/_stats

# 預期結果:
# - documents_processed: ~140000 (5分鐘的數據)
# - 處理時間: 幾秒鐘
# - 不會掃描歷史數據
```

---

## 七、常見問題

### Q1: 如果我想補上昨天的數據怎麼辦？

**方法 1: 修改 query 範圍**

```bash
# 停止 Transform
POST _transform/netflow_continuous/_stop

# 更新配置
POST _transform/netflow_continuous/_update
{
  "source": {
    "query": {
      "range": {
        "FLOW_START_MILLISECONDS": {
          "gte": "now-1d"  // 改成過去1天
        }
      }
    }
  }
}

# 重啟
POST _transform/netflow_continuous/_start
```

**方法 2: 創建臨時 Transform**

```bash
# 專門處理昨天的數據
PUT _transform/netflow_backfill_yesterday
{
  "source": {
    "index": "radar_flow_collector-2025.11.10",  // 指定昨天
    "query": {"match_all": {}}
  },
  "dest": {
    "index": "netflow_stats_5m"
  },
  "pivot": {...}
}

POST _transform/netflow_backfill_yesterday/_start

# 處理完後刪除
DELETE _transform/netflow_backfill_yesterday
```

---

### Q2: Transform 會不會重複處理數據？

**答案：不會（有 checkpoint 機制）**

```
Time: 12:00 - 處理數據 A
  └─ checkpoint = 12:00

Time: 12:05 - 只處理 12:00 之後的新數據 B
  └─ checkpoint = 12:05
  └─ 數據 A 不會重複處理

如果 12:05 失敗重試:
  └─ 從 checkpoint 12:00 開始
  └─ 重新處理數據 B
  └─ 但不會處理數據 A
```

---

### Q3: 我可以重置 Transform 重新處理嗎？

**可以，但要小心：**

```bash
# 停止 Transform
POST _transform/netflow_continuous/_stop

# 刪除目標索引（會刪除所有已處理的數據）
DELETE netflow_stats_5m

# 重啟 Transform（會從頭開始）
POST _transform/netflow_continuous/_start
```

---

## 八、您的最佳配置建議

基於您的場景（每天 4000萬筆），我建議：

### 推薦配置：只處理未來數據

```json
PUT _transform/netflow_production
{
  "source": {
    "index": "radar_flow_collector-*",
    "query": {
      "range": {
        "FLOW_START_MILLISECONDS": {
          "gte": "now-10m"  // ⭐ 只處理最近10分鐘
        }
      }
    }
  },
  "dest": {
    "index": "netflow_stats_5m",
    "pipeline": "netflow_enrich"  // 可選：添加 ingest pipeline
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
          "size": 10000  // ⭐ 每個時間桶最多10000個IP
        }
      },
      "dst_ip": {
        "terms": {
          "field": "IPV4_DST_ADDR",
          "size": 1000
        }
      },
      "protocol": {
        "terms": {"field": "PROTOCOL"}
      }
    },
    "aggregations": {
      "flow_count": {
        "value_count": {"field": "IPV4_SRC_ADDR"}
      },
      "total_bytes": {
        "sum": {"field": "IN_BYTES"}
      },
      "total_packets": {
        "sum": {"field": "IN_PKTS"}
      },
      "unique_dst_ips": {
        "cardinality": {"field": "IPV4_DST_ADDR", "precision_threshold": 3000}
      },
      "unique_dst_ports": {
        "cardinality": {"field": "L4_DST_PORT"}
      },
      "avg_bytes_per_flow": {
        "avg": {"field": "IN_BYTES"}
      },
      "max_bytes": {
        "max": {"field": "IN_BYTES"}
      }
    }
  },
  "frequency": "5m",  // 每5分鐘執行
  "sync": {
    "time": {
      "field": "FLOW_START_MILLISECONDS",
      "delay": "60s"  // 延遲60秒確保數據完整
    }
  },
  "settings": {
    "max_page_search_size": 5000,  // 每批處理5000個文檔
    "docs_per_second": null  // 不限制速度（可設置限制避免影響ES）
  }
}
```

**行為:**
1. 首次啟動：處理最近10分鐘數據（約140萬筆）
2. 後續運行：每5分鐘處理新增的5分鐘數據（約70萬筆）
3. 處理時間：每次幾秒到幾十秒
4. 不會回頭處理歷史數據

**如果需要歷史數據:**
- 用 Python 腳本單獨處理
- 或創建臨時 Transform 分批處理

---

## 九、總結

### ✅ Transform 預設行為

| 配置 | 首次啟動 | 後續運行 |
|------|---------|---------|
| 無 `query` + 無 `sync` | 處理**所有歷史** | 處理新數據（低效） |
| 有 `query` + 無 `sync` | 處理 query 範圍 | 處理新數據（低效） |
| 有 `query` + 有 `sync` | 處理 query 範圍 | **只處理新數據**（高效）✅ |

### 🎯 建議

```
生產環境：
  gte: "now-10m" + sync
  → 只處理未來新數據

需要回填歷史：
  單獨用 Python 腳本處理
  → 更靈活、可控
```

需要我幫您建立實際的 Transform 配置並測試嗎？