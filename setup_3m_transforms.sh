#!/bin/bash
# 建立 3 分鐘聚合 Transform（by_src 和 by_dst）
# 更新日期: 2025-11-22
# Delay 設定: 90s (從 60s 更新)

ES_HOST="http://localhost:9200"

echo "========================================================================"
echo "建立 3 分鐘聚合 Transform (by_src 和 by_dst)"
echo "========================================================================"
echo ""
echo "設定參數："
echo "  - 聚合間隔: 3 分鐘 (fixed_interval: 3m)"
echo "  - 執行頻率: 3 分鐘 (frequency: 3m)"
echo "  - 延遲時間: 90 秒 (delay: 90s)"
echo "  - 時區: Asia/Taipei"
echo "  - 資料來源: radar_flow_collector-* (最近 15 分鐘)"
echo ""
echo "========================================================================"
echo ""

# ============================================================================
# Transform 1: By Source IP
# ============================================================================
echo "步驟 1: 建立 netflow_agg_3m_by_src Transform"
echo "------------------------------------------------------------------------"

curl -X PUT "${ES_HOST}/_transform/netflow_agg_3m_by_src" \
  -H 'Content-Type: application/json' \
  -d '{
  "source": {
    "index": ["radar_flow_collector-*"],
    "query": {
      "range": {
        "FLOW_START_MILLISECONDS": {
          "gte": "now-15m"
        }
      }
    }
  },
  "dest": {
    "index": "netflow_stats_3m_by_src"
  },
  "frequency": "3m",
  "sync": {
    "time": {
      "field": "FLOW_START_MILLISECONDS",
      "delay": "90s"
    }
  },
  "pivot": {
    "group_by": {
      "time_bucket": {
        "date_histogram": {
          "field": "FLOW_START_MILLISECONDS",
          "fixed_interval": "3m",
          "time_zone": "Asia/Taipei"
        }
      },
      "src_ip": {
        "terms": {
          "field": "IPV4_SRC_ADDR"
        }
      }
    },
    "aggregations": {
      "total_bytes": {
        "sum": {
          "field": "IN_BYTES"
        }
      },
      "total_packets": {
        "sum": {
          "field": "IN_PKTS"
        }
      },
      "flow_count": {
        "value_count": {
          "field": "IPV4_SRC_ADDR"
        }
      },
      "unique_dsts": {
        "cardinality": {
          "field": "IPV4_DST_ADDR",
          "precision_threshold": 3000
        }
      },
      "unique_src_ports": {
        "cardinality": {
          "field": "L4_SRC_PORT",
          "precision_threshold": 1000
        }
      },
      "unique_dst_ports": {
        "cardinality": {
          "field": "L4_DST_PORT",
          "precision_threshold": 1000
        }
      },
      "avg_bytes": {
        "avg": {
          "field": "IN_BYTES"
        }
      },
      "max_bytes": {
        "max": {
          "field": "IN_BYTES"
        }
      },
      "top_src_ports": {
        "terms": {
          "field": "L4_SRC_PORT",
          "size": 5
        }
      },
      "top_dst_ports": {
        "terms": {
          "field": "L4_DST_PORT",
          "size": 5
        }
      }
    }
  },
  "settings": {
    "max_page_search_size": 5000,
    "align_checkpoints": true
  },
  "description": "Aggregate NetFlow by source IP - 3min buckets (Asia/Taipei), 90s delay, 3min frequency"
}' | python3 -m json.tool

echo ""
echo "啟動 netflow_agg_3m_by_src..."
curl -X POST "${ES_HOST}/_transform/netflow_agg_3m_by_src/_start" | python3 -m json.tool

echo ""
echo ""

# ============================================================================
# Transform 2: By Destination IP
# ============================================================================
echo "步驟 2: 建立 netflow_agg_3m_by_dst Transform"
echo "------------------------------------------------------------------------"

curl -X PUT "${ES_HOST}/_transform/netflow_agg_3m_by_dst" \
  -H 'Content-Type: application/json' \
  -d '{
  "source": {
    "index": ["radar_flow_collector-*"],
    "query": {
      "range": {
        "FLOW_START_MILLISECONDS": {
          "gte": "now-15m"
        }
      }
    }
  },
  "dest": {
    "index": "netflow_stats_3m_by_dst"
  },
  "frequency": "3m",
  "sync": {
    "time": {
      "field": "FLOW_START_MILLISECONDS",
      "delay": "90s"
    }
  },
  "pivot": {
    "group_by": {
      "time_bucket": {
        "date_histogram": {
          "field": "FLOW_START_MILLISECONDS",
          "fixed_interval": "3m",
          "time_zone": "Asia/Taipei"
        }
      },
      "dst_ip": {
        "terms": {
          "field": "IPV4_DST_ADDR"
        }
      }
    },
    "aggregations": {
      "total_bytes": {
        "sum": {
          "field": "IN_BYTES"
        }
      },
      "total_packets": {
        "sum": {
          "field": "IN_PKTS"
        }
      },
      "flow_count": {
        "value_count": {
          "field": "IPV4_DST_ADDR"
        }
      },
      "unique_srcs": {
        "cardinality": {
          "field": "IPV4_SRC_ADDR",
          "precision_threshold": 3000
        }
      },
      "unique_src_ports": {
        "cardinality": {
          "field": "L4_SRC_PORT",
          "precision_threshold": 1000
        }
      },
      "unique_dst_ports": {
        "cardinality": {
          "field": "L4_DST_PORT",
          "precision_threshold": 1000
        }
      },
      "avg_bytes": {
        "avg": {
          "field": "IN_BYTES"
        }
      },
      "max_bytes": {
        "max": {
          "field": "IN_BYTES"
        }
      },
      "top_src_ports": {
        "terms": {
          "field": "L4_SRC_PORT",
          "size": 5
        }
      },
      "top_dst_ports": {
        "terms": {
          "field": "L4_DST_PORT",
          "size": 5
        }
      }
    }
  },
  "settings": {
    "max_page_search_size": 5000,
    "align_checkpoints": true
  },
  "description": "Aggregate NetFlow by destination IP for DDoS detection - 3min buckets (Asia/Taipei), 90s delay, 3min frequency"
}' | python3 -m json.tool

echo ""
echo "啟動 netflow_agg_3m_by_dst..."
curl -X POST "${ES_HOST}/_transform/netflow_agg_3m_by_dst/_start" | python3 -m json.tool

echo ""
echo ""

# ============================================================================
# 驗證 Transform 狀態
# ============================================================================
echo "========================================================================"
echo "驗證 Transform 狀態"
echo "========================================================================"
echo ""

sleep 5

echo "Transform 狀態："
echo "------------------------------------------------------------------------"
curl -s "${ES_HOST}/_transform/netflow_agg_3m_by_src,netflow_agg_3m_by_dst/_stats" | python3 -m json.tool

echo ""
echo ""

# ============================================================================
# 檢查生成的索引
# ============================================================================
echo "========================================================================"
echo "檢查生成的索引"
echo "========================================================================"
echo ""

sleep 30

echo "索引統計："
echo "------------------------------------------------------------------------"
curl -s "${ES_HOST}/_cat/indices/netflow_stats_3m_by_*?v&h=index,docs.count,store.size"

echo ""
echo ""

# ============================================================================
# 使用說明
# ============================================================================
echo "========================================================================"
echo "監控命令"
echo "========================================================================"
echo ""
echo "查看 Transform 狀態："
echo "  curl -s \"${ES_HOST}/_transform/netflow_agg_3m_by_src/_stats\" | python3 -m json.tool"
echo "  curl -s \"${ES_HOST}/_transform/netflow_agg_3m_by_dst/_stats\" | python3 -m json.tool"
echo ""
echo "查看索引大小："
echo "  curl -s \"${ES_HOST}/_cat/indices/netflow_stats_3m_by_*?v\""
echo ""
echo "查看最新數據（by_src）："
echo "  curl -s \"${ES_HOST}/netflow_stats_3m_by_src/_search?size=3&sort=time_bucket:desc\" | python3 -m json.tool"
echo ""
echo "查看最新數據（by_dst）："
echo "  curl -s \"${ES_HOST}/netflow_stats_3m_by_dst/_search?size=3&sort=time_bucket:desc\" | python3 -m json.tool"
echo ""
echo "停止 Transform："
echo "  curl -X POST \"${ES_HOST}/_transform/netflow_agg_3m_by_src/_stop\""
echo "  curl -X POST \"${ES_HOST}/_transform/netflow_agg_3m_by_dst/_stop\""
echo ""
echo "更新 Transform 設定 (例如修改 delay)："
echo "  1. 先停止: curl -X POST \"${ES_HOST}/_transform/netflow_agg_3m_by_src/_stop\""
echo "  2. 更新: curl -X POST \"${ES_HOST}/_transform/netflow_agg_3m_by_src/_update\" -H 'Content-Type: application/json' -d '{\"sync\":{\"time\":{\"field\":\"FLOW_START_MILLISECONDS\",\"delay\":\"90s\"}}}'"
echo "  3. 啟動: curl -X POST \"${ES_HOST}/_transform/netflow_agg_3m_by_src/_start\""
echo ""
echo "========================================================================"
echo "重要說明"
echo "========================================================================"
echo ""
echo "1. Delay 設定為 90s 的原因："
echo "   - Netflow exporter 通常有 30-60 秒的緩衝時間"
echo "   - 90s delay 確保更多延遲到達的 flow 被包含"
echo "   - 減少數據遺漏，提高異常檢測準確度"
echo ""
echo "2. 檢測延遲時間線："
echo "   - Netflow 事件發生 → Exporter 緩衝 (0-60s)"
echo "   - → ES 索引 (0-30s) → Transform delay (90s)"
echo "   - → 聚合完成 (0-180s) → 異常檢測 (0-600s)"
echo "   - 總延遲: 約 4.5-17 分鐘 (平均 8-10 分鐘)"
echo ""
echo "3. Transform 資源使用："
echo "   - 每 3 分鐘執行一次"
echo "   - 處理最近 15 分鐘的數據"
echo "   - max_page_search_size: 5000"
echo ""
echo "4. 時區設定："
echo "   - 使用 Asia/Taipei (UTC+8)"
echo "   - time_bucket 會自動對齊台北時區的時間邊界"
echo "   - 例如: 08:00, 08:03, 08:06, 08:09... (台北時間)"
echo ""
echo "========================================================================"
echo "完成！"
echo "========================================================================"
