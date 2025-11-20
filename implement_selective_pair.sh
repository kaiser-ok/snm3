#!/bin/bash
# 實作有限 Pair 聚合（只聚合外部連線和重要流量）

ES_HOST="http://localhost:9200"

echo "========================================================================"
echo "創建有限 Pair 聚合 Transform"
echo "========================================================================"
echo ""
echo "策略：只聚合以下流量的 pairs："
echo "  1. 外部連線（dst_ip 不是內網 IP）"
echo "  2. 大流量（> 1MB）"
echo "  3. 異常端口（< 1024 或 >= 49152）"
echo ""
echo "預期數據量：2,000-5,000 pairs/5min（原始流量的 2.5-6%）"
echo "========================================================================"
echo ""

# 創建 Transform
curl -X PUT "${ES_HOST}/_transform/netflow_by_pair_selective" \
  -H 'Content-Type: application/json' \
  -d '{
  "source": {
    "index": ["radar_flow_collector-*"],
    "query": {
      "bool": {
        "must": [
          {
            "range": {
              "FLOW_START_MILLISECONDS": {
                "gte": "now-10m"
              }
            }
          }
        ],
        "should": [
          {
            "comment": "規則 1: 外部連線（最重要）",
            "bool": {
              "must_not": [
                {"wildcard": {"IPV4_DST_ADDR": "192.168.*"}},
                {"wildcard": {"IPV4_DST_ADDR": "10.*"}},
                {"wildcard": {"IPV4_DST_ADDR": "172.16.*"}},
                {"wildcard": {"IPV4_DST_ADDR": "172.17.*"}},
                {"wildcard": {"IPV4_DST_ADDR": "172.18.*"}},
                {"wildcard": {"IPV4_DST_ADDR": "172.19.*"}},
                {"wildcard": {"IPV4_DST_ADDR": "172.20.*"}},
                {"wildcard": {"IPV4_DST_ADDR": "172.21.*"}},
                {"wildcard": {"IPV4_DST_ADDR": "172.22.*"}},
                {"wildcard": {"IPV4_DST_ADDR": "172.23.*"}},
                {"wildcard": {"IPV4_DST_ADDR": "172.24.*"}},
                {"wildcard": {"IPV4_DST_ADDR": "172.25.*"}},
                {"wildcard": {"IPV4_DST_ADDR": "172.26.*"}},
                {"wildcard": {"IPV4_DST_ADDR": "172.27.*"}},
                {"wildcard": {"IPV4_DST_ADDR": "172.28.*"}},
                {"wildcard": {"IPV4_DST_ADDR": "172.29.*"}},
                {"wildcard": {"IPV4_DST_ADDR": "172.30.*"}},
                {"wildcard": {"IPV4_DST_ADDR": "172.31.*"}}
              ]
            }
          },
          {
            "comment": "規則 2: 大流量 pairs",
            "range": {
              "IN_BYTES": {
                "gte": 1000000
              }
            }
          },
          {
            "comment": "規則 3: 系統端口（可能是服務掃描）",
            "range": {
              "L4_DST_PORT": {
                "lt": 1024
              }
            }
          },
          {
            "comment": "規則 4: 動態端口（可能是掃描或後門）",
            "range": {
              "L4_DST_PORT": {
                "gte": 49152
              }
            }
          }
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
        "terms": {
          "field": "IPV4_SRC_ADDR"
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
          "field": "IPV4_SRC_ADDR"
        }
      },
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
      "min_bytes": {
        "min": {
          "field": "IN_BYTES"
        }
      }
    }
  },
  "settings": {
    "max_page_search_size": 5000
  },
  "description": "Selective pair aggregation: external connections, large flows, and abnormal ports only"
}' | python3 -m json.tool

echo ""
echo "========================================================================"
echo "啟動 Transform"
echo "========================================================================"
echo ""

# 啟動 Transform
curl -X POST "${ES_HOST}/_transform/netflow_by_pair_selective/_start" | python3 -m json.tool

echo ""
echo "========================================================================"
echo "等待 10 秒讓 Transform 開始處理..."
echo "========================================================================"
echo ""

sleep 10

# 檢查狀態
echo "Transform 狀態："
curl -s "${ES_HOST}/_transform/netflow_by_pair_selective/_stats" | python3 -m json.tool

echo ""
echo "========================================================================"
echo "檢查生成的數據"
echo "========================================================================"
echo ""

# 等待數據
sleep 30

# 檢查索引
echo "索引統計："
curl -s "${ES_HOST}/_cat/indices/netflow_stats_5m_by_pair?v&h=index,docs.count,store.size"

echo ""
echo "範例數據："
curl -s "${ES_HOST}/netflow_stats_5m_by_pair/_search?size=2&sort=time_bucket:desc" | python3 -m json.tool

echo ""
echo "========================================================================"
echo "監控命令"
echo "========================================================================"
echo ""
echo "持續監控數據增長："
echo "  watch -n 60 'curl -s \"${ES_HOST}/_cat/indices/netflow_stats_5m_by_pair?v&h=index,docs.count,store.size\"'"
echo ""
echo "查看 Transform 狀態："
echo "  curl -s \"${ES_HOST}/_transform/netflow_by_pair_selective/_stats\" | python3 -m json.tool"
echo ""
echo "查看最新數據："
echo "  curl -s \"${ES_HOST}/netflow_stats_5m_by_pair/_search?size=5&sort=time_bucket:desc\" | python3 -m json.tool"
echo ""
echo "檢查數據量（每5分鐘）："
echo "  curl -s \"${ES_HOST}/netflow_stats_5m_by_pair/_search\" -H 'Content-Type: application/json' -d '{\"size\":0,\"aggs\":{\"per_bucket\":{\"date_histogram\":{\"field\":\"time_bucket\",\"fixed_interval\":\"5m\"},\"aggs\":{\"doc_count\":{\"value_count\":{\"field\":\"src_ip\"}}}}}}' | python3 -m json.tool"
echo ""
echo "========================================================================"
echo "完成！"
echo "========================================================================"
