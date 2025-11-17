#!/bin/bash

ES_HOST="http://localhost:9200"
INDEX="radar_flow_collector-2025.11.11"

# 計算1小時前的時間戳 (毫秒)
ONE_HOUR_AGO=$(date -d '1 hour ago' +%s)000
NOW=$(date +%s)000

echo "=== 網路流量分析報告 ==="
echo "分析時間: $(date '+%Y-%m-%d %H:%M:%S')"
echo "分析區間: 過去1小時"
echo ""

# 1. 總流量統計
echo "--- 1. 流量總覽 ---"
curl -s -X POST "${ES_HOST}/${INDEX}/_search?pretty" -H 'Content-Type: application/json' -d"{
  \"query\": {
    \"range\": {
      \"FLOW_START_MILLISECONDS\": {
        \"gte\": ${ONE_HOUR_AGO},
        \"lte\": ${NOW}
      }
    }
  },
  \"aggs\": {
    \"total_bytes\": { \"sum\": { \"field\": \"IN_BYTES\" } },
    \"total_packets\": { \"sum\": { \"field\": \"IN_PKTS\" } },
    \"total_flows\": { \"value_count\": { \"field\": \"IPV4_SRC_ADDR\" } }
  },
  \"size\": 0
}" > /tmp/total_stats.json

TOTAL_BYTES=$(cat /tmp/total_stats.json | grep -A1 '"total_bytes"' | grep 'value' | awk '{print $3}' | tr -d ',')
TOTAL_PACKETS=$(cat /tmp/total_stats.json | grep -A1 '"total_packets"' | grep 'value' | awk '{print $3}' | tr -d ',')
TOTAL_FLOWS=$(cat /tmp/total_stats.json | grep -A1 '"total_flows"' | grep 'value' | awk '{print $3}' | tr -d ',')

if [ -n "$TOTAL_BYTES" ] && [ "$TOTAL_BYTES" != "0.0" ]; then
  TOTAL_GB=$(echo "scale=2; $TOTAL_BYTES / 1024 / 1024 / 1024" | bc)
  echo "總流量: ${TOTAL_GB} GB"
  echo "總封包數: ${TOTAL_PACKETS}"
  echo "總連線數: ${TOTAL_FLOWS}"
else
  echo "過去1小時無流量數據"
fi
echo ""

# 2. Top 10 流量來源 IP
echo "--- 2. Top 10 流量來源 IP ---"
curl -s -X POST "${ES_HOST}/${INDEX}/_search?pretty" -H 'Content-Type: application/json' -d"{
  \"query\": {
    \"range\": {
      \"FLOW_START_MILLISECONDS\": {
        \"gte\": ${ONE_HOUR_AGO},
        \"lte\": ${NOW}
      }
    }
  },
  \"aggs\": {
    \"top_src_ips\": {
      \"terms\": {
        \"field\": \"IPV4_SRC_ADDR\",
        \"size\": 10,
        \"order\": { \"total_bytes\": \"desc\" }
      },
      \"aggs\": {
        \"total_bytes\": { \"sum\": { \"field\": \"IN_BYTES\" } },
        \"total_packets\": { \"sum\": { \"field\": \"IN_PKTS\" } },
        \"total_flows\": { \"value_count\": { \"field\": \"IPV4_SRC_ADDR\" } }
      }
    }
  },
  \"size\": 0
}" > /tmp/top_src_ips.json

cat /tmp/top_src_ips.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
buckets = data.get('aggregations', {}).get('top_src_ips', {}).get('buckets', [])
for i, bucket in enumerate(buckets, 1):
    ip = bucket['key']
    bytes_val = bucket['total_bytes']['value']
    packets = bucket['total_packets']['value']
    flows = bucket['total_flows']['value']
    mb = bytes_val / 1024 / 1024
    print(f'{i}. {ip}')
    print(f'   流量: {mb:.2f} MB')
    print(f'   封包數: {int(packets):,}')
    print(f'   連線數: {int(flows):,}')
"
echo ""

# 3. Top 10 流量目的 IP
echo "--- 3. Top 10 流量目的 IP ---"
curl -s -X POST "${ES_HOST}/${INDEX}/_search?pretty" -H 'Content-Type: application/json' -d"{
  \"query\": {
    \"range\": {
      \"FLOW_START_MILLISECONDS\": {
        \"gte\": ${ONE_HOUR_AGO},
        \"lte\": ${NOW}
      }
    }
  },
  \"aggs\": {
    \"top_dst_ips\": {
      \"terms\": {
        \"field\": \"IPV4_DST_ADDR\",
        \"size\": 10,
        \"order\": { \"total_bytes\": \"desc\" }
      },
      \"aggs\": {
        \"total_bytes\": { \"sum\": { \"field\": \"IN_BYTES\" } },
        \"total_packets\": { \"sum\": { \"field\": \"IN_PKTS\" } },
        \"total_flows\": { \"value_count\": { \"field\": \"IPV4_DST_ADDR\" } }
      }
    }
  },
  \"size\": 0
}" > /tmp/top_dst_ips.json

cat /tmp/top_dst_ips.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
buckets = data.get('aggregations', {}).get('top_dst_ips', {}).get('buckets', [])
for i, bucket in enumerate(buckets, 1):
    ip = bucket['key']
    bytes_val = bucket['total_bytes']['value']
    packets = bucket['total_packets']['value']
    flows = bucket['total_flows']['value']
    mb = bytes_val / 1024 / 1024
    print(f'{i}. {ip}')
    print(f'   流量: {mb:.2f} MB')
    print(f'   封包數: {int(packets):,}')
    print(f'   連線數: {int(flows):,}')
"
echo ""

# 4. 異常高流量連線
echo "--- 4. 異常高流量連線 (單一連線 > 100MB) ---"
curl -s -X POST "${ES_HOST}/${INDEX}/_search?pretty" -H 'Content-Type: application/json' -d"{
  \"query\": {
    \"bool\": {
      \"must\": [
        {
          \"range\": {
            \"FLOW_START_MILLISECONDS\": {
              \"gte\": ${ONE_HOUR_AGO},
              \"lte\": ${NOW}
            }
          }
        },
        {
          \"range\": {
            \"IN_BYTES\": {
              \"gte\": 104857600
            }
          }
        }
      ]
    }
  },
  \"sort\": [
    { \"IN_BYTES\": \"desc\" }
  ],
  \"size\": 20,
  \"_source\": [\"IPV4_SRC_ADDR\", \"IPV4_DST_ADDR\", \"L4_DST_PORT\", \"PROTOCOL\", \"IN_BYTES\", \"IN_PKTS\", \"FLOW_START_MILLISECONDS\"]
}" > /tmp/high_volume.json

cat /tmp/high_volume.json | python3 -c "
import json, sys
from datetime import datetime
data = json.load(sys.stdin)
hits = data.get('hits', {}).get('hits', [])
if hits:
    print(f'⚠️  發現 {len(hits)} 個異常高流量連線:')
    for i, hit in enumerate(hits, 1):
        src = hit['_source']
        start_time = datetime.fromtimestamp(src.get('FLOW_START_MILLISECONDS', 0)/1000).strftime('%H:%M:%S')
        src_ip = src.get('IPV4_SRC_ADDR', 'N/A')
        dst_ip = src.get('IPV4_DST_ADDR', 'N/A')
        dst_port = src.get('L4_DST_PORT', 'N/A')
        protocol = src.get('PROTOCOL', 'N/A')
        in_bytes = src.get('IN_BYTES', 0)
        in_pkts = src.get('IN_PKTS', 0)
        mb = in_bytes / 1024 / 1024
        print(f'\n{i}. [{start_time}]')
        print(f'   來源: {src_ip} → 目的: {dst_ip}:{dst_port}')
        print(f'   協定: {protocol}')
        print(f'   流量: {mb:.2f} MB')
        print(f'   封包數: {int(in_pkts):,}')
else:
    print('✓ 未發現異常高流量連線')
"
echo ""

# 5. 異常高連線數 IP
echo "--- 5. 異常高連線數 IP (單一IP > 1000 連線) ---"
curl -s -X POST "${ES_HOST}/${INDEX}/_search?pretty" -H 'Content-Type: application/json' -d"{
  \"query\": {
    \"range\": {
      \"FLOW_START_MILLISECONDS\": {
        \"gte\": ${ONE_HOUR_AGO},
        \"lte\": ${NOW}
      }
    }
  },
  \"aggs\": {
    \"src_ips\": {
      \"terms\": {
        \"field\": \"IPV4_SRC_ADDR\",
        \"size\": 100,
        \"min_doc_count\": 1000
      },
      \"aggs\": {
        \"total_bytes\": { \"sum\": { \"field\": \"IN_BYTES\" } },
        \"unique_destinations\": {
          \"cardinality\": { \"field\": \"IPV4_DST_ADDR\" }
        }
      }
    }
  },
  \"size\": 0
}" > /tmp/high_conn.json

cat /tmp/high_conn.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
buckets = data.get('aggregations', {}).get('src_ips', {}).get('buckets', [])
if buckets:
    print(f'⚠️  發現 {len(buckets)} 個異常高連線數 IP:')
    for i, bucket in enumerate(buckets, 1):
        ip = bucket['key']
        conn_count = bucket['doc_count']
        bytes_val = bucket['total_bytes']['value']
        unique_dests = bucket['unique_destinations']['value']
        mb = bytes_val / 1024 / 1024
        print(f'\n{i}. {ip}')
        print(f'   連線數: {int(conn_count):,}')
        print(f'   流量: {mb:.2f} MB')
        print(f'   連線到不同目的地數量: {unique_dests}')
else:
    print('✓ 未發現異常高連線數 IP')
"
echo ""

# 6. 可疑掃描行為
echo "--- 6. 可疑掃描行為偵測 ---"
curl -s -X POST "${ES_HOST}/${INDEX}/_search?pretty" -H 'Content-Type: application/json' -d"{
  \"query\": {
    \"range\": {
      \"FLOW_START_MILLISECONDS\": {
        \"gte\": ${ONE_HOUR_AGO},
        \"lte\": ${NOW}
      }
    }
  },
  \"aggs\": {
    \"src_ips\": {
      \"terms\": {
        \"field\": \"IPV4_SRC_ADDR\",
        \"size\": 100,
        \"min_doc_count\": 100
      },
      \"aggs\": {
        \"total_bytes\": { \"sum\": { \"field\": \"IN_BYTES\" } },
        \"unique_destinations\": {
          \"cardinality\": { \"field\": \"IPV4_DST_ADDR\" }
        },
        \"avg_bytes_per_flow\": {
          \"avg\": { \"field\": \"IN_BYTES\" }
        }
      }
    }
  },
  \"size\": 0
}" > /tmp/scanning.json

cat /tmp/scanning.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
buckets = data.get('aggregations', {}).get('src_ips', {}).get('buckets', [])
suspicious = [b for b in buckets if b['avg_bytes_per_flow']['value'] < 10000 and b['unique_destinations']['value'] > 50]
if suspicious:
    print(f'⚠️  發現 {len(suspicious)} 個可疑掃描 IP:')
    for i, bucket in enumerate(suspicious, 1):
        ip = bucket['key']
        conn_count = bucket['doc_count']
        unique_dests = bucket['unique_destinations']['value']
        avg_bytes = bucket['avg_bytes_per_flow']['value']
        total_bytes = bucket['total_bytes']['value']
        mb = total_bytes / 1024 / 1024
        kb_avg = avg_bytes / 1024
        print(f'\n{i}. {ip}')
        print(f'   連線數: {int(conn_count):,}')
        print(f'   連線到不同目的地: {unique_dests}')
        print(f'   平均每連線流量: {kb_avg:.2f} KB')
        print(f'   總流量: {mb:.2f} MB')
else:
    print('✓ 未發現可疑掃描行為')
"
echo ""

# 7. 協定分布
echo "--- 7. 流量協定分布 ---"
curl -s -X POST "${ES_HOST}/${INDEX}/_search?pretty" -H 'Content-Type: application/json' -d"{
  \"query\": {
    \"range\": {
      \"FLOW_START_MILLISECONDS\": {
        \"gte\": ${ONE_HOUR_AGO},
        \"lte\": ${NOW}
      }
    }
  },
  \"aggs\": {
    \"protocols\": {
      \"terms\": {
        \"field\": \"PROTOCOL\",
        \"size\": 10
      },
      \"aggs\": {
        \"total_bytes\": { \"sum\": { \"field\": \"IN_BYTES\" } }
      }
    }
  },
  \"size\": 0
}" > /tmp/protocols.json

cat /tmp/protocols.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
buckets = data.get('aggregations', {}).get('protocols', {}).get('buckets', [])
for i, bucket in enumerate(buckets, 1):
    protocol = bucket['key']
    bytes_val = bucket['total_bytes']['value']
    mb = bytes_val / 1024 / 1024
    print(f'{i}. 協定 {protocol}: {mb:.2f} MB')
"
echo ""

echo "=== 分析完成 ==="
