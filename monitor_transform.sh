#!/bin/bash
echo "======================================"
echo "Transform 監控 - $(date)"
echo "======================================"
echo ""

# Transform 狀態
echo "📊 Transform 狀態:"
curl -s "http://localhost:9200/_transform/netflow_production/_stats" | \
  python3 -c "import sys,json;d=json.load(sys.stdin);t=d['transforms'][0];s=t['stats'];c=t['checkpointing'];print(f\"  狀態: {t['state']}\");print(f\"  已處理: {s['documents_processed']:,} 筆\");print(f\"  已寫入: {s['documents_indexed']:,} 筆\");print(f\"  待處理: {c.get('operations_behind', 0):,} 筆\")"
echo ""

# 新資料統計
echo "📈 新資料統計:"
NEW_COUNT=$(curl -s "http://localhost:9200/netflow_stats_5m/_count?q=unique_src_ports:*" | python3 -c "import sys,json;print(json.load(sys.stdin)['count'])")
TOTAL_COUNT=$(curl -s "http://localhost:9200/netflow_stats_5m/_count" | python3 -c "import sys,json;print(json.load(sys.stdin)['count'])")
PERCENTAGE=$(python3 -c "print(f'{$NEW_COUNT/$TOTAL_COUNT*100:.2f}')" 2>/dev/null || echo "0")
echo "  有新欄位: $NEW_COUNT 筆"
echo "  總記錄數: $TOTAL_COUNT 筆"
echo "  覆蓋率: ${PERCENTAGE}%"
echo ""

# 時間範圍
echo "⏰ 時間範圍:"
curl -s "http://localhost:9200/netflow_stats_5m/_search" -H 'Content-Type: application/json' -d '{"size":0,"query":{"exists":{"field":"unique_src_ports"}},"aggs":{"min_time":{"min":{"field":"time_bucket"}},"max_time":{"max":{"field":"time_bucket"}}}}' | \
  python3 -c "import sys,json;from datetime import datetime;d=json.load(sys.stdin);a=d['aggregations'];print(f\"  最早: {datetime.fromtimestamp(a['min_time']['value']/1000)}\");print(f\"  最新: {datetime.fromtimestamp(a['max_time']['value']/1000)}\")"
echo ""

# 建議
if [ $NEW_COUNT -lt 1000 ]; then
  echo "💡 建議: 資料量不足，建議等待"
elif [ $NEW_COUNT -lt 10000 ]; then
  echo "💡 建議: 可以進行初步測試（python3 train_isolation_forest.py --hours 1）"
else
  echo "💡 建議: 資料充足，可以進行完整訓練（python3 train_isolation_forest.py --days 1）"
fi
echo ""
