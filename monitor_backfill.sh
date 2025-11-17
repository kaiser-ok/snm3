#!/bin/bash
# 監控回填進度

echo "======================================"
echo "回填進度監控 - $(date)"
echo "======================================"
echo ""

# 檢查進程
if ps aux | grep "backfill.*days 7" | grep -v grep > /dev/null; then
    echo "✅ 回填程式運行中"
    ps aux | grep "backfill.*days 7" | grep -v grep | awk '{print "   PID: " $2 "  CPU: " $3 "%  記憶體: " $4 "%  執行時間: " $10}'
    echo ""
else
    echo "⚠️  回填程式未運行"
    echo ""
fi

# 資料量統計
echo "📊 資料統計:"
NEW_COUNT=$(curl -s "http://localhost:9200/netflow_stats_5m/_count?q=unique_src_ports:*" | python3 -c "import sys,json;print(json.load(sys.stdin)['count'])" 2>/dev/null)
TOTAL_COUNT=$(curl -s "http://localhost:9200/netflow_stats_5m/_count" | python3 -c "import sys,json;print(json.load(sys.stdin)['count'])" 2>/dev/null)

echo "  有新欄位: $NEW_COUNT 筆"
echo "  總記錄數: $TOTAL_COUNT 筆"

if [ ! -z "$NEW_COUNT" ] && [ ! -z "$TOTAL_COUNT" ]; then
    PERCENTAGE=$(python3 -c "print(f'{$NEW_COUNT/$TOTAL_COUNT*100:.2f}')" 2>/dev/null || echo "計算中")
    echo "  覆蓋率: ${PERCENTAGE}%"
fi
echo ""

# 時間範圍
echo "⏰ 時間範圍:"
curl -s "http://localhost:9200/netflow_stats_5m/_search" -H 'Content-Type: application/json' -d '{"size":0,"query":{"exists":{"field":"unique_src_ports"}},"aggs":{"min_time":{"min":{"field":"time_bucket"}},"max_time":{"max":{"field":"time_bucket"}}}}' 2>/dev/null | \
  python3 -c "import sys,json;from datetime import datetime;d=json.load(sys.stdin);a=d['aggregations'];min_ts=a['min_time']['value']/1000;max_ts=a['max_time']['value']/1000;print(f\"  最早: {datetime.fromtimestamp(min_ts)}\");print(f\"  最新: {datetime.fromtimestamp(max_ts)}\");hours=(max_ts-min_ts)/3600;print(f\"  時間跨度: {hours:.1f} 小時 ({hours/24:.1f} 天)\")" 2>/dev/null
echo ""

# 預估進度（7天 = 168小時，每小時一批）
if [ ! -z "$NEW_COUNT" ]; then
    # 粗略估算：7天約需要 100萬+ 筆記錄（根據之前 1天 = 192k 筆）
    TARGET=1350000
    PROGRESS=$(python3 -c "print(f'{$NEW_COUNT/$TARGET*100:.1f}')" 2>/dev/null || echo "計算中")
    echo "📈 預估進度: ${PROGRESS}% (目標: 7 天資料)"

    if (( $(echo "$NEW_COUNT > $TARGET" | bc -l 2>/dev/null || echo 0) )); then
        echo "   ✅ 已達到目標！"
    else
        REMAINING=$((TARGET - NEW_COUNT))
        echo "   剩餘約: $REMAINING 筆記錄"
    fi
fi

echo ""
echo "======================================"
