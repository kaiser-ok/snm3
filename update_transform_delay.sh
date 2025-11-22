#!/bin/bash
# 更新 3m Transform 的 delay 設定
# 使用方法: ./update_transform_delay.sh <delay_seconds>
# 例如: ./update_transform_delay.sh 90

ES_HOST="http://localhost:9200"

# 檢查參數
if [ -z "$1" ]; then
    echo "錯誤: 請提供 delay 秒數"
    echo ""
    echo "使用方法:"
    echo "  $0 <delay_seconds>"
    echo ""
    echo "範例:"
    echo "  $0 60   # 設定 delay 為 60 秒"
    echo "  $0 90   # 設定 delay 為 90 秒"
    echo "  $0 120  # 設定 delay 為 120 秒"
    exit 1
fi

DELAY_SECONDS=$1
DELAY_STRING="${DELAY_SECONDS}s"

echo "========================================================================"
echo "更新 Transform Delay 設定"
echo "========================================================================"
echo ""
echo "目標 delay: ${DELAY_STRING}"
echo ""

# ============================================================================
# 顯示當前設定
# ============================================================================
echo "步驟 1: 檢查當前設定"
echo "------------------------------------------------------------------------"

CURRENT_DELAY_SRC=$(curl -s "${ES_HOST}/_transform/netflow_agg_3m_by_src" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['transforms'][0]['sync']['time']['delay'])" 2>/dev/null)
CURRENT_DELAY_DST=$(curl -s "${ES_HOST}/_transform/netflow_agg_3m_by_dst" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['transforms'][0]['sync']['time']['delay'])" 2>/dev/null)

echo "當前設定:"
echo "  - netflow_agg_3m_by_src: ${CURRENT_DELAY_SRC}"
echo "  - netflow_agg_3m_by_dst: ${CURRENT_DELAY_DST}"
echo ""

if [ "${CURRENT_DELAY_SRC}" == "${DELAY_STRING}" ] && [ "${CURRENT_DELAY_DST}" == "${DELAY_STRING}" ]; then
    echo "ℹ️  兩個 transform 的 delay 已經是 ${DELAY_STRING}，無需更新"
    exit 0
fi

# ============================================================================
# 停止 Transform
# ============================================================================
echo "步驟 2: 停止 Transform"
echo "------------------------------------------------------------------------"

echo "停止 netflow_agg_3m_by_src..."
curl -s -X POST "${ES_HOST}/_transform/netflow_agg_3m_by_src/_stop" | python3 -m json.tool
echo ""

echo "停止 netflow_agg_3m_by_dst..."
curl -s -X POST "${ES_HOST}/_transform/netflow_agg_3m_by_dst/_stop" | python3 -m json.tool
echo ""

sleep 2

# ============================================================================
# 更新設定
# ============================================================================
echo "步驟 3: 更新 delay 設定為 ${DELAY_STRING}"
echo "------------------------------------------------------------------------"

echo "更新 netflow_agg_3m_by_src..."
curl -s -X POST "${ES_HOST}/_transform/netflow_agg_3m_by_src/_update" \
  -H 'Content-Type: application/json' \
  -d "{
  \"sync\": {
    \"time\": {
      \"field\": \"FLOW_START_MILLISECONDS\",
      \"delay\": \"${DELAY_STRING}\"
    }
  }
}" | python3 -c "import sys, json; data=json.load(sys.stdin); print(f\"✓ delay 已更新為: {data['sync']['time']['delay']}\")"
echo ""

echo "更新 netflow_agg_3m_by_dst..."
curl -s -X POST "${ES_HOST}/_transform/netflow_agg_3m_by_dst/_update" \
  -H 'Content-Type: application/json' \
  -d "{
  \"sync\": {
    \"time\": {
      \"field\": \"FLOW_START_MILLISECONDS\",
      \"delay\": \"${DELAY_STRING}\"
    }
  }
}" | python3 -c "import sys, json; data=json.load(sys.stdin); print(f\"✓ delay 已更新為: {data['sync']['time']['delay']}\")"
echo ""

# ============================================================================
# 重新啟動 Transform
# ============================================================================
echo "步驟 4: 重新啟動 Transform"
echo "------------------------------------------------------------------------"

echo "啟動 netflow_agg_3m_by_src..."
curl -s -X POST "${ES_HOST}/_transform/netflow_agg_3m_by_src/_start" | python3 -m json.tool
echo ""

echo "啟動 netflow_agg_3m_by_dst..."
curl -s -X POST "${ES_HOST}/_transform/netflow_agg_3m_by_dst/_start" | python3 -m json.tool
echo ""

sleep 2

# ============================================================================
# 驗證設定
# ============================================================================
echo "步驟 5: 驗證新設定"
echo "------------------------------------------------------------------------"

NEW_DELAY_SRC=$(curl -s "${ES_HOST}/_transform/netflow_agg_3m_by_src" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['transforms'][0]['sync']['time']['delay'])")
NEW_DELAY_DST=$(curl -s "${ES_HOST}/_transform/netflow_agg_3m_by_dst" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['transforms'][0]['sync']['time']['delay'])")

STATE_SRC=$(curl -s "${ES_HOST}/_transform/netflow_agg_3m_by_src/_stats" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['transforms'][0]['state'])")
STATE_DST=$(curl -s "${ES_HOST}/_transform/netflow_agg_3m_by_dst/_stats" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['transforms'][0]['state'])")

echo "更新後設定:"
echo "  - netflow_agg_3m_by_src: ${NEW_DELAY_SRC} (狀態: ${STATE_SRC})"
echo "  - netflow_agg_3m_by_dst: ${NEW_DELAY_DST} (狀態: ${STATE_DST})"
echo ""

# ============================================================================
# 完成
# ============================================================================
if [ "${NEW_DELAY_SRC}" == "${DELAY_STRING}" ] && [ "${NEW_DELAY_DST}" == "${DELAY_STRING}" ]; then
    echo "========================================================================"
    echo "✓ 更新完成！"
    echo "========================================================================"
    echo ""
    echo "影響說明:"
    echo "  - 舊 delay: ${CURRENT_DELAY_SRC}"
    echo "  - 新 delay: ${DELAY_STRING}"
    echo "  - 延遲增減: $((DELAY_SECONDS - ${CURRENT_DELAY_SRC//s/})) 秒"
    echo ""
    echo "檢測延遲時間線 (使用 ${DELAY_STRING} delay):"
    echo "  1. Netflow 事件發生"
    echo "  2. → Exporter 緩衝 (0-60s)"
    echo "  3. → ES 索引 (0-30s)"
    echo "  4. → Transform delay (${DELAY_SECONDS}s)"
    echo "  5. → 聚合完成 (0-180s)"
    echo "  6. → 異常檢測 (0-600s)"
    echo "  總延遲: 約 $((DELAY_SECONDS/60 + 4))-17 分鐘"
    echo ""
else
    echo "========================================================================"
    echo "⚠️  更新可能失敗，請檢查設定"
    echo "========================================================================"
    exit 1
fi
