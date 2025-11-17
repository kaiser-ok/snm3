#!/bin/bash
#
# 檢查回填程序執行狀態
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="${SCRIPT_DIR}/backfill.pid"

echo "========================================"
echo "回填程序狀態檢查"
echo "========================================"
echo ""

# 檢查 PID 檔案是否存在
if [ ! -f "${PID_FILE}" ]; then
    echo "❌ 未找到 PID 檔案"
    echo "   可能尚未執行回填程序"
    echo ""
    echo "執行方式："
    echo "  ./run_backfill.sh --execute --days 3"
    exit 1
fi

PID=$(cat "${PID_FILE}")

# 檢查程序是否還在執行
if ps -p ${PID} > /dev/null 2>&1; then
    echo "✅ 回填程序正在執行中"
    echo "   PID: ${PID}"

    # 顯示程序資訊
    echo ""
    echo "程序資訊："
    ps -p ${PID} -o pid,etime,pcpu,pmem,cmd

    echo ""
    echo "========================================"
else
    echo "⏹️  回填程序已結束"
    echo "   PID: ${PID} (已不存在)"
    echo ""
fi

# 找到最新的日誌檔案
LATEST_LOG=$(ls -t "${SCRIPT_DIR}"/backfill_*.log 2>/dev/null | head -1)

if [ -n "${LATEST_LOG}" ]; then
    echo ""
    echo "最新日誌："
    echo "  ${LATEST_LOG}"
    echo ""

    # 檢查是否已完成
    if grep -q "執行總結" "${LATEST_LOG}"; then
        echo "✅ 回填已完成！"
        echo ""
        echo "執行摘要："
        echo "----------------------------------------"
        grep -A 10 "執行總結" "${LATEST_LOG}"
        echo ""

        # 清理 PID 檔案
        rm -f "${PID_FILE}"
    else
        echo "⏳ 回填進行中..."
        echo ""
        echo "最新進度 (最後 20 行)："
        echo "----------------------------------------"
        tail -20 "${LATEST_LOG}"
        echo "----------------------------------------"
        echo ""
        echo "即時監控命令："
        echo "  tail -f ${LATEST_LOG}"
    fi
else
    echo "❌ 未找到日誌檔案"
fi

echo ""
echo "========================================"
