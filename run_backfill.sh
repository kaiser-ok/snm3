#!/bin/bash
#
# NetFlow 歷史資料回填 - 背景執行腳本
# 使用 nohup 在背景執行，即使登出也不會中斷
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/backfill_$(date +%Y%m%d_%H%M%S).log"

echo "========================================"
echo "NetFlow 歷史資料回填 - 背景執行"
echo "========================================"
echo "工作目錄: ${SCRIPT_DIR}"
echo "日誌檔案: ${LOG_FILE}"
echo "開始時間: $(date)"
echo ""

# 預設參數
DAYS=3
BATCH_HOURS=2
EXECUTE=""

# 解析參數
while [[ $# -gt 0 ]]; do
    case $1 in
        --days)
            DAYS="$2"
            shift 2
            ;;
        --batch-hours)
            BATCH_HOURS="$2"
            shift 2
            ;;
        --execute)
            EXECUTE="--execute"
            shift
            ;;
        *)
            echo "未知參數: $1"
            echo "用法: $0 [--days N] [--batch-hours N] [--execute]"
            exit 1
            ;;
    esac
done

# 顯示配置
echo "配置："
echo "  回填天數: ${DAYS}"
echo "  批次大小: ${BATCH_HOURS} 小時"
if [ -z "$EXECUTE" ]; then
    echo "  模式: 測試模式 (不寫入)"
    echo ""
    echo "⚠️  這是測試模式，不會實際寫入數據"
    echo "   若要正式執行，請加上 --execute 參數"
else
    echo "  模式: 正式執行 (會寫入)"
    echo ""
    echo "⚠️  即將開始回填，寫入數據到 netflow_stats_5m"
fi

echo ""
echo "========================================"
echo ""

# 使用 nohup 在背景執行
cd "${SCRIPT_DIR}"
nohup python3 backfill_historical_data.py \
    --days ${DAYS} \
    --batch-hours ${BATCH_HOURS} \
    ${EXECUTE} \
    --auto-confirm \
    > "${LOG_FILE}" 2>&1 &

PID=$!

echo "✅ 已在背景啟動回填程序"
echo ""
echo "程序 PID: ${PID}"
echo "日誌檔案: ${LOG_FILE}"
echo ""
echo "========================================"
echo "監控命令："
echo "========================================"
echo ""
echo "# 即時查看進度"
echo "tail -f ${LOG_FILE}"
echo ""
echo "# 查看最後 50 行"
echo "tail -50 ${LOG_FILE}"
echo ""
echo "# 檢查程序是否還在執行"
echo "ps -p ${PID}"
echo ""
echo "# 查看執行摘要（等執行完畢）"
echo "grep -A 10 '執行總結' ${LOG_FILE}"
echo ""
echo "# 停止執行（如需要）"
echo "kill ${PID}"
echo ""
echo "========================================"

# 將 PID 寫入檔案
echo ${PID} > "${SCRIPT_DIR}/backfill.pid"
echo "PID 已儲存至: ${SCRIPT_DIR}/backfill.pid"
echo ""
echo "你現在可以安全登出，程序會繼續執行"
echo ""
