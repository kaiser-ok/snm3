#!/bin/bash
#
# 批量驗證異常 IP 的便捷腳本
#
# 使用方法：
#   ./batch_verify.sh                    # 檢測最近30分鐘，驗證前5個異常
#   ./batch_verify.sh --minutes 60 --top 10  # 檢測最近60分鐘，驗證前10個

set -e

# 默認參數
MINUTES=30
TOP_N=5

# 解析參數
while [[ $# -gt 0 ]]; do
    case $1 in
        --minutes)
            MINUTES="$2"
            shift 2
            ;;
        --top)
            TOP_N="$2"
            shift 2
            ;;
        *)
            echo "未知參數: $1"
            echo "使用方法: $0 [--minutes 分鐘數] [--top 驗證數量]"
            exit 1
            ;;
    esac
done

echo "=================================================="
echo "批量異常驗證流程"
echo "=================================================="
echo "檢測時間範圍: 最近 $MINUTES 分鐘"
echo "驗證異常數量: 前 $TOP_N 個"
echo ""

# Step 1: 運行異常檢測
echo "Step 1: 運行異常檢測..."
echo ""
python3 realtime_detection.py --minutes $MINUTES > /tmp/detection_result.txt 2>&1

# Step 2: 提取異常 IP
echo "Step 2: 提取異常 IP..."
echo ""

# 從輸出中提取 IP（第2欄，跳過表頭和分隔線）
ANOMALY_IPS=$(cat /tmp/detection_result.txt | \
    grep -E "^\s*[0-9]+\s+" | \
    grep -v "排名" | \
    grep -v "===" | \
    head -n $TOP_N | \
    awk '{print $2}')

if [ -z "$ANOMALY_IPS" ]; then
    echo "❌ 沒有檢測到異常 IP"
    exit 0
fi

echo "檢測到以下異常 IP:"
echo "$ANOMALY_IPS" | nl
echo ""

# Step 3: 逐一深入分析
echo "Step 3: 深入分析每個異常 IP..."
echo ""

IP_COUNT=0
for IP in $ANOMALY_IPS; do
    IP_COUNT=$((IP_COUNT + 1))

    echo ""
    echo "=================================================="
    echo "[$IP_COUNT/$TOP_N] 分析 $IP"
    echo "=================================================="
    echo ""

    python3 verify_anomaly.py --ip "$IP" --minutes $MINUTES

    echo ""
    echo "按 Enter 繼續下一個，或 Ctrl+C 退出..."
    read -r
done

echo ""
echo "=================================================="
echo "✅ 完成所有驗證"
echo "=================================================="
echo ""
echo "💡 下一步:"
echo "  1. 如果誤報較多，運行: python3 tune_thresholds.py --file <IP列表>"
echo "  2. 根據建議調整 nad/config.yaml"
echo "  3. 重新訓練: python3 train_isolation_forest.py --days 7"
echo ""
