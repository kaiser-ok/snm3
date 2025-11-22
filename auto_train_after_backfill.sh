#!/bin/bash
# 自動監控回填完成後開始訓練

echo "=========================================="
echo "自動訓練監控腳本"
echo "=========================================="
echo "開始時間: $(date)"
echo ""

# 監控回填程序
echo "🔍 等待回填程序完成..."
while true; do
    # 檢查兩個 backfill 程序是否還在執行
    by_src_running=$(ps aux | grep "backfill_historical_data.py --mode by_src" | grep -v grep | wc -l)
    by_dst_running=$(ps aux | grep "backfill_historical_data.py --mode by_dst" | grep -v grep | wc -l)

    if [ $by_src_running -eq 0 ] && [ $by_dst_running -eq 0 ]; then
        echo ""
        echo "✅ 回填程序已全部完成！"
        echo "完成時間: $(date)"
        break
    fi

    echo -ne "\r等待中... by_src: $by_src_running, by_dst: $by_dst_running"
    sleep 30
done

echo ""
echo ""
echo "=========================================="
echo "開始模型訓練"
echo "=========================================="
echo ""

# 訓練 by_src 模型
echo "📊 訓練 isolation_forest (by_src) 模型..."
echo "執行時間: $(date)"
cd /home/kaisermac/snm_flow
python3 train_isolation_forest.py --days 7 2>&1 | tee train_by_src_7days.log

if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo "✅ by_src 模型訓練完成"
else
    echo "❌ by_src 模型訓練失敗"
    exit 1
fi

echo ""
echo "=========================================="
echo ""

# 訓練 by_dst 模型
echo "📊 訓練 isolation_forest_by_dst 模型..."
echo "執行時間: $(date)"
python3 train_isolation_forest_by_dst.py --days 7 2>&1 | tee train_by_dst_7days.log

if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo "✅ by_dst 模型訓練完成"
else
    echo "❌ by_dst 模型訓練失敗"
    exit 1
fi

echo ""
echo "=========================================="
echo "🔄 重啟偵測服務"
echo "=========================================="
echo ""

sudo systemctl restart nad-realtime-detection.service
sleep 3
sudo systemctl status nad-realtime-detection.service --no-pager

echo ""
echo "=========================================="
echo "✅ 全部完成！"
echo "=========================================="
echo "結束時間: $(date)"
echo ""
echo "查看訓練日誌："
echo "  - by_src: tail -f train_by_src_7days.log"
echo "  - by_dst: tail -f train_by_dst_7days.log"
