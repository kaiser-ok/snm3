#!/bin/bash
#
# 持續監控管理腳本
# 用於啟動、停止、查看實時異常檢測的持續監控模式
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/realtime_detection.pid"
LOG_FILE="$SCRIPT_DIR/realtime_detection.log"
PYTHON_SCRIPT="$SCRIPT_DIR/realtime_detection.py"

# 預設參數
INTERVAL=10
WINDOW=10
EXCLUDE_SERVERS=""

# 顏色輸出
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 顯示使用說明
show_usage() {
    echo "用法: $0 {start|stop|restart|status|logs|tail}"
    echo ""
    echo "命令:"
    echo "  start           - 啟動持續監控（背景執行）"
    echo "  stop            - 停止持續監控"
    echo "  restart         - 重啟持續監控"
    echo "  status          - 查看運行狀態"
    echo "  logs            - 查看所有日誌"
    echo "  tail            - 實時跟蹤日誌（Ctrl+C 退出）"
    echo ""
    echo "選項（在 start 時使用）:"
    echo "  --interval N    - 檢測間隔（分鐘，默認: 10）"
    echo "  --minutes N     - 分析窗口（分鐘，默認: 10）"
    echo "  --exclude-servers - 過濾服務器回應流量"
    echo ""
    echo "範例:"
    echo "  $0 start"
    echo "  $0 start --interval 5 --minutes 15"
    echo "  $0 start --interval 10 --minutes 10 --exclude-servers"
    echo "  $0 tail"
    echo "  $0 stop"
}

# 檢查是否正在運行
is_running() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            return 0  # 正在運行
        else
            # PID 文件存在但進程不存在
            rm -f "$PID_FILE"
            return 1  # 未運行
        fi
    else
        return 1  # 未運行
    fi
}

# 啟動監控
start_monitor() {
    if is_running; then
        PID=$(cat "$PID_FILE")
        echo -e "${YELLOW}⚠️  監控已在運行中 (PID: $PID)${NC}"
        echo -e "${BLUE}使用 '$0 stop' 停止，或 '$0 restart' 重啟${NC}"
        exit 1
    fi

    # 解析啟動參數
    shift  # 移除 'start' 命令
    while [[ $# -gt 0 ]]; do
        case $1 in
            --interval)
                INTERVAL="$2"
                shift 2
                ;;
            --minutes)
                WINDOW="$2"
                shift 2
                ;;
            --exclude-servers)
                EXCLUDE_SERVERS="--exclude-servers"
                shift
                ;;
            *)
                echo -e "${RED}未知參數: $1${NC}"
                show_usage
                exit 1
                ;;
        esac
    done

    echo -e "${BLUE}=====================================================================================================${NC}"
    echo -e "${GREEN}🚀 啟動持續監控${NC}"
    echo -e "${BLUE}=====================================================================================================${NC}"
    echo -e "檢測間隔: ${GREEN}$INTERVAL${NC} 分鐘"
    echo -e "分析窗口: ${GREEN}$WINDOW${NC} 分鐘"
    if [ -n "$EXCLUDE_SERVERS" ]; then
        echo -e "過濾服務器回應: ${GREEN}是${NC}"
    fi
    echo -e "日誌文件: ${BLUE}$LOG_FILE${NC}"
    echo ""

    # 啟動監控（使用 -u 參數禁用緩衝）
    nohup python3 -u "$PYTHON_SCRIPT" --continuous --interval "$INTERVAL" --minutes "$WINDOW" $EXCLUDE_SERVERS > "$LOG_FILE" 2>&1 &
    PID=$!

    # 保存 PID
    echo $PID > "$PID_FILE"

    # 等待一下確認啟動成功
    sleep 2

    if is_running; then
        echo -e "${GREEN}✅ 監控已啟動 (PID: $PID)${NC}"
        echo ""
        echo -e "${BLUE}常用命令:${NC}"
        echo -e "  查看狀態: ${YELLOW}$0 status${NC}"
        echo -e "  實時日誌: ${YELLOW}$0 tail${NC}"
        echo -e "  停止監控: ${YELLOW}$0 stop${NC}"
        echo -e "${BLUE}=====================================================================================================${NC}"
    else
        echo -e "${RED}❌ 啟動失敗，請查看日誌: $LOG_FILE${NC}"
        exit 1
    fi
}

# 停止監控
stop_monitor() {
    if ! is_running; then
        echo -e "${YELLOW}⚠️  監控未運行${NC}"
        exit 1
    fi

    PID=$(cat "$PID_FILE")
    echo -e "${BLUE}停止監控 (PID: $PID)...${NC}"

    kill $PID 2>/dev/null

    # 等待進程結束
    for i in {1..10}; do
        if ! ps -p "$PID" > /dev/null 2>&1; then
            rm -f "$PID_FILE"
            echo -e "${GREEN}✅ 監控已停止${NC}"
            return
        fi
        sleep 1
    done

    # 如果還沒停止，強制停止
    echo -e "${YELLOW}強制停止...${NC}"
    kill -9 $PID 2>/dev/null
    rm -f "$PID_FILE"
    echo -e "${GREEN}✅ 監控已強制停止${NC}"
}

# 重啟監控
restart_monitor() {
    echo -e "${BLUE}重啟監控...${NC}"
    if is_running; then
        stop_monitor
        sleep 2
    fi
    start_monitor "$@"
}

# 查看狀態
show_status() {
    echo -e "${BLUE}=====================================================================================================${NC}"
    echo -e "${BLUE}持續監控狀態${NC}"
    echo -e "${BLUE}=====================================================================================================${NC}"

    if is_running; then
        PID=$(cat "$PID_FILE")
        echo -e "狀態: ${GREEN}運行中${NC}"
        echo -e "PID: ${GREEN}$PID${NC}"
        echo -e "日誌文件: ${BLUE}$LOG_FILE${NC}"

        # 顯示日誌大小
        if [ -f "$LOG_FILE" ]; then
            LOG_SIZE=$(du -h "$LOG_FILE" | cut -f1)
            echo -e "日誌大小: ${BLUE}$LOG_SIZE${NC}"
        fi

        # 顯示運行時間
        if ps -p "$PID" -o etime= > /dev/null 2>&1; then
            UPTIME=$(ps -p "$PID" -o etime= | tr -d ' ')
            echo -e "運行時間: ${BLUE}$UPTIME${NC}"
        fi

        # 顯示最新的幾行日誌
        echo ""
        echo -e "${BLUE}最新日誌 (最後 10 行):${NC}"
        echo -e "${BLUE}----------------------------------------------------------------------------------------------------${NC}"
        tail -n 10 "$LOG_FILE" 2>/dev/null || echo "無日誌"
        echo -e "${BLUE}=====================================================================================================${NC}"

    else
        echo -e "狀態: ${RED}未運行${NC}"
        echo -e "${BLUE}=====================================================================================================${NC}"
    fi
}

# 查看所有日誌
show_logs() {
    if [ ! -f "$LOG_FILE" ]; then
        echo -e "${RED}日誌文件不存在${NC}"
        exit 1
    fi

    less +G "$LOG_FILE"
}

# 實時跟蹤日誌
tail_logs() {
    if [ ! -f "$LOG_FILE" ]; then
        echo -e "${RED}日誌文件不存在${NC}"
        exit 1
    fi

    echo -e "${BLUE}實時日誌 (按 Ctrl+C 退出)${NC}"
    echo -e "${BLUE}=====================================================================================================${NC}"
    tail -f "$LOG_FILE"
}

# 主程序
case "$1" in
    start)
        start_monitor "$@"
        ;;
    stop)
        stop_monitor
        ;;
    restart)
        restart_monitor "$@"
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs
        ;;
    tail)
        tail_logs
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
