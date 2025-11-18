#!/bin/bash
# NAD Web UI Backend 啟動腳本

set -e

# 顏色輸出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}NAD Web UI Backend 啟動腳本${NC}"
echo -e "${GREEN}=====================================${NC}\n"

# 檢查虛擬環境
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}虛擬環境不存在，正在創建...${NC}"
    python3 -m venv venv
    echo -e "${GREEN}✓ 虛擬環境已創建${NC}\n"
fi

# 啟動虛擬環境
echo -e "${YELLOW}啟動虛擬環境...${NC}"
source venv/bin/activate
echo -e "${GREEN}✓ 虛擬環境已啟動${NC}\n"

# 檢查依賴
if [ ! -f "venv/bin/flask" ]; then
    echo -e "${YELLOW}安裝依賴套件...${NC}"
    pip install -r requirements.txt
    echo -e "${GREEN}✓ 依賴套件已安裝${NC}\n"
fi

# 檢查 .env 文件
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}警告: .env 文件不存在${NC}"
    echo -e "${YELLOW}複製 .env.example 到 .env 並編輯配置${NC}"
    cp .env.example .env
    echo -e "${GREEN}✓ 已創建 .env 文件，請編輯後再啟動${NC}\n"
    exit 1
fi

# 創建日誌目錄
mkdir -p ../logs

# 檢查 NAD 模組路徑
NAD_PATH="/home/kaisermac/snm_flow/nad"
if [ ! -d "$NAD_PATH" ]; then
    echo -e "${RED}錯誤: NAD 模組路徑不存在: $NAD_PATH${NC}"
    exit 1
fi

echo -e "${GREEN}✓ 所有檢查通過${NC}\n"

# 啟動方式選擇
echo "選擇啟動方式:"
echo "  1) 開發模式 (Flask debug server)"
echo "  2) 生產模式 (Gunicorn)"
read -p "請輸入選項 (1 或 2, 默認: 1): " choice
choice=${choice:-1}

if [ "$choice" == "1" ]; then
    echo -e "\n${GREEN}啟動開發伺服器...${NC}"
    export FLASK_ENV=development
    python3 app.py
elif [ "$choice" == "2" ]; then
    echo -e "\n${GREEN}啟動生產伺服器 (Gunicorn)...${NC}"
    export FLASK_ENV=production
    gunicorn --bind 0.0.0.0:5000 \
             --workers 4 \
             --timeout 300 \
             --access-logfile ../logs/access.log \
             --error-logfile ../logs/error.log \
             app:app
else
    echo -e "${RED}無效選項${NC}"
    exit 1
fi
