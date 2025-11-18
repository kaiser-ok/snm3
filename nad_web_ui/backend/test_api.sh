#!/bin/bash
# API 測試腳本

BASE_URL="http://localhost:5000"

echo "======================================"
echo "NAD Web UI Backend API 測試"
echo "======================================"
echo ""

# 測試健康檢查
echo "1. 測試健康檢查..."
curl -s ${BASE_URL}/api/health | python3 -m json.tool
echo -e "\n"

# 測試模型狀態
echo "2. 測試模型狀態..."
curl -s ${BASE_URL}/api/detection/status | python3 -m json.tool
echo -e "\n"

# 測試訓練配置
echo "3. 測試訓練配置..."
curl -s ${BASE_URL}/api/training/config | python3 -m json.tool
echo -e "\n"

# 測試執行檢測
echo "4. 測試執行檢測 (30 分鐘)..."
JOB_RESPONSE=$(curl -s -X POST ${BASE_URL}/api/detection/run \
  -H "Content-Type: application/json" \
  -d '{"minutes": 30}')
echo $JOB_RESPONSE | python3 -m json.tool

# 提取 job_id
JOB_ID=$(echo $JOB_RESPONSE | python3 -c "import sys, json; print(json.load(sys.stdin).get('job_id', ''))")

if [ ! -z "$JOB_ID" ]; then
    echo -e "\nJob ID: $JOB_ID"
    echo "等待 3 秒..."
    sleep 3

    echo -e "\n5. 獲取檢測結果..."
    curl -s ${BASE_URL}/api/detection/results/${JOB_ID} | python3 -m json.tool | head -50
fi

echo -e "\n\n======================================"
echo "測試完成！"
echo "======================================"
