#!/bin/bash
# 測試 threshold API 功能

BASE_URL="http://localhost:5000"

echo "=== 測試 1: 獲取訓練配置（應包含 anomaly_threshold） ==="
curl -s -X GET "${BASE_URL}/api/training/config" | python3 -m json.tool

echo -e "\n\n=== 測試 2: 更新配置（包含 anomaly_threshold） ==="
curl -s -X PUT "${BASE_URL}/api/training/config" \
  -H "Content-Type: application/json" \
  -d '{"anomaly_threshold": 0.7}' | python3 -m json.tool

echo -e "\n\n=== 測試 3: 驗證配置已更新 ==="
curl -s -X GET "${BASE_URL}/api/training/config" | python3 -m json.tool | grep -A 1 "anomaly_threshold"

echo -e "\n\n=== 測試 4: 開始訓練（包含 anomaly_threshold 參數） ==="
curl -s -X POST "${BASE_URL}/api/training/start" \
  -H "Content-Type: application/json" \
  -d '{
    "days": 1,
    "n_estimators": 100,
    "contamination": 0.05,
    "anomaly_threshold": 0.65,
    "exclude_servers": false
  }' | python3 -m json.tool

echo -e "\n\n測試完成！"
