#!/bin/bash
# 測試設備映射 API 功能

BASE_URL="http://localhost:5000"

echo "=== 測試 1: 獲取設備映射配置 ==="
curl -s -X GET "${BASE_URL}/api/device-mapping" | python3 -m json.tool | head -60

echo -e "\n\n=== 測試 2: 添加 IP 網段到 station 設備類型 ==="
curl -s -X POST "${BASE_URL}/api/device-mapping/station/ip-ranges" \
  -H "Content-Type: application/json" \
  -d '{"ip_range": "192.168.100.0/24"}' | python3 -m json.tool

echo -e "\n\n=== 測試 3: 驗證 IP 網段已添加 ==="
curl -s -X GET "${BASE_URL}/api/device-mapping" | python3 -m json.tool | grep -A 5 "station"

echo -e "\n\n=== 測試 4: 更新設備類型描述 ==="
curl -s -X PUT "${BASE_URL}/api/device-mapping/station" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "工作站、PC、筆電、iPad等終端設備（已更新）",
    "characteristics": ["主動發起連線", "低到中等流量", "訪問外部服務", "新增特徵測試"]
  }' | python3 -m json.tool

echo -e "\n\n=== 測試 5: 更新特殊設備 ==="
curl -s -X PUT "${BASE_URL}/api/device-mapping/special/test_servers" \
  -H "Content-Type: application/json" \
  -d '{
    "device_type": "server_farm",
    "ips": ["192.168.10.100", "192.168.10.101"]
  }' | python3 -m json.tool

echo -e "\n\n=== 測試 6: 移除 IP 網段 ==="
curl -s -X DELETE "${BASE_URL}/api/device-mapping/station/ip-ranges" \
  -H "Content-Type: application/json" \
  -d '{"ip_range": "192.168.100.0/24"}' | python3 -m json.tool

echo -e "\n\n測試完成！"
