#!/bin/bash
# 測試 IP 分析時間參數功能

BACKEND_URL="http://localhost:5000"

echo "========================================"
echo "測試 IP 分析時間參數功能"
echo "========================================"

# 測試 1: 24 小時分析，Top 20
echo ""
echo "測試 1: 24 小時分析，Top 20"
echo "----------------------------------------"
curl -X POST "${BACKEND_URL}/api/analysis/ip" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.10.135",
    "hours": 24,
    "top_n": 20
  }' 2>/dev/null | jq -r '
    if .status == "success" then
      "✓ 成功: IP=\(.ip), 時間範圍=\(.time_range.duration_hours)小時, Top目的地數量=\(.details.top_destinations | length)"
    else
      "✗ 失敗: \(.error)"
    end
  '

# 測試 2: 10 分鐘分析 (0.167 小時)，Top 10
echo ""
echo "測試 2: 10 分鐘分析，Top 10"
echo "----------------------------------------"
curl -X POST "${BACKEND_URL}/api/analysis/ip" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.10.135",
    "hours": 0.167,
    "top_n": 10
  }' 2>/dev/null | jq -r '
    if .status == "success" then
      "✓ 成功: IP=\(.ip), 時間範圍=\(.time_range.duration_hours)小時, Top目的地數量=\(.details.top_destinations | length)"
    else
      "✗ 失敗: \(.error)"
    end
  '

# 測試 3: 測試 top_n 參數驗證（超出範圍應該失敗）
echo ""
echo "測試 3: top_n 參數驗證 (top_n=100 應該失敗)"
echo "----------------------------------------"
curl -X POST "${BACKEND_URL}/api/analysis/ip" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.10.135",
    "hours": 1,
    "top_n": 100
  }' 2>/dev/null | jq -r '
    if .status == "error" then
      "✓ 驗證通過: \(.error)"
    else
      "✗ 驗證失敗: 應該拒絕 top_n=100"
    end
  '

echo ""
echo "========================================"
echo "測試完成"
echo "========================================"
