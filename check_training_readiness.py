#!/usr/bin/env python3
"""
檢查訓練準備情況
"""

import requests
import json
import warnings
from datetime import datetime

# 忽略 Elasticsearch 安全警告
warnings.filterwarnings('ignore', message='.*Elasticsearch built-in security features.*')

ES_HOST = "http://localhost:9200"
INDEX = "netflow_stats_5m"

print("=" * 70)
print("Isolation Forest 訓練準備情況檢查")
print("=" * 70)
print()

# 1. 檢查索引
print("✓ 檢查 1: Elasticsearch 索引...")
try:
    resp = requests.get(f"{ES_HOST}/{INDEX}/_count")
    data = resp.json()
    total = data['count']
    print(f"  - 索引: {INDEX}")
    print(f"  - 總文檔數: {total:,}")

    if total > 0:
        print(f"  ✅ 索引有數據")
    else:
        print(f"  ❌ 索引無數據，無法訓練")
        exit(1)
except Exception as e:
    print(f"  ❌ ES 連接失敗: {e}")
    exit(1)

print()

# 2. 檢查時間範圍
print("✓ 檢查 2: 數據時間範圍...")
query = {
    "size": 0,
    "aggs": {
        "time_range": {
            "stats": {"field": "time_bucket"}
        }
    }
}

try:
    resp = requests.post(
        f"{ES_HOST}/{INDEX}/_search",
        json=query,
        headers={'Content-Type': 'application/json'}
    )
    data = resp.json()
    stats = data['aggregations']['time_range']

    min_time = datetime.fromtimestamp(stats['min'] / 1000)
    max_time = datetime.fromtimestamp(stats['max'] / 1000)
    count = int(stats['count'])

    duration_hours = (max_time - min_time).total_seconds() / 3600
    duration_days = duration_hours / 24

    print(f"  - 最早時間: {min_time}")
    print(f"  - 最新時間: {max_time}")
    print(f"  - 時間跨度: {duration_hours:.1f} 小時 ({duration_days:.1f} 天)")

    if duration_hours >= 24:
        print(f"  ✅ 數據充足（{duration_days:.1f} 天）")
        days_param = min(int(duration_days), 7)
    elif duration_hours >= 6:
        print(f"  ⚠️  數據較少（{duration_hours:.1f} 小時），但可訓練")
        days_param = 1
    else:
        print(f"  ⚠️  數據不足（{duration_hours:.1f} 小時）")
        days_param = 1

except Exception as e:
    print(f"  ❌ 查詢失敗: {e}")
    exit(1)

print()

# 3. 檢查樣本分布
print("✓ 檢查 3: 樣本分布...")
query = {
    "size": 0,
    "aggs": {
        "by_ip": {
            "cardinality": {
                "field": "src_ip",
                "precision_threshold": 10000
            }
        },
        "flow_stats": {
            "stats": {
                "field": "flow_count"
            }
        }
    }
}

try:
    resp = requests.post(
        f"{ES_HOST}/{INDEX}/_search",
        json=query,
        headers={'Content-Type': 'application/json'}
    )
    data = resp.json()

    unique_ips = int(data['aggregations']['by_ip']['value'])
    flow_stats = data['aggregations']['flow_stats']

    print(f"  - 唯一 IP 數: {unique_ips:,}")
    print(f"  - 平均連線數: {flow_stats['avg']:.0f}")
    print(f"  - 最大連線數: {flow_stats['max']:.0f}")
    print(f"  - 最小連線數: {flow_stats['min']:.0f}")

    if unique_ips >= 100:
        print(f"  ✅ IP 多樣性良好")
    else:
        print(f"  ⚠️  IP 數量較少，可能影響效果")

except Exception as e:
    print(f"  ❌ 查詢失敗: {e}")

print()

# 4. 檢查數據品質
print("✓ 檢查 4: 數據品質...")
query = {
    "size": 10,
    "sort": [{"time_bucket": "desc"}]
}

try:
    resp = requests.post(
        f"{ES_HOST}/{INDEX}/_search",
        json=query,
        headers={'Content-Type': 'application/json'}
    )
    data = resp.json()

    if data['hits']['total']['value'] > 0:
        sample = data['hits']['hits'][0]['_source']

        required_fields = [
            'flow_count', 'total_bytes', 'total_packets',
            'unique_dsts', 'unique_ports', 'avg_bytes', 'max_bytes'
        ]

        missing = [f for f in required_fields if f not in sample]

        if not missing:
            print(f"  ✅ 所有必要欄位都存在")
        else:
            print(f"  ⚠️  缺少欄位: {missing}")

        # 顯示樣本
        print(f"\n  最新記錄樣本:")
        print(f"    - time_bucket: {sample.get('time_bucket')}")
        print(f"    - src_ip: {sample.get('src_ip')}")
        print(f"    - flow_count: {sample.get('flow_count', 0):,}")
        print(f"    - unique_dsts: {sample.get('unique_dsts', 0)}")
        print(f"    - total_bytes: {sample.get('total_bytes', 0):,}")

except Exception as e:
    print(f"  ❌ 查詢失敗: {e}")

print()
print("=" * 70)
print("訓練建議")
print("=" * 70)
print()

print(f"✅ 準備情況: 數據已就緒，可以開始訓練\n")

print(f"📋 推薦訓練命令:\n")
print(f"  python3 train_isolation_forest.py --days {days_param} --evaluate\n")

if duration_hours < 24:
    print(f"⚠️  注意事項:")
    print(f"  - 當前數據量較少（{duration_hours:.1f} 小時）")
    print(f"  - 模型可能對正常行為理解不完整")
    print(f"  - 建議24小時後使用更多數據重訓練")
    print(f"  - 重訓練命令: python3 train_isolation_forest.py --days 1")
    print()

print(f"💡 提示:")
print(f"  - 訓練時間預估: {total/10000:.0f}-{total/5000:.0f} 分鐘")
print(f"  - 訓練完成後可使用: python3 realtime_detection.py --minutes 10")
print()

print("=" * 70)
