#!/usr/bin/env python3
"""
測試通訊埠改進效果

快速測試新的源/目的通訊埠特徵是否正確計算
"""

import sys
from elasticsearch import Elasticsearch
from nad.utils.config_loader import load_config
from nad.ml.feature_engineer import FeatureEngineer

def test_feature_extraction():
    """測試特徵提取"""
    print("\n" + "="*100)
    print("測試通訊埠特徵提取")
    print("="*100 + "\n")

    # 載入配置
    config = load_config()
    es_host = config.get('elasticsearch', {}).get('host', 'http://localhost:9200')
    es = Elasticsearch([es_host], timeout=30)

    if not es.ping():
        print(f"❌ 無法連接到 Elasticsearch: {es_host}")
        sys.exit(1)

    print(f"✓ 已連接到 Elasticsearch: {es_host}\n")

    # 查詢有新欄位的記錄
    query = {
        "size": 10,
        "query": {
            "exists": {"field": "unique_src_ports"}
        },
        "sort": [{"time_bucket": "desc"}]
    }

    try:
        response = es.search(index="netflow_stats_5m", **query)
        hits = response['hits']['hits']

        if not hits:
            print("❌ 沒有找到有新欄位的記錄")
            print("   請等待 Transform 產生資料後再試")
            sys.exit(1)

        print(f"✓ 找到 {len(hits)} 筆測試記錄\n")

        # 創建特徵工程器
        fe = FeatureEngineer(config)

        print(f"📊 特徵數量: {len(fe.feature_names)}")
        print(f"   特徵名稱: {', '.join(fe.feature_names)}\n")

        print("="*100)
        print("測試記錄特徵提取")
        print("="*100 + "\n")

        # 測試幾個記錄
        for i, hit in enumerate(hits[:5], 1):
            record = hit['_source']
            print(f"{i}. IP: {record['src_ip']}")
            print(f"   時間: {record['time_bucket']}")
            print(f"   連線數: {record['flow_count']:,}")
            print(f"   不同目的地: {record['unique_dsts']}")
            print(f"   不同源通訊埠: {record.get('unique_src_ports', 'N/A')}")
            print(f"   不同目的通訊埠: {record.get('unique_dst_ports', 'N/A')}")

            # 提取特徵
            features = fe.extract_features(record)

            print(f"\n   計算的特徵:")
            print(f"     目的地分散度: {features['dst_diversity']:.3f}")
            print(f"     源通訊埠分散度: {features['src_port_diversity']:.3f}")
            print(f"     目的通訊埠分散度: {features['dst_port_diversity']:.3f}")
            print(f"     是否高連線數: {features['is_high_connection']}")
            print(f"     是否掃描模式: {features['is_scanning_pattern']}")
            print(f"     是否伺服器回應: {features['is_likely_server_response']}")

            # 判斷
            if features['is_likely_server_response']:
                print(f"   ✅ 判斷: 伺服器回應流量")
            elif features['is_scanning_pattern']:
                print(f"   🚨 判斷: 掃描模式")
            elif features['is_high_connection']:
                print(f"   ⚠️  判斷: 高連線數")
            else:
                print(f"   ✓ 判斷: 正常流量")

            print()

        print("="*100)
        print("✅ 特徵提取測試完成")
        print("="*100 + "\n")

        # 統計伺服器回應的比例
        server_responses = sum(1 for hit in hits if
                               fe.extract_features(hit['_source'])['is_likely_server_response'])
        scanning = sum(1 for hit in hits if
                      fe.extract_features(hit['_source'])['is_scanning_pattern'])

        print("📈 統計結果:")
        print(f"   伺服器回應: {server_responses}/{len(hits)} ({server_responses/len(hits)*100:.1f}%)")
        print(f"   掃描模式: {scanning}/{len(hits)} ({scanning/len(hits)*100:.1f}%)")
        print()

        print("💡 下一步:")
        print("   1. 執行 ./monitor_transform.sh 檢查資料量")
        print("   2. 當資料量 > 10,000 筆時:")
        print("      python3 train_isolation_forest.py --days 1 --evaluate --exclude-servers")
        print("   3. 測試 AD 伺服器:")
        print("      python3 realtime_detection.py --minutes 30 --exclude-servers")
        print("      python3 verify_anomaly.py --ip 192.168.10.135 --minutes 30")
        print()

    except Exception as e:
        print(f"❌ 測試失敗: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def test_server_detection_logic():
    """測試伺服器檢測邏輯"""
    print("\n" + "="*100)
    print("測試伺服器檢測邏輯")
    print("="*100 + "\n")

    config = load_config()
    fe = FeatureEngineer(config)

    # 測試案例
    test_cases = [
        {
            "name": "AD 伺服器（DNS + LDAP）",
            "record": {
                "flow_count": 6000,
                "total_bytes": 120000000,
                "total_packets": 600000,
                "unique_dsts": 67,
                "unique_src_ports": 2,      # 53, 389
                "unique_dst_ports": 6000,   # 客戶端隨機埠
                "avg_bytes": 20000,
                "max_bytes": 100000,
            },
            "expected": "伺服器回應"
        },
        {
            "name": "DNS 伺服器",
            "record": {
                "flow_count": 5000,
                "total_bytes": 25000000,
                "total_packets": 250000,
                "unique_dsts": 50,
                "unique_src_ports": 1,      # 53
                "unique_dst_ports": 5000,   # 客戶端隨機埠
                "avg_bytes": 5000,
                "max_bytes": 15000,
            },
            "expected": "伺服器回應"
        },
        {
            "name": "通訊埠掃描",
            "record": {
                "flow_count": 5000,
                "total_bytes": 25000000,
                "total_packets": 250000,
                "unique_dsts": 50,
                "unique_src_ports": 4800,   # 隨機源埠
                "unique_dst_ports": 200,    # 掃描多個埠
                "avg_bytes": 5000,
                "max_bytes": 15000,
            },
            "expected": "掃描"
        },
        {
            "name": "網路掃描",
            "record": {
                "flow_count": 1000,
                "total_bytes": 5000000,
                "total_packets": 50000,
                "unique_dsts": 100,
                "unique_src_ports": 900,    # 隨機源埠
                "unique_dst_ports": 5,      # 固定埠（如 22, 80）
                "avg_bytes": 5000,
                "max_bytes": 10000,
            },
            "expected": "掃描"
        },
    ]

    for case in test_cases:
        print(f"測試: {case['name']}")
        print(f"  預期: {case['expected']}")

        features = fe.extract_features(case['record'])

        print(f"  特徵:")
        print(f"    源通訊埠分散度: {features['src_port_diversity']:.3f}")
        print(f"    目的通訊埠分散度: {features['dst_port_diversity']:.3f}")
        print(f"    不同源通訊埠: {features['unique_src_ports']}")
        print(f"    不同目的通訊埠: {features['unique_dst_ports']}")

        if features['is_likely_server_response']:
            result = "伺服器回應"
            icon = "✅"
        elif features['is_scanning_pattern']:
            result = "掃描"
            icon = "🚨"
        else:
            result = "正常"
            icon = "✓"

        match = "✅ 正確" if result == case['expected'] else "❌ 錯誤"
        print(f"  結果: {icon} {result} {match}")
        print()

    print("="*100)
    print("✅ 邏輯測試完成")
    print("="*100 + "\n")


if __name__ == "__main__":
    print("\n" + "="*100)
    print("通訊埠改進測試")
    print("="*100)

    # 測試 1: 邏輯測試（不需要資料）
    test_server_detection_logic()

    # 測試 2: 實際資料測試（需要 Transform 資料）
    test_feature_extraction()
