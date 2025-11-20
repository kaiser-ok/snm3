#!/usr/bin/env python3
"""
測試後處理模組功能

驗證：
1. AnomalyPostProcessor 能正確識別微服務模式
2. Port Scan 誤報能被成功排除
3. DDoS 偵測功能正常
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nad.ml.post_processor import AnomalyPostProcessor
from nad.ml.isolation_forest_detector import OptimizedIsolationForest
from nad.ml.anomaly_classifier import AnomalyClassifier


def test_post_processor_basic():
    """測試基本功能"""
    print("="*70)
    print("測試 1: AnomalyPostProcessor 基本功能")
    print("="*70)

    post_processor = AnomalyPostProcessor()

    # 創建測試異常（模擬 ML 偵測的 Port Scan）
    test_anomalies = [
        {
            'src_ip': '192.168.10.135',
            'time_bucket': '2025-11-17T13:00:00.000Z',
            'anomaly_score': 0.65,
            'confidence': 0.75,
            'flow_count': 1200,
            'unique_dsts': 45,
            'unique_dst_ports': 1000,
            'avg_bytes': 1200,
            'total_bytes': 1440000,
            'features': {
                'flow_count': 1200,
                'unique_dsts': 45,
                'unique_dst_ports': 1000,
                'avg_bytes': 1200
            },
            'classification': {
                'class': 'PORT_SCAN',
                'class_name': '埠掃描',
                'confidence': 0.95,
                'severity': 'HIGH'
            }
        }
    ]

    print(f"\n輸入: {len(test_anomalies)} 個 ML 偵測的異常")
    print(f"  - {test_anomalies[0]['src_ip']}")
    print(f"  - ML 判斷: {test_anomalies[0]['classification']['class']}")
    print(f"  - unique_dst_ports: {test_anomalies[0]['unique_dst_ports']}")
    print()

    # 驗證
    result = post_processor.validate_anomalies(test_anomalies, time_range="now-1h")

    print(f"輸出:")
    print(f"  - 真實異常: {len(result['validated'])}")
    print(f"  - 誤報: {len(result['false_positives'])}")
    print()

    if result['false_positives']:
        print("誤報詳情:")
        for fp in result['false_positives']:
            print(f"  - {fp['src_ip']}: {fp['false_positive_reason']}")

    print()
    return result


def test_with_real_ml_detections():
    """使用真實的 ML 偵測結果進行測試"""
    print("="*70)
    print("測試 2: 使用真實 ML 偵測結果")
    print("="*70)

    # 初始化組件
    detector = OptimizedIsolationForest()
    classifier = AnomalyClassifier()
    post_processor = AnomalyPostProcessor()

    # 加載模型
    try:
        detector._load_model()
    except FileNotFoundError:
        print("\n⚠️  Isolation Forest 模型未找到")
        print("請先訓練模型: python3 train_isolation_forest.py")
        return

    # Step 1: 獲取 ML 偵測結果
    print("\nStep 1: Isolation Forest 偵測...")
    anomalies = detector.predict_realtime(recent_minutes=30)
    print(f"✓ 偵測到 {len(anomalies)} 個異常")

    if not anomalies:
        print("未發現異常，測試結束")
        return

    # Step 2: 分類
    print("\nStep 2: 威脅分類...")
    classified = []
    for anomaly in anomalies:
        classification = classifier.classify(
            features=anomaly['features'],
            context={'src_ip': anomaly['src_ip']}
        )
        classified.append({**anomaly, 'classification': classification})

    # 統計分類結果
    class_counts = {}
    for a in classified:
        c = a['classification']['class']
        class_counts[c] = class_counts.get(c, 0) + 1

    print(f"✓ 分類結果:")
    for threat_class, count in class_counts.items():
        print(f"  - {threat_class}: {count}")

    # 只測試 Port Scan
    port_scans = [a for a in classified if a['classification']['class'] == 'PORT_SCAN']

    if not port_scans:
        print("\n未發現 Port Scan 告警，測試其他異常...")
        port_scans = classified[:5]  # 測試前 5 個

    print(f"\n測試樣本: {len(port_scans)} 個")

    # Step 3: 後處理驗證
    print("\nStep 3: 雙向驗證...")
    result = post_processor.validate_anomalies(port_scans, time_range="now-1h")

    print(f"✓ 驗證結果:")
    print(f"  - 真實異常: {len(result['validated'])}")
    print(f"  - 誤報: {len(result['false_positives'])}")
    print(f"  - 誤報率: {result['stats']['reduction_rate']*100:.1f}%")

    # 顯示詳細報告
    print()
    report = post_processor.generate_report(
        result['validated'],
        result['false_positives']
    )
    print(report)

    return result


def test_ddos_detection():
    """測試 DDoS 偵測"""
    print("="*70)
    print("測試 3: DDoS 偵測")
    print("="*70)

    post_processor = AnomalyPostProcessor()

    print("\n偵測最近 1 小時的 DDoS 攻擊...")
    ddos_attacks = post_processor.detect_ddos(time_range="now-1h", threshold=50)

    print(f"✓ 偵測到 {len(ddos_attacks)} 個可能的 DDoS 攻擊")

    if ddos_attacks:
        print(f"\nDDoS 攻擊詳情:")
        print(f"{'目標IP':<16} {'來源數':>8} {'連線數':>10} {'平均封包':>10} {'類型':^15} {'嚴重性':^10}")
        print("-"*80)

        for ddos in ddos_attacks[:10]:
            print(f"{ddos['target_ip']:<16} "
                  f"{ddos['unique_sources']:>8} "
                  f"{ddos['total_connections']:>10,} "
                  f"{ddos['avg_packet_size']:>10.0f} "
                  f"{ddos['ddos_type']:^15} "
                  f"{ddos['severity']:^10}")

    print()
    return ddos_attacks


def main():
    """主測試流程"""
    print("\n" + "🧪 " * 25)
    print("AnomalyPostProcessor 功能測試")
    print("🧪 " * 25 + "\n")

    # 測試 1: 基本功能
    test_post_processor_basic()

    # 測試 2: 真實 ML 偵測
    test_with_real_ml_detections()

    # 測試 3: DDoS 偵測
    test_ddos_detection()

    print("\n" + "="*70)
    print("所有測試完成")
    print("="*70)


if __name__ == "__main__":
    main()
