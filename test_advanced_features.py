#!/usr/bin/env python3
"""
測試進階功能

測試內容：
1. 四種進階 Pattern 識別
   - SINGLE_TARGET_PATTERN (垂直掃描)
   - BROADCAST_PATTERN (水平掃描)
   - REVERSE_SCAN_PATTERN (目標被掃描)
   - MICROSERVICE_PATTERN (微服務架構)

2. Baseline 驗證機制
   - 學習 IP 行為基準線
   - 偵測行為偏離
   - 計算偏離嚴重程度
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nad.ml.bidirectional_analyzer import BidirectionalAnalyzer
from nad.ml.baseline_manager import BaselineManager
from nad.ml.post_processor import AnomalyPostProcessor
from nad.ml.isolation_forest_detector import OptimizedIsolationForest
from nad.ml.anomaly_classifier import AnomalyClassifier


def test_pattern_recognition():
    """測試四種 Pattern 識別"""
    print("=" * 70)
    print("測試 1: 四種進階 Pattern 識別")
    print("=" * 70)

    analyzer = BidirectionalAnalyzer()

    # 從最近的異常中選擇幾個測試樣本
    print("\n正在從實時數據中測試 pattern 識別...")

    # 獲取最近的異常數據
    detector = OptimizedIsolationForest()
    try:
        detector._load_model()
    except FileNotFoundError:
        print("\n⚠️  Isolation Forest 模型未找到")
        print("請先訓練模型: python3 train_isolation_forest.py")
        return

    anomalies = detector.predict_realtime(recent_minutes=30)

    if not anomalies:
        print("\n未發現異常，無法測試 pattern 識別")
        return

    print(f"\n發現 {len(anomalies)} 個異常，測試前 5 個...")
    print()

    pattern_counts = {
        'SINGLE_TARGET_PATTERN': 0,
        'BROADCAST_PATTERN': 0,
        'REVERSE_SCAN_PATTERN': 0,
        'MICROSERVICE_PATTERN': 0,
        'LOAD_BALANCER': 0,
        'OTHER': 0
    }

    for i, anomaly in enumerate(anomalies[:5], 1):
        src_ip = anomaly['src_ip']

        print(f"{i}. 測試 {src_ip}")
        print(f"   - unique_dsts: {anomaly.get('unique_dsts', 0)}")
        print(f"   - unique_dst_ports: {anomaly.get('unique_dst_ports', 0)}")
        print(f"   - flow_count: {anomaly.get('flow_count', 0)}")
        print(f"   - avg_bytes: {anomaly.get('avg_bytes', 0):.0f}")

        # 使用改進的 pattern 識別
        result = analyzer.detect_port_scan_improved(src_ip, time_range="now-30m")

        pattern = result.get('pattern', 'UNKNOWN')
        is_scan = result.get('is_port_scan', False)

        print(f"   >>> Pattern: {pattern}")
        print(f"   >>> Is Scan: {is_scan}")
        print(f"   >>> Confidence: {result.get('confidence', 0):.0%}")

        if 'indicators' in result:
            for indicator in result['indicators']:
                print(f"       - {indicator}")

        pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
        print()

    # 統計結果
    print("Pattern 識別統計:")
    for pattern, count in pattern_counts.items():
        if count > 0:
            print(f"  - {pattern}: {count}")
    print()


def test_baseline_verification():
    """測試 Baseline 驗證機制"""
    print("=" * 70)
    print("測試 2: Baseline 驗證機制")
    print("=" * 70)

    manager = BaselineManager(learning_days=7)

    # 選擇幾個常見的 IP 進行測試
    test_ips = ['192.168.10.135', '192.168.10.100', '192.168.10.50']

    print(f"\n學習 {len(test_ips)} 個 IP 的行為基準線（過去 7 天）...")
    print()

    baselines_learned = 0
    for test_ip in test_ips:
        print(f"學習 {test_ip}...")
        baseline = manager.learn_baseline(test_ip)

        if baseline:
            baselines_learned += 1
            print(f"  ✓ 基準線學習成功")
            print(f"    - 樣本數: {baseline['sample_count']}")
            print(f"    - unique_dst_ports (平均): {baseline['unique_dst_ports']['mean']:.1f}")
            print(f"    - unique_dst_ports (最大): {baseline['unique_dst_ports']['max']:.0f}")
            print(f"    - unique_dsts (平均): {baseline['unique_dsts']['mean']:.1f}")
        else:
            print(f"  ✗ 歷史數據不足")
        print()

    if baselines_learned == 0:
        print("所有 IP 的歷史數據都不足，無法測試偏離偵測")
        return

    # 使用實時數據測試偏離偵測
    print("=" * 70)
    print("測試偏離偵測（使用實時異常數據）")
    print("=" * 70)
    print()

    detector = OptimizedIsolationForest()
    anomalies = detector.predict_realtime(recent_minutes=30)

    if not anomalies:
        print("未發現異常，無法測試偏離偵測")
        return

    deviation_count = 0
    for anomaly in anomalies[:5]:
        src_ip = anomaly['src_ip']
        features = anomaly['features']

        current_data = {
            'unique_dst_ports': features.get('unique_dst_ports', 0),
            'unique_dsts': features.get('unique_dsts', 0),
            'flow_count': features.get('flow_count', 0),
            'avg_bytes': features.get('avg_bytes', 0),
            'total_bytes': features.get('total_bytes', 0)
        }

        print(f"檢查 {src_ip} 的行為偏離...")
        result = manager.check_deviation(src_ip, current_data)

        if result['has_deviation']:
            deviation_count += 1
            print(f"  ⚠️  偵測到行為偏離！")
            print(f"  嚴重程度: {result['severity']}")

            for metric_name, deviation in result['deviations'].items():
                print(f"  - {metric_name}:")
                print(f"    當前: {deviation['current_value']:.0f}")
                print(f"    基準平均: {deviation['baseline_mean']:.0f}")
                print(f"    基準最大: {deviation['baseline_max']:.0f}")
                print(f"    Z-score: {deviation['z_score']:.2f}")
        else:
            print(f"  ✓ 行為正常")
        print()

    print(f"偏離統計: {deviation_count}/{min(5, len(anomalies))} 個異常偵測到基準線偏離")
    print()


def test_integrated_detection_with_baseline():
    """測試整合的偵測系統（包含 Baseline）"""
    print("=" * 70)
    print("測試 3: 整合偵測系統（Pattern + Baseline）")
    print("=" * 70)

    # 初始化組件
    detector = OptimizedIsolationForest()
    classifier = AnomalyClassifier()
    post_processor = AnomalyPostProcessor(enable_baseline=True, baseline_learning_days=7)

    # 加載模型
    try:
        detector._load_model()
    except FileNotFoundError:
        print("\n⚠️  Isolation Forest 模型未找到")
        return

    # Step 1: Isolation Forest 偵測
    print("\nStep 1: Isolation Forest 偵測（最近 30 分鐘）...")
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

    class_counts = {}
    for a in classified:
        c = a['classification']['class']
        class_counts[c] = class_counts.get(c, 0) + 1

    print(f"✓ 分類結果:")
    for threat_class, count in class_counts.items():
        print(f"  - {threat_class}: {count}")

    # Step 3: 後處理驗證（包含 Pattern 識別 + Baseline 驗證）
    print("\nStep 3: 後處理驗證（Pattern + Baseline）...")
    result = post_processor.validate_anomalies(classified, time_range="now-30m")

    validated = result['validated']
    false_positives = result['false_positives']

    print(f"✓ 驗證結果:")
    print(f"  - 真實異常: {len(validated)}")
    print(f"  - 誤報: {len(false_positives)}")
    print(f"  - 基準線偏離: {post_processor.stats.get('baseline_deviations', 0)}")

    # 顯示詳細報告
    print("\n" + "=" * 70)
    print("詳細報告")
    print("=" * 70)

    if validated:
        print("\n真實異常（前 3 個）:")
        for i, v in enumerate(validated[:3], 1):
            print(f"\n{i}. {v['src_ip']}")
            print(f"   威脅類別: {v['classification']['class']}")
            print(f"   Pattern: {v.get('verification_details', {}).get('pattern', 'Unknown')}")

            # 顯示基準線偏離
            if 'baseline_deviation' in v:
                baseline_dev = v['baseline_deviation']
                if baseline_dev.get('has_deviation'):
                    print(f"   基準線偏離: {baseline_dev['severity']}")
                    print(f"   偏離指標: {', '.join(baseline_dev['deviations'].keys())}")

    if false_positives:
        print("\n誤報（前 3 個）:")
        for i, fp in enumerate(false_positives[:3], 1):
            print(f"\n{i}. {fp['src_ip']}")
            print(f"   ML 判斷: {fp['classification']['class']}")
            print(f"   誤報原因: {fp['false_positive_reason']}")

    print("\n" + "=" * 70)


def main():
    """主測試流程"""
    print("\n" + "🧪 " * 25)
    print("進階功能測試")
    print("🧪 " * 25 + "\n")

    # 測試 1: Pattern 識別
    test_pattern_recognition()

    # 測試 2: Baseline 驗證
    test_baseline_verification()

    # 測試 3: 整合偵測
    test_integrated_detection_with_baseline()

    print("\n" + "=" * 70)
    print("所有測試完成")
    print("=" * 70)


if __name__ == "__main__":
    main()
