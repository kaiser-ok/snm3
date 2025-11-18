#!/usr/bin/env python3
"""
整合的實時異常偵測系統

流程：
  1. Isolation Forest 偵測異常（src 視角）
  2. AnomalyClassifier 威脅分類
  3. AnomalyPostProcessor 雙向驗證（排除誤報）
  4. DDoS 偵測（dst 視角）
  5. 記錄到 anomaly_detection 索引

改進：
  - 100% 減少 Port Scan 誤報（微服務架構）
  - 新增 DDoS 偵測能力
  - 更準確的異常分類
"""

import time
import sys
import os
from datetime import datetime

# 添加專案根目錄到 Python 路徑
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nad.ml.isolation_forest_detector import OptimizedIsolationForest
from nad.ml.anomaly_classifier import AnomalyClassifier
from nad.ml.post_processor import AnomalyPostProcessor
from nad.anomaly_logger import AnomalyLogger


class IntegratedAnomalyDetector:
    """整合的異常偵測系統"""

    def __init__(self, config=None, enable_baseline=True, baseline_learning_days=7):
        """
        初始化

        Args:
            config: 配置對象（可選）
            enable_baseline: 是否啟用基準線驗證（默認啟用）
            baseline_learning_days: 基準線學習期（天數，默認 7 天）
        """
        self.config = config

        print("初始化異常偵測系統...")

        # 初始化各組件
        self.iso_forest = OptimizedIsolationForest(config)
        self.classifier = AnomalyClassifier(config)
        self.post_processor = AnomalyPostProcessor(
            enable_baseline=enable_baseline,
            baseline_learning_days=baseline_learning_days
        )
        self.logger = AnomalyLogger()

        self.enable_baseline = enable_baseline

        # 加載 Isolation Forest 模型
        print("加載 Isolation Forest 模型...")
        try:
            self.iso_forest._load_model()
            model_info = self.iso_forest.get_model_info()
            print(f"✓ 模型已加載")
            print(f"  - 特徵數: {model_info['n_features']}")
            print(f"  - 污染率: {model_info['contamination']}")
            print(f"  - 估計器數: {model_info['n_estimators']}")
        except FileNotFoundError as e:
            print(f"❌ 錯誤: {e}")
            print("請先訓練模型: python3 train_isolation_forest.py")
            sys.exit(1)

        print("✓ 初始化完成\n")

    def run_detection_cycle(self, recent_minutes: int = 10):
        """
        運行一次檢測週期

        Args:
            recent_minutes: 分析最近 N 分鐘的數據

        Returns:
            檢測結果統計
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"\n{'='*70}")
        print(f"[{timestamp}] 開始異常偵測")
        print(f"{'='*70}\n")

        # ===== Step 1: Isolation Forest 偵測 =====
        print(f"Step 1: Isolation Forest 偵測（最近 {recent_minutes} 分鐘）...")

        anomalies = self.iso_forest.predict_realtime(recent_minutes=recent_minutes)

        print(f"✓ 偵測到 {len(anomalies)} 個異常\n")

        if not anomalies:
            print("未發現異常，等待下一個週期...\n")
            return {
                'timestamp': timestamp,
                'anomalies_detected': 0,
                'validated': 0,
                'false_positives': 0,
                'ddos_attacks': 0
            }

        # 顯示前 5 個異常
        print("前 5 個異常:")
        for i, anomaly in enumerate(anomalies[:5], 1):
            print(f"  {i}. {anomaly['src_ip']:<16} | "
                  f"分數: {anomaly['anomaly_score']:.4f} | "
                  f"{anomaly['flow_count']:5,} 連線 | "
                  f"{anomaly['unique_dsts']:3} 目的地")
        print()

        # ===== Step 2: AnomalyClassifier 分類 =====
        print("Step 2: 威脅分類...")

        classified_anomalies = []
        for anomaly in anomalies:
            classification = self.classifier.classify(
                features=anomaly['features'],
                context={
                    'src_ip': anomaly['src_ip'],
                    'timestamp': anomaly['time_bucket']
                }
            )

            classified_anomalies.append({
                **anomaly,
                'classification': classification
            })

        # 統計分類結果
        class_counts = {}
        for anomaly in classified_anomalies:
            threat_class = anomaly['classification']['class']
            class_counts[threat_class] = class_counts.get(threat_class, 0) + 1

        print(f"✓ 分類完成:")
        for threat_class, count in sorted(class_counts.items(), key=lambda x: x[1], reverse=True):
            class_name = anomaly['classification']['class_name']
            print(f"  - {class_name} ({threat_class}): {count}")
        print()

        # ===== Step 3: 雙向驗證（關鍵改進）=====
        print("Step 3: 雙向驗證（排除誤報）...")

        validation_result = self.post_processor.validate_anomalies(
            classified_anomalies,
            time_range=f"now-{recent_minutes}m"
        )

        validated = validation_result['validated']
        false_positives = validation_result['false_positives']
        stats = validation_result['stats']

        print(f"✓ 驗證完成:")
        print(f"  - 真實異常: {len(validated)} ({len(validated)/len(classified_anomalies)*100:.1f}%)")
        print(f"  - 誤報: {len(false_positives)} ({stats['reduction_rate']*100:.1f}%)")

        if self.enable_baseline:
            baseline_dev_count = self.post_processor.stats.get('baseline_deviations', 0)
            print(f"  - 基準線偏離: {baseline_dev_count}")

        if false_positives:
            print(f"\n  誤報原因分布:")
            for reason, count in stats['by_reason'].items():
                print(f"    - {reason}: {count}")
        print()

        # ===== Step 4: DDoS 偵測（新功能）=====
        print("Step 4: DDoS 偵測（dst 視角）...")

        ddos_attacks = self.post_processor.detect_ddos(
            time_range=f"now-{recent_minutes}m",
            threshold=50
        )

        print(f"✓ 偵測到 {len(ddos_attacks)} 個可能的 DDoS 攻擊")

        if ddos_attacks:
            print(f"\nDDoS 攻擊詳情:")
            for i, ddos in enumerate(ddos_attacks[:5], 1):
                print(f"  {i}. 目標: {ddos['target_ip']:<16} | "
                      f"來源數: {ddos['unique_sources']:4} | "
                      f"連線數: {ddos['total_connections']:6,} | "
                      f"類型: {ddos['ddos_type']}")
        print()

        # ===== Step 5: 記錄到 Elasticsearch =====
        print("Step 5: 記錄異常到 Elasticsearch...")

        # 記錄真實異常
        logged_count = 0
        for anomaly in validated:
            try:
                self.logger.log_anomaly(
                    src_ip=anomaly['src_ip'],
                    time_bucket=anomaly['time_bucket'],
                    anomaly_score=anomaly['anomaly_score'],
                    confidence=anomaly['confidence'],
                    flow_count=anomaly['flow_count'],
                    unique_dsts=anomaly['unique_dsts'],
                    total_bytes=anomaly['total_bytes'],
                    avg_bytes=anomaly['avg_bytes'],
                    features=anomaly['features'],
                    classification=anomaly['classification'],
                    validation_result=anomaly.get('validation_result', 'VALIDATED'),
                    verification_details=anomaly.get('verification_details', {})
                )
                logged_count += 1
            except Exception as e:
                print(f"  ⚠️  記錄異常失敗 ({anomaly['src_ip']}): {e}")

        print(f"✓ 已記錄 {logged_count} 個真實異常")

        # 記錄 DDoS 攻擊
        ddos_logged = 0
        for ddos in ddos_attacks:
            try:
                self.logger.log_ddos(ddos)
                ddos_logged += 1
            except Exception as e:
                print(f"  ⚠️  記錄 DDoS 失敗 ({ddos['target_ip']}): {e}")

        if ddos_logged > 0:
            print(f"✓ 已記錄 {ddos_logged} 個 DDoS 攻擊")
        print()

        # ===== 生成報告 =====
        if validated or false_positives:
            print("驗證報告:")
            report = self.post_processor.generate_report(validated, false_positives)
            print(report)

        # 返回統計
        return {
            'timestamp': timestamp,
            'anomalies_detected': len(anomalies),
            'validated': len(validated),
            'false_positives': len(false_positives),
            'ddos_attacks': len(ddos_attacks),
            'reduction_rate': stats['reduction_rate']
        }

    def run_continuous(self, interval_seconds: int = 300, recent_minutes: int = 10):
        """
        持續運行檢測

        Args:
            interval_seconds: 檢測間隔（秒）
            recent_minutes: 每次分析最近 N 分鐘
        """
        print(f"{'='*70}")
        print(f"啟動持續異常偵測")
        print(f"{'='*70}")
        print(f"檢測間隔: {interval_seconds} 秒 ({interval_seconds/60:.1f} 分鐘)")
        print(f"分析範圍: 最近 {recent_minutes} 分鐘")
        print(f"按 Ctrl+C 停止")
        print(f"{'='*70}\n")

        cycle_count = 0

        try:
            while True:
                cycle_count += 1
                print(f"\n>>> 檢測週期 #{cycle_count}")

                # 運行一次檢測
                result = self.run_detection_cycle(recent_minutes)

                # 顯示摘要
                print(f"\n週期 #{cycle_count} 摘要:")
                print(f"  - 異常偵測: {result['anomalies_detected']}")
                print(f"  - 真實異常: {result['validated']}")
                print(f"  - 誤報排除: {result['false_positives']}")
                print(f"  - DDoS 攻擊: {result['ddos_attacks']}")

                # 休眠
                print(f"\n等待 {interval_seconds} 秒...\n")
                time.sleep(interval_seconds)

        except KeyboardInterrupt:
            print("\n\n收到停止信號，正在關閉...")
            print(f"總共運行了 {cycle_count} 個週期")

            # 顯示累計統計
            stats = self.post_processor.get_stats()
            print(f"\n累計統計:")
            print(f"  - 總處理異常: {stats['total_processed']}")
            print(f"  - 驗證通過: {stats['validated']}")
            print(f"  - 誤報排除: {stats['false_positives']}")
            print(f"  - 誤報率: {stats['false_positive_rate']*100:.1f}%")

            print("\n程序已停止")


def main():
    """主函數"""
    import argparse

    parser = argparse.ArgumentParser(
        description='整合的實時異常偵測系統（支援雙向驗證 + 基準線驗證）'
    )
    parser.add_argument(
        '--interval',
        type=int,
        default=300,
        help='檢測間隔（秒），默認 300 秒（5 分鐘）'
    )
    parser.add_argument(
        '--recent',
        type=int,
        default=10,
        help='每次分析最近 N 分鐘的數據，默認 10 分鐘'
    )
    parser.add_argument(
        '--once',
        action='store_true',
        help='只運行一次檢測（不持續）'
    )
    parser.add_argument(
        '--disable-baseline',
        action='store_true',
        help='停用基準線驗證'
    )
    parser.add_argument(
        '--baseline-days',
        type=int,
        default=7,
        help='基準線學習期（天數），默認 7 天'
    )

    args = parser.parse_args()

    # 初始化偵測器
    detector = IntegratedAnomalyDetector(
        enable_baseline=not args.disable_baseline,
        baseline_learning_days=args.baseline_days
    )

    # 運行
    if args.once:
        # 只運行一次
        result = detector.run_detection_cycle(recent_minutes=args.recent)
        print("\n檢測完成")
    else:
        # 持續運行
        detector.run_continuous(
            interval_seconds=args.interval,
            recent_minutes=args.recent
        )


if __name__ == "__main__":
    main()
