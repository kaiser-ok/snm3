#!/usr/bin/env python3
"""
雙模型整合的實時異常偵測系統

流程：
  1. Isolation Forest (by_src) → src 視角異常
  2. Isolation Forest (by_dst) → dst 視角異常
  3. 合併異常列表
  4. AnomalyClassifier 分類（支援 src + dst）
  5. AnomalyPostProcessor 雙向驗證
  6. Baseline 驗證（可選）
  7. 記錄到 anomaly_detection 索引

改進：
  - 100% 覆蓋：src + dst 視角異常都能偵測
  - DDoS 攻擊目標偵測
  - 被掃描目標偵測
  - 資料外洩目標端偵測
"""

import time
import sys
import os
from datetime import datetime

# 添加專案根目錄到 Python 路徑
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nad.ml.isolation_forest_detector import OptimizedIsolationForest
from nad.ml.isolation_forest_by_dst import IsolationForestByDst
from nad.ml.anomaly_classifier import AnomalyClassifier
from nad.ml.post_processor import AnomalyPostProcessor
from nad.anomaly_logger import AnomalyLogger
from nad.device_classifier import DeviceClassifier


class DualModelAnomalyDetector:
    """雙模型異常偵測系統"""

    def __init__(self, config=None, enable_baseline=True, enable_dst_model=True):
        """
        初始化

        Args:
            config: 配置對象（可選）
            enable_baseline: 是否啟用基準線驗證
            enable_dst_model: 是否啟用 dst 模型
        """
        self.config = config
        self.enable_dst_model = enable_dst_model

        print("初始化雙模型異常偵測系統...")

        # 初始化 Src 視角模型
        print("  - 初始化 Isolation Forest (by_src)...")
        self.iso_forest_src = OptimizedIsolationForest(config)

        # 初始化 Dst 視角模型
        if enable_dst_model:
            print("  - 初始化 Isolation Forest (by_dst)...")
            self.iso_forest_dst = IsolationForestByDst(config)
        else:
            self.iso_forest_dst = None

        # 初始化其他組件
        self.classifier = AnomalyClassifier(config)
        self.post_processor = AnomalyPostProcessor(
            enable_baseline=enable_baseline
        )
        self.logger = AnomalyLogger()
        self.device_classifier = DeviceClassifier()

        # 加載模型
        print("\n加載模型...")
        try:
            self.iso_forest_src._load_model()
            print("✓ Src 模型已加載")
        except FileNotFoundError as e:
            print(f"❌ 錯誤: {e}")
            print("請先訓練模型: python3 train_isolation_forest.py")
            sys.exit(1)

        if enable_dst_model:
            try:
                self.iso_forest_dst._load_model()
                print("✓ Dst 模型已加載")
            except FileNotFoundError as e:
                print(f"❌ 錯誤: {e}")
                print("請先訓練模型: python3 train_isolation_forest_by_dst.py")
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
        print(f"[{timestamp}] 開始異常偵測（雙模型）")
        print(f"{'='*70}\n")

        # ===== Step 1a: Isolation Forest (by_src) 偵測 =====
        print(f"Step 1a: Isolation Forest (by_src) 偵測（最近 {recent_minutes} 分鐘）...")
        anomalies_src = self.iso_forest_src.predict_realtime(recent_minutes=recent_minutes)
        print(f"✓ 偵測到 {len(anomalies_src)} 個 src 視角異常\n")

        # ===== Step 1b: Isolation Forest (by_dst) 偵測 =====
        anomalies_dst = []
        if self.enable_dst_model:
            print(f"Step 1b: Isolation Forest (by_dst) 偵測（最近 {recent_minutes} 分鐘）...")
            anomalies_dst = self.iso_forest_dst.predict_realtime(recent_minutes=recent_minutes)
            print(f"✓ 偵測到 {len(anomalies_dst)} 個 dst 視角異常\n")

        # ===== Step 1c: 合併異常 =====
        print(f"Step 1c: 合併異常列表...")
        all_anomalies = anomalies_src + anomalies_dst
        print(f"✓ 總異常數: {len(all_anomalies)} (src: {len(anomalies_src)}, dst: {len(anomalies_dst)})\n")

        if not all_anomalies:
            print("未發現異常，等待下一個週期....\n")
            return {
                'timestamp': timestamp,
                'anomalies_detected_src': 0,
                'anomalies_detected_dst': 0,
                'anomalies_total': 0,
                'validated': 0,
                'false_positives': 0
            }

        # 顯示前 5 個異常
        print("前 5 個異常:")
        for i, anomaly in enumerate(all_anomalies[:5], 1):
            perspective = anomaly.get('perspective', 'SRC')
            if perspective == 'SRC':
                print(f"  {i}. [SRC] {anomaly['src_ip']:<16} | "
                      f"分數: {anomaly['anomaly_score']:.4f} | "
                      f"{anomaly['flow_count']:5,} 連線")
            else:
                print(f"  {i}. [DST] {anomaly['dst_ip']:<16} | "
                      f"分數: {anomaly['anomaly_score']:.4f} | "
                      f"{anomaly['unique_srcs']:3} 來源")
        print()

        # ===== Step 2: AnomalyClassifier 分類 =====
        print("Step 2: 威脅分類（支援 src + dst 視角）...")

        classified_anomalies = []
        for anomaly in all_anomalies:
            perspective = anomaly.get('perspective', 'SRC')

            if perspective == 'SRC':
                # Src 視角分類
                classification = self.classifier.classify(
                    features=anomaly['features'],
                    context={'src_ip': anomaly['src_ip']}
                )
            else:
                # Dst 視角分類
                classification = self.classifier.classify_dst(
                    features=anomaly['features'],
                    context={'dst_ip': anomaly['dst_ip']}
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
            print(f"  - {threat_class}: {count}")
        print()

        # ===== Step 3: 後處理驗證 =====
        print("Step 3: 雙向驗證（Pattern + Baseline）...")

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

        if hasattr(self.post_processor, 'baseline_manager') and self.post_processor.baseline_manager:
            baseline_dev_count = self.post_processor.stats.get('baseline_deviations', 0)
            print(f"  - 基準線偏離: {baseline_dev_count}")

        if false_positives:
            print(f"\n  誤報原因分布:")
            for reason, count in stats['by_reason'].items():
                print(f"    - {reason}: {count}")
        print()

        # ===== Step 4: 記錄到 Elasticsearch =====
        print("Step 4: 記錄異常到 Elasticsearch...")

        logged_count = 0
        for anomaly in validated:
            try:
                perspective = anomaly.get('perspective', 'SRC')

                # 根據視角確定要分類的 IP
                if perspective == 'DST':
                    target_ip = anomaly.get('dst_ip')
                else:
                    target_ip = anomaly.get('src_ip')

                # 使用 DeviceClassifier 判斷設備類型
                device_type = self.device_classifier.classify(target_ip) if target_ip else 'unknown'

                self.logger.log_anomaly(
                    anomaly=anomaly,
                    device_type=device_type,
                    classification=anomaly.get('classification')
                )

                logged_count += 1
            except Exception as e:
                ip = anomaly.get('src_ip') or anomaly.get('dst_ip')
                print(f"  ⚠️  記錄異常失敗 ({ip}): {e}")

        print(f"✓ 已記錄 {logged_count} 個真實異常\n")

        # ===== 生成報告 =====
        if validated or false_positives:
            print("驗證報告:")
            report = self.post_processor.generate_report(validated, false_positives)
            print(report)

        # 返回統計
        return {
            'timestamp': timestamp,
            'anomalies_detected_src': len(anomalies_src),
            'anomalies_detected_dst': len(anomalies_dst),
            'anomalies_total': len(all_anomalies),
            'validated': len(validated),
            'false_positives': len(false_positives),
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
        print(f"啟動持續異常偵測（雙模型）")
        print(f"{'='*70}")
        print(f"檢測間隔: {interval_seconds} 秒 ({interval_seconds/60:.1f} 分鐘)")
        print(f"分析範圍: 最近 {recent_minutes} 分鐘")
        print(f"模型: Isolation Forest (src + dst)")
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
                print(f"  - Src 異常: {result['anomalies_detected_src']}")
                print(f"  - Dst 異常: {result['anomalies_detected_dst']}")
                print(f"  - 總異常: {result['anomalies_total']}")
                print(f"  - 真實異常: {result['validated']}")
                print(f"  - 誤報排除: {result['false_positives']}")

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
        description='雙模型整合的實時異常偵測系統'
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
        '--disable-dst-model',
        action='store_true',
        help='停用 dst 模型（只使用 src 模型）'
    )

    args = parser.parse_args()

    # 初始化偵測器
    detector = DualModelAnomalyDetector(
        enable_baseline=not args.disable_baseline,
        enable_dst_model=not args.disable_dst_model
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
