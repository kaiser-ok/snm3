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

        # ===== Step 2b: 合併 SRC/DST 異常視角 =====
        print("Step 2b: 合併 SRC/DST 異常視角（智能去重）...")
        classified_anomalies = self._merge_src_dst_anomalies(classified_anomalies)
        print(f"✓ 合併後剩餘 {len(classified_anomalies)} 個異常\n")

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

    def _merge_src_dst_anomalies(self, anomalies: list) -> list:
        """
        合併 SRC 和 DST 視角的異常記錄

        邏輯：
        1. 如果同一 IP 在同一時間段既有 SRC 異常，又有 DST 異常
        2. 且符合特定模式（掃描回應、正常服務器等），則合併
        3. 其他情況保留兩筆記錄（真實威脅）

        Args:
            anomalies: 原始異常列表

        Returns:
            合併後的異常列表
        """
        from collections import defaultdict

        # 按 (IP, time_bucket) 分組
        grouped = defaultdict(lambda: {'src': None, 'dst': None})

        for anomaly in anomalies:
            time_bucket = anomaly.get('time_bucket')
            perspective = anomaly.get('perspective', 'SRC')

            # 判斷 IP（SRC 用 src_ip，DST 用 dst_ip）
            if perspective == 'SRC':
                ip = anomaly.get('src_ip')
                if ip:
                    key = (ip, time_bucket)
                    grouped[key]['src'] = anomaly
            elif perspective == 'DST':
                ip = anomaly.get('dst_ip')
                if ip:
                    key = (ip, time_bucket)
                    grouped[key]['dst'] = anomaly

        # 合併邏輯
        merged_anomalies = []

        for (ip, time_bucket), records in grouped.items():
            src_record = records['src']
            dst_record = records['dst']

            # 情況 1: 只有 SRC 異常
            if src_record and not dst_record:
                merged_anomalies.append(src_record)

            # 情況 2: 只有 DST 異常
            elif dst_record and not src_record:
                merged_anomalies.append(dst_record)

            # 情況 3: 同時有 SRC 和 DST 異常
            elif src_record and dst_record:
                src_threat_class = src_record['classification'].get('class_name_en', '')
                dst_threat_class = dst_record['classification'].get('class_name_en', '')

                # 合併規則 1: 掃描行為（移除掃描回應）
                if dst_threat_class == 'Scan Response Traffic' and src_threat_class in ['Network Scanning', 'Port Scanning']:
                    # 將 DST 的統計數據合併到 SRC
                    src_record['dst_response'] = {
                        'unique_srcs': dst_record.get('unique_srcs'),
                        'flow_count': dst_record.get('flow_count'),
                        'total_bytes': dst_record.get('total_bytes'),
                        'unique_dst_ports': dst_record.get('unique_dst_ports')
                    }
                    merged_anomalies.append(src_record)
                    print(f"  ✓ 合併 {ip} 的掃描行為（SRC={src_threat_class}, 移除 DST 掃描回應）")

                # 合併規則 2: 正常雙向服務（SNMP、DNS、Web 等）
                # 檢查連線數是否接近（容許 20% 誤差）
                src_flows = src_record.get('flow_count', 0)
                dst_flows = dst_record.get('flow_count', 0)
                src_targets = src_record.get('unique_dsts', 0)
                dst_sources = dst_record.get('unique_srcs', 0)

                # 計算流量比和對象數匹配
                flow_ratio = 0
                if src_flows > 0 and dst_flows > 0:
                    flow_ratio = min(src_flows, dst_flows) / max(src_flows, dst_flows)
                    target_match = (src_targets == dst_sources)

                    # 如果雙向流量接近 + 對象數量匹配 → 這是正常的雙向服務
                    # 即使 SRC 被誤判為 Port Scan，只要流量對稱就應該合併
                    is_bidirectional_service = (flow_ratio > 0.8 and target_match)

                    # 特別處理：Port Scan + Unknown（可能是 SNMP、DNS 等 request-response 服務）
                    is_request_response_service = (
                        src_threat_class in ['Port Scanning', 'Network Scanning'] and
                        dst_threat_class == 'Unknown Anomaly' and
                        is_bidirectional_service and
                        src_targets < 100  # 掃描對象不多，可能是正常服務
                    )

                    # 一般雙向服務模式
                    is_normal_bidirectional = (
                        src_threat_class in ['Normal High Traffic', 'Unknown Anomaly'] and
                        dst_threat_class in ['Popular Server', 'Unknown Anomaly'] and
                        is_bidirectional_service
                    )

                    if is_request_response_service or is_normal_bidirectional:
                        # 保留 DST（服務器視角），標記為正常服務
                        dst_record['is_bidirectional_service'] = True
                        dst_record['src_traffic'] = {
                            'flow_count': src_flows,
                            'total_bytes': src_record.get('total_bytes'),
                            'unique_dsts': src_targets
                        }
                        # 重新分類為正常服務
                        dst_record['classification']['class_name'] = '正常雙向服務'
                        dst_record['classification']['class_name_en'] = 'Normal Bidirectional Service'
                        dst_record['classification']['severity'] = 'LOW'

                        # 如果是 request-response 服務，添加說明
                        if is_request_response_service:
                            dst_record['service_note'] = 'Request-Response Service (e.g., SNMP, DNS)'

                        merged_anomalies.append(dst_record)
                        print(f"  ✓ 合併 {ip} 的雙向服務（流量比 {flow_ratio:.2f}, 對象數 {src_targets}, SRC={src_threat_class}）")
                        continue

                # 其他情況：不合併，保留兩筆記錄（可能是真實威脅）
                merged_anomalies.append(src_record)
                merged_anomalies.append(dst_record)
                print(f"  ⚠ 保留 {ip} 的雙向異常（SRC={src_threat_class}, DST={dst_threat_class}）")

        return merged_anomalies


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
