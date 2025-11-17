#!/usr/bin/env python3
"""
閾值調優工具

批量分析異常檢測結果，提供特徵閾值調整建議
"""

import sys
import json
import argparse
from collections import defaultdict, Counter
from elasticsearch import Elasticsearch
from nad.utils.config_loader import load_config
from verify_anomaly import AnomalyVerifier


class ThresholdTuner:
    """閾值調優器"""

    def __init__(self, es_client, config):
        self.es = es_client
        self.config = config
        self.verifier = AnomalyVerifier(es_client, config)

    def analyze_batch(self, anomaly_ips, time_range_minutes=30):
        """
        批量分析異常 IP

        Args:
            anomaly_ips: 異常 IP 列表（可以包含分數）
            time_range_minutes: 分析時間範圍

        Returns:
            調優建議
        """
        print(f"\n{'='*100}")
        print(f"📊 批量分析 {len(anomaly_ips)} 個異常 IP")
        print(f"{'='*100}\n")

        results = []
        for ip_data in anomaly_ips:
            # 支持兩種格式
            if isinstance(ip_data, dict):
                ip = ip_data['ip']
                score = ip_data.get('score', 0)
            else:
                ip = ip_data
                score = 0

            print(f"分析: {ip} (異常分數: {score:.3f})...")
            analysis = self.verifier.verify_ip(ip, time_range_minutes)

            if analysis:
                analysis['anomaly_score'] = score
                results.append(analysis)

            print()  # 空行分隔

        # 生成調優建議
        recommendations = self._generate_recommendations(results)

        # 列印報告
        self._print_summary_report(results, recommendations)

        return recommendations

    def _generate_recommendations(self, results):
        """根據分析結果生成調優建議"""
        recommendations = {
            'false_positives': [],
            'true_anomalies': [],
            'threshold_adjustments': [],
            'feature_analysis': defaultdict(list),
        }

        # 統計分類
        for result in results:
            verdict = result['verdict']['verdict']

            if verdict == 'FALSE_POSITIVE':
                recommendations['false_positives'].append(result)
            elif verdict == 'TRUE_ANOMALY':
                recommendations['true_anomalies'].append(result)

            # 收集特徵數據
            recommendations['feature_analysis']['flow_count'].append(
                result['basic_stats']['total_flows']
            )
            recommendations['feature_analysis']['unique_dsts'].append(
                result['destination_analysis']['unique_destinations']
            )
            recommendations['feature_analysis']['unique_ports'].append(
                result['port_analysis']['unique_ports']
            )
            recommendations['feature_analysis']['avg_bytes'].append(
                result['basic_stats']['avg_bytes_per_flow']
            )

        # 分析閾值調整需求
        if recommendations['false_positives']:
            self._analyze_false_positives(recommendations)

        return recommendations

    def _analyze_false_positives(self, recommendations):
        """分析誤報模式，提供閾值調整建議"""
        fps = recommendations['false_positives']

        # 分析誤報的共同特徵
        fp_behaviors = defaultdict(int)
        for fp in fps:
            behaviors = fp['behavioral_analysis']
            if behaviors:
                for b in behaviors:
                    fp_behaviors[b['type']] += 1

        # 分析特徵值分布
        fp_features = {
            'flow_counts': [fp['basic_stats']['total_flows'] for fp in fps],
            'unique_dsts': [fp['destination_analysis']['unique_destinations'] for fp in fps],
            'unique_ports': [fp['port_analysis']['unique_ports'] for fp in fps],
            'avg_bytes': [fp['basic_stats']['avg_bytes_per_flow'] for fp in fps],
        }

        # 生成調整建議
        adjustments = []

        # 1. 高連線數閾值
        high_flow_count = [fc for fc in fp_features['flow_counts'] if fc > 1000]
        if len(high_flow_count) >= len(fps) * 0.5:  # 50% 以上
            import numpy as np
            suggested_threshold = int(np.percentile(high_flow_count, 75))
            adjustments.append({
                'parameter': 'thresholds.high_connection',
                'current_value': 1000,
                'suggested_value': suggested_threshold,
                'reason': f'{len(high_flow_count)} 個誤報的連線數超過當前閾值',
                'affected_ips': len(high_flow_count),
            })

        # 2. 掃描目的地數閾值
        high_dst_count = [dc for dc in fp_features['unique_dsts'] if dc > 30]
        if len(high_dst_count) >= len(fps) * 0.5:
            import numpy as np
            suggested_threshold = int(np.percentile(high_dst_count, 75))
            adjustments.append({
                'parameter': 'thresholds.scanning_dsts',
                'current_value': 30,
                'suggested_value': suggested_threshold,
                'reason': f'{len(high_dst_count)} 個誤報的目的地數超過當前閾值',
                'affected_ips': len(high_dst_count),
            })

        # 3. 平均流量閾值
        low_avg_bytes = [ab for ab in fp_features['avg_bytes'] if ab < 10000]
        if len(low_avg_bytes) >= len(fps) * 0.5:
            import numpy as np
            suggested_threshold = int(np.percentile(low_avg_bytes, 25))
            adjustments.append({
                'parameter': 'thresholds.scanning_avg_bytes',
                'current_value': 10000,
                'suggested_value': suggested_threshold,
                'reason': f'{len(low_avg_bytes)} 個誤報的平均流量低於當前閾值',
                'affected_ips': len(low_avg_bytes),
            })

        # 4. contamination 參數
        fp_ratio = len(fps) / len(recommendations['false_positives'] + recommendations['true_anomalies'])
        if fp_ratio > 0.5:  # 誤報率 > 50%
            current_contamination = self.config.get('isolation_forest', {}).get('contamination', 0.05)
            suggested_contamination = max(0.01, current_contamination * 0.6)  # 降低 40%
            adjustments.append({
                'parameter': 'isolation_forest.contamination',
                'current_value': current_contamination,
                'suggested_value': round(suggested_contamination, 3),
                'reason': f'誤報率過高 ({fp_ratio*100:.1f}%)，建議降低異常比例',
                'affected_ips': len(fps),
            })

        recommendations['threshold_adjustments'] = adjustments

    def _print_summary_report(self, results, recommendations):
        """列印匯總報告"""
        print(f"\n{'='*100}")
        print(f"📊 分析匯總報告")
        print(f"{'='*100}\n")

        # 統計
        total = len(results)
        true_anomalies = len(recommendations['true_anomalies'])
        false_positives = len(recommendations['false_positives'])
        suspicious = sum(1 for r in results if r['verdict']['verdict'] == 'SUSPICIOUS')
        unclear = sum(1 for r in results if r['verdict']['verdict'] == 'UNCLEAR')

        print(f"📈 檢測結果統計:")
        print(f"   • 總共分析: {total} 個 IP")
        print(f"   • 🚨 真實異常: {true_anomalies} ({true_anomalies/total*100:.1f}%)")
        print(f"   • ⚠️  可疑行為: {suspicious} ({suspicious/total*100:.1f}%)")
        print(f"   • ✅ 誤報: {false_positives} ({false_positives/total*100:.1f}%)")
        print(f"   • ❓ 無法確定: {unclear} ({unclear/total*100:.1f}%)")
        print()

        # 行為分類統計
        behavior_counter = Counter()
        for result in results:
            for behavior in result['behavioral_analysis']:
                behavior_counter[behavior['type']] += 1

        if behavior_counter:
            print(f"🔍 檢測到的行為類型:")
            for behavior_type, count in behavior_counter.most_common():
                print(f"   • {behavior_type}: {count} 次")
            print()

        # 真實異常詳情
        if recommendations['true_anomalies']:
            print(f"🚨 真實異常詳情:")
            for anomaly in recommendations['true_anomalies']:
                print(f"\n   IP: {anomaly['src_ip']}")
                print(f"   異常分數: {anomaly.get('anomaly_score', 0):.3f}")
                for behavior in anomaly['behavioral_analysis']:
                    if behavior['severity'] in ['HIGH', 'MEDIUM']:
                        print(f"   • [{behavior['severity']}] {behavior['description']}")
            print()

        # 調優建議
        if recommendations['threshold_adjustments']:
            print(f"{'='*100}")
            print(f"🔧 閾值調優建議")
            print(f"{'='*100}\n")

            for adj in recommendations['threshold_adjustments']:
                print(f"📌 參數: {adj['parameter']}")
                print(f"   當前值: {adj['current_value']}")
                print(f"   建議值: {adj['suggested_value']}")
                print(f"   原因: {adj['reason']}")
                print(f"   影響: {adj['affected_ips']} 個 IP")
                print()

            print(f"💡 如何應用調整:")
            print(f"   1. 編輯 nad/config.yaml")
            print(f"   2. 修改相應參數")
            print(f"   3. 重新訓練模型: python3 train_isolation_forest.py --days 7")
            print(f"   4. 重新檢測: python3 realtime_detection.py --minutes 30")
            print()
        else:
            print(f"✅ 當前閾值設置良好，無需調整\n")

        # 誤報分析
        if recommendations['false_positives']:
            print(f"{'='*100}")
            print(f"✅ 誤報分析")
            print(f"{'='*100}\n")

            for fp in recommendations['false_positives']:
                print(f"IP: {fp['src_ip']} (異常分數: {fp.get('anomaly_score', 0):.3f})")

                # 找出為什麼被標記為正常
                behaviors = fp['behavioral_analysis']
                if any(b['type'] == 'NORMAL_SERVICE' for b in behaviors):
                    top_ports = fp['port_analysis']['top_ports'][:3]
                    ports_str = ', '.join([f"{p['port']}({p['service']})" for p in top_ports])
                    print(f"   → 正常服務流量: {ports_str}")
                else:
                    print(f"   → 未檢測到明顯異常行為")

                print()


def main():
    parser = argparse.ArgumentParser(description='閾值調優工具')
    parser.add_argument('--ips', type=str, help='要分析的 IP 列表（逗號分隔）')
    parser.add_argument('--file', type=str, help='從文件讀取 IP 列表（每行一個）')
    parser.add_argument('--minutes', type=int, default=30, help='分析時間範圍（分鐘）')
    parser.add_argument('--json', type=str, help='從 JSON 文件讀取異常檢測結果')

    args = parser.parse_args()

    # 載入配置
    config = load_config()

    # 連接 Elasticsearch
    es_host = config.get('elasticsearch', {}).get('host', 'http://localhost:9200')
    es = Elasticsearch([es_host], timeout=30)

    if not es.ping():
        print(f"❌ 無法連接到 Elasticsearch: {es_host}")
        sys.exit(1)

    print(f"✓ 已連接到 Elasticsearch: {es_host}\n")

    tuner = ThresholdTuner(es, config)

    # 準備 IP 列表
    ip_list = []

    if args.json:
        # 從 JSON 文件讀取
        with open(args.json, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                ip_list = data
            elif 'anomalies' in data:
                ip_list = data['anomalies']

    elif args.file:
        # 從文件讀取
        with open(args.file, 'r') as f:
            ip_list = [line.strip() for line in f if line.strip()]

    elif args.ips:
        # 從命令行讀取
        ip_list = [ip.strip() for ip in args.ips.split(',')]

    else:
        print("用法:")
        print("  python3 tune_thresholds.py --ips '192.168.1.100,192.168.1.101'")
        print("  python3 tune_thresholds.py --file anomaly_ips.txt")
        print("  python3 tune_thresholds.py --json detection_result.json")
        print()
        sys.exit(1)

    if not ip_list:
        print("❌ 沒有找到要分析的 IP")
        sys.exit(1)

    # 執行批量分析
    tuner.analyze_batch(ip_list, args.minutes)


if __name__ == '__main__':
    main()
