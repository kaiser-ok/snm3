#!/usr/bin/env python3
"""
分類器閾值優化工具

基於歷史異常數據，分析並優化威脅分類器的閾值。
這個工具會：
1. 收集 Isolation Forest 檢測到的所有異常
2. 分析每種威脅類型的特徵分佈
3. 基於統計方法推薦最優閾值
4. 生成詳細的分析報告

參考文獻：
- Port Scan: PLOS ONE (2018) - Detection of slow port scans in flow-based network traffic
- DNS Tunneling: GIAC (2016) - Detecting DNS Tunneling
- DDoS Detection: MDPI Sensors (2023) - Detection and Mitigation of SYN Flooding Attacks
- Data Exfiltration: TU Delft (2019) - Automated data exfiltration detection using netflow metadata
- C2 Detection: ScienceDirect (2013) - Periodic behavior in botnet traffic
- Network Scan: Splunk Research - Detection of Internal Horizontal Port Scan
"""

import sys
import argparse
import json
import warnings
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Tuple
import numpy as np

# 忽略警告
warnings.filterwarnings('ignore')

from nad.utils import load_config
from nad.ml import OptimizedIsolationForest
from nad.ml.anomaly_classifier import AnomalyClassifier


class ClassifierThresholdOptimizer:
    """
    分類器閾值優化器

    基於歷史異常數據分析最優閾值
    """

    def __init__(self, config):
        """初始化優化器"""
        self.config = config
        self.detector = OptimizedIsolationForest(config)
        self.classifier = AnomalyClassifier(config)

        # 存儲各類異常的特徵數據
        self.anomaly_features = {
            'PORT_SCAN': [],
            'NETWORK_SCAN': [],
            'DNS_TUNNELING': [],
            'DDOS': [],
            'DATA_EXFILTRATION': [],
            'C2_COMMUNICATION': [],
            'NORMAL_HIGH_TRAFFIC': [],
            'UNKNOWN': []
        }

        # 所有異常特徵（用於全局統計）
        self.all_anomaly_features = []

    def collect_historical_anomalies(self, days: int = 7) -> int:
        """
        收集歷史異常數據

        Args:
            days: 分析過去 N 天的數據

        Returns:
            收集到的異常數量
        """
        print(f"\n{'='*80}")
        print(f"收集過去 {days} 天的異常數據...")
        print(f"{'='*80}\n")

        # 載入模型
        try:
            self.detector._load_model()
        except Exception as e:
            print(f"❌ 無法載入模型: {e}")
            print(f"   請先訓練模型: python3 train_isolation_forest.py --days 7\n")
            return 0

        total_anomalies = 0

        # 按天收集數據（避免一次查詢太多數據）
        for day_offset in range(days):
            print(f"📅 分析第 {day_offset + 1}/{days} 天...")

            # 計算該天的分鐘數
            minutes = (day_offset * 1440) + 720  # 從 day_offset 天前的中間開始

            try:
                # 檢測該時間段的異常
                anomalies = self.detector.predict_realtime(recent_minutes=1440)

                if anomalies:
                    print(f"   找到 {len(anomalies)} 個異常")

                    # 對每個異常進行分類並存儲
                    for anomaly in anomalies:
                        features = anomaly['features']
                        context = {
                            'timestamp': datetime.fromisoformat(
                                anomaly['time_bucket'].replace('Z', '+00:00')
                            ),
                            'src_ip': anomaly['src_ip'],
                            'anomaly_score': anomaly['anomaly_score']
                        }

                        # 使用當前分類器進行分類
                        classification = self.classifier.classify(features, context)
                        threat_class = classification['class']

                        # 存儲特徵數據
                        self.anomaly_features[threat_class].append(features)
                        self.all_anomaly_features.append({
                            'features': features,
                            'class': threat_class,
                            'timestamp': context['timestamp'],
                            'src_ip': context['src_ip']
                        })

                    total_anomalies += len(anomalies)
                else:
                    print(f"   未發現異常")

            except Exception as e:
                print(f"   ⚠️  分析失敗: {e}")
                continue

        print(f"\n{'='*80}")
        print(f"收集完成：共 {total_anomalies} 個異常")
        print(f"{'='*80}\n")

        # 顯示各類別統計
        print("威脅類別分佈：\n")
        for threat_class, features_list in self.anomaly_features.items():
            count = len(features_list)
            if count > 0:
                percentage = (count / total_anomalies * 100) if total_anomalies > 0 else 0
                print(f"  {threat_class:25} {count:5} 個 ({percentage:5.1f}%)")

        print()
        return total_anomalies

    def analyze_threat_class(self, threat_class: str) -> Dict:
        """
        分析特定威脅類別的特徵分佈

        Args:
            threat_class: 威脅類別名稱

        Returns:
            分析結果字典
        """
        features_list = self.anomaly_features[threat_class]

        if not features_list:
            return {
                'count': 0,
                'message': '無數據'
            }

        # 提取關鍵特徵
        key_features = [
            'flow_count', 'unique_dsts', 'unique_dst_ports',
            'avg_bytes', 'total_bytes', 'dst_diversity',
            'dst_port_diversity'
        ]

        analysis = {
            'count': len(features_list),
            'features': {}
        }

        for feature in key_features:
            values = [f.get(feature, 0) for f in features_list]

            if values:
                analysis['features'][feature] = {
                    'min': float(np.min(values)),
                    'max': float(np.max(values)),
                    'mean': float(np.mean(values)),
                    'median': float(np.median(values)),
                    'std': float(np.std(values)),
                    'p10': float(np.percentile(values, 10)),
                    'p25': float(np.percentile(values, 25)),
                    'p75': float(np.percentile(values, 75)),
                    'p90': float(np.percentile(values, 90)),
                    'p95': float(np.percentile(values, 95)),
                    'p99': float(np.percentile(values, 99))
                }

        return analysis

    def recommend_thresholds(self) -> Dict:
        """
        基於數據分析推薦新的閾值

        Returns:
            推薦閾值字典
        """
        recommendations = {}

        # ========== 1. PORT_SCAN ==========
        port_scan_analysis = self.analyze_threat_class('PORT_SCAN')
        if port_scan_analysis['count'] > 5:
            features = port_scan_analysis['features']

            # 根據研究文獻：端口掃描通常掃描 > 100 個端口
            # 我們使用 P10 作為最小閾值（保守估計）
            recommendations['PORT_SCAN'] = {
                'unique_dst_ports': {
                    'current': 100,
                    'recommended': max(50, int(features['unique_dst_ports']['p10'])),
                    'rationale': 'P10 值，基於 PLOS ONE (2018) 端口掃描研究',
                    'reference': 'https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0204507'
                },
                'avg_bytes': {
                    'current': 5000,
                    'recommended': int(features['avg_bytes']['p75']),
                    'rationale': 'P75 值，端口掃描使用小封包',
                    'reference': 'Nmap 工具特徵分析'
                },
                'dst_port_diversity': {
                    'current': 0.5,
                    'recommended': round(features['dst_port_diversity']['p25'], 2),
                    'rationale': 'P25 值，保證端口分散性',
                    'reference': '特徵工程最佳實踐'
                }
            }

        # ========== 2. NETWORK_SCAN ==========
        network_scan_analysis = self.analyze_threat_class('NETWORK_SCAN')
        if network_scan_analysis['count'] > 5:
            features = network_scan_analysis['features']

            # 根據 Splunk 研究：水平掃描通常 > 50 個目標
            recommendations['NETWORK_SCAN'] = {
                'unique_dsts': {
                    'current': 50,
                    'recommended': max(30, int(features['unique_dsts']['p10'])),
                    'rationale': 'P10 值，基於 Splunk 水平掃描檢測研究',
                    'reference': 'https://research.splunk.com/network/1ff9eb9a-7d72-4993-a55e-59a839e607f1/'
                },
                'dst_diversity': {
                    'current': 0.3,
                    'recommended': round(features['dst_diversity']['p25'], 2),
                    'rationale': 'P25 值，目標分散度指標',
                    'reference': '網路掃描行為分析'
                },
                'flow_count': {
                    'current': 1000,
                    'recommended': int(features['flow_count']['p10']),
                    'rationale': 'P10 值，掃描通常產生大量連線',
                    'reference': '流量分析最佳實踐'
                }
            }

        # ========== 3. DNS_TUNNELING ==========
        dns_tunnel_analysis = self.analyze_threat_class('DNS_TUNNELING')
        if dns_tunnel_analysis['count'] > 5:
            features = dns_tunnel_analysis['features']

            # 根據 GIAC 研究：DNS 隧道特徵
            recommendations['DNS_TUNNELING'] = {
                'flow_count': {
                    'current': 1000,
                    'recommended': int(features['flow_count']['p10']),
                    'rationale': 'P10 值，DNS 隧道需要大量查詢',
                    'reference': 'https://www.giac.org/paper/gcia/1116/detecting-dns-tunneling/108367'
                },
                'avg_bytes': {
                    'current': 1000,
                    'recommended': int(features['avg_bytes']['p75']),
                    'rationale': 'P75 值，DNS 查詢通常 < 512 bytes',
                    'reference': 'DNS 協議標準 (RFC 1035)'
                },
                'unique_dsts': {
                    'current': 5,
                    'recommended': max(3, int(features['unique_dsts']['p90'])),
                    'rationale': 'P90 值，隧道通常只用少數 DNS 服務器',
                    'reference': 'DNS 隧道工具特徵分析'
                }
            }

        # ========== 4. DDOS ==========
        ddos_analysis = self.analyze_threat_class('DDOS')
        if ddos_analysis['count'] > 5:
            features = ddos_analysis['features']

            # 根據 MDPI Sensors (2023) 研究
            recommendations['DDOS'] = {
                'flow_count': {
                    'current': 10000,
                    'recommended': int(features['flow_count']['p10']),
                    'rationale': 'P10 值，DDoS 產生極高連線數',
                    'reference': 'https://www.mdpi.com/1424-8220/23/8/3817'
                },
                'avg_bytes': {
                    'current': 500,
                    'recommended': int(features['avg_bytes']['p75']),
                    'rationale': 'P75 值，SYN Flood 使用極小封包',
                    'reference': 'SYN Flood 攻擊特徵分析'
                },
                'unique_dsts': {
                    'current': 20,
                    'recommended': max(10, int(features['unique_dsts']['p90'])),
                    'rationale': 'P90 值，攻擊目標集中',
                    'reference': 'DDoS 攻擊模式研究'
                }
            }

        # ========== 5. DATA_EXFILTRATION ==========
        exfil_analysis = self.analyze_threat_class('DATA_EXFILTRATION')
        if exfil_analysis['count'] > 5:
            features = exfil_analysis['features']

            # 根據 TU Delft 研究
            recommendations['DATA_EXFILTRATION'] = {
                'total_bytes': {
                    'current': 1e9,  # 1GB
                    'recommended': int(features['total_bytes']['p10']),
                    'rationale': 'P10 值，數據外洩閾值',
                    'reference': 'https://repository.tudelft.nl/islandora/object/uuid:19aa873d-b38d-4133-bcf8-7c6c625af739'
                },
                'unique_dsts': {
                    'current': 5,
                    'recommended': max(3, int(features['unique_dsts']['p90'])),
                    'rationale': 'P90 值，外洩目標集中',
                    'reference': 'NetFlow 數據外洩檢測研究'
                },
                'dst_diversity': {
                    'current': 0.1,
                    'recommended': round(features['dst_diversity']['p75'], 2),
                    'rationale': 'P75 值，流量高度集中',
                    'reference': '數據外洩行為模式分析'
                }
            }

        # ========== 6. C2_COMMUNICATION ==========
        c2_analysis = self.analyze_threat_class('C2_COMMUNICATION')
        if c2_analysis['count'] > 5:
            features = c2_analysis['features']

            # 根據 ScienceDirect (2013) 殭屍網路研究
            recommendations['C2_COMMUNICATION'] = {
                'flow_count': {
                    'current': (100, 1000),  # 範圍
                    'recommended': (
                        int(features['flow_count']['p10']),
                        int(features['flow_count']['p90'])
                    ),
                    'rationale': 'P10-P90 範圍，C2 通訊中等連線數',
                    'reference': 'https://www.sciencedirect.com/science/article/pii/S2090123213001410'
                },
                'avg_bytes': {
                    'current': (1000, 100000),  # 範圍
                    'recommended': (
                        int(features['avg_bytes']['p10']),
                        int(features['avg_bytes']['p90'])
                    ),
                    'rationale': 'P10-P90 範圍，命令和控制數據大小',
                    'reference': '殭屍網路行為分析'
                }
            }

        return recommendations

    def generate_report(self, recommendations: Dict, output_file: str = None):
        """
        生成詳細的分析報告

        Args:
            recommendations: 推薦閾值字典
            output_file: 輸出文件路徑（可選）
        """
        report_lines = []

        # 標題
        report_lines.append("=" * 100)
        report_lines.append("分類器閾值優化報告")
        report_lines.append(f"生成時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("=" * 100)
        report_lines.append("")

        # 數據統計
        report_lines.append("## 數據統計")
        report_lines.append("")
        total = len(self.all_anomaly_features)
        report_lines.append(f"總異常數量: {total}")
        report_lines.append("")

        for threat_class, features_list in self.anomaly_features.items():
            count = len(features_list)
            if count > 0:
                percentage = (count / total * 100) if total > 0 else 0
                report_lines.append(f"  {threat_class:25} {count:5} 個 ({percentage:5.1f}%)")

        report_lines.append("")
        report_lines.append("=" * 100)
        report_lines.append("")

        # 推薦閾值
        report_lines.append("## 推薦閾值")
        report_lines.append("")

        if not recommendations:
            report_lines.append("⚠️  數據不足，無法生成推薦閾值")
            report_lines.append("   建議：收集更多天數的數據（--days 14 或更多）")
        else:
            for threat_class, thresholds in recommendations.items():
                report_lines.append(f"### {threat_class}")
                report_lines.append("")

                for param, details in thresholds.items():
                    report_lines.append(f"**{param}:**")
                    report_lines.append(f"  當前值: {details['current']}")
                    report_lines.append(f"  推薦值: {details['recommended']}")
                    report_lines.append(f"  理由: {details['rationale']}")
                    report_lines.append(f"  參考: {details['reference']}")
                    report_lines.append("")

        report_lines.append("=" * 100)
        report_lines.append("")

        # 詳細特徵分析
        report_lines.append("## 詳細特徵分析")
        report_lines.append("")

        for threat_class in ['PORT_SCAN', 'NETWORK_SCAN', 'DNS_TUNNELING',
                            'DDOS', 'DATA_EXFILTRATION', 'C2_COMMUNICATION']:
            analysis = self.analyze_threat_class(threat_class)

            if analysis['count'] > 0:
                report_lines.append(f"### {threat_class} ({analysis['count']} 個樣本)")
                report_lines.append("")

                for feature, stats in analysis.get('features', {}).items():
                    report_lines.append(f"**{feature}:**")

                    # 對於 diversity 類特徵使用更高精度（4位小數）
                    # 因為它們是比率，通常在 0-1 之間
                    if 'diversity' in feature:
                        precision = 4
                    # 對於 bytes 類特徵使用整數格式
                    elif 'bytes' in feature:
                        precision = 0
                    # 其他使用 2 位小數
                    else:
                        precision = 2

                    if precision == 0:
                        report_lines.append(f"  範圍: {stats['min']:.0f} - {stats['max']:.0f}")
                        report_lines.append(f"  平均: {stats['mean']:.0f} ± {stats['std']:.0f}")
                        report_lines.append(f"  中位數: {stats['median']:.0f}")
                        report_lines.append(f"  P10/P25/P75/P90: {stats['p10']:.0f} / {stats['p25']:.0f} / {stats['p75']:.0f} / {stats['p90']:.0f}")
                    elif precision == 4:
                        report_lines.append(f"  範圍: {stats['min']:.4f} - {stats['max']:.4f}")
                        report_lines.append(f"  平均: {stats['mean']:.4f} ± {stats['std']:.4f}")
                        report_lines.append(f"  中位數: {stats['median']:.4f}")
                        report_lines.append(f"  P10/P25/P75/P90: {stats['p10']:.4f} / {stats['p25']:.4f} / {stats['p75']:.4f} / {stats['p90']:.4f}")
                    else:
                        report_lines.append(f"  範圍: {stats['min']:.2f} - {stats['max']:.2f}")
                        report_lines.append(f"  平均: {stats['mean']:.2f} ± {stats['std']:.2f}")
                        report_lines.append(f"  中位數: {stats['median']:.2f}")
                        report_lines.append(f"  P10/P25/P75/P90: {stats['p10']:.2f} / {stats['p25']:.2f} / {stats['p75']:.2f} / {stats['p90']:.2f}")

                    report_lines.append("")

        report_lines.append("=" * 100)

        # 打印報告
        report_text = "\n".join(report_lines)
        print(report_text)

        # 保存到文件
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(report_text)
                print(f"\n✅ 報告已保存到: {output_file}\n")
            except Exception as e:
                print(f"\n⚠️  無法保存報告: {e}\n")


def main():
    parser = argparse.ArgumentParser(
        description='分類器閾值優化工具 - 基於歷史數據分析最優閾值'
    )
    parser.add_argument(
        '--days',
        type=int,
        default=7,
        help='分析過去 N 天的數據（默認: 7）'
    )
    parser.add_argument(
        '--config',
        type=str,
        default='nad/config.yaml',
        help='配置文件路徑'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='reports/classifier_threshold_optimization.txt',
        help='報告輸出路徑'
    )

    args = parser.parse_args()

    # 載入配置
    print(f"\n📋 載入配置...")
    try:
        config = load_config(args.config)
        print(f"✓ 配置載入成功\n")
    except Exception as e:
        print(f"❌ 配置載入失敗: {e}\n")
        sys.exit(1)

    # 創建優化器
    optimizer = ClassifierThresholdOptimizer(config)

    # 收集歷史異常
    total = optimizer.collect_historical_anomalies(days=args.days)

    if total == 0:
        print("❌ 沒有收集到異常數據，無法優化閾值\n")
        print("建議：")
        print("  1. 確保 Isolation Forest 模型已訓練")
        print("  2. 確保有足夠的歷史流量數據")
        print("  3. 嘗試增加分析天數（--days 14）\n")
        sys.exit(1)

    # 分析並推薦閾值
    print(f"\n{'='*80}")
    print("分析特徵分佈並推薦閾值...")
    print(f"{'='*80}\n")

    recommendations = optimizer.recommend_thresholds()

    # 生成報告
    optimizer.generate_report(recommendations, args.output)


if __name__ == "__main__":
    main()
