#!/usr/bin/env python3
"""
異常檢測後處理模組

對 Isolation Forest + AnomalyClassifier 的結果進行驗證，
使用雙向聚合數據排除誤報。

主要功能：
1. Port Scan 驗證（區分真實掃描 vs 微服務架構）
2. DDoS 偵測（基於 dst 視角）
3. 異常行為交叉驗證
"""

from typing import List, Dict, Tuple
from datetime import datetime
from .bidirectional_analyzer import BidirectionalAnalyzer
from .baseline_manager import BaselineManager
from .bidirectional_correlation import BidirectionalCorrelationAnalyzer


class AnomalyPostProcessor:
    """
    異常檢測後處理器

    在 Isolation Forest 和 AnomalyClassifier 之後運行，
    使用雙向聚合數據進行驗證，減少誤報。
    """

    def __init__(self, es_host="http://localhost:9200", enable_baseline=True, baseline_learning_days=7):
        """
        初始化後處理器

        Args:
            es_host: Elasticsearch 主機地址
            enable_baseline: 是否啟用基準線驗證
            baseline_learning_days: 基準線學習期（天數）
        """
        self.bi_analyzer = BidirectionalAnalyzer(es_host)
        self.bidirectional_correlation = BidirectionalCorrelationAnalyzer(es_host)

        # 基準線管理器（可選）
        self.enable_baseline = enable_baseline
        if enable_baseline:
            self.baseline_manager = BaselineManager(es_host, learning_days=baseline_learning_days)
        else:
            self.baseline_manager = None

        # 統計信息
        self.stats = {
            'total_processed': 0,
            'validated': 0,
            'false_positives': 0,
            'by_reason': {},
            'baseline_deviations': 0,
            'server_identified': 0  # 新增：識別為 Server 的數量
        }

    def validate_anomalies(self, anomalies: List[Dict], time_range: str = "now-10m") -> Dict:
        """
        驗證異常列表，排除誤報

        Args:
            anomalies: 來自 Isolation Forest + Classifier 的異常列表
            time_range: 時間範圍（用於查詢雙向數據）

        Returns:
            {
                'validated': [...],  # 真實異常
                'false_positives': [...],  # 誤報
                'stats': {...}  # 統計信息
            }
        """
        validated = []
        false_positives = []

        for anomaly in anomalies:
            self.stats['total_processed'] += 1

            # 獲取 IP（根據視角不同）
            perspective = anomaly.get('perspective', 'SRC')
            if perspective == 'SRC':
                ip = anomaly.get('src_ip')
            else:  # DST
                ip = anomaly.get('dst_ip')

            threat_class = anomaly.get('classification', {}).get('class', 'UNKNOWN')

            # Step 1: 雙向關聯分析（檢查是否為 Server）
            server_analysis = self._check_server_pattern(ip, time_range)

            # Step 2: 原有的雙向驗證
            verification_result = self._verify_anomaly(
                ip,
                threat_class,
                anomaly,
                time_range
            )

            # Step 3: 基準線驗證（如果啟用）
            baseline_result = None
            if self.enable_baseline and self.baseline_manager:
                baseline_result = self._check_baseline_deviation(ip, anomaly)

            # 合併驗證結果
            # 如果雙向分析識別為 Server，降低異常嚴重性
            if server_analysis['is_server'] and server_analysis['confidence'] > 0.6:
                # 標記為誤報（正常 Server 行為）
                anomaly['validation_result'] = 'FALSE_POSITIVE'
                anomaly['false_positive_reason'] = 'LEGITIMATE_SERVER_PATTERN'
                anomaly['server_analysis'] = server_analysis

                false_positives.append(anomaly)
                self.stats['false_positives'] += 1
                self.stats['server_identified'] += 1
                self.stats['by_reason']['LEGITIMATE_SERVER_PATTERN'] = self.stats['by_reason'].get('LEGITIMATE_SERVER_PATTERN', 0) + 1

            elif verification_result['is_false_positive']:
                # 標記為誤報
                anomaly['validation_result'] = 'FALSE_POSITIVE'
                anomaly['false_positive_reason'] = verification_result['reason']
                anomaly['verification_details'] = verification_result.get('details', {})

                false_positives.append(anomaly)
                self.stats['false_positives'] += 1

                # 統計誤報原因
                reason = verification_result['reason']
                self.stats['by_reason'][reason] = self.stats['by_reason'].get(reason, 0) + 1

            else:
                # 保留為真實異常
                anomaly['validation_result'] = 'VALIDATED'
                anomaly['verification_details'] = verification_result.get('details', {})

                # 添加基準線偏離信息（如果有）
                if baseline_result and baseline_result.get('has_deviation'):
                    anomaly['baseline_deviation'] = baseline_result
                    self.stats['baseline_deviations'] += 1

                validated.append(anomaly)
                self.stats['validated'] += 1

        # 計算統計
        total = len(anomalies)
        reduction_rate = len(false_positives) / total if total > 0 else 0

        return {
            'validated': validated,
            'false_positives': false_positives,
            'stats': {
                'total': total,
                'validated': len(validated),
                'false_positives': len(false_positives),
                'reduction_rate': reduction_rate,
                'by_reason': self.stats['by_reason']
            }
        }

    def _verify_anomaly(self, src_ip: str, threat_class: str,
                       anomaly: Dict, time_range: str) -> Dict:
        """
        驗證單個異常

        Args:
            src_ip: 源 IP
            threat_class: 威脅類別
            anomaly: 異常記錄
            time_range: 時間範圍

        Returns:
            {
                'is_false_positive': bool,
                'reason': str,
                'details': {...}
            }
        """
        # 1. Port Scan 驗證（最重要）
        if threat_class == 'PORT_SCAN':
            return self._verify_port_scan(src_ip, anomaly, time_range)

        # 2. Network Scan 驗證
        elif threat_class == 'NETWORK_SCAN':
            return self._verify_network_scan(src_ip, anomaly, time_range)

        # 3. 其他威脅類別（暫時不驗證）
        else:
            return {
                'is_false_positive': False,
                'reason': 'No verification needed for this threat class',
                'details': {}
            }

    def _verify_port_scan(self, src_ip: str, anomaly: Dict, time_range: str) -> Dict:
        """
        驗證 Port Scan（支援四種進階 Pattern）

        使用雙向分析檢查是否為：
        - SINGLE_TARGET_PATTERN: 真實的垂直掃描
        - BROADCAST_PATTERN: 真實的水平掃描
        - REVERSE_SCAN_PATTERN: 目標被掃描
        - MICROSERVICE_PATTERN: 微服務架構（誤報）
        - LOAD_BALANCER: 負載均衡器（誤報）

        Args:
            src_ip: 源 IP
            anomaly: 異常記錄
            time_range: 時間範圍

        Returns:
            驗證結果
        """
        # 使用雙向分析器重新分析
        verification = self.bi_analyzer.detect_port_scan_improved(
            src_ip,
            time_range
        )

        pattern = verification.get('pattern', 'UNKNOWN')

        # 如果雙向分析認為不是 Port Scan（誤報）
        if not verification.get('is_port_scan'):
            # 確定是誤報
            if pattern == 'MICROSERVICE_PATTERN':
                return {
                    'is_false_positive': True,
                    'reason': 'Microservice Architecture',
                    'details': {
                        'pattern': pattern,
                        'confidence': verification.get('confidence', 0),
                        'unique_dsts': verification.get('details', {}).get('unique_dsts', 0),
                        'evidence': 'Each service uses only 1-3 fixed ports'
                    }
                }

            elif pattern == 'LOAD_BALANCER':
                return {
                    'is_false_positive': True,
                    'reason': 'Load Balancer Pattern',
                    'details': {
                        'pattern': pattern,
                        'confidence': verification.get('confidence', 0),
                        'evidence': 'Distributing traffic to multiple backends'
                    }
                }

            elif pattern == 'LEGITIMATE_HIGH_PORT_DIVERSITY':
                return {
                    'is_false_positive': True,
                    'reason': 'Legitimate High Port Diversity',
                    'details': {
                        'pattern': pattern,
                        'confidence': verification.get('confidence', 0),
                        'warning': verification.get('warning', '')
                    }
                }

        # 確認是真實的 Port Scan - 識別具體的掃描類型
        else:
            scan_type = verification.get('scan_type', 'UNKNOWN')

            # SINGLE_TARGET_PATTERN - 垂直掃描
            if pattern == 'SINGLE_TARGET_PATTERN':
                return {
                    'is_false_positive': False,
                    'reason': f'Confirmed Vertical Port Scan (Single Target)',
                    'details': {
                        'pattern': pattern,
                        'scan_type': scan_type,
                        'confidence': verification.get('confidence', 0),
                        'indicators': verification.get('indicators', []),
                        'threat_level': 'HIGH',
                        'description': '針對少數目標進行大量端口掃描'
                    }
                }

            # BROADCAST_PATTERN - 水平掃描
            elif pattern == 'BROADCAST_PATTERN':
                return {
                    'is_false_positive': False,
                    'reason': f'Confirmed Horizontal Scan (Broadcast)',
                    'details': {
                        'pattern': pattern,
                        'scan_type': scan_type,
                        'confidence': verification.get('confidence', 0),
                        'indicators': verification.get('indicators', []),
                        'threat_level': 'MEDIUM',
                        'description': '掃描多個目標的相同端口（如 SSH/RDP 掃描）'
                    }
                }

            # REVERSE_SCAN_PATTERN - 目標被掃描
            elif pattern == 'REVERSE_SCAN_PATTERN':
                return {
                    'is_false_positive': False,
                    'reason': f'Target Being Scanned (Reverse Scan)',
                    'details': {
                        'pattern': pattern,
                        'confidence': verification.get('confidence', 0),
                        'indicators': verification.get('indicators', []),
                        'threat_level': 'MEDIUM',
                        'description': '目標 IP 正在被掃描（從 dst 視角偵測）'
                    }
                }

            # 其他掃描類型
            else:
                return {
                    'is_false_positive': False,
                    'reason': f'Confirmed Port Scan: {scan_type}',
                    'details': {
                        'pattern': pattern,
                        'scan_type': scan_type,
                        'confidence': verification.get('confidence', 0),
                        'indicators': verification.get('indicators', [])
                    }
                }

        # 默認：無法確定，保守處理（可能是掃描）
        return {
            'is_false_positive': False,
            'reason': 'Uncertain - Default to scan',
            'details': verification
        }

    def _verify_network_scan(self, src_ip: str, anomaly: Dict, time_range: str) -> Dict:
        """
        驗證 Network Scan

        檢查是否為正常的服務發現或微服務通訊

        Args:
            src_ip: 源 IP
            anomaly: 異常記錄
            time_range: 時間範圍

        Returns:
            驗證結果
        """
        # 獲取特徵
        features = anomaly.get('features', {})
        unique_dsts = features.get('unique_dsts', 0)
        avg_bytes = features.get('avg_bytes', 0)

        # 如果是高流量的內網通訊，可能是正常的
        if avg_bytes > 5000 and unique_dsts < 100:
            return {
                'is_false_positive': True,
                'reason': 'Internal Service Communication',
                'details': {
                    'unique_dsts': unique_dsts,
                    'avg_bytes': avg_bytes,
                    'evidence': 'High traffic volume suggests legitimate communication'
                }
            }

        # 默認保留為 Network Scan
        return {
            'is_false_positive': False,
            'reason': 'Confirmed Network Scan',
            'details': {
                'unique_dsts': unique_dsts,
                'avg_bytes': avg_bytes
            }
        }

    def _check_server_pattern(self, ip: str, time_range: str) -> Dict:
        """
        使用雙向關聯分析檢查 IP 是否為 Server

        Args:
            ip: IP 地址
            time_range: 時間範圍

        Returns:
            {
                'is_server': bool,
                'confidence': float,
                'reasons': list,
                'features': dict
            }
        """
        try:
            result = self.bidirectional_correlation.analyze_server_confidence(ip, time_range)
            return result
        except Exception as e:
            # 如果分析失敗，返回默認值
            return {
                'is_server': False,
                'confidence': 0.0,
                'reasons': [f'Analysis failed: {e}'],
                'features': {}
            }

    def _check_baseline_deviation(self, src_ip: str, anomaly: Dict) -> Dict:
        """
        檢查是否偏離基準線

        Args:
            src_ip: 源 IP
            anomaly: 異常記錄（包含 features）

        Returns:
            基準線偏離結果
        """
        if not self.baseline_manager:
            return {'has_deviation': False}

        # 從 features 中提取當前數據
        features = anomaly.get('features', {})
        current_data = {
            'unique_dst_ports': features.get('unique_dst_ports', 0),
            'unique_dsts': features.get('unique_dsts', 0),
            'flow_count': features.get('flow_count', 0),
            'avg_bytes': features.get('avg_bytes', 0),
            'total_bytes': features.get('total_bytes', 0)
        }

        # 檢查偏離
        deviation_result = self.baseline_manager.check_deviation(src_ip, current_data)

        return deviation_result

    def detect_ddos(self, time_range: str = "now-10m", threshold: int = 50) -> List[Dict]:
        """
        獨立的 DDoS 偵測

        使用 dst 視角的聚合數據偵測 DDoS 攻擊

        Args:
            time_range: 時間範圍
            threshold: unique_srcs 閾值

        Returns:
            DDoS 攻擊列表
        """
        ddos_attacks = self.bi_analyzer.detect_ddos_by_dst(
            time_range=time_range,
            threshold=threshold
        )

        return ddos_attacks

    def get_stats(self) -> Dict:
        """
        獲取處理統計

        Returns:
            統計信息
        """
        return {
            **self.stats,
            'false_positive_rate': (
                self.stats['false_positives'] / self.stats['total_processed']
                if self.stats['total_processed'] > 0 else 0
            )
        }

    def reset_stats(self):
        """重置統計"""
        self.stats = {
            'total_processed': 0,
            'validated': 0,
            'false_positives': 0,
            'by_reason': {}
        }

    def generate_report(self, validated: List[Dict], false_positives: List[Dict]) -> str:
        """
        生成驗證報告

        Args:
            validated: 驗證後的真實異常
            false_positives: 誤報列表

        Returns:
            報告文本
        """
        total = len(validated) + len(false_positives)

        report = []
        report.append("=" * 70)
        report.append("異常驗證報告")
        report.append("=" * 70)
        report.append("")
        report.append(f"總異常數: {total}")
        report.append(f"真實異常: {len(validated)} ({len(validated)/total*100:.1f}%)")
        report.append(f"誤報: {len(false_positives)} ({len(false_positives)/total*100:.1f}%)")
        report.append("")

        # 誤報原因統計
        if false_positives:
            report.append("誤報原因分布:")
            reason_counts = {}
            for fp in false_positives:
                reason = fp.get('false_positive_reason', 'Unknown')
                reason_counts[reason] = reason_counts.get(reason, 0) + 1

            for reason, count in sorted(reason_counts.items(), key=lambda x: x[1], reverse=True):
                report.append(f"  - {reason}: {count} ({count/len(false_positives)*100:.1f}%)")
            report.append("")

        # 真實異常分類統計
        if validated:
            report.append("真實異常分類:")
            class_counts = {}
            for v in validated:
                threat_class = v.get('classification', {}).get('class', 'Unknown')
                class_counts[threat_class] = class_counts.get(threat_class, 0) + 1

            for threat_class, count in sorted(class_counts.items(), key=lambda x: x[1], reverse=True):
                report.append(f"  - {threat_class}: {count}")
            report.append("")

        # Top 誤報範例
        if false_positives:
            report.append("誤報範例（前 5 個）:")
            for i, fp in enumerate(false_positives[:5], 1):
                report.append(f"  {i}. {fp['src_ip']}")
                report.append(f"     ML 判斷: {fp.get('classification', {}).get('class', 'Unknown')}")
                report.append(f"     誤報原因: {fp.get('false_positive_reason', 'Unknown')}")
            report.append("")

        # Top 真實異常範例
        if validated:
            report.append("真實異常範例（前 5 個）:")
            for i, v in enumerate(validated[:5], 1):
                report.append(f"  {i}. {v['src_ip']}")
                report.append(f"     威脅類別: {v.get('classification', {}).get('class', 'Unknown')}")
                report.append(f"     置信度: {v.get('classification', {}).get('confidence', 0):.0%}")

                # 顯示基準線偏離信息
                if 'baseline_deviation' in v:
                    baseline_dev = v['baseline_deviation']
                    if baseline_dev.get('has_deviation'):
                        report.append(f"     基準線偏離: {baseline_dev.get('severity', 'UNKNOWN')}")
                        deviations = baseline_dev.get('deviations', {})
                        if deviations:
                            dev_metrics = ', '.join(deviations.keys())
                            report.append(f"     偏離指標: {dev_metrics}")
            report.append("")

        report.append("=" * 70)

        return "\n".join(report)
