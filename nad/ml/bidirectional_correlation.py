#!/usr/bin/env python3
"""
雙向關聯分析器 (Bidirectional Correlation Analyzer)

用於分析同一 IP 在 SRC 和 DST 兩個視角下的行為一致性，
幫助識別正常 Server 模式並降低誤判率。

主要功能：
1. 查詢同一 IP 的 SRC 和 DST 視角數據
2. 計算雙向對稱性（流量、連線數、unique IPs）
3. 檢測 Port 角色一致性
4. 識別 Server 行為模式
"""

import requests
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
import numpy as np


class BidirectionalCorrelationAnalyzer:
    """
    雙向關聯分析器

    分析同一 IP 在 SRC 和 DST 視角的行為一致性
    """

    def __init__(self, es_host: str = "http://localhost:9200"):
        """
        初始化分析器

        Args:
            es_host: Elasticsearch 主機地址
        """
        self.es_host = es_host
        self.src_index = "netflow_stats_3m_by_src"
        self.dst_index = "netflow_stats_3m_by_dst"

    def get_bidirectional_features(self, ip: str, time_range: str = "now-10m") -> Dict:
        """
        獲取 IP 的雙向關聯特徵

        Args:
            ip: IP 地址
            time_range: 時間範圍（ES 格式，如 "now-10m"）

        Returns:
            雙向特徵字典
        """
        # 查詢 SRC 視角數據
        src_stats = self._query_src_view(ip, time_range)

        # 查詢 DST 視角數據
        dst_stats = self._query_dst_view(ip, time_range)

        # 計算雙向關聯特徵
        features = self._calculate_bidirectional_features(src_stats, dst_stats)

        return features

    def _query_src_view(self, ip: str, time_range: str) -> Optional[Dict]:
        """
        查詢 IP 在 SRC 視角的統計數據

        Args:
            ip: IP 地址
            time_range: 時間範圍

        Returns:
            SRC 視角的統計數據（聚合結果）
        """
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"src_ip": ip}},
                        {"range": {"time_bucket": {"gte": time_range}}}
                    ]
                }
            },
            "aggs": {
                "stats": {
                    "stats": {"field": "flow_count"}
                },
                "total_bytes": {
                    "sum": {"field": "total_bytes"}
                },
                "unique_dsts": {
                    "sum": {"field": "unique_dsts"}
                },
                "unique_dst_ports": {
                    "sum": {"field": "unique_dst_ports"}
                },
                "top_src_ports": {
                    "terms": {"field": "top_src_ports", "size": 5}
                },
                "records_count": {
                    "value_count": {"field": "src_ip"}
                }
            }
        }

        try:
            response = requests.post(
                f"{self.es_host}/{self.src_index}/_search",
                json=query,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            if data['hits']['total']['value'] == 0:
                return None

            aggs = data['aggregations']
            return {
                'total_flows': aggs['stats']['sum'],
                'total_bytes': aggs['total_bytes']['value'],
                'unique_dsts': aggs['unique_dsts']['value'],
                'unique_dst_ports': aggs['unique_dst_ports']['value'],
                'records_count': aggs['records_count']['value'],
                'top_src_ports': aggs['top_src_ports']['buckets']
            }
        except Exception as e:
            print(f"Warning: Failed to query SRC view for {ip}: {e}")
            return None

    def _query_dst_view(self, ip: str, time_range: str) -> Optional[Dict]:
        """
        查詢 IP 在 DST 視角的統計數據

        Args:
            ip: IP 地址
            time_range: 時間範圍

        Returns:
            DST 視角的統計數據（聚合結果）
        """
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"dst_ip": ip}},
                        {"range": {"time_bucket": {"gte": time_range}}}
                    ]
                }
            },
            "aggs": {
                "stats": {
                    "stats": {"field": "flow_count"}
                },
                "total_bytes": {
                    "sum": {"field": "total_bytes"}
                },
                "unique_srcs": {
                    "sum": {"field": "unique_srcs"}
                },
                "unique_src_ports": {
                    "sum": {"field": "unique_src_ports"}
                },
                "top_dst_ports": {
                    "terms": {"field": "top_dst_ports", "size": 5}
                },
                "records_count": {
                    "value_count": {"field": "dst_ip"}
                }
            }
        }

        try:
            response = requests.post(
                f"{self.es_host}/{self.dst_index}/_search",
                json=query,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            if data['hits']['total']['value'] == 0:
                return None

            aggs = data['aggregations']
            return {
                'total_flows': aggs['stats']['sum'],
                'total_bytes': aggs['total_bytes']['value'],
                'unique_srcs': aggs['unique_srcs']['value'],
                'unique_src_ports': aggs['unique_src_ports']['value'],
                'records_count': aggs['records_count']['value'],
                'top_dst_ports': aggs['top_dst_ports']['buckets']
            }
        except Exception as e:
            print(f"Warning: Failed to query DST view for {ip}: {e}")
            return None

    def _calculate_bidirectional_features(self, src_stats: Optional[Dict],
                                         dst_stats: Optional[Dict]) -> Dict:
        """
        計算雙向關聯特徵

        Args:
            src_stats: SRC 視角統計
            dst_stats: DST 視角統計

        Returns:
            雙向特徵字典
        """
        features = {
            # 默認值
            'has_bidirectional_data': 0,
            'bidirectional_symmetry_score': 0.0,
            'unique_ips_symmetry': 0.0,
            'port_role_consistency': 0.0,
            'is_likely_server_pattern': 0,
            'traffic_direction_ratio': 0.0,
            'bidirectional_confidence': 0.0
        }

        # 如果沒有雙向數據，返回默認值
        if not src_stats or not dst_stats:
            return features

        features['has_bidirectional_data'] = 1

        # === 1. 雙向對稱性分數 ===
        # Server 模式：unique_srcs (DST view) ≈ unique_dsts (SRC view)
        # 因為訪問 server 的客戶端數量 ≈ server 回應的客戶端數量
        unique_srcs_dst = dst_stats['unique_srcs']
        unique_dsts_src = src_stats['unique_dsts']

        if unique_srcs_dst > 0 and unique_dsts_src > 0:
            symmetry = 1.0 - abs(unique_srcs_dst - unique_dsts_src) / max(unique_srcs_dst, unique_dsts_src)
            features['bidirectional_symmetry_score'] = symmetry
            features['unique_ips_symmetry'] = symmetry

        # === 2. Port 角色一致性 ===
        # Server 的 src_port (SRC view) 應該等於 dst_port (DST view)
        port_consistency = self._calculate_port_consistency(
            src_stats.get('top_src_ports', []),
            dst_stats.get('top_dst_ports', [])
        )
        features['port_role_consistency'] = port_consistency

        # === 3. Server 模式識別 ===
        # 綜合判斷：高對稱性 + 高 port 一致性 + dst 視角有多個來源
        is_server = (
            features['bidirectional_symmetry_score'] > 0.7 and
            port_consistency > 0.5 and
            unique_srcs_dst > 10
        )
        features['is_likely_server_pattern'] = 1 if is_server else 0

        # === 4. 流量方向比 ===
        # 比較作為 SRC 和 DST 的流量大小
        total_bytes_src = src_stats['total_bytes']
        total_bytes_dst = dst_stats['total_bytes']

        if total_bytes_src + total_bytes_dst > 0:
            # > 0.5 表示主要是送出流量，< 0.5 表示主要是接收流量
            features['traffic_direction_ratio'] = total_bytes_src / (total_bytes_src + total_bytes_dst)

        # === 5. 雙向特徵置信度 ===
        # 基於數據完整性和樣本數量
        min_records = min(src_stats['records_count'], dst_stats['records_count'])
        features['bidirectional_confidence'] = min(1.0, min_records / 10.0)  # 10 條記錄達到滿置信度

        return features

    def _calculate_port_consistency(self, src_ports: list, dst_ports: list) -> float:
        """
        計算 Port 角色一致性

        Server 模式：SRC view 的 src_port 應該等於 DST view 的 dst_port

        Args:
            src_ports: SRC 視角的 top_src_ports (ES terms aggregation 結果)
            dst_ports: DST 視角的 top_dst_ports (ES terms aggregation 結果)

        Returns:
            一致性分數 (0-1)
        """
        if not src_ports or not dst_ports:
            return 0.0

        # 提取 port 集合（ES terms agg 格式：[{'key': 'port', 'doc_count': count}, ...]）
        src_port_set = set()
        for bucket in src_ports:
            try:
                # key 可能是字串形式的數字
                port = int(bucket['key']) if isinstance(bucket['key'], str) else bucket['key']
                src_port_set.add(port)
            except (ValueError, KeyError):
                continue

        dst_port_set = set()
        for bucket in dst_ports:
            try:
                port = int(bucket['key']) if isinstance(bucket['key'], str) else bucket['key']
                dst_port_set.add(port)
            except (ValueError, KeyError):
                continue

        # 計算交集比例
        if not src_port_set or not dst_port_set:
            return 0.0

        intersection = src_port_set & dst_port_set
        union = src_port_set | dst_port_set

        return len(intersection) / len(union) if union else 0.0

    def analyze_server_confidence(self, ip: str, time_range: str = "now-30m") -> Dict:
        """
        分析 IP 是否為 Server 的置信度（綜合評估）

        Args:
            ip: IP 地址
            time_range: 分析時間範圍

        Returns:
            {
                'is_server': bool,
                'confidence': float,
                'reasons': [str],
                'features': dict
            }
        """
        features = self.get_bidirectional_features(ip, time_range)

        reasons = []
        score = 0.0

        # 評分規則
        if features['has_bidirectional_data']:
            score += 0.1
            reasons.append("有雙向流量數據")

        if features['bidirectional_symmetry_score'] > 0.8:
            score += 0.3
            reasons.append(f"高雙向對稱性 ({features['bidirectional_symmetry_score']:.2f})")
        elif features['bidirectional_symmetry_score'] > 0.6:
            score += 0.15
            reasons.append(f"中等雙向對稱性 ({features['bidirectional_symmetry_score']:.2f})")

        if features['port_role_consistency'] > 0.7:
            score += 0.3
            reasons.append(f"Port 角色一致 ({features['port_role_consistency']:.2f})")
        elif features['port_role_consistency'] > 0.4:
            score += 0.15
            reasons.append(f"Port 部分一致 ({features['port_role_consistency']:.2f})")

        if features['is_likely_server_pattern']:
            score += 0.2
            reasons.append("符合 Server 行為模式")

        # 流量方向（Server 通常送出較多）
        if 0.3 < features['traffic_direction_ratio'] < 0.7:
            score += 0.1
            reasons.append("雙向流量平衡（Server 特徵）")

        return {
            'is_server': score > 0.5,
            'confidence': min(1.0, score),
            'reasons': reasons,
            'features': features
        }


# 測試程式
if __name__ == '__main__':
    analyzer = BidirectionalCorrelationAnalyzer()

    # 測試範例
    test_ip = "192.168.10.50"

    print(f"分析 IP: {test_ip}")
    print("=" * 70)

    result = analyzer.analyze_server_confidence(test_ip)

    print(f"\n是否為 Server: {'✓' if result['is_server'] else '✗'}")
    print(f"置信度: {result['confidence']:.2%}")
    print(f"\n判斷依據:")
    for reason in result['reasons']:
        print(f"  • {reason}")

    print(f"\n詳細特徵:")
    for key, value in result['features'].items():
        print(f"  {key}: {value}")
