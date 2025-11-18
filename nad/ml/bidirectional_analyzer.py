#!/usr/bin/env python3
"""
雙向流量分析器 (Bidirectional Traffic Analyzer)

結合 src 和 dst 視角的聚合數據，提供更準確的異常偵測，減少誤報。

主要功能：
1. Port Scan 偵測改進（區分真實掃描 vs 微服務/服務器流量）
2. DDoS 偵測（基於 dst 視角的多對一攻擊）
3. 微服務模式識別（減少誤報）
4. 服務器流量模式識別（減少誤報）
"""

import requests
import json
from typing import Dict, List, Tuple, Optional
from datetime import datetime


class BidirectionalAnalyzer:
    """
    雙向流量分析器

    結合 netflow_stats_5m (by src) 和 netflow_stats_5m_by_dst (by dst)
    進行交叉分析，減少誤報並提高偵測準確率。
    """

    def __init__(self, es_host="http://localhost:9200"):
        self.es_host = es_host
        self.src_index = f"{es_host}/netflow_stats_5m/_search"
        self.dst_index = f"{es_host}/netflow_stats_5m_by_dst/_search"

        # 內部網段定義
        self.internal_networks = [
            '192.168.',
            '10.',
            '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.'
        ]

    # ========== Port Scan 偵測（改進版）==========

    def detect_port_scan_improved(self, src_ip: str, time_range: str = "now-5m") -> Dict:
        """
        改進的 Port Scan 偵測（新增四種進階 Pattern）

        結合 src 和 dst 視角，識別：
        1. SINGLE_TARGET_PATTERN: 針對單一目標的垂直掃描（True Vertical Scan）
        2. BROADCAST_PATTERN: 水平掃描（多目標，相同端口）
        3. REVERSE_SCAN_PATTERN: Destination 被大量掃描（dst 視角）
        4. MICROSERVICE_PATTERN: 微服務架構（正常流量）

        Args:
            src_ip: 要分析的源 IP
            time_range: 時間範圍（Elasticsearch 格式）

        Returns:
            偵測結果字典，包含 pattern 類型
        """
        # 1. 獲取 src 視角的數據
        src_data = self._get_src_perspective(src_ip, time_range)

        if not src_data:
            return {'is_port_scan': False, 'reason': 'No data found'}

        # 2. 獲取該 src_ip 連接的所有目標的 dst 視角數據
        dst_data_list = self._get_targets_perspective(src_ip, time_range)

        # 3. SINGLE_TARGET_PATTERN - 垂直掃描（針對單一目標的大量端口）
        if self._is_single_target_scan(src_data):
            return {
                'is_port_scan': True,
                'pattern': 'SINGLE_TARGET_PATTERN',
                'scan_type': 'VERTICAL_SCAN',
                'confidence': 0.95,
                'reason': 'Single target port scan detected',
                'details': {
                    'unique_dsts': src_data['unique_dsts'],
                    'unique_dst_ports': src_data['unique_dst_ports'],
                    'avg_bytes': src_data.get('avg_bytes', 0),
                    'flow_count': src_data['flow_count']
                },
                'indicators': [
                    f"針對 {src_data['unique_dsts']} 個目標掃描 {src_data['unique_dst_ports']} 個端口",
                    f"平均封包大小: {src_data.get('avg_bytes', 0):.0f} bytes（探測特徵）",
                    "典型的垂直端口掃描行為"
                ]
            }

        # 4. BROADCAST_PATTERN - 水平掃描（多目標，少量端口）
        if self._is_broadcast_scan(src_data):
            avg_ports_per_dst = src_data['unique_dst_ports'] / src_data['unique_dsts']
            return {
                'is_port_scan': True,
                'pattern': 'BROADCAST_PATTERN',
                'scan_type': 'HORIZONTAL_SCAN',
                'confidence': 0.90,
                'reason': 'Horizontal scan pattern detected',
                'details': {
                    'unique_dsts': src_data['unique_dsts'],
                    'unique_dst_ports': src_data['unique_dst_ports'],
                    'avg_ports_per_dst': avg_ports_per_dst,
                    'avg_bytes': src_data.get('avg_bytes', 0)
                },
                'indicators': [
                    f"掃描 {src_data['unique_dsts']} 個不同主機",
                    f"平均每個主機掃描 {avg_ports_per_dst:.1f} 個端口",
                    f"總連線數: {src_data['flow_count']:,}",
                    "典型的水平掃描行為（如 SSH/RDP 掃描）"
                ]
            }

        # 5. MICROSERVICE_PATTERN - 微服務架構（正常流量）
        if self._is_microservice_pattern(src_data, dst_data_list):
            return {
                'is_port_scan': False,
                'pattern': 'MICROSERVICE_PATTERN',
                'confidence': 0.85,
                'reason': 'Microservice architecture pattern detected',
                'details': {
                    'unique_dsts': src_data['unique_dsts'],
                    'unique_dst_ports': src_data['unique_dst_ports'],
                    'avg_ports_per_dst': src_data['unique_dst_ports'] / src_data['unique_dsts'],
                    'evidence': '每個服務使用固定的少量端口'
                }
            }

        # 6. REVERSE_SCAN_PATTERN - 檢查目標是否被大量掃描（dst 視角）
        reverse_scan = self._check_reverse_scan_pattern(src_ip, src_data, time_range)
        if reverse_scan['is_reverse_scan']:
            return reverse_scan

        # 7. 負載均衡模式
        if self._is_load_balancer_pattern(src_data, dst_data_list):
            return {
                'is_port_scan': False,
                'pattern': 'LOAD_BALANCER',
                'confidence': 0.80,
                'reason': 'Load balancer traffic pattern detected'
            }

        # 8. 如果 unique_dst_ports 很高，但不符合掃描模式
        if src_data.get('unique_dst_ports', 0) > 100:
            return {
                'is_port_scan': False,
                'pattern': 'LEGITIMATE_HIGH_PORT_DIVERSITY',
                'confidence': 0.70,
                'reason': 'High port diversity but legitimate pattern',
                'warning': 'Monitor for changes in behavior'
            }

        return {'is_port_scan': False}

    def _check_targeted_port_scan(self, src_data: Dict, dst_data_list: List[Dict]) -> Dict:
        """
        檢查是否對單一目標進行 Port Scan

        特徵：
        - 對單一 dst_ip 連接大量不同的 dst_ports
        - 封包很小（探測性質）
        - 連線數高但流量低
        """
        for dst_info in dst_data_list:
            dst_ip = dst_info.get('dst_ip')
            flow_count_to_this_dst = dst_info.get('flow_count', 0)
            unique_dst_ports = dst_info.get('unique_dst_ports', 0)
            avg_bytes = dst_info.get('avg_bytes', 0)
            unique_src_ports = dst_info.get('unique_src_ports', 1)

            # 判斷：對這個目標掃描了很多端口
            if (unique_dst_ports > 100 and          # 掃描超過 100 個端口
                avg_bytes < 5000 and                # 小封包（探測）
                flow_count_to_this_dst > 100):      # 連線數多

                # 計算置信度
                confidence = 0.7
                if unique_dst_ports > 500:
                    confidence += 0.15
                if avg_bytes < 2000:
                    confidence += 0.1
                if unique_dst_ports / unique_src_ports > 10:  # 目標端口遠多於來源端口
                    confidence += 0.05

                return {
                    'is_port_scan': True,
                    'is_scan': True,  # 別名
                    'scan_type': 'TARGETED_PORT_SCAN',
                    'confidence': min(confidence, 0.95),
                    'target': dst_ip,
                    'scanned_ports': unique_dst_ports,
                    'flow_count': flow_count_to_this_dst,
                    'avg_packet_size': avg_bytes,
                    'indicators': [
                        f"對目標 {dst_ip} 掃描 {unique_dst_ports} 個端口",
                        f"平均封包 {avg_bytes:.0f} bytes（探測性小封包）",
                        f"總連線數 {flow_count_to_this_dst:,}"
                    ]
                }

        return {'is_scan': False}

    def _check_horizontal_scan(self, src_data: Dict, dst_data_list: List[Dict]) -> Dict:
        """
        檢查水平掃描（掃描多台機器的相同端口）

        特徵：
        - 連接到大量不同的 dst_ip
        - 每個 dst_ip 只用少量固定端口
        - 這些端口通常是常見服務端口（22, 80, 443, 3389, 445 等）
        """
        unique_dsts = src_data.get('unique_dsts', 0)

        if unique_dsts < 30:  # 目標太少，不是水平掃描
            return {'is_scan': False}

        # 檢查每個目標的端口使用情況
        ports_per_target = []
        for dst_info in dst_data_list:
            unique_dst_ports = dst_info.get('unique_dst_ports', 0)
            ports_per_target.append(unique_dst_ports)

        if not ports_per_target:
            return {'is_scan': False}

        avg_ports_per_dst = sum(ports_per_target) / len(ports_per_target)

        # 水平掃描特徵：大量目標 + 每個目標少量端口
        if (unique_dsts > 30 and
            avg_ports_per_dst < 5 and           # 每個目標平均只掃描少數端口
            src_data.get('avg_bytes', 0) < 5000):  # 小封包

            confidence = 0.75
            if unique_dsts > 100:
                confidence += 0.1
            if avg_ports_per_dst < 3:
                confidence += 0.1

            return {
                'is_port_scan': True,
                'is_scan': True,
                'scan_type': 'HORIZONTAL_SCAN',
                'confidence': min(confidence, 0.95),
                'targets_count': unique_dsts,
                'avg_ports_per_target': avg_ports_per_dst,
                'total_flow_count': src_data.get('flow_count', 0),
                'indicators': [
                    f"掃描 {unique_dsts} 個不同主機",
                    f"每個主機平均掃描 {avg_ports_per_dst:.1f} 個端口",
                    f"總連線數 {src_data.get('flow_count', 0):,}"
                ]
            }

        return {'is_scan': False}

    def _is_single_target_scan(self, src_data: Dict) -> bool:
        """
        SINGLE_TARGET_PATTERN - 針對單一目標的垂直掃描

        特徵：
        - 目標數量很少（1-3 個）
        - 掃描大量端口（>100）
        - 小封包（探測特徵）
        """
        unique_dsts = src_data.get('unique_dsts', 0)
        unique_dst_ports = src_data.get('unique_dst_ports', 0)
        avg_bytes = src_data.get('avg_bytes', 0)

        return (
            unique_dsts <= 3 and              # 目標很少
            unique_dst_ports > 100 and        # 掃描很多端口
            avg_bytes < 5000                  # 小封包
        )

    def _is_broadcast_scan(self, src_data: Dict) -> bool:
        """
        BROADCAST_PATTERN - 水平掃描（多目標，少量端口）

        特徵：
        - 大量目標（>50）
        - 平均每個目標只掃描少量端口（<3）
        - 小封包
        """
        unique_dsts = src_data.get('unique_dsts', 0)
        unique_dst_ports = src_data.get('unique_dst_ports', 0)
        avg_bytes = src_data.get('avg_bytes', 0)

        if unique_dsts < 50:
            return False

        # 平均每個目標的端口數
        avg_ports_per_dst = unique_dst_ports / unique_dsts

        return (
            unique_dsts > 50 and              # 很多目標
            avg_ports_per_dst < 3 and         # 每個目標少量端口
            avg_bytes < 5000                  # 小封包
        )

    def _check_reverse_scan_pattern(self, src_ip: str, src_data: Dict, time_range: str) -> Dict:
        """
        REVERSE_SCAN_PATTERN - 檢查目標是否被大量掃描（dst 視角）

        特徵：
        - 從 src 視角看，連接到某些 dst_ip
        - 從 dst 視角看，這些 dst_ip 被大量不同的 src_ports 掃描
        - 表示目標可能正在被掃描，而不是 src 主動掃描

        注意：這需要查詢 by_dst 索引中的 unique_src_ports
        """
        # 獲取 src_ip 連接的目標（從 src 視角）
        unique_dsts = src_data.get('unique_dsts', 0)

        if unique_dsts == 0:
            return {'is_reverse_scan': False}

        # 查詢 by_dst 索引，檢查這些目標是否被大量掃描
        # 簡化實作：查詢 by_dst 索引中 unique_src_ports 很高的記錄
        query = {
            "size": 10,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"time_bucket": {"gte": time_range}}},
                        {"range": {"unique_src_ports": {"gte": 100}}}  # 被大量不同 src_ports 連接
                    ]
                }
            },
            "sort": [{"unique_src_ports": "desc"}]
        }

        try:
            response = requests.post(self.dst_index, json=query,
                                    headers={'Content-Type': 'application/json'})
            data = response.json()

            hits = data.get('hits', {}).get('hits', [])
            if hits:
                # 檢查是否有目標被高度掃描
                for hit in hits:
                    dst_data = hit['_source']
                    unique_src_ports = dst_data.get('unique_src_ports', 0)

                    if unique_src_ports > 100:
                        return {
                            'is_port_scan': True,
                            'is_reverse_scan': True,
                            'pattern': 'REVERSE_SCAN_PATTERN',
                            'confidence': 0.80,
                            'reason': 'Target being scanned from multiple source ports',
                            'details': {
                                'target_ip': dst_data.get('dst_ip', 'unknown'),
                                'unique_src_ports': unique_src_ports,
                                'unique_srcs': dst_data.get('unique_srcs', 0),
                                'flow_count': dst_data.get('flow_count', 0)
                            },
                            'indicators': [
                                f"目標 {dst_data.get('dst_ip')} 被從 {unique_src_ports} 個不同來源端口掃描",
                                f"來源 IP 數: {dst_data.get('unique_srcs', 0)}",
                                "目標可能正在被掃描"
                            ]
                        }
        except Exception as e:
            # 查詢失敗，忽略
            pass

        return {'is_reverse_scan': False}

    def _is_microservice_pattern(self, src_data: Dict, dst_data_list: List[Dict]) -> bool:
        """
        檢查是否是微服務架構模式

        特徵：
        - 連接多個內部服務
        - 每個服務使用 1-3 個固定端口
        - 有實際的數據傳輸（不是探測）
        - 連線持續且穩定
        """
        unique_dsts = src_data.get('unique_dsts', 0)

        if unique_dsts < 5:  # 微服務通常連接多個服務
            return False

        # 檢查所有目標
        internal_services = 0
        fixed_port_services = 0

        for dst_info in dst_data_list:
            dst_ip = dst_info.get('dst_ip', '')
            unique_dst_ports = dst_info.get('unique_dst_ports', 0)
            avg_bytes = dst_info.get('avg_bytes', 0)

            # 是內部 IP
            if self._is_internal_ip(dst_ip):
                internal_services += 1

            # 使用固定少量端口 + 有實際數據傳輸
            if unique_dst_ports <= 3 and avg_bytes > 500:
                fixed_port_services += 1

        # 判斷：大部分是內部服務且使用固定端口
        if (internal_services >= len(dst_data_list) * 0.8 and  # 80% 是內部 IP
            fixed_port_services >= len(dst_data_list) * 0.7):  # 70% 使用固定端口
            return True

        return False

    def _is_load_balancer_pattern(self, src_data: Dict, dst_data_list: List[Dict]) -> bool:
        """
        檢查是否是負載均衡器模式

        特徵：
        - 連接多個後端服務器
        - 使用相同的端口（如都是 8080）
        - 流量分配相對均勻
        """
        unique_dsts = src_data.get('unique_dsts', 0)

        if unique_dsts < 3:
            return False

        # 檢查是否都使用相同/類似的端口
        common_ports_count = 0
        for dst_info in dst_data_list:
            unique_dst_ports = dst_info.get('unique_dst_ports', 0)
            # 負載均衡通常對每個後端只用 1-2 個端口
            if unique_dst_ports <= 2:
                common_ports_count += 1

        # 大部分後端都使用相同的端口配置
        if common_ports_count >= len(dst_data_list) * 0.8:
            return True

        return False

    # ========== DDoS 偵測（基於 dst 視角）==========

    def detect_ddos_by_dst(self, time_range: str = "now-5m", threshold: int = 100) -> List[Dict]:
        """
        基於 dst 視角偵測 DDoS 攻擊

        特徵：
        - 單一 dst_ip 收到來自大量不同 src_ip 的連線
        - 連線數暴增
        - 小封包（SYN flood 等）
        - 來源高度分散

        Args:
            time_range: 時間範圍
            threshold: unique_srcs 閾值

        Returns:
            可能的 DDoS 目標列表
        """
        query = {
            "size": 100,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"time_bucket": {"gte": time_range}}},
                        {"range": {"unique_srcs": {"gte": threshold}}},  # 來源數量閾值
                        {"range": {"flow_count": {"gte": 1000}}}         # 連線數閾值
                    ]
                }
            },
            "sort": [{"unique_srcs": "desc"}]
        }

        response = requests.post(self.dst_index, json=query,
                                headers={'Content-Type': 'application/json'})
        data = response.json()

        ddos_candidates = []

        for hit in data.get('hits', {}).get('hits', []):
            dst_data = hit['_source']
            dst_ip = dst_data['dst_ip']
            unique_srcs = dst_data['unique_srcs']
            flow_count = dst_data['flow_count']
            avg_bytes = dst_data.get('avg_bytes', 0)
            total_bytes = dst_data.get('total_bytes', 0)

            # 計算 DDoS 置信度
            confidence = self._calculate_ddos_confidence(dst_data)

            # 排除正常的高流量服務器
            if self._is_legitimate_server_traffic(dst_data):
                continue

            ddos_candidates.append({
                'target_ip': dst_ip,
                'unique_sources': unique_srcs,
                'total_connections': flow_count,
                'avg_packet_size': avg_bytes,
                'total_traffic_mb': total_bytes / 1024 / 1024,
                'confidence': confidence,
                'ddos_type': self._classify_ddos_type(dst_data),
                'severity': self._calculate_severity(confidence, flow_count),
                'indicators': [
                    f"收到來自 {unique_srcs} 個不同來源的流量",
                    f"總連線數 {flow_count:,}",
                    f"平均封包 {avg_bytes:.0f} bytes",
                    f"總流量 {total_bytes/1024/1024:.2f} MB"
                ]
            })

        return ddos_candidates

    def _calculate_ddos_confidence(self, dst_data: Dict) -> float:
        """計算 DDoS 置信度"""
        confidence = 0.5

        unique_srcs = dst_data.get('unique_srcs', 0)
        flow_count = dst_data.get('flow_count', 0)
        avg_bytes = dst_data.get('avg_bytes', 0)

        # 來源數量越多，置信度越高
        if unique_srcs > 500:
            confidence += 0.2
        elif unique_srcs > 200:
            confidence += 0.15
        elif unique_srcs > 100:
            confidence += 0.1

        # 連線數越多，置信度越高
        if flow_count > 50000:
            confidence += 0.2
        elif flow_count > 10000:
            confidence += 0.1

        # 小封包（SYN flood 特徵）
        if avg_bytes < 100:
            confidence += 0.2
        elif avg_bytes < 500:
            confidence += 0.1

        return min(confidence, 0.95)

    def _is_legitimate_server_traffic(self, dst_data: Dict) -> bool:
        """
        判斷是否是正常的服務器流量

        特徵：
        - 雖然來源很多，但封包大小正常
        - 有實際的數據傳輸
        - 使用標準服務端口
        """
        avg_bytes = dst_data.get('avg_bytes', 0)
        unique_dst_ports = dst_data.get('unique_dst_ports', 0)

        # 正常 Web 服務器：封包較大，端口少
        if avg_bytes > 5000 and unique_dst_ports <= 5:
            return True

        return False

    def _classify_ddos_type(self, dst_data: Dict) -> str:
        """分類 DDoS 類型"""
        avg_bytes = dst_data.get('avg_bytes', 0)
        flow_count = dst_data.get('flow_count', 0)

        if avg_bytes < 100:
            return "SYN_FLOOD"
        elif avg_bytes < 500:
            return "UDP_FLOOD"
        elif flow_count > 100000:
            return "CONNECTION_FLOOD"
        else:
            return "VOLUMETRIC_ATTACK"

    def _calculate_severity(self, confidence: float, flow_count: int) -> str:
        """計算嚴重程度"""
        if confidence > 0.8 and flow_count > 50000:
            return "CRITICAL"
        elif confidence > 0.7 and flow_count > 10000:
            return "HIGH"
        elif confidence > 0.6:
            return "MEDIUM"
        else:
            return "LOW"

    # ========== 輔助方法 ==========

    def _get_src_perspective(self, src_ip: str, time_range: str) -> Optional[Dict]:
        """獲取 src 視角的數據"""
        query = {
            "size": 1,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"src_ip": src_ip}},
                        {"range": {"time_bucket": {"gte": time_range}}}
                    ]
                }
            },
            "sort": [{"time_bucket": "desc"}]
        }

        response = requests.post(self.src_index, json=query,
                                headers={'Content-Type': 'application/json'})
        data = response.json()

        hits = data.get('hits', {}).get('hits', [])
        if hits:
            return hits[0]['_source']
        return None

    def _get_targets_perspective(self, src_ip: str, time_range: str) -> List[Dict]:
        """
        獲取該 src_ip 所有目標的 dst 視角數據

        注意：這裡需要查詢 by_dst 索引中，所有收到來自這個 src_ip 流量的 dst_ip
        由於 by_dst 索引只有 dst_ip 作為 group key，我們需要：
        1. 先從原始 flow 數據獲取該 src_ip 連接的所有 dst_ip
        2. 然後查詢這些 dst_ip 在 by_dst 索引中的統計

        為了簡化，這裡返回空列表，實際應用中可以改進
        """
        # TODO: 實作更精確的查詢
        # 目前的限制：by_dst 索引沒有記錄「哪些 src_ip 連到這個 dst_ip」
        # 只記錄了總的 unique_srcs 數量

        # 暫時返回空列表，Port Scan 偵測會基於 src 視角的數據
        return []

    def _calc_avg_ports_per_dst(self, dst_data_list: List[Dict]) -> float:
        """計算平均每個目標使用的端口數"""
        if not dst_data_list:
            return 0

        total_ports = sum(dst.get('unique_dst_ports', 0) for dst in dst_data_list)
        return total_ports / len(dst_data_list)

    def _is_internal_ip(self, ip: str) -> bool:
        """判斷是否為內部 IP"""
        if not ip:
            return False
        return any(ip.startswith(prefix) for prefix in self.internal_networks)


# ========== 測試和範例 ==========

def test_ddos_detection():
    """測試 DDoS 偵測"""
    analyzer = BidirectionalAnalyzer()

    print("=" * 70)
    print("DDoS 偵測測試（基於 dst 視角）")
    print("=" * 70)

    # 偵測最近 5 分鐘的 DDoS
    ddos_list = analyzer.detect_ddos_by_dst(time_range="now-1h", threshold=50)

    if ddos_list:
        print(f"\n⚠️  發現 {len(ddos_list)} 個可能的 DDoS 目標:\n")
        for i, ddos in enumerate(ddos_list, 1):
            print(f"{i}. 目標: {ddos['target_ip']}")
            print(f"   來源數: {ddos['unique_sources']}")
            print(f"   連線數: {ddos['total_connections']:,}")
            print(f"   平均封包: {ddos['avg_packet_size']:.0f} bytes")
            print(f"   類型: {ddos['ddos_type']}")
            print(f"   嚴重性: {ddos['severity']}")
            print(f"   置信度: {ddos['confidence']:.2%}")
            print()
    else:
        print("\n✓ 未發現 DDoS 攻擊")


if __name__ == "__main__":
    test_ddos_detection()
