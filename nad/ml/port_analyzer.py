#!/usr/bin/env python3
"""
通訊埠分析模組 (Port Analyzer)

實現非臨時埠計數法 (Non-Ephemeral Port Counting)，
用於區分真正的掃描行為 vs 正常的服務器回應/資料收集行為。

主要功能：
1. 分離臨時埠 (>32000) 和服務埠 (<=32000)
2. 基於服務埠數量判斷是否為掃描
3. 識別常見的服務器回應模式
4. 識別資料收集行為（如 WHOIS、API 查詢）
"""

from typing import Dict, List, Optional
from collections import Counter
import requests


class PortAnalyzer:
    """
    通訊埠分析器

    使用非臨時埠計數法判斷異常流量類型
    """

    # 臨時埠起始點 (Linux 預設 32768, 使用 32000 較寬鬆)
    EPHEMERAL_PORT_START = 32000

    # 常見服務埠定義
    WELL_KNOWN_SERVICES = {
        43: 'WHOIS',
        53: 'DNS',
        80: 'HTTP',
        443: 'HTTPS',
        22: 'SSH',
        25: 'SMTP',
        161: 'SNMP',
        162: 'SNMP-Trap',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        9200: 'Elasticsearch',
        9100: 'Prometheus',
    }

    # 正常客戶端常用的服務埠（用於識別 NORMAL_CLIENT_ACTIVITY）
    COMMON_CLIENT_PORTS = {80, 443, 53, 8080, 8443, 22, 3389}

    def __init__(self, es_host: str = "http://localhost:9200"):
        """
        初始化通訊埠分析器

        Args:
            es_host: Elasticsearch 主機地址
        """
        self.es_host = es_host

    def analyze_port_pattern(
        self,
        ip: str,
        perspective: str,
        time_range: str = "now-10m",
        aggregated_data: Optional[Dict] = None
    ) -> Dict:
        """
        分析通訊埠模式（支援從聚合數據或原始數據）

        Args:
            ip: 要分析的 IP
            perspective: 'SRC' 或 'DST'
            time_range: 時間範圍
            aggregated_data: 可選的聚合數據（如果已經查詢過）

        Returns:
            {
                'total_unique_ports': int,
                'unique_service_ports': int,
                'unique_ephemeral_ports': int,
                'ephemeral_ratio': float,
                'is_scanning': bool,
                'pattern_type': str,  # 'SCANNING', 'SERVER_RESPONSE', 'DATA_COLLECTION', 'NORMAL', 'MULTI_SERVICE'
                'confidence': float,
                'details': {...}
            }
        """
        # 如果提供了聚合數據，直接使用
        if aggregated_data:
            return self._analyze_from_aggregated(aggregated_data, perspective)

        # 否則查詢聚合數據
        agg_data = self._fetch_aggregated_port_data(ip, perspective, time_range)
        if not agg_data:
            return {
                'error': 'No data found',
                'is_scanning': False,
                'pattern_type': 'UNKNOWN'
            }

        return self._analyze_from_aggregated(agg_data, perspective)

    def _fetch_aggregated_port_data(self, ip: str, perspective: str, time_range: str) -> Optional[Dict]:
        """
        從聚合索引查詢通訊埠數據

        Args:
            ip: IP 地址
            perspective: 'SRC' 或 'DST'
            time_range: 時間範圍

        Returns:
            聚合數據字典
        """
        # 根據視角選擇索引（使用 3m 聚合索引）
        if perspective == 'SRC':
            index = f"{self.es_host}/netflow_stats_3m_by_src/_search"
            ip_field = "src_ip"
        else:
            index = f"{self.es_host}/netflow_stats_3m_by_dst/_search"
            ip_field = "dst_ip"

        # 查詢該 IP 的聚合數據
        query = {
            "size": 100,
            "query": {
                "bool": {
                    "must": [
                        {"term": {ip_field: ip}},
                        {"range": {"time_bucket": {"gte": time_range}}}
                    ]
                }
            },
            "sort": [{"time_bucket": "desc"}]
        }

        try:
            response = requests.post(index, json=query, headers={'Content-Type': 'application/json'})
            data = response.json()

            if not data.get('hits', {}).get('hits'):
                return None

            # 合併所有時間段的數據
            merged = self._merge_aggregated_data(data['hits']['hits'], perspective)
            return merged

        except Exception as e:
            print(f"查詢失敗: {e}")
            return None

    def _merge_aggregated_data(self, hits: List, perspective: str) -> Dict:
        """
        合併多個時間段的聚合數據

        Args:
            hits: Elasticsearch 查詢結果
            perspective: 'SRC' 或 'DST'

        Returns:
            合併後的數據
        """
        total_flows = 0
        all_ports = set()

        # 收集所有通訊埠
        for hit in hits:
            src = hit['_source']
            total_flows += src.get('flow_count', 0)

            # 根據視角選擇埠欄位
            if perspective == 'SRC':
                # SRC 視角：看目的埠
                port_field = 'dst_ports'
            else:
                # DST 視角：看來源埠
                port_field = 'src_ports'

            # 合併埠列表（如果有 top_ports 或類似欄位）
            # 注意：這裡假設聚合數據中有 port 相關欄位
            # 實際需根據你的聚合數據結構調整

            # 簡化版：使用 unique_dst_ports / unique_src_ports
            if perspective == 'SRC':
                unique_ports = src.get('unique_dst_ports', 0)
            else:
                unique_ports = src.get('unique_src_ports', 0)

        return {
            'flow_count': total_flows,
            'unique_ports': unique_ports,
            'perspective': perspective
        }

    def _analyze_from_aggregated(self, agg_data: Dict, perspective: str) -> Dict:
        """
        從聚合數據分析通訊埠模式

        Args:
            agg_data: 聚合數據
            perspective: 'SRC' 或 'DST'

        Returns:
            分析結果
        """
        # 注意：聚合數據中只有 unique_ports 計數，沒有實際埠號列表
        # 需要查詢原始數據才能做非臨時埠分類
        # 這裡使用啟發式規則進行判斷

        # 【修正】判斷掃描時，兩個視角都應該看 unique_dst_ports：
        # - SRC 視角：連到多少個目的埠 (unique_dst_ports)
        # - DST 視角：有多少個服務埠被訪問 (unique_dst_ports) ← 關鍵修正！
        unique_ports = agg_data.get('unique_dst_ports', 0)
        flow_count = agg_data.get('flow_count', 0)
        unique_targets = agg_data.get('unique_dsts' if perspective == 'SRC' else 'unique_srcs', 0)

        # 【補充】DST 視角時，同時記錄來源埠資訊（用於展示，不影響判斷）
        unique_src_ports = agg_data.get('unique_src_ports', 0) if perspective == 'DST' else 0

        # 【關鍵啟發式規則】
        # 如果 unique_ports ≈ flow_count (>80% 比例) 且 unique_targets 很少 (<10)
        # → 極可能是伺服器回應到多個客戶端臨時埠（每個連線使用不同的臨時埠）
        port_flow_ratio = unique_ports / flow_count if flow_count > 0 else 0

        if unique_ports > 100 and port_flow_ratio > 0.8 and unique_targets < 10:
            # 高埠多樣性 + 高 port/flow 比例 + 少量目標 → 伺服器回應模式
            pattern_type = 'SERVER_RESPONSE_TO_CLIENTS'
            is_scanning = False
            confidence = 0.9
            reason = f'High port/flow ratio ({port_flow_ratio:.2f}) with few targets ({unique_targets}), likely server responses to ephemeral ports'

        elif unique_ports < 10:
            pattern_type = 'NORMAL'
            is_scanning = False
            confidence = 0.8
            reason = 'Low port count'

        elif unique_ports < 30:
            pattern_type = 'DATA_COLLECTION' if perspective == 'SRC' else 'MULTI_SERVICE'
            is_scanning = False
            confidence = 0.75
            reason = 'Moderate port count with limited diversity'

        else:
            # 高埠數但不符合伺服器回應模式 → 可能是掃描
            pattern_type = 'SCANNING'
            is_scanning = True
            confidence = 0.7
            reason = f'High port diversity ({unique_ports} ports) without server response pattern'

        result = {
            'total_unique_ports': unique_ports,
            'is_scanning': is_scanning,
            'pattern_type': pattern_type,
            'confidence': confidence,
            'details': {
                'flow_count': flow_count,
                'unique_ports': unique_ports,
                'unique_targets': unique_targets,
                'port_flow_ratio': round(port_flow_ratio, 3),
                'reason': reason
            }
        }

        # 【補充】DST 視角時，添加來源埠資訊
        if perspective == 'DST' and unique_src_ports > 0:
            result['source_port_info'] = {
                'unique_src_ports': unique_src_ports,
                'note': '來源埠資訊（展示用，掃描判定基於 unique_dst_ports）'
            }

        return result

    @staticmethod
    def classify_ports_from_list(ports: List[int]) -> Dict:
        """
        從埠號列表分類臨時埠和服務埠

        Args:
            ports: 埠號列表

        Returns:
            {
                'service_ports': set,  # 服務埠集合
                'ephemeral_ports': set,  # 臨時埠集合
                'service_port_count': int,
                'ephemeral_port_count': int,
                'ephemeral_ratio': float
            }
        """
        service_ports = set()
        ephemeral_ports = set()

        for port in ports:
            if port <= PortAnalyzer.EPHEMERAL_PORT_START:
                service_ports.add(port)
            else:
                ephemeral_ports.add(port)

        total = len(ports)
        ephemeral_ratio = len([p for p in ports if p > PortAnalyzer.EPHEMERAL_PORT_START]) / total if total > 0 else 0

        return {
            'service_ports': service_ports,
            'ephemeral_ports': ephemeral_ports,
            'service_port_count': len(service_ports),
            'ephemeral_port_count': len(ephemeral_ports),
            'ephemeral_ratio': ephemeral_ratio
        }

    @staticmethod
    def determine_scanning_pattern(
        unique_ports: int,
        service_port_count: int,
        ephemeral_port_count: int,
        ephemeral_ratio: float,
        perspective: str,
        flow_count: int = 0,
        unique_targets: int = 0,
        common_port_ratio: float = 0.0,
        top_dst_ports: List[int] = None
    ) -> Dict:
        """
        基於非臨時埠計數法判斷掃描模式

        Args:
            unique_ports: 總埠數
            service_port_count: 服務埠數量
            ephemeral_port_count: 臨時埠數量
            ephemeral_ratio: 臨時埠比例
            perspective: 'SRC' 或 'DST'
            flow_count: 流量數
            unique_targets: 不同目標數量（SRC 視角為 unique_dsts）
            common_port_ratio: 常見客戶端埠流量佔比
            top_dst_ports: 主要連到的目的埠列表

        Returns:
            {
                'is_scanning': bool,
                'pattern_type': str,
                'reason': str,
                'confidence': float
            }
        """
        if top_dst_ports is None:
            top_dst_ports = []

        # DST 視角（被連線）
        if perspective == 'DST':
            if unique_ports > 20:
                if service_port_count < 10:
                    # 大量臨時埠，少量服務埠 → 正常伺服器混合流量
                    return {
                        'is_scanning': False,
                        'pattern_type': 'HYBRID_SERVER_CLIENT',
                        'reason': f'Normal hybrid traffic: {service_port_count} service ports, {ephemeral_port_count} ephemeral ports',
                        'confidence': 0.95
                    }
                elif service_port_count < 30:
                    # 適量服務埠 → 多服務主機
                    return {
                        'is_scanning': False,
                        'pattern_type': 'MULTI_SERVICE_HOST',
                        'reason': f'Multi-service host: {service_port_count} service ports',
                        'confidence': 0.85
                    }
                else:
                    # 大量服務埠 → 被掃描
                    return {
                        'is_scanning': True,
                        'pattern_type': 'UNDER_PORT_SCAN',
                        'reason': f'Many service ports targeted: {service_port_count}',
                        'confidence': 0.90
                    }
            else:
                return {
                    'is_scanning': False,
                    'pattern_type': 'NORMAL',
                    'reason': 'Low port count',
                    'confidence': 0.8
                }

        # SRC 視角（主動連線）
        else:
            if unique_ports > 20 and flow_count > 100:
                if ephemeral_ratio > 0.9 and service_port_count < 20:
                    # 連到大量臨時埠 → 伺服器回應流量
                    return {
                        'is_scanning': False,
                        'pattern_type': 'SERVER_RESPONSE_TO_CLIENTS',
                        'reason': f'Server response: {ephemeral_port_count} ephemeral ports ({ephemeral_ratio*100:.1f}%)',
                        'confidence': 0.95
                    }
                elif service_port_count < 30:
                    # 少量服務埠 → 資料收集
                    return {
                        'is_scanning': False,
                        'pattern_type': 'DATA_COLLECTION',
                        'reason': f'Data collection: {service_port_count} service ports',
                        'confidence': 0.85
                    }
                else:
                    # 大量服務埠 → 真正掃描
                    return {
                        'is_scanning': True,
                        'pattern_type': 'PORT_SCANNING',
                        'reason': f'Scanning many service ports: {service_port_count}',
                        'confidence': 0.90
                    }
            else:
                return {
                    'is_scanning': False,
                    'pattern_type': 'NORMAL',
                    'reason': 'Below threshold',
                    'confidence': 0.8
                }

    @staticmethod
    def check_normal_client_activity(
        unique_targets: int,
        service_port_count: int,
        common_port_ratio: float,
        top_dst_ports: List[int] = None
    ) -> Dict:
        """
        【新增】檢查是否為正常客戶端行為

        正常客戶端行為特徵：
        1. 主要連到常見服務埠（80, 443, 53 等）
        2. 目的埠集中（少量埠，多個目的地）
        3. 連到多個目的地但埠數適中

        Args:
            unique_targets: 不同目標數量 (unique_dsts)
            service_port_count: 服務埠數量 (unique_service_ports)
            common_port_ratio: 常見客戶端埠流量佔比
            top_dst_ports: 主要連到的目的埠列表

        Returns:
            {
                'is_normal_client': bool,
                'pattern_type': str,
                'reason': str,
                'confidence': float
            }
        """
        if top_dst_ports is None:
            top_dst_ports = []

        # 條件：
        # 1. 常見客戶端埠流量佔比 > 50%
        # 2. 服務埠數量適中 < 30
        # 3. 連到多個目的地 (unique_targets > 50 代表高度分散)
        if common_port_ratio > 0.5 and service_port_count < 30 and unique_targets > 50:
            return {
                'is_normal_client': True,
                'pattern_type': 'NORMAL_CLIENT_ACTIVITY',
                'reason': f'Normal client: {unique_targets} destinations, {common_port_ratio*100:.1f}% common port traffic, {service_port_count} service ports',
                'confidence': 0.90,
                'details': {
                    'unique_destinations': unique_targets,
                    'common_port_ratio': common_port_ratio,
                    'service_port_count': service_port_count,
                    'top_dst_ports': top_dst_ports[:5]
                }
            }

        return {
            'is_normal_client': False,
            'pattern_type': None,
            'reason': 'Does not match normal client pattern',
            'confidence': 0.0
        }
