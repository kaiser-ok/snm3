#!/usr/bin/env python3
"""
異常分類器 (Anomaly Classifier)

在 Isolation Forest 檢測出異常後，進一步分類異常類型。

分類類別:
- PORT_SCAN: 埠掃描
- NETWORK_SCAN: 網路掃描
- DATA_EXFILTRATION: 數據外洩
- DNS_TUNNELING: DNS 隧道
- DDOS: DDoS 攻擊
- C2_COMMUNICATION: C&C 通訊
- NORMAL_HIGH_TRAFFIC: 正常高流量
- UNKNOWN: 未知異常
"""

import numpy as np
from datetime import datetime
from typing import Dict, List, Tuple
import yaml
import os


# 威脅類別定義
THREAT_CLASSES = {
    'PORT_SCAN': {
        'name': '埠掃描',
        'name_en': 'Port Scanning',
        'severity': 'HIGH',
        'priority': 'P0',
        'description': '探測大量埠，尋找漏洞',
        'indicators': [
            '掃描大量不同埠（通常 > 100）',
            '小封包模式（平均 < 5KB）',
            '埠高度分散（diversity > 0.5）'
        ],
        'response': [
            '立即隔離主機',
            '檢查主機是否被入侵',
            '掃描惡意軟件',
            '追蹤掃描目標，檢查是否已被攻破'
        ],
        'auto_action': 'ISOLATE'
    },
    'NETWORK_SCAN': {
        'name': '網路掃描',
        'name_en': 'Network Scanning',
        'severity': 'HIGH',
        'priority': 'P0',
        'description': '掃描多個主機，可能是橫向移動',
        'indicators': [
            '掃描大量不同主機（> 50）',
            '高連線數但低流量',
            '目的地高度分散'
        ],
        'response': [
            '立即隔離主機',
            '追蹤掃描的目標主機',
            '檢查被掃描主機的安全狀態',
            '調查掃描來源'
        ],
        'auto_action': 'ISOLATE'
    },
    'DATA_EXFILTRATION': {
        'name': '數據外洩',
        'name_en': 'Data Exfiltration',
        'severity': 'CRITICAL',
        'priority': 'P0',
        'description': '大量數據傳輸到外部，疑似數據竊取',
        'indicators': [
            '大流量傳輸（通常 > 1GB）',
            '目的地極少（< 5 個）',
            '連接外部 IP',
            '持續時間長'
        ],
        'response': [
            '立即封鎖目標 IP',
            '終止所有活動連線',
            '調查數據來源和內容',
            '檢查內網是否被入侵',
            '報告安全事件'
        ],
        'auto_action': 'BLOCK'
    },
    'DNS_TUNNELING': {
        'name': 'DNS 隧道',
        'name_en': 'DNS Tunneling',
        'severity': 'HIGH',
        'priority': 'P0',
        'description': '通過 DNS 查詢傳輸數據，繞過防火牆',
        'indicators': [
            '大量 DNS 查詢（> 1000）',
            '僅使用 DNS 埠（53）',
            '查詢異常長的域名',
            '目的地 DNS 服務器極少'
        ],
        'response': [
            '封鎖目標 DNS 服務器',
            '分析 DNS 查詢內容',
            '檢查主機是否被植入後門',
            '監控 DNS 流量模式'
        ],
        'auto_action': 'BLOCK'
    },
    'DDOS': {
        'name': 'DDoS 攻擊',
        'name_en': 'DDoS Attack',
        'severity': 'CRITICAL',
        'priority': 'P0',
        'description': '分散式拒絕服務攻擊',
        'indicators': [
            '極高連線數（> 10000）',
            '小封包（< 500 bytes）',
            '目的地集中',
            'SYN Flood 模式'
        ],
        'response': [
            '啟動 DDoS 防護',
            '限速/黑洞路由',
            '聯繫 ISP 協助',
            '分析攻擊源'
        ],
        'auto_action': 'RATE_LIMIT'
    },
    'C2_COMMUNICATION': {
        'name': 'C&C 通訊',
        'name_en': 'C&C Communication',
        'severity': 'CRITICAL',
        'priority': 'P0',
        'description': '與控制服務器通訊（殭屍網路）',
        'indicators': [
            '週期性連線（固定時間間隔）',
            '單一目的地',
            '中等流量',
            '連接到已知惡意 IP'
        ],
        'response': [
            '立即隔離主機',
            '全面掃描惡意軟件',
            '分析通訊內容',
            '追蹤感染源',
            '檢查其他主機是否也被感染'
        ],
        'auto_action': 'ISOLATE'
    },
    'NORMAL_HIGH_TRAFFIC': {
        'name': '正常高流量',
        'name_en': 'Normal High Traffic',
        'severity': 'LOW',
        'priority': 'P3',
        'description': '合法的高流量服務（如備份、更新、視頻會議）',
        'indicators': [
            '大流量但目標是已知服務器',
            '固定時間段（如備份時間）',
            '使用標準服務埠',
            '可能是服務器回應流量'
        ],
        'response': [
            '加入白名單',
            '持續監控流量模式',
            '驗證服務合法性',
            '無需立即行動'
        ],
        'auto_action': 'WHITELIST'
    },
    'UNKNOWN': {
        'name': '未知異常',
        'name_en': 'Unknown Anomaly',
        'severity': 'MEDIUM',
        'priority': 'P2',
        'description': '無法分類的異常行為',
        'indicators': [
            '異常特徵組合不匹配已知模式'
        ],
        'response': [
            '人工審查',
            '持續監控',
            '收集更多數據',
            '可能需要更新分類規則'
        ],
        'auto_action': 'MONITOR'
    },

    # ===== Dst 視角威脅類別 =====
    'DDOS_TARGET': {
        'name': 'DDoS 攻擊目標',
        'name_en': 'DDoS Target',
        'severity': 'CRITICAL',
        'priority': 'P0',
        'description': '主機正遭受 DDoS 攻擊',
        'indicators': [
            '大量不同來源 IP（> 100）',
            '極高連線數（> 1000）',
            '小封包模式（< 500 bytes）'
        ],
        'response': [
            '啟動 DDoS 防護機制',
            '限速或黑洞路由',
            '分析攻擊模式',
            '聯繫 ISP 協助'
        ],
        'auto_action': 'RATE_LIMIT'
    },
    'SCAN_TARGET': {
        'name': '掃描目標',
        'name_en': 'Scan Target',
        'severity': 'HIGH',
        'priority': 'P0',
        'description': '主機正被掃描端口',
        'indicators': [
            '大量不同來源端口（> 100）',
            '掃描多個目標端口',
            '小封包探測'
        ],
        'response': [
            '加強防火牆規則',
            '監控掃描來源',
            '檢查主機漏洞',
            '記錄掃描行為'
        ],
        'auto_action': 'MONITOR'
    },
    'DATA_SINK': {
        'name': '資料外洩目標端',
        'name_en': 'Data Sink',
        'severity': 'CRITICAL',
        'priority': 'P0',
        'description': '外部 IP 收到大量內部數據',
        'indicators': [
            '多個內部 IP 連接同一外部 IP',
            '大流量傳輸',
            '外部 IP 地址'
        ],
        'response': [
            '立即封鎖外部 IP',
            '調查內部感染主機',
            '檢查數據洩漏範圍',
            '報告安全事件'
        ],
        'auto_action': 'BLOCK'
    },
    'MALWARE_DISTRIBUTION': {
        'name': '惡意軟體分發服務器',
        'name_en': 'Malware Distribution Server',
        'severity': 'CRITICAL',
        'priority': 'P0',
        'description': '外部服務器向多個內部 IP 分發數據（疑似惡意軟體）',
        'indicators': [
            '多個內部 IP 下載相同外部資源',
            '大流量入站',
            '外部 IP 地址'
        ],
        'response': [
            '立即封鎖外部 IP',
            '隔離已下載的內部主機',
            '掃描惡意軟體',
            '調查感染源'
        ],
        'auto_action': 'BLOCK'
    },
    'POPULAR_SERVER': {
        'name': '熱門服務器',
        'name_en': 'Popular Server',
        'severity': 'LOW',
        'priority': 'P3',
        'description': '合法的熱門服務（如內網 DNS, Web 服務）',
        'indicators': [
            '大量內部 IP 訪問',
            '正常封包大小',
            '內部 IP 地址'
        ],
        'response': ['監控流量模式', '確保服務正常運行'],
        'auto_action': 'MONITOR'
    }
}


class AnomalyClassifier:
    """
    異常分類器

    使用規則型方法對 Isolation Forest 檢測出的異常進行分類
    """

    def __init__(self, config=None):
        """
        初始化分類器

        Args:
            config: 配置對象
        """
        self.config = config
        self.threat_classes = THREAT_CLASSES

        # 載入 classifier 閾值配置
        self.thresholds_config = self._load_classifier_thresholds()

        # 從配置中讀取 Src 和 Dst 威脅閾值
        self.src_thresholds = self.thresholds_config.get('src_threats', {})
        self.dst_thresholds = self.thresholds_config.get('dst_threats', {})
        self.global_config = self.thresholds_config.get('global', {})

        # 載入內部網段（從 device_mapping.yaml）
        self.internal_networks = self._load_internal_networks()

        # 已知的合法服務器（可配置）
        self.known_servers = config.get('known_servers', []) if config else []

        # 備份時間窗口（從配置讀取，預設凌晨 1-5 點）
        backup_hours_list = self.global_config.get('backup_hours', [1, 2, 3, 4, 5])
        self.backup_hours = range(min(backup_hours_list), max(backup_hours_list) + 1) if backup_hours_list else range(1, 6)

    def _load_classifier_thresholds(self) -> Dict:
        """載入 classifier 閾值配置"""
        config_path = '/home/kaisermac/snm_flow/nad/config/classifier_thresholds.yaml'
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f) or {}
            else:
                print(f"⚠️ Classifier config not found: {config_path}, using defaults")
                return {}
        except Exception as e:
            print(f"⚠️ Error loading classifier config: {e}, using defaults")
            return {}

    def _load_internal_networks(self) -> List[str]:
        """從 device_mapping.yaml 載入內部網段"""
        device_mapping_path = '/home/kaisermac/snm_flow/nad/config/device_mapping.yaml'
        try:
            if os.path.exists(device_mapping_path):
                with open(device_mapping_path, 'r', encoding='utf-8') as f:
                    device_config = yaml.safe_load(f) or {}

                # 提取所有 network_segments
                segments = device_config.get('network_segments', {})
                internal_nets = []
                for segment_name, segment_info in segments.items():
                    subnet = segment_info.get('subnet', '')
                    if subnet:
                        # 將 CIDR 轉換為前綴（例如 192.168.1.0/24 -> 192.168.1.）
                        # 簡化處理：取前3段或前1段
                        if '/' in subnet:
                            ip_part = subnet.split('/')[0]
                            # 根據網段大小決定前綴
                            parts = ip_part.split('.')
                            if parts[0] == '10':
                                internal_nets.append('10.')
                            elif parts[0] == '172' and 16 <= int(parts[1]) <= 31:
                                internal_nets.append(f'172.{parts[1]}.')
                            elif parts[0] == '192' and parts[1] == '168':
                                internal_nets.append(f'192.168.')
                            else:
                                # 其他情況使用前3段
                                internal_nets.append('.'.join(parts[:3]) + '.')
                        else:
                            # 如果沒有 CIDR，直接使用
                            internal_nets.append(subnet)

                # 去重並返回
                if internal_nets:
                    return list(set(internal_nets))
        except Exception as e:
            print(f"⚠️ Error loading device mapping: {e}, using default internal networks")

        # 預設內部網段
        return [
            '192.168.',
            '10.',
            '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.'
        ]

    def classify(self, features: Dict, context: Dict = None) -> Dict:
        """
        分類異常

        Args:
            features: 特徵字典（來自 feature_engineer）
            context: 上下文信息（可選）
                - timestamp: 時間戳
                - src_ip: 源 IP
                - dst_ips: 目的地 IP 列表
                - anomaly_score: 異常分數

        Returns:
            分類結果字典
        """
        # 預設上下文
        if context is None:
            context = {}

        # 提取關鍵特徵
        flow_count = features.get('flow_count', 0)
        unique_dsts = features.get('unique_dsts', 0)
        unique_dst_ports = features.get('unique_dst_ports', 0)
        unique_src_ports = features.get('unique_src_ports', 0)
        total_bytes = features.get('total_bytes', 0)
        avg_bytes = features.get('avg_bytes', 0)
        dst_diversity = features.get('dst_diversity', 0)
        dst_port_diversity = features.get('dst_port_diversity', 0)

        # 新增分類特徵
        flow_rate = features.get('flow_rate', 0)
        byte_rate = features.get('byte_rate', 0)
        common_ports_ratio = features.get('common_ports_ratio', 0)

        # 二值特徵
        is_high_connection = features.get('is_high_connection', 0)
        is_scanning_pattern = features.get('is_scanning_pattern', 0)
        is_small_packet = features.get('is_small_packet', 0)
        is_large_flow = features.get('is_large_flow', 0)

        # 上下文
        timestamp = context.get('timestamp', datetime.now())
        src_ip = context.get('src_ip', '')
        dst_ips = context.get('dst_ips', [])

        # ========== 分類邏輯 ==========

        # 1. 埠掃描：關鍵特徵是掃描大量埠
        if self._is_port_scan(features):
            return self._create_classification(
                'PORT_SCAN',
                confidence=self._calculate_port_scan_confidence(features),
                features=features,
                context=context
            )

        # 2. 網路掃描：關鍵特徵是掃描大量主機
        if self._is_network_scan(features):
            return self._create_classification(
                'NETWORK_SCAN',
                confidence=self._calculate_network_scan_confidence(features),
                features=features,
                context=context
            )

        # 3. DNS 隧道：大量 DNS 查詢且目的地少
        if self._is_dns_tunneling(features, context):
            return self._create_classification(
                'DNS_TUNNELING',
                confidence=self._calculate_dns_tunneling_confidence(features),
                features=features,
                context=context
            )

        # 4. DDoS 攻擊：極高連線數 + 小封包
        if self._is_ddos(features):
            return self._create_classification(
                'DDOS',
                confidence=self._calculate_ddos_confidence(features),
                features=features,
                context=context
            )

        # 5. 數據外洩：大流量 + 少量外部目的地
        if self._is_data_exfiltration(features, dst_ips):
            return self._create_classification(
                'DATA_EXFILTRATION',
                confidence=self._calculate_exfil_confidence(features, dst_ips),
                features=features,
                context=context
            )

        # 6. C&C 通訊：週期性 + 單一目的地
        if self._is_c2_communication(features, context):
            return self._create_classification(
                'C2_COMMUNICATION',
                confidence=self._calculate_c2_confidence(features),
                features=features,
                context=context
            )

        # 7. 正常高流量：大流量但符合正常模式
        if self._is_normal_high_traffic(features, dst_ips, timestamp):
            return self._create_classification(
                'NORMAL_HIGH_TRAFFIC',
                confidence=self._calculate_normal_confidence(features, dst_ips, timestamp),
                features=features,
                context=context
            )

        # 8. 未知異常
        return self._create_classification(
            'UNKNOWN',
            confidence=0.5,
            features=features,
            context=context
        )

    # ========== 分類判斷方法 ==========

    def _is_port_scan(self, features: Dict) -> bool:
        """判斷是否為埠掃描"""
        unique_dst_ports = features.get('unique_dst_ports', 0)
        avg_bytes = features.get('avg_bytes', 0)
        dst_port_diversity = features.get('dst_port_diversity', 0)

        # 從配置讀取閾值，如果沒有配置則使用預設值
        config = self.src_thresholds.get('PORT_SCAN', {})
        if not config.get('enabled', True):
            return False

        thresholds = config.get('thresholds', {})
        threshold_ports = thresholds.get('unique_dst_ports', 100)
        threshold_bytes = thresholds.get('avg_bytes', 5000)
        threshold_diversity = thresholds.get('dst_port_diversity', 0.5)

        # 埠掃描特徵：
        # 1. 掃描大量埠
        # 2. 小封包
        # 3. 埠高度分散
        return (
            unique_dst_ports > threshold_ports and
            avg_bytes < threshold_bytes and
            dst_port_diversity > threshold_diversity
        )

    def _is_network_scan(self, features: Dict) -> bool:
        """判斷是否為網路掃描"""
        unique_dsts = features.get('unique_dsts', 0)
        dst_diversity = features.get('dst_diversity', 0)
        flow_count = features.get('flow_count', 0)
        avg_bytes = features.get('avg_bytes', 0)

        # 從配置讀取閾值
        config = self.src_thresholds.get('NETWORK_SCAN', {})
        if not config.get('enabled', True):
            return False

        thresholds = config.get('thresholds', {})
        threshold_dsts = thresholds.get('unique_dsts', 50)
        threshold_diversity = thresholds.get('dst_diversity', 0.3)
        threshold_flows = thresholds.get('flow_count', 1000)
        threshold_bytes = thresholds.get('avg_bytes', 50000)

        # 網路掃描特徵：
        # 1. 掃描大量主機
        # 2. 目的地高度分散
        # 3. 高連線數
        # 4. 小到中等流量
        return (
            unique_dsts > threshold_dsts and
            dst_diversity > threshold_diversity and
            flow_count > threshold_flows and
            avg_bytes < threshold_bytes
        )

    def _is_dns_tunneling(self, features: Dict, context: Dict) -> bool:
        """判斷是否為 DNS 隧道"""
        flow_count = features.get('flow_count', 0)
        unique_dsts = features.get('unique_dsts', 0)
        avg_bytes = features.get('avg_bytes', 0)
        unique_dst_ports = features.get('unique_dst_ports', 0)

        # 從配置讀取閾值
        config = self.src_thresholds.get('DNS_TUNNELING', {})
        if not config.get('enabled', True):
            return False

        thresholds = config.get('thresholds', {})
        threshold_flows = thresholds.get('flow_count', 1000)
        threshold_ports = thresholds.get('unique_dst_ports', 2)
        threshold_bytes = thresholds.get('avg_bytes', 1000)
        threshold_dsts = thresholds.get('unique_dsts', 5)

        # DNS 隧道特徵：
        # 1. 大量連線
        # 2. 只用 DNS 埠（unique_dst_ports 接近 1）
        # 3. 小封包
        # 4. 目的地極少
        return (
            flow_count > threshold_flows and
            unique_dst_ports <= threshold_ports and
            avg_bytes < threshold_bytes and
            unique_dsts <= threshold_dsts
        )

    def _is_ddos(self, features: Dict) -> bool:
        """判斷是否為 DDoS 攻擊"""
        flow_count = features.get('flow_count', 0)
        avg_bytes = features.get('avg_bytes', 0)
        unique_dsts = features.get('unique_dsts', 0)
        flow_rate = features.get('flow_rate', 0)

        # 從配置讀取閾值
        config = self.src_thresholds.get('DDOS', {})
        if not config.get('enabled', True):
            return False

        thresholds = config.get('thresholds', {})
        threshold_flows = thresholds.get('flow_count', 10000)
        threshold_rate = thresholds.get('flow_rate', 30)
        threshold_bytes = thresholds.get('avg_bytes', 500)
        threshold_dsts = thresholds.get('unique_dsts', 20)

        # DDoS 特徵：
        # 1. 極高連線數或高連線速率
        # 2. 極小封包 - SYN Flood
        # 3. 目的地少
        return (
            (flow_count > threshold_flows or flow_rate > threshold_rate) and
            avg_bytes < threshold_bytes and
            unique_dsts < threshold_dsts
        )

    def _is_data_exfiltration(self, features: Dict, dst_ips: List[str]) -> bool:
        """判斷是否為數據外洩"""
        total_bytes = features.get('total_bytes', 0)
        unique_dsts = features.get('unique_dsts', 0)
        dst_diversity = features.get('dst_diversity', 0)
        byte_rate = features.get('byte_rate', 0)

        # 從配置讀取閾值
        config = self.src_thresholds.get('DATA_EXFILTRATION', {})
        if not config.get('enabled', True):
            return False

        thresholds = config.get('thresholds', {})
        threshold_bytes = thresholds.get('total_bytes', 1000000000)  # 1GB
        threshold_rate = thresholds.get('byte_rate', 3000000)  # 3MB/s
        threshold_dsts = thresholds.get('unique_dsts', 5)
        threshold_diversity = thresholds.get('dst_diversity', 0.1)

        # 檢查是否有外部 IP
        has_external = any(not self._is_internal_ip(ip) for ip in dst_ips) if dst_ips else False

        # 數據外洩特徵：
        # 1. 大流量或高傳輸速率
        # 2. 目的地極少
        # 3. 目的地集中
        # 4. 有外部 IP
        return (
            (total_bytes > threshold_bytes or byte_rate > threshold_rate) and
            unique_dsts <= threshold_dsts and
            dst_diversity < threshold_diversity and
            has_external
        )

    def _is_c2_communication(self, features: Dict, context: Dict) -> bool:
        """判斷是否為 C&C 通訊"""
        flow_count = features.get('flow_count', 0)
        unique_dsts = features.get('unique_dsts', 0)
        avg_bytes = features.get('avg_bytes', 0)

        # 從配置讀取閾值
        config = self.src_thresholds.get('C2_COMMUNICATION', {})
        if not config.get('enabled', True):
            return False

        thresholds = config.get('thresholds', {})
        threshold_dsts = thresholds.get('unique_dsts', 1)
        threshold_flow_min = thresholds.get('flow_count_min', 100)
        threshold_flow_max = thresholds.get('flow_count_max', 1000)
        threshold_bytes_min = thresholds.get('avg_bytes_min', 1000)
        threshold_bytes_max = thresholds.get('avg_bytes_max', 100000)

        # C&C 通訊特徵：
        # 1. 單一目的地
        # 2. 中等連線數
        # 3. 中等流量
        # 4. 週期性（需要時間序列分析，這裡簡化）
        return (
            unique_dsts == threshold_dsts and
            threshold_flow_min < flow_count < threshold_flow_max and
            threshold_bytes_min < avg_bytes < threshold_bytes_max
        )

    def _is_normal_high_traffic(self, features: Dict, dst_ips: List[str], timestamp) -> bool:
        """判斷是否為正常高流量"""
        total_bytes = features.get('total_bytes', 0)
        unique_dsts = features.get('unique_dsts', 0)
        is_likely_server = features.get('is_likely_server_response', 0)

        # 從配置讀取閾值
        config = self.src_thresholds.get('NORMAL_HIGH_TRAFFIC', {})
        if not config.get('enabled', True):
            return False

        thresholds = config.get('thresholds', {})
        threshold_bytes = thresholds.get('total_bytes', 1000000000)  # 1GB
        threshold_dsts_min = thresholds.get('unique_dsts_min', 10)
        threshold_dsts_max = thresholds.get('unique_dsts_max', 100)

        # 檢查是否都是內部 IP
        all_internal = all(self._is_internal_ip(ip) for ip in dst_ips) if dst_ips else False

        # 檢查是否是備份時間
        hour = timestamp.hour if isinstance(timestamp, datetime) else 0
        is_backup_time = hour in self.backup_hours

        # 正常高流量特徵：
        # 1. 大流量但目標是內網
        # 2. 或者是服務器回應流量
        # 3. 或者在備份時間
        # 4. 目的地數量合理（不是單一也不是太分散）
        return (
            total_bytes > threshold_bytes and
            (all_internal or is_likely_server == 1 or is_backup_time) and
            threshold_dsts_min < unique_dsts < threshold_dsts_max
        )

    # ========== 置信度計算方法 ==========

    def _calculate_port_scan_confidence(self, features: Dict) -> float:
        """計算埠掃描的置信度"""
        unique_dst_ports = features.get('unique_dst_ports', 0)
        dst_port_diversity = features.get('dst_port_diversity', 0)
        avg_bytes = features.get('avg_bytes', 0)

        confidence = 0.6  # 基礎置信度

        # 埠數量越多，置信度越高
        if unique_dst_ports > 1000:
            confidence += 0.2
        elif unique_dst_ports > 500:
            confidence += 0.1

        # 埠分散度越高，置信度越高
        if dst_port_diversity > 0.7:
            confidence += 0.15
        elif dst_port_diversity > 0.6:
            confidence += 0.08

        # 封包越小，置信度越高
        if avg_bytes < 2000:
            confidence += 0.1
        elif avg_bytes < 3000:
            confidence += 0.05

        return min(confidence, 0.99)

    def _calculate_network_scan_confidence(self, features: Dict) -> float:
        """計算網路掃描的置信度"""
        unique_dsts = features.get('unique_dsts', 0)
        dst_diversity = features.get('dst_diversity', 0)

        confidence = 0.6

        if unique_dsts > 100:
            confidence += 0.2
        elif unique_dsts > 70:
            confidence += 0.1

        if dst_diversity > 0.5:
            confidence += 0.15
        elif dst_diversity > 0.4:
            confidence += 0.08

        return min(confidence, 0.99)

    def _calculate_dns_tunneling_confidence(self, features: Dict) -> float:
        """計算 DNS 隧道的置信度"""
        flow_count = features.get('flow_count', 0)
        unique_dst_ports = features.get('unique_dst_ports', 0)

        confidence = 0.7

        # 只使用 DNS 埠，置信度很高
        if unique_dst_ports == 1:
            confidence += 0.2

        # 連線數越多，置信度越高
        if flow_count > 5000:
            confidence += 0.1

        return min(confidence, 0.99)

    def _calculate_ddos_confidence(self, features: Dict) -> float:
        """計算 DDoS 的置信度"""
        flow_count = features.get('flow_count', 0)
        avg_bytes = features.get('avg_bytes', 0)
        flow_rate = features.get('flow_rate', 0)

        confidence = 0.7

        if flow_count > 50000 or flow_rate > 100:
            confidence += 0.2
        elif flow_count > 20000 or flow_rate > 50:
            confidence += 0.1

        if avg_bytes < 300:
            confidence += 0.1

        return min(confidence, 0.99)

    def _calculate_exfil_confidence(self, features: Dict, dst_ips: List[str]) -> float:
        """計算數據外洩的置信度"""
        total_bytes = features.get('total_bytes', 0)
        unique_dsts = features.get('unique_dsts', 0)
        dst_diversity = features.get('dst_diversity', 0)
        byte_rate = features.get('byte_rate', 0)

        confidence = 0.7

        # 流量越大，置信度越高
        if total_bytes > 10e9 or byte_rate > 30e6:  # > 10GB or > 30MB/s
            confidence += 0.15
        elif total_bytes > 5e9 or byte_rate > 15e6:  # > 5GB or > 15MB/s
            confidence += 0.1

        # 目的地越集中，置信度越高
        if unique_dsts == 1:
            confidence += 0.1
        elif unique_dsts <= 3:
            confidence += 0.05

        if dst_diversity < 0.05:
            confidence += 0.05

        return min(confidence, 0.99)

    def _calculate_c2_confidence(self, features: Dict) -> float:
        """計算 C&C 通訊的置信度"""
        unique_dsts = features.get('unique_dsts', 0)

        confidence = 0.6

        # 單一目的地，置信度較高
        if unique_dsts == 1:
            confidence += 0.2

        # 需要時間序列分析才能更準確判斷，這裡給較低置信度
        return min(confidence, 0.85)

    def _calculate_normal_confidence(self, features: Dict, dst_ips: List[str], timestamp) -> float:
        """計算正常流量的置信度"""
        is_likely_server = features.get('is_likely_server_response', 0)

        confidence = 0.5

        # 是服務器回應流量
        if is_likely_server == 1:
            confidence += 0.3

        # 都是內部 IP
        if dst_ips and all(self._is_internal_ip(ip) for ip in dst_ips):
            confidence += 0.2

        # 在備份時間
        hour = timestamp.hour if isinstance(timestamp, datetime) else 0
        if hour in self.backup_hours:
            confidence += 0.1

        return min(confidence, 0.95)

    # ========== 輔助方法 ==========

    def _is_internal_ip(self, ip: str) -> bool:
        """判斷是否為內部 IP"""
        if not ip:
            return False
        return any(ip.startswith(prefix) for prefix in self.internal_networks)

    def _create_classification(self, class_name: str, confidence: float,
                              features: Dict, context: Dict) -> Dict:
        """
        創建分類結果

        Returns:
            {
                'class': 類別名稱,
                'class_info': 類別詳細信息,
                'confidence': 置信度,
                'severity': 嚴重性,
                'priority': 優先級,
                'indicators': 關鍵指標列表,
                'response': 響應建議列表,
                'auto_action': 自動化行動
            }
        """
        class_info = self.threat_classes[class_name]

        # 生成關鍵指標
        indicators = self._generate_indicators(class_name, features, context)

        return {
            'class': class_name,
            'class_name': class_info['name'],
            'class_name_en': class_info['name_en'],
            'confidence': confidence,
            'severity': class_info['severity'],
            'priority': class_info['priority'],
            'description': class_info['description'],
            'indicators': indicators,
            'response': class_info['response'],
            'auto_action': class_info['auto_action']
        }

    def _generate_indicators(self, class_name: str, features: Dict, context: Dict) -> List[str]:
        """生成具體的威脅指標"""
        indicators = []

        if class_name == 'PORT_SCAN':
            unique_dst_ports = features.get('unique_dst_ports', 0)
            avg_bytes = features.get('avg_bytes', 0)
            dst_port_diversity = features.get('dst_port_diversity', 0)

            indicators.append(f"掃描 {unique_dst_ports:,} 個不同埠")
            indicators.append(f"平均封包 {avg_bytes:,.0f} bytes（小封包）")
            indicators.append(f"埠分散度 {dst_port_diversity:.2f}（高度分散）")

        elif class_name == 'NETWORK_SCAN':
            unique_dsts = features.get('unique_dsts', 0)
            flow_count = features.get('flow_count', 0)

            indicators.append(f"掃描 {unique_dsts} 個不同主機")
            indicators.append(f"總連線數 {flow_count:,}")

        elif class_name == 'DATA_EXFILTRATION':
            total_bytes = features.get('total_bytes', 0)
            unique_dsts = features.get('unique_dsts', 0)

            indicators.append(f"傳輸 {total_bytes/1e9:.2f} GB 數據")
            indicators.append(f"僅 {unique_dsts} 個目的地（高度集中）")

            dst_ips = context.get('dst_ips', [])
            external_ips = [ip for ip in dst_ips if not self._is_internal_ip(ip)]
            if external_ips:
                indicators.append(f"目標外部 IP: {', '.join(external_ips[:3])}")

        elif class_name == 'DNS_TUNNELING':
            flow_count = features.get('flow_count', 0)
            indicators.append(f"{flow_count:,} 次 DNS 查詢")
            indicators.append("僅使用 DNS 埠（port 53）")

        elif class_name == 'DDOS':
            flow_count = features.get('flow_count', 0)
            avg_bytes = features.get('avg_bytes', 0)

            indicators.append(f"極高連線數: {flow_count:,}")
            indicators.append(f"極小封包: {avg_bytes:.0f} bytes")

        elif class_name == 'C2_COMMUNICATION':
            indicators.append("單一目的地（疑似控制服務器）")
            indicators.append("中等流量模式")

        elif class_name == 'NORMAL_HIGH_TRAFFIC':
            total_bytes = features.get('total_bytes', 0)
            indicators.append(f"大流量: {total_bytes/1e9:.2f} GB")

            dst_ips = context.get('dst_ips', [])
            if dst_ips and all(self._is_internal_ip(ip) for ip in dst_ips):
                indicators.append("所有目標均為內網 IP")

            if features.get('is_likely_server_response', 0) == 1:
                indicators.append("可能是服務器回應流量")

        return indicators

    def get_severity_emoji(self, severity: str) -> str:
        """獲取嚴重性對應的 emoji"""
        emoji_map = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        return emoji_map.get(severity, '⚪')

    # ========== Dst 視角分類 ==========

    def classify_dst(self, features: Dict, context: Dict = None) -> Dict:
        """
        Dst 視角的異常分類

        Args:
            features: 特徵字典（from dst perspective）
                - unique_srcs: 來源 IP 數量
                - unique_src_ports: 來源端口數量
                - unique_dst_ports: 目標端口數量
                - flow_count: 連線數
                - total_bytes: 總流量
                - avg_bytes: 平均封包大小
                - flows_per_src: 每個來源的平均連線數
                - bytes_per_src: 每個來源的平均流量
            context: 上下文信息
                - dst_ip: 目標 IP
                - timestamp: 時間戳

        Returns:
            分類結果字典
        """
        if context is None:
            context = {}

        dst_ip = context.get('dst_ip', 'unknown')

        # 1. DDoS 攻擊目標
        if self._is_ddos_target(features, context):
            return self._create_classification('DDOS_TARGET', 0.95, features, context)

        # 2. 掃描目標
        if self._is_scan_target(features, context):
            return self._create_classification('SCAN_TARGET', 0.90, features, context)

        # 3. 資料外洩目標端
        if self._is_data_sink(features, context):
            return self._create_classification('DATA_SINK', 0.85, features, context)

        # 4. 惡意軟體分發服務器
        if self._is_malware_distribution(features, context):
            return self._create_classification('MALWARE_DISTRIBUTION', 0.80, features, context)

        # 5. 熱門服務器（內部服務）
        if self._is_popular_server(features, context):
            return self._create_classification('POPULAR_SERVER', 0.70, features, context)

        # 6. 未知 dst 異常
        return self._create_classification('UNKNOWN', 0.50, features, context)

    def _is_ddos_target(self, features: Dict, context: Dict) -> bool:
        """判斷是否為 DDoS 攻擊目標"""
        unique_srcs = features.get('unique_srcs', 0)
        flow_count = features.get('flow_count', 0)
        avg_bytes = features.get('avg_bytes', 0)

        # 從配置讀取閾值
        config = self.dst_thresholds.get('DDOS_TARGET', {})
        if not config.get('enabled', True):
            return False

        thresholds = config.get('thresholds', {})
        threshold_srcs = thresholds.get('unique_srcs', 100)
        threshold_flows = thresholds.get('flow_count', 1000)
        threshold_bytes = thresholds.get('avg_bytes', 500)

        # DDoS 特徵：
        # 1. 大量不同來源
        # 2. 極高連線數
        # 3. 小封包 - SYN flood 特徵
        return (
            unique_srcs > threshold_srcs and
            flow_count > threshold_flows and
            avg_bytes < threshold_bytes
        )

    def _is_scan_target(self, features: Dict, context: Dict) -> bool:
        """判斷是否為掃描目標"""
        unique_src_ports = features.get('unique_src_ports', 0)
        unique_dst_ports = features.get('unique_dst_ports', 0)
        avg_bytes = features.get('avg_bytes', 0)

        # 從配置讀取閾值
        config = self.dst_thresholds.get('SCAN_TARGET', {})
        if not config.get('enabled', True):
            return False

        thresholds = config.get('thresholds', {})
        threshold_src_ports = thresholds.get('unique_src_ports', 100)
        threshold_dst_ports = thresholds.get('unique_dst_ports', 50)
        threshold_bytes = thresholds.get('avg_bytes', 2000)

        # 掃描目標特徵：
        # 1. 大量不同來源端口 - 掃描器隨機化來源端口
        # 2. 多個目標端口被探測
        # 3. 小封包（探測性質）
        return (
            unique_src_ports > threshold_src_ports and
            unique_dst_ports > threshold_dst_ports and
            avg_bytes < threshold_bytes
        )

    def _is_data_sink(self, features: Dict, context: Dict) -> bool:
        """判斷是否為資料外洩目標端"""
        unique_srcs = features.get('unique_srcs', 0)
        total_bytes = features.get('total_bytes', 0)
        avg_bytes = features.get('avg_bytes', 0)
        dst_ip = context.get('dst_ip', '')

        # 從配置讀取閾值
        config = self.dst_thresholds.get('DATA_SINK', {})
        if not config.get('enabled', True):
            return False

        thresholds = config.get('thresholds', {})
        threshold_srcs = thresholds.get('unique_srcs', 10)
        threshold_bytes = thresholds.get('total_bytes', 100000000)  # 100MB
        threshold_avg_bytes = thresholds.get('avg_bytes', 10000)

        # 資料外洩目標端特徵：
        # 1. 多個內部來源
        # 2. 大流量
        # 3. 目標是外部 IP
        return (
            unique_srcs > threshold_srcs and
            total_bytes > threshold_bytes and
            avg_bytes > threshold_avg_bytes and
            not self._is_internal_ip(dst_ip)
        )

    def _is_malware_distribution(self, features: Dict, context: Dict) -> bool:
        """判斷是否為惡意軟體分發服務器"""
        unique_srcs = features.get('unique_srcs', 0)
        total_bytes = features.get('total_bytes', 0)
        flows_per_src = features.get('flows_per_src', 0)
        dst_ip = context.get('dst_ip', '')

        # 從配置讀取閾值
        config = self.dst_thresholds.get('MALWARE_DISTRIBUTION', {})
        if not config.get('enabled', True):
            return False

        thresholds = config.get('thresholds', {})
        threshold_srcs = thresholds.get('unique_srcs', 5)
        threshold_bytes = thresholds.get('total_bytes', 50000000)  # 50MB
        threshold_flows_per_src = thresholds.get('flows_per_src', 10)

        # 惡意軟體分發特徵：
        # 1. 多個內部來源下載
        # 2. 大流量入站
        # 3. 每個來源連線次數少 - 下載後就斷開
        # 4. 目標是外部 IP
        return (
            unique_srcs > threshold_srcs and
            total_bytes > threshold_bytes and
            flows_per_src < threshold_flows_per_src and
            not self._is_internal_ip(dst_ip)
        )

    def _is_popular_server(self, features: Dict, context: Dict) -> bool:
        """判斷是否為熱門服務器（正常）"""
        unique_srcs = features.get('unique_srcs', 0)
        avg_bytes = features.get('avg_bytes', 0)
        dst_ip = context.get('dst_ip', '')

        # 從配置讀取閾值
        config = self.dst_thresholds.get('POPULAR_SERVER', {})
        if not config.get('enabled', True):
            return False

        thresholds = config.get('thresholds', {})
        threshold_srcs = thresholds.get('unique_srcs', 20)
        threshold_bytes_min = thresholds.get('avg_bytes_min', 500)
        threshold_bytes_max = thresholds.get('avg_bytes_max', 50000)

        # 熱門服務器特徵：
        # 1. 大量內部來源訪問
        # 2. 正常封包大小
        # 3. 目標是內部 IP
        return (
            unique_srcs > threshold_srcs and
            threshold_bytes_min < avg_bytes < threshold_bytes_max and
            self._is_internal_ip(dst_ip)
        )
