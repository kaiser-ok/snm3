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
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from functools import lru_cache
from collections import OrderedDict
import threading
import yaml
import os
import requests
import json
import logging

# 設定 post_process logger
post_process_logger = logging.getLogger('post_process')
post_process_logger.setLevel(logging.INFO)

# 確保 logs 目錄存在並設定 FileHandler
_log_dir = '/home/kaisermac/snm_flow/nad/logs'
os.makedirs(_log_dir, exist_ok=True)
_log_file = os.path.join(_log_dir, 'post_process.log')

# 只在沒有 handler 時添加
if not any(isinstance(h, logging.FileHandler) and h.baseFilename == _log_file for h in post_process_logger.handlers):
    _fh = logging.FileHandler(_log_file, encoding='utf-8')
    _fh.setLevel(logging.INFO)
    _fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    post_process_logger.addHandler(_fh)


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
    },
    'SCAN_RESPONSE': {
        'name': '掃描回應流量',
        'name_en': 'Scan Response Traffic',
        'severity': 'MEDIUM',
        'priority': 'P2',
        'description': '主機執行掃描後收到的回應流量（非攻擊）',
        'indicators': [
            '大量不同來源 IP 回應',
            '使用大量不同本地端口',
            '每個來源僅少量連線（掃描回應特徵）'
        ],
        'response': ['確認掃描行為是否授權', '檢查掃描來源主機', '記錄掃描活動'],
        'auto_action': 'MONITOR'
    },
    'NORMAL_DST_TRAFFIC': {
        'name': '正常目的地流量',
        'name_en': 'Normal Destination Traffic',
        'severity': 'LOW',
        'priority': 'P3',
        'description': '正常的點對點通訊或少量來源的服務訪問',
        'indicators': [
            '少量來源 IP（1-3 個）',
            '正常封包大小',
            '適中的連線數量',
            '內部 IP 通訊'
        ],
        'response': [
            '加入白名單',
            '調整異常檢測閾值',
            '持續監控確認為正常行為'
        ],
        'auto_action': 'WHITELIST'
    },
    'SERVER_RESPONSE_TRAFFIC': {
        'name': '伺服器回應流量',
        'name_en': 'Server Response Traffic',
        'severity': 'LOW',
        'priority': 'P3',
        'description': '伺服器回應到客戶端的正常流量（DST 視角的大量埠是回應到臨時埠）',
        'indicators': [
            'SRC 視角主要連到知名服務埠（SNMP/DNS/HTTP 等）',
            'SRC 視角使用大量來源埠（每次查詢用不同臨時埠）',
            'DST 視角的大量目的埠是回應流量',
            '跨視角分析確認為伺服器行為'
        ],
        'response': [
            '加入白名單',
            '這是正常的伺服器回應流量',
            '無需處理'
        ],
        'auto_action': 'WHITELIST'
    }
}


class AnomalyClassifier:
    """
    異常分類器

    使用規則型方法對 Isolation Forest 檢測出的異常進行分類
    """

    def __init__(self, config=None, es_host: str = None):
        """
        初始化分類器

        Args:
            config: 配置對象
            es_host: Elasticsearch 連線 URL（用於跨視角查詢）
        """
        self.config = config
        self.threat_classes = THREAT_CLASSES

        # ES 連線設定（從環境變數或參數取得）
        self.es_host = es_host or os.environ.get('ES_HOST', 'http://localhost:9200')

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

        # ===== SRC 視角檢查結果快取 =====
        # 用於避免重複查詢相同 IP 的 SRC 視角資料
        # key: (dst_ip, time_bucket_rounded)  -> 將時間桶捨入到 10 分鐘
        # value: {'result': 'SERVER_RESPONSE' | 'NOT_SERVER' | 'NO_DATA', 'timestamp': datetime}
        self._src_check_cache = OrderedDict()
        self._src_check_cache_lock = threading.Lock()

        # 從 config 讀取快取設定
        cache_config = self.thresholds_config.get('src_check_cache', {})
        self._src_check_cache_max_size = cache_config.get('max_size', 500)
        self._src_check_cache_ttl = cache_config.get('ttl_seconds', 1200)  # 預設 20 分鐘

        # 快取統計
        self._cache_stats = {
            'hits': 0,
            'misses': 0,
            'expired': 0
        }

        # 定期 log 統計的設定
        self._last_stats_log_time = datetime.now()
        self._stats_log_interval = cache_config.get('stats_log_interval', 300)  # 預設 5 分鐘
        self._last_logged_stats = {'hits': 0, 'misses': 0}  # 記錄上次 log 時的數值

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
        unique_dsts = features.get('unique_dsts', 0)

        # Port 相關特徵
        top_dst_port_concentration = features.get('top_dst_port_concentration', 0)

        # ✅ Phase 1: 連續端口檢測特徵
        has_sequential = features.get('has_sequential_dst_ports', 0)

        # 從配置讀取閾值，如果沒有配置則使用預設值
        config = self.src_thresholds.get('PORT_SCAN', {})
        if not config.get('enabled', True):
            return False

        thresholds = config.get('thresholds', {})
        threshold_ports = thresholds.get('unique_dst_ports', 100)
        threshold_bytes = thresholds.get('avg_bytes', 5000)
        threshold_diversity = thresholds.get('dst_port_diversity', 0.5)

        # ✅ 快速路徑：連續端口掃描（如 1-1024）是明顯的掃描行為
        # 即使不滿足其他條件，只要是連續掃描大量端口就判定為掃描
        if has_sequential == 1 and unique_dst_ports > 50:
            return True

        # 埠掃描特徵（標準判斷）：
        # 1. 掃描大量埠
        # 2. 小封包
        # 3. 埠高度分散
        # 4. 目標主機少（專注於少數目標的端口掃描）
        # 5. 端口流量分散（沒有集中在特定端口）
        return (
            unique_dst_ports > threshold_ports and
            avg_bytes < threshold_bytes and
            dst_port_diversity > threshold_diversity and
            unique_dsts < 50 and  # 少於 50 個目標（與網路掃描區分）
            top_dst_port_concentration < 0.3  # 端口流量分散
        )

    def _is_network_scan(self, features: Dict) -> bool:
        """判斷是否為網路掃描"""
        unique_dsts = features.get('unique_dsts', 0)
        dst_diversity = features.get('dst_diversity', 0)
        flow_count = features.get('flow_count', 0)
        avg_bytes = features.get('avg_bytes', 0)

        # Port 相關特徵
        top_dst_port_concentration = features.get('top_dst_port_concentration', 0)
        dst_well_known_ratio = features.get('dst_well_known_ratio', 0)
        top_src_port_concentration = features.get('top_src_port_concentration', 0)

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
        # 5. 【新增】目的端口集中在常見服務（知名端口比例高）
        # 6. 【新增】來源端口高度分散（隨機化）

        # 基本掃描特徵
        is_basic_scan = (
            unique_dsts > threshold_dsts and
            dst_diversity > threshold_diversity and
            flow_count > threshold_flows and
            avg_bytes < threshold_bytes
        )

        # Port 特徵加成：提高識別準確度
        has_scan_port_pattern = (
            top_dst_port_concentration > 0.3 and  # 目的端口相對集中（掃描常見服務）
            dst_well_known_ratio > 0.7 and         # 70% 以上是知名端口
            top_src_port_concentration < 0.2       # 來源端口高度分散
        )

        return is_basic_scan or (unique_dsts > threshold_dsts and has_scan_port_pattern)

    def _is_dns_tunneling(self, features: Dict, context: Dict) -> bool:
        """判斷是否為 DNS 隧道"""
        flow_count = features.get('flow_count', 0)
        unique_dsts = features.get('unique_dsts', 0)
        avg_bytes = features.get('avg_bytes', 0)
        unique_dst_ports = features.get('unique_dst_ports', 0)

        # Port 相關特徵
        top_dst_port_concentration = features.get('top_dst_port_concentration', 0)

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
        # 5. 【新增】端口極度集中（幾乎只用 port 53）
        return (
            flow_count > threshold_flows and
            unique_dst_ports <= threshold_ports and
            avg_bytes < threshold_bytes and
            unique_dsts <= threshold_dsts and
            top_dst_port_concentration > 0.9  # 90% 流量集中在單一端口（DNS:53）
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

        # Port 相關特徵
        dst_well_known_ratio = features.get('dst_well_known_ratio', 0)
        common_ports_ratio = features.get('common_ports_ratio', 0)

        # ✅ Phase 2: 註冊端口比例（數據外洩常用非標準端口規避檢測）
        dst_registered_ratio = features.get('dst_registered_ratio', 0)
        dst_ephemeral_ratio = features.get('dst_ephemeral_ratio', 0)

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

        # ✅ Phase 2: 使用非標準端口（規避檢測的常見手法）
        # 註冊端口（1024-49151）或臨時端口（49152-65535）比例高，知名端口比例低
        uses_non_standard_ports = (
            (dst_registered_ratio > 0.5 or dst_ephemeral_ratio > 0.3) and
            dst_well_known_ratio < 0.3
        )

        # 數據外洩特徵：
        # 1. 大流量或高傳輸速率
        # 2. 目的地極少
        # 3. 目的地集中
        # 4. 有外部 IP
        # 5. ✅ Phase 2: 使用非標準端口（提高置信度）
        basic_exfil = (
            (total_bytes > threshold_bytes or byte_rate > threshold_rate) and
            unique_dsts <= threshold_dsts and
            dst_diversity < threshold_diversity and
            has_external
        )

        # ✅ Phase 2: 如果使用非標準端口，更可疑（強化檢測）
        return basic_exfil and uses_non_standard_ports

    def _is_c2_communication(self, features: Dict, context: Dict) -> bool:
        """判斷是否為 C&C 通訊"""
        flow_count = features.get('flow_count', 0)
        unique_dsts = features.get('unique_dsts', 0)
        avg_bytes = features.get('avg_bytes', 0)

        # Port 相關特徵
        unique_dst_ports = features.get('unique_dst_ports', 0)
        common_ports_ratio = features.get('common_ports_ratio', 0)

        # ✅ Phase 2: 臨時端口比例（C&C 通常使用註冊或動態端口）
        dst_ephemeral_ratio = features.get('dst_ephemeral_ratio', 0)
        dst_registered_ratio = features.get('dst_registered_ratio', 0)

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

        # C&C 常用高端口號或非標準端口（規避檢測）
        uses_high_ports = (common_ports_ratio < 0.5)  # 少於 50% 使用標準端口

        # ✅ C&C 通常使用註冊端口（1024-49151）或動態端口（49152-65535）
        # 如果主要使用這些端口，增加 C&C 可能性
        uses_non_well_known = (dst_registered_ratio > 0.5 or dst_ephemeral_ratio > 0.5)

        # C&C 通訊特徵：
        # 1. 單一目的地
        # 2. 中等連線數
        # 3. 中等流量
        # 4. 通常使用少數端口（1-3個）
        # 5. ✅ 使用非知名端口（註冊或動態端口，規避檢測）
        basic_c2_pattern = (
            unique_dsts == threshold_dsts and
            threshold_flow_min < flow_count < threshold_flow_max and
            threshold_bytes_min < avg_bytes < threshold_bytes_max and
            unique_dst_ports <= 3
        )

        # 如果符合基本模式且使用非知名端口，判定為 C&C
        return basic_c2_pattern and uses_non_well_known

    def _is_normal_high_traffic(self, features: Dict, dst_ips: List[str], timestamp) -> bool:
        """判斷是否為正常高流量"""
        total_bytes = features.get('total_bytes', 0)
        unique_dsts = features.get('unique_dsts', 0)
        is_likely_server = features.get('is_likely_server_response', 0)

        # ✅ Phase 1: Server 角色識別特徵
        is_web_server = features.get('is_likely_web_server', 0)
        is_dns_server = features.get('is_likely_dns_server', 0)
        is_db_server = features.get('is_likely_db_server', 0)
        is_mail_server = features.get('is_likely_mail_server', 0)

        # 明確識別為已知服務器類型
        is_known_server = any([
            is_web_server == 1,
            is_dns_server == 1,
            is_db_server == 1,
            is_mail_server == 1
        ])

        # ✅ Phase 2: 臨時端口比例檢查（服務器回應特徵）
        dst_ephemeral_ratio = features.get('dst_ephemeral_ratio', 0)
        # 如果回應到大量臨時端口（> 80%），這是典型的服務器回應客戶端模式
        # 與 verify_anomaly.py 的 ephemeral_ratio > 0.9 邏輯一致（但稍微寬鬆）
        is_server_response_pattern = (dst_ephemeral_ratio > 0.8)

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
        # 2. 或者是服務器回應流量（原有判斷）
        # 3. ✅ 或者是已知服務器類型（Web/DNS/DB/Mail）
        # 4. ✅ 或者有服務器回應模式（回應到大量臨時端口）
        # 5. 或者在備份時間
        # 6. 目的地數量合理（不是單一也不是太分散）
        return (
            total_bytes > threshold_bytes and
            (all_internal or is_likely_server == 1 or is_known_server or
             is_server_response_pattern or is_backup_time) and
            threshold_dsts_min < unique_dsts < threshold_dsts_max
        )

    # ========== 置信度計算方法 ==========

    def _calculate_port_scan_confidence(self, features: Dict) -> float:
        """計算埠掃描的置信度"""
        unique_dst_ports = features.get('unique_dst_ports', 0)
        dst_port_diversity = features.get('dst_port_diversity', 0)
        avg_bytes = features.get('avg_bytes', 0)

        # ✅ Phase 1: 連續端口檢測特徵
        has_sequential = features.get('has_sequential_dst_ports', 0)

        confidence = 0.6  # 基礎置信度

        # ✅ 連續端口掃描是非常明顯的特徵
        if has_sequential == 1:
            confidence += 0.2  # 連續掃描（如 1-1024）

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

        # Port 相關特徵
        top_dst_port_concentration = features.get('top_dst_port_concentration', 0)
        dst_well_known_ratio = features.get('dst_well_known_ratio', 0)
        top_src_port_concentration = features.get('top_src_port_concentration', 0)

        confidence = 0.6

        # 掃描主機數量
        if unique_dsts > 100:
            confidence += 0.15
        elif unique_dsts > 70:
            confidence += 0.08

        # 目的地分散度
        if dst_diversity > 0.5:
            confidence += 0.1
        elif dst_diversity > 0.4:
            confidence += 0.05

        # 【新增】Port 特徵加成
        # 掃描常見服務端口（知名端口比例高）
        if dst_well_known_ratio > 0.8:
            confidence += 0.1
        elif dst_well_known_ratio > 0.6:
            confidence += 0.05

        # 目的端口集中在少數服務
        if top_dst_port_concentration > 0.5:
            confidence += 0.08

        # 來源端口高度隨機化（掃描器特徵）
        if top_src_port_concentration < 0.1:
            confidence += 0.06

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

        # ✅ Phase 1: 明確識別為已知服務器類型
        is_known_server = any([
            features.get('is_likely_web_server', 0) == 1,
            features.get('is_likely_dns_server', 0) == 1,
            features.get('is_likely_db_server', 0) == 1,
            features.get('is_likely_mail_server', 0) == 1
        ])

        if is_known_server:
            confidence += 0.25  # 明確的服務器類型識別，高置信度

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

    # ========== SRC 視角檢查快取方法 ==========

    def _round_time_bucket(self, time_bucket: str) -> str:
        """
        將時間桶捨入到 10 分鐘，用於快取 key
        例如: 2025-11-26T15:07:00.000Z -> 2025-11-26T15:00:00Z
        """
        try:
            if isinstance(time_bucket, str):
                dt = datetime.fromisoformat(time_bucket.replace('Z', '+00:00'))
            else:
                dt = time_bucket

            # 移除時區資訊
            if dt.tzinfo:
                dt = dt.replace(tzinfo=None)

            # 捨入到 10 分鐘
            rounded_minute = (dt.minute // 10) * 10
            rounded_dt = dt.replace(minute=rounded_minute, second=0, microsecond=0)
            return rounded_dt.strftime('%Y-%m-%dT%H:%M:00Z')
        except Exception:
            return time_bucket

    def _get_cache_key(self, dst_ip: str, time_bucket: str) -> str:
        """生成快取 key"""
        rounded_time = self._round_time_bucket(time_bucket)
        return f"{dst_ip}|{rounded_time}"

    def _check_src_cache(self, dst_ip: str, time_bucket: str) -> Optional[Dict]:
        """
        檢查快取中是否有此 IP 的 SRC 視角檢查結果

        Returns:
            快取的結果，如果未命中或已過期則返回 None
        """
        cache_key = self._get_cache_key(dst_ip, time_bucket)

        with self._src_check_cache_lock:
            if cache_key in self._src_check_cache:
                cached = self._src_check_cache[cache_key]
                age = (datetime.now() - cached['timestamp']).total_seconds()

                if age < self._src_check_cache_ttl:
                    # 快取命中且未過期
                    self._cache_stats['hits'] += 1
                    # 移到最後（LRU）
                    self._src_check_cache.move_to_end(cache_key)
                    return cached
                else:
                    # 快取已過期
                    self._cache_stats['expired'] += 1
                    del self._src_check_cache[cache_key]

            self._cache_stats['misses'] += 1
            return None

    def _update_src_cache(self, dst_ip: str, time_bucket: str, result: str,
                          src_features: Optional[Dict] = None):
        """
        更新快取

        Args:
            dst_ip: 目的地 IP
            time_bucket: 時間桶
            result: 檢查結果 ('SERVER_RESPONSE' | 'NOT_SERVER' | 'NO_DATA')
            src_features: SRC 視角的特徵資料（可選）
        """
        cache_key = self._get_cache_key(dst_ip, time_bucket)

        with self._src_check_cache_lock:
            # 如果快取已滿，移除最舊的項目
            while len(self._src_check_cache) >= self._src_check_cache_max_size:
                self._src_check_cache.popitem(last=False)

            self._src_check_cache[cache_key] = {
                'result': result,
                'src_features': src_features,
                'timestamp': datetime.now()
            }

    def get_cache_stats(self) -> Dict:
        """獲取快取統計資訊"""
        with self._src_check_cache_lock:
            total = self._cache_stats['hits'] + self._cache_stats['misses']
            hit_rate = self._cache_stats['hits'] / total if total > 0 else 0

            return {
                'hits': self._cache_stats['hits'],
                'misses': self._cache_stats['misses'],
                'expired': self._cache_stats['expired'],
                'hit_rate': f"{hit_rate:.1%}",
                'cache_size': len(self._src_check_cache),
                'max_size': self._src_check_cache_max_size,
                'ttl_seconds': self._src_check_cache_ttl
            }

    def clear_cache(self):
        """清除快取"""
        with self._src_check_cache_lock:
            self._src_check_cache.clear()
            self._cache_stats = {'hits': 0, 'misses': 0, 'expired': 0}
            self._last_logged_stats = {'hits': 0, 'misses': 0}

    def _maybe_log_cache_stats(self):
        """
        定期輸出快取統計到 log
        每隔 stats_log_interval 秒輸出一次
        """
        now = datetime.now()
        elapsed = (now - self._last_stats_log_time).total_seconds()

        if elapsed >= self._stats_log_interval:
            with self._src_check_cache_lock:
                total = self._cache_stats['hits'] + self._cache_stats['misses']
                hit_rate = self._cache_stats['hits'] / total if total > 0 else 0

                # 計算這個區間的增量
                interval_hits = self._cache_stats['hits'] - self._last_logged_stats['hits']
                interval_misses = self._cache_stats['misses'] - self._last_logged_stats['misses']
                interval_total = interval_hits + interval_misses
                interval_hit_rate = interval_hits / interval_total if interval_total > 0 else 0

                post_process_logger.info(
                    f"[CACHE_STATS] interval={int(elapsed)}s, "
                    f"interval_hits={interval_hits}, interval_misses={interval_misses}, "
                    f"interval_hit_rate={interval_hit_rate:.1%}, "
                    f"total_hits={self._cache_stats['hits']}, total_misses={self._cache_stats['misses']}, "
                    f"total_hit_rate={hit_rate:.1%}, cache_size={len(self._src_check_cache)}, "
                    f"expired={self._cache_stats['expired']}"
                )

                # 更新上次 log 的時間和數值
                self._last_stats_log_time = now
                self._last_logged_stats = {
                    'hits': self._cache_stats['hits'],
                    'misses': self._cache_stats['misses']
                }

    def _fetch_src_perspective(self, ip: str, time_bucket: str) -> Optional[Dict]:
        """
        從 ES 查詢 SRC 視角的資料

        當分析 DST 視角異常時，可以透過這個方法查詢同一 IP 的 SRC 視角資料，
        以判斷該 IP 是否實際上是一個伺服器正在回應客戶端請求。

        Args:
            ip: 目的地 IP（在 SRC 視角中就是 src_ip）
            time_bucket: 時間桶（ISO 格式）

        Returns:
            SRC 視角的特徵資料，如果查無資料則返回 None
        """
        try:
            # 解析時間桶，設定 ±6 分鐘的時間容錯
            if isinstance(time_bucket, str):
                bucket_time = datetime.fromisoformat(time_bucket.replace('Z', '+00:00'))
            else:
                bucket_time = time_bucket

            # 移除時區資訊以便計算
            if bucket_time.tzinfo:
                bucket_time = bucket_time.replace(tzinfo=None)

            time_start = (bucket_time - timedelta(minutes=6)).isoformat() + 'Z'
            time_end = (bucket_time + timedelta(minutes=6)).isoformat() + 'Z'

            # 查詢 SRC 視角資料
            query = {
                "size": 1,
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"src_ip": ip}},
                            {"range": {"time_bucket": {"gte": time_start, "lte": time_end}}}
                        ]
                    }
                },
                "sort": [{"time_bucket": {"order": "desc"}}]
            }

            url = f"{self.es_host}/netflow_stats_3m_by_src/_search"
            response = requests.post(
                url,
                json=query,
                headers={"Content-Type": "application/json"},
                timeout=5
            )

            if response.status_code != 200:
                return None

            result = response.json()
            hits = result.get('hits', {}).get('hits', [])

            if not hits:
                return None

            return hits[0].get('_source', {})

        except Exception as e:
            # 查詢失敗時靜默返回 None，不影響主流程
            return None

    def _is_server_response_traffic(self, dst_features: Dict, src_features: Dict) -> bool:
        """
        判斷 DST 視角的流量是否實際上是伺服器回應流量

        這個方法比對 DST 和 SRC 視角的特徵，識別以下模式：
        - SRC 視角：IP 作為客戶端，連接到知名服務埠（如 161, 53, 80）
        - DST 視角：同一 IP 收到大量不同埠的流量（這些是回應到客戶端的臨時埠）

        典型案例：
        - SNMP 伺服器：SRC 連到 port 161，DST 收到回應
        - DNS 伺服器：SRC 連到 port 53，DST 收到回應
        - Web 伺服器：SRC 連到 port 80/443，DST 收到回應

        Args:
            dst_features: DST 視角的特徵
            src_features: SRC 視角的特徵

        Returns:
            True 如果這是伺服器回應流量
        """
        # 臨時埠起始值（>32000 視為臨時埠）
        EPHEMERAL_PORT_START = 32000

        # 知名服務埠（擴展列表）
        well_known_service_ports = {
            161, 162,  # SNMP
            53,        # DNS
            80, 443, 8080, 8443,  # HTTP/HTTPS
            22,        # SSH
            23,        # Telnet
            25, 110, 143, 465, 587, 993, 995,  # Mail
            389, 636, 3268,  # LDAP/AD
            88,        # Kerberos
            3306,      # MySQL
            5432,      # PostgreSQL
            6379,      # Redis
            27017,     # MongoDB
            1514,      # Syslog/SIEM
            5601,      # Kibana
            9200, 9300,  # Elasticsearch
            5173,      # Vite dev server
            60022,     # Custom SSH
            445, 139,  # SMB
            123,       # NTP
        }

        # ===== 方法 1: 檢查 DST 視角的臨時埠比例 =====
        # 如果 DST 被訪問的埠大部分是臨時埠（>32000），說明這是伺服器回應流量
        dst_top_dst_ports = dst_features.get('top_dst_ports', {})
        if isinstance(dst_top_dst_ports, str):
            try:
                dst_top_dst_ports = json.loads(dst_top_dst_ports)
            except:
                dst_top_dst_ports = {}

        if dst_top_dst_ports:
            total_dst_flows = sum(dst_top_dst_ports.values())
            ephemeral_flows = sum(
                count for port, count in dst_top_dst_ports.items()
                if int(port) > EPHEMERAL_PORT_START
            )
            ephemeral_ratio = ephemeral_flows / total_dst_flows if total_dst_flows > 0 else 0

            # 如果 90% 以上的流量是到臨時埠，這是典型的伺服器回應流量
            if ephemeral_ratio > 0.9:
                post_process_logger.debug(
                    f"[SERVER_RESPONSE_CHECK] ephemeral_ratio={ephemeral_ratio:.2f} > 0.9, "
                    f"detected as server response by ephemeral port ratio"
                )
                return True

        # ===== 方法 2: 檢查 SRC 視角是否連到知名服務埠 =====
        src_top_dst_ports = src_features.get('top_dst_ports', {})
        if isinstance(src_top_dst_ports, str):
            try:
                src_top_dst_ports = json.loads(src_top_dst_ports)
            except:
                src_top_dst_ports = {}

        if not src_top_dst_ports:
            return False

        # 計算連到知名服務埠的比例
        total_flows = sum(src_top_dst_ports.values())
        well_known_flows = sum(
            count for port, count in src_top_dst_ports.items()
            if int(port) in well_known_service_ports
        )

        if total_flows == 0:
            return False

        well_known_ratio = well_known_flows / total_flows

        # 取得 DST 視角的特徵
        dst_unique_dst_ports = dst_features.get('unique_dst_ports', 0)
        dst_flow_count = dst_features.get('flow_count', 0)
        port_to_flow_ratio = dst_unique_dst_ports / max(dst_flow_count, 1)

        # 伺服器回應流量的特徵：
        # 1. SRC 視角主要連到知名服務埠（> 50%）
        # 2. DST 視角有大量不同的目的埠（這些是臨時埠）
        # 3. DST 視角的埠數量相對於連線數很高（每個連線用不同埠）
        is_server_response = (
            well_known_ratio > 0.5 and
            dst_unique_dst_ports > 20 and
            port_to_flow_ratio > 0.3
        )

        # 記錄判斷細節
        post_process_logger.debug(
            f"[SERVER_RESPONSE_CHECK] well_known_ratio={well_known_ratio:.2f}, "
            f"dst_unique_ports={dst_unique_dst_ports}, dst_flow_count={dst_flow_count}, "
            f"port_to_flow_ratio={port_to_flow_ratio:.2f}, is_server_response={is_server_response}"
        )

        return is_server_response

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

            # ✅ Phase 1: 連續端口檢測
            has_sequential = features.get('has_sequential_dst_ports', 0)

            indicators.append(f"掃描 {unique_dst_ports:,} 個不同埠")
            indicators.append(f"平均封包 {avg_bytes:,.0f} bytes（小封包）")
            indicators.append(f"埠分散度 {dst_port_diversity:.2f}（高度分散）")

            # ✅ 如果是連續掃描，添加明確指標
            if has_sequential == 1:
                indicators.append("檢測到連續端口掃描模式（如 1-1024）")

        elif class_name == 'NETWORK_SCAN':
            unique_dsts = features.get('unique_dsts', 0)
            flow_count = features.get('flow_count', 0)
            dst_well_known_ratio = features.get('dst_well_known_ratio', 0)
            top_dst_port_concentration = features.get('top_dst_port_concentration', 0)

            indicators.append(f"掃描 {unique_dsts} 個不同主機")
            indicators.append(f"總連線數 {flow_count:,}")

            # 添加 port 特徵指標
            if dst_well_known_ratio > 0.7:
                indicators.append(f"目標端口 {dst_well_known_ratio*100:.1f}% 為知名服務端口")
            if top_dst_port_concentration > 0.3:
                indicators.append(f"端口集中度 {top_dst_port_concentration*100:.1f}%（集中在少數常見服務）")

        elif class_name == 'DATA_EXFILTRATION':
            total_bytes = features.get('total_bytes', 0)
            unique_dsts = features.get('unique_dsts', 0)

            indicators.append(f"傳輸 {total_bytes/1e9:.2f} GB 數據")
            indicators.append(f"僅 {unique_dsts} 個目的地（高度集中）")

            dst_ips = context.get('dst_ips', [])
            external_ips = [ip for ip in dst_ips if not self._is_internal_ip(ip)]
            if external_ips:
                indicators.append(f"目標外部 IP: {', '.join(external_ips[:3])}")

            # ✅ Phase 2: 端口類型信息
            dst_registered_ratio = features.get('dst_registered_ratio', 0)
            dst_ephemeral_ratio = features.get('dst_ephemeral_ratio', 0)
            dst_well_known_ratio = features.get('dst_well_known_ratio', 0)
            if dst_registered_ratio > 0.5:
                indicators.append(f"使用註冊端口 {dst_registered_ratio*100:.1f}%（可能規避檢測）")
            elif dst_ephemeral_ratio > 0.3:
                indicators.append(f"使用臨時端口 {dst_ephemeral_ratio*100:.1f}%（非標準通訊）")
            if dst_well_known_ratio < 0.3:
                indicators.append("較少使用知名服務端口")

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

            # ✅ Phase 2: 端口類型信息
            dst_registered_ratio = features.get('dst_registered_ratio', 0)
            dst_ephemeral_ratio = features.get('dst_ephemeral_ratio', 0)
            if dst_registered_ratio > 0.5:
                indicators.append(f"使用註冊端口 {dst_registered_ratio*100:.1f}%（典型 C&C 通訊模式）")
            elif dst_ephemeral_ratio > 0.5:
                indicators.append(f"使用臨時端口 {dst_ephemeral_ratio*100:.1f}%（動態端口通訊）")

        elif class_name == 'NORMAL_HIGH_TRAFFIC':
            total_bytes = features.get('total_bytes', 0)
            indicators.append(f"大流量: {total_bytes/1e9:.2f} GB")

            dst_ips = context.get('dst_ips', [])
            if dst_ips and all(self._is_internal_ip(ip) for ip in dst_ips):
                indicators.append("所有目標均為內網 IP")

            if features.get('is_likely_server_response', 0) == 1:
                indicators.append("可能是服務器回應流量")

            # ✅ Phase 1: Server 角色識別
            server_types = []
            if features.get('is_likely_web_server', 0) == 1:
                server_types.append('Web Server')
            if features.get('is_likely_dns_server', 0) == 1:
                server_types.append('DNS Server')
            if features.get('is_likely_db_server', 0) == 1:
                server_types.append('Database Server')
            if features.get('is_likely_mail_server', 0) == 1:
                server_types.append('Mail Server')

            if server_types:
                indicators.append(f"識別為: {', '.join(server_types)}")

            # ✅ Phase 2: 端口類型信息（服務器回應模式）
            dst_ephemeral_ratio = features.get('dst_ephemeral_ratio', 0)
            if dst_ephemeral_ratio > 0.8:
                indicators.append(f"回應到臨時端口 {dst_ephemeral_ratio*100:.1f}%（典型服務器回應模式）")

        elif class_name == 'SCAN_RESPONSE':
            unique_srcs = features.get('unique_srcs', 0)
            unique_dst_ports = features.get('unique_dst_ports', 0)
            flows_per_src = features.get('flows_per_src', 0)

            indicators.append(f"{unique_srcs:,} 個不同來源 IP 回應")
            indicators.append(f"使用 {unique_dst_ports:,} 個不同本地端口")
            indicators.append(f"每個來源平均 {flows_per_src:.1f} 個連線（掃描回應特徵）")

        # ===== DST 視角威脅類型 =====
        elif class_name == 'DDOS_TARGET':
            unique_srcs = features.get('unique_srcs', 0)
            flow_count = features.get('flow_count', 0)
            avg_bytes = features.get('avg_bytes', 0)

            indicators.append(f"遭受 {unique_srcs:,} 個不同來源 IP 攻擊")
            indicators.append(f"總連線數 {flow_count:,}")
            indicators.append(f"平均封包 {avg_bytes:.0f} bytes（小封包攻擊）")

        elif class_name == 'SCAN_TARGET':
            unique_src_ports = features.get('unique_src_ports', 0)
            unique_dst_ports = features.get('unique_dst_ports', 0)

            indicators.append(f"被掃描 {unique_dst_ports:,} 個不同端口")
            indicators.append(f"來源使用 {unique_src_ports:,} 個不同端口（隨機化）")

        elif class_name == 'DATA_SINK':
            unique_srcs = features.get('unique_srcs', 0)
            total_bytes = features.get('total_bytes', 0)

            indicators.append(f"{unique_srcs:,} 個內部 IP 傳輸數據到此")
            indicators.append(f"總流量 {total_bytes/1e6:.2f} MB")

        elif class_name == 'MALWARE_DISTRIBUTION':
            unique_srcs = features.get('unique_srcs', 0)
            total_bytes = features.get('total_bytes', 0)
            flows_per_src = features.get('flows_per_src', 0)

            indicators.append(f"{unique_srcs:,} 個內部 IP 下載數據")
            indicators.append(f"總流量 {total_bytes/1e6:.2f} MB")
            indicators.append(f"每個來源平均 {flows_per_src:.1f} 個連線（下載後斷開）")

        elif class_name == 'POPULAR_SERVER':
            unique_srcs = features.get('unique_srcs', 0)
            avg_bytes = features.get('avg_bytes', 0)

            indicators.append(f"{unique_srcs:,} 個內部 IP 訪問此服務")
            indicators.append(f"平均封包 {avg_bytes:.0f} bytes（正常服務流量）")

        elif class_name == 'NORMAL_DST_TRAFFIC':
            unique_srcs = features.get('unique_srcs', 0)
            flow_count = features.get('flow_count', 0)
            avg_bytes = features.get('avg_bytes', 0)
            unique_dst_ports = features.get('unique_dst_ports', 0)
            dst_ip = context.get('dst_ip', '')

            indicators.append(f"僅 {unique_srcs} 個來源 IP（正常點對點通訊）")
            indicators.append(f"連線數 {flow_count}（適中）")
            indicators.append(f"平均封包 {avg_bytes:.0f} bytes（正常大小）")
            if unique_dst_ports > 1:
                indicators.append(f"使用 {unique_dst_ports} 個服務埠")
            if self._is_internal_ip(dst_ip):
                indicators.append("內部 IP 之間的正常通訊")

        elif class_name == 'SERVER_RESPONSE_TRAFFIC':
            unique_dst_ports = features.get('unique_dst_ports', 0)
            unique_srcs = features.get('unique_srcs', 0)
            flow_count = features.get('flow_count', 0)
            dst_ip = context.get('dst_ip', '')

            # 從 context 取得 SRC 視角資料
            src_perspective = context.get('src_perspective', {})
            src_top_dst_ports = src_perspective.get('top_dst_ports', {})
            if isinstance(src_top_dst_ports, str):
                try:
                    src_top_dst_ports = json.loads(src_top_dst_ports)
                except:
                    src_top_dst_ports = {}

            # 找出主要服務埠
            if src_top_dst_ports:
                sorted_ports = sorted(src_top_dst_ports.items(), key=lambda x: x[1], reverse=True)
                top_ports = [p[0] for p in sorted_ports[:3]]
                indicators.append(f"SRC 視角主要連到埠: {', '.join(map(str, top_ports))}")

            indicators.append(f"DST 視角顯示 {unique_dst_ports} 個不同埠（客戶端臨時埠）")
            indicators.append(f"來源 IP 數: {unique_srcs}，連線數: {flow_count}")
            indicators.append("跨視角分析確認：這是伺服器回應到客戶端的正常流量")

            if self._is_internal_ip(dst_ip):
                indicators.append(f"內部伺服器: {dst_ip}")

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
                - timestamp / time_bucket: 時間戳

        Returns:
            分類結果字典
        """
        if context is None:
            context = {}

        dst_ip = context.get('dst_ip', 'unknown')
        time_bucket = context.get('time_bucket') or context.get('timestamp')

        # 定期輸出快取統計
        self._maybe_log_cache_stats()

        # ========== 跨視角查詢：排除伺服器回應流量誤判 ==========
        # 當 DST 視角顯示大量不同埠時，可能是：
        # 1. 被掃描（真正的威脅）
        # 2. 伺服器回應到客戶端的臨時埠（正常流量）
        # 透過查詢 SRC 視角來區分這兩種情況
        unique_dst_ports = features.get('unique_dst_ports', 0)
        unique_srcs = features.get('unique_srcs', 0)
        flow_count = features.get('flow_count', 0)

        if unique_dst_ports > 20 and dst_ip != 'unknown' and time_bucket:
            # ===== 先檢查快取 =====
            cached_result = self._check_src_cache(dst_ip, time_bucket)

            if cached_result:
                # 快取命中
                cache_result_type = cached_result['result']
                post_process_logger.info(
                    f"[CACHE_HIT] dst_ip={dst_ip}, result={cache_result_type}, "
                    f"unique_dst_ports={unique_dst_ports}"
                )

                if cache_result_type == 'SERVER_RESPONSE':
                    # 從快取中取得 src_features
                    context['src_perspective'] = cached_result.get('src_features', {})
                    return self._create_classification('SERVER_RESPONSE_TRAFFIC', 0.90, features, context)
                # 如果是 'NOT_SERVER' 或 'NO_DATA'，繼續後續分類邏輯

            else:
                # 快取未命中，執行實際查詢
                post_process_logger.info(
                    f"[SRC_CHECK_TRIGGERED] dst_ip={dst_ip}, unique_dst_ports={unique_dst_ports}, "
                    f"unique_srcs={unique_srcs}, flow_count={flow_count}, time_bucket={time_bucket}"
                )

                src_features = self._fetch_src_perspective(dst_ip, time_bucket)

                if src_features:
                    # 記錄找到 SRC 視角資料
                    src_unique_dsts = src_features.get('unique_dsts', 0)
                    src_flow_count = src_features.get('flow_count', 0)
                    src_top_dst_ports = src_features.get('top_dst_ports', {})
                    post_process_logger.info(
                        f"[SRC_DATA_FOUND] dst_ip={dst_ip}, src_unique_dsts={src_unique_dsts}, "
                        f"src_flow_count={src_flow_count}, src_top_dst_ports={src_top_dst_ports}"
                    )

                    # 檢查是否為伺服器回應流量
                    if self._is_server_response_traffic(features, src_features):
                        # 更新快取
                        self._update_src_cache(dst_ip, time_bucket, 'SERVER_RESPONSE', src_features)

                        # 補充 context 供生成 indicators 使用
                        context['src_perspective'] = src_features
                        post_process_logger.info(
                            f"[FALSE_POSITIVE_EXCLUDED] dst_ip={dst_ip}, reason=SERVER_RESPONSE_TRAFFIC, "
                            f"dst_unique_ports={unique_dst_ports}, src_unique_dsts={src_unique_dsts}"
                        )
                        return self._create_classification('SERVER_RESPONSE_TRAFFIC', 0.90, features, context)
                    else:
                        # 更新快取（非伺服器回應）
                        self._update_src_cache(dst_ip, time_bucket, 'NOT_SERVER', src_features)
                        post_process_logger.info(
                            f"[SRC_CHECK_NOT_EXCLUDED] dst_ip={dst_ip}, reason=NOT_SERVER_RESPONSE, "
                            f"will_continue_to_classify"
                        )
                else:
                    # 更新快取（無資料）
                    self._update_src_cache(dst_ip, time_bucket, 'NO_DATA')
                    post_process_logger.info(
                        f"[SRC_DATA_NOT_FOUND] dst_ip={dst_ip}, no_src_perspective_data"
                    )

        # ========== 原有分類邏輯 ==========

        # 1. 掃描回應流量（優先判斷，避免誤判為 DDoS）
        if self._is_scan_response(features, context):
            return self._create_classification('SCAN_RESPONSE', 0.90, features, context)

        # 2. DDoS 攻擊目標
        if self._is_ddos_target(features, context):
            return self._create_classification('DDOS_TARGET', 0.95, features, context)

        # 3. 掃描目標
        if self._is_scan_target(features, context):
            return self._create_classification('SCAN_TARGET', 0.90, features, context)

        # 4. 資料外洩目標端
        if self._is_data_sink(features, context):
            return self._create_classification('DATA_SINK', 0.85, features, context)

        # 5. 惡意軟體分發服務器
        if self._is_malware_distribution(features, context):
            return self._create_classification('MALWARE_DISTRIBUTION', 0.80, features, context)

        # 6. 熱門服務器（內部服務）
        if self._is_popular_server(features, context):
            return self._create_classification('POPULAR_SERVER', 0.70, features, context)

        # 7. 正常 DST 流量（少量來源的點對點通訊）
        if self._is_normal_dst_traffic(features, context):
            return self._create_classification('NORMAL_DST_TRAFFIC', 0.85, features, context)

        # 8. 未知 dst 異常
        return self._create_classification('UNKNOWN', 0.50, features, context)

    def _is_scan_response(self, features: Dict, context: Dict) -> bool:
        """判斷是否為掃描回應流量"""
        unique_srcs = features.get('unique_srcs', 0)
        unique_dst_ports = features.get('unique_dst_ports', 0)
        flows_per_src = features.get('flows_per_src', 1)
        avg_bytes = features.get('avg_bytes', 0)

        # 掃描回應流量特徵：
        # 1. 大量不同來源 IP（被掃描的主機回應）
        # 2. 大量不同的本地端口（掃描器隨機分配的本地端口）
        # 3. 每個來源僅少量連線（通常 1-3 個，因為是掃描探測回應）
        # 4. 小封包（探測回應）
        return (
            unique_srcs > 50 and
            unique_dst_ports > 100 and
            flows_per_src < 5 and
            avg_bytes < 2000
        )

    def _is_ddos_target(self, features: Dict, context: Dict) -> bool:
        """判斷是否為 DDoS 攻擊目標"""
        unique_srcs = features.get('unique_srcs', 0)
        flow_count = features.get('flow_count', 0)
        avg_bytes = features.get('avg_bytes', 0)
        unique_dst_ports = features.get('unique_dst_ports', 0)
        flows_per_src = features.get('flows_per_src', 1)

        # 從配置讀取閾值
        config = self.dst_thresholds.get('DDOS_TARGET', {})
        if not config.get('enabled', True):
            return False

        thresholds = config.get('thresholds', {})
        threshold_srcs = thresholds.get('unique_srcs', 100)
        threshold_flows = thresholds.get('flow_count', 1000)
        threshold_bytes = thresholds.get('avg_bytes', 500)

        # ⚠️ 排除掃描回應流量：
        # 如果有大量不同的目標端口 (> 100) 且每個來源平均連線少 (< 5)
        # 這是掃描後的回應流量，不是 DDoS
        is_scan_response = (unique_dst_ports > 100 and flows_per_src < 5)

        if is_scan_response:
            return False

        # DDoS 特徵：
        # 1. 大量不同來源
        # 2. 極高連線數
        # 3. 小封包 - SYN flood 特徵
        # 4. 不是掃描回應流量
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

    def _is_normal_dst_traffic(self, features: Dict, context: Dict) -> bool:
        """
        【新增】判斷是否為正常的 DST 流量（少量來源的點對點通訊）

        這個類型用來減少誤報，識別以下情況：
        - 只有 1-3 個來源 IP 連到這個目的地
        - 封包大小正常（不是 DDoS 小封包，也不是超大異常封包）
        - 連線數適中（不是掃描，也不是攻擊）
        - 內部 IP 之間的正常通訊

        典型案例：
        - SSH/RDP 遠端連線
        - 應用程式服務
        - 資料庫連線
        - 檔案共享
        """
        unique_srcs = features.get('unique_srcs', 0)
        avg_bytes = features.get('avg_bytes', 0)
        flow_count = features.get('flow_count', 0)
        unique_dst_ports = features.get('unique_dst_ports', 0)
        dst_ip = context.get('dst_ip', '')

        # 從配置讀取閾值（如果有的話）
        config = self.dst_thresholds.get('NORMAL_DST_TRAFFIC', {})
        thresholds = config.get('thresholds', {})

        threshold_srcs_max = thresholds.get('unique_srcs_max', 3)
        threshold_bytes_min = thresholds.get('avg_bytes_min', 500)
        threshold_bytes_max = thresholds.get('avg_bytes_max', 100000)
        threshold_flows_max = thresholds.get('flow_count_max', 100)
        threshold_ports_max = thresholds.get('unique_dst_ports_max', 10)

        # 正常 DST 流量特徵：
        # 1. 少量來源（1-3 個）- 不是 DDoS 或分散式攻擊
        # 2. 正常封包大小（500 bytes - 100 KB）- 排除掃描小封包和異常大封包
        # 3. 適中連線數（< 100）- 不是攻擊或掃描
        # 4. 少量服務埠（< 10）- 正常服務使用模式
        # 5. 內部 IP - 內網正常通訊
        return (
            1 <= unique_srcs <= threshold_srcs_max and
            threshold_bytes_min < avg_bytes < threshold_bytes_max and
            flow_count < threshold_flows_max and
            unique_dst_ports < threshold_ports_max and
            self._is_internal_ip(dst_ip)
        )
