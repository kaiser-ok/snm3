#!/usr/bin/env python3
"""
異常驗證分析工具

深入分析 Isolation Forest 檢測出的異常 IP，
查詢原始 netflow 數據，判斷是否為真正的異常行為。
"""

import sys
import json
import math
import argparse
import warnings
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from elasticsearch import Elasticsearch
from nad.utils.config_loader import load_config

# 關閉 Elasticsearch 安全警告
warnings.filterwarnings('ignore', message='.*Elasticsearch built-in security features are not enabled.*')

# MySQL 支援（可選）
try:
    import pymysql
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False


class AnomalyVerifier:
    """異常驗證器"""

    def __init__(self, es_client, config):
        self.es = es_client
        self.config = config
        self.netflow_index = config.get('elasticsearch', {}).get('indices', {}).get('raw', 'radar_flow_collector-*')

        # 初始化 MySQL 連線（可選）
        self.mysql_conn = None
        self.mysql_connected = False  # MySQL 連線狀態
        self.ip_name_cache = {}  # IP 名稱快取
        self._init_mysql_connection()

    def _init_mysql_connection(self):
        """初始化 MySQL 連線（如果可用且配置正確）"""
        if not MYSQL_AVAILABLE:
            self.mysql_connected = False
            return

        mysql_config = self.config.get('mysql', {})
        if not mysql_config:
            self.mysql_connected = False
            return

        try:
            self.mysql_conn = pymysql.connect(
                host=mysql_config.get('host', 'localhost'),
                port=mysql_config.get('port', 3306),
                user=mysql_config.get('user'),
                password=mysql_config.get('password'),
                database=mysql_config.get('database'),
                connect_timeout=3
            )
            # 測試連線
            with self.mysql_conn.cursor() as cursor:
                cursor.execute("SELECT 1")
            self.mysql_connected = True
        except Exception as e:
            # 連線失敗時靜默處理，不影響主要功能
            self.mysql_conn = None
            self.mysql_connected = False

    def _get_ip_name(self, ip):
        """
        從 MySQL 查詢 IP 對應的設備名稱

        Args:
            ip: IP 地址

        Returns:
            設備名稱，如果找不到則返回 None
        """
        # 檢查快取
        if ip in self.ip_name_cache:
            return self.ip_name_cache[ip]

        # 如果 MySQL 不可用，直接返回
        if not self.mysql_conn:
            self.ip_name_cache[ip] = None
            return None

        try:
            with self.mysql_conn.cursor() as cursor:
                # 先查詢 Device 表
                cursor.execute(
                    "SELECT Name FROM Device WHERE IP = %s LIMIT 1",
                    (ip,)
                )
                result = cursor.fetchone()
                if result and result[0]:
                    name = result[0].strip()
                    self.ip_name_cache[ip] = name
                    return name

                # 再查詢 ip_alias 表
                cursor.execute(
                    "SELECT alias FROM ip_alias WHERE ip = %s LIMIT 1",
                    (ip,)
                )
                result = cursor.fetchone()
                if result and result[0]:
                    name = result[0].strip()
                    self.ip_name_cache[ip] = name
                    return name

            # 沒找到
            self.ip_name_cache[ip] = None
            return None

        except Exception:
            # 查詢失敗時靜默處理
            self.ip_name_cache[ip] = None
            return None

    def _format_ip_with_name(self, ip):
        """
        格式化 IP 顯示（如果有設備名稱則附加）

        Args:
            ip: IP 地址

        Returns:
            格式化的字串，例如 "192.168.1.1 (Web Server)"
        """
        name = self._get_ip_name(ip)
        if name:
            return f"{ip} ({name})"
        return ip

    def verify_ip(self, src_ip, time_range_minutes=30):
        """
        深入分析單個異常 IP（雙向完整分析）

        Args:
            src_ip: 要分析的 IP 地址
            time_range_minutes: 分析時間範圍（分鐘）

        Returns:
            分析報告字典（包含雙向分析結果）
        """
        print(f"\n{'='*100}")
        print(f"🔍 深入分析: {src_ip}")
        print(f"{'='*100}\n")

        # 查詢作為源 IP 的流量
        flows_as_src = self._fetch_netflow_data(src_ip, time_range_minutes, role='src')
        # 查詢作為目的地的流量
        flows_as_dst = self._fetch_netflow_data(src_ip, time_range_minutes, role='dst')

        print(f"📊 作為源 IP: {len(flows_as_src):,} 筆記錄")
        print(f"📊 作為目的地: {len(flows_as_dst):,} 筆記錄\n")

        if not flows_as_src and not flows_as_dst:
            print(f"⚠️  沒有找到 {src_ip} 的 netflow 數據")
            return None

        # 雙向分析：分析兩個方向
        analysis_result = {
            'target_ip': src_ip,
            'time_range_minutes': time_range_minutes,
            'as_source': None,
            'as_destination': None,
        }

        # 分析作為源 IP 的情況
        if flows_as_src:
            print(f"📊 分析作為源 IP 的 {len(flows_as_src):,} 筆記錄...\n")
            analysis_result['as_source'] = {
                'role': 'src',
                'total_flows': len(flows_as_src),
                'basic_stats': self._analyze_basic_stats(flows_as_src),
                'destination_analysis': self._analyze_destinations(flows_as_src, 'src'),
                'port_analysis': self._analyze_ports(flows_as_src, 'src'),
                'protocol_analysis': self._analyze_protocols(flows_as_src),
                'temporal_analysis': self._analyze_temporal_pattern(flows_as_src),
                'traffic_analysis': self._analyze_traffic_pattern(flows_as_src),
                'behavioral_analysis': self._analyze_behavior(flows_as_src, 'src'),
            }

        # 分析作為目的地 IP 的情況
        if flows_as_dst:
            print(f"📊 分析作為目的地 IP 的 {len(flows_as_dst):,} 筆記錄...\n")
            analysis_result['as_destination'] = {
                'role': 'dst',
                'total_flows': len(flows_as_dst),
                'basic_stats': self._analyze_basic_stats(flows_as_dst),
                'destination_analysis': self._analyze_destinations(flows_as_dst, 'dst'),
                'port_analysis': self._analyze_ports(flows_as_dst, 'dst'),
                'protocol_analysis': self._analyze_protocols(flows_as_dst),
                'temporal_analysis': self._analyze_temporal_pattern(flows_as_dst),
                'traffic_analysis': self._analyze_traffic_pattern(flows_as_dst),
                'behavioral_analysis': self._analyze_behavior(flows_as_dst, 'dst'),
            }

        # 生成綜合判斷
        analysis_result['verdict'] = self._generate_bidirectional_verdict(analysis_result)

        # 顯示雙向報告
        self._print_bidirectional_report(analysis_result)

        return analysis_result

    def _fetch_netflow_data(self, ip, minutes, role='src'):
        """
        查詢原始 netflow 數據（使用 scroll API 獲取所有記錄）

        Args:
            ip: IP 地址
            minutes: 時間範圍（分鐘）
            role: 'src' 或 'dst'，指定查詢源 IP 還是目的 IP
        """
        # 支持 IPv4 和 IPv6
        if role == 'src':
            query = {
                "size": 10000,  # 每批次取 10000 筆
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"IPV4_SRC_ADDR": ip}},
                            {"term": {"IPV6_SRC_ADDR": ip}},
                        ],
                        "minimum_should_match": 1,
                        "filter": [
                            {"range": {"FLOW_START_MILLISECONDS": {
                                "gte": f"now-{minutes}m",
                                "lte": "now+1m"  # 避免未來時間戳（2106年的錯誤數據）
                            }}}
                        ]
                    }
                },
                "sort": [{"FLOW_START_MILLISECONDS": "desc"}]
            }
        else:  # dst
            query = {
                "size": 10000,
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"IPV4_DST_ADDR": ip}},
                            {"term": {"IPV6_DST_ADDR": ip}},
                        ],
                        "minimum_should_match": 1,
                        "filter": [
                            {"range": {"FLOW_START_MILLISECONDS": {
                                "gte": f"now-{minutes}m",
                                "lte": "now+1m"  # 避免未來時間戳
                            }}}
                        ]
                    }
                },
                "sort": [{"FLOW_START_MILLISECONDS": "desc"}]
            }

        try:
            # 使用 scroll API 獲取所有數據
            flows_raw = []

            # 初始查詢
            response = self.es.search(index=self.netflow_index, scroll='5m', **query)
            scroll_id = response.get('_scroll_id')
            hits = response['hits']['hits']
            flows_raw.extend([hit['_source'] for hit in hits])

            # 繼續滾動獲取
            while len(hits) > 0:
                response = self.es.scroll(scroll_id=scroll_id, scroll='5m')
                scroll_id = response.get('_scroll_id')
                hits = response['hits']['hits']
                flows_raw.extend([hit['_source'] for hit in hits])

                # 進度提示（每10000筆顯示一次）
                if len(flows_raw) % 10000 == 0 and len(hits) > 0:
                    print(f"   已載入 {len(flows_raw):,} 筆記錄...")

            # 清理 scroll
            if scroll_id:
                try:
                    self.es.clear_scroll(scroll_id=scroll_id)
                except:
                    pass

            # 標準化欄位名稱，方便後續處理
            flows = []
            for f in flows_raw:
                normalized = {
                    'src_ip': f.get('IPV4_SRC_ADDR') or f.get('IPV6_SRC_ADDR'),
                    'dst_ip': f.get('IPV4_DST_ADDR') or f.get('IPV6_DST_ADDR'),
                    'src_port': f.get('L4_SRC_PORT', 0),
                    'dst_port': f.get('L4_DST_PORT', 0),
                    'protocol': f.get('PROTOCOL', 0),
                    'in_bytes': f.get('IN_BYTES', 0),
                    'out_bytes': 0,  # 原始數據沒有 out_bytes
                    'in_pkts': f.get('IN_PKTS', 0),
                    'out_pkts': 0,  # 原始數據沒有 out_pkts
                    '@timestamp': f.get('FLOW_START_MILLISECONDS'),
                    'timestamp': f.get('FLOW_START_MILLISECONDS'),
                }
                flows.append(normalized)

            return flows
        except Exception as e:
            print(f"❌ 查詢失敗: {e}")
            import traceback
            traceback.print_exc()
            return []

    def _analyze_basic_stats(self, flows):
        """基本統計"""
        total_bytes = sum(f.get('in_bytes', 0) + f.get('out_bytes', 0) for f in flows)
        total_packets = sum(f.get('in_pkts', 0) + f.get('out_pkts', 0) for f in flows)

        return {
            'total_flows': len(flows),
            'total_bytes': total_bytes,
            'total_packets': total_packets,
            'avg_bytes_per_flow': total_bytes / len(flows) if flows else 0,
            'avg_packets_per_flow': total_packets / len(flows) if flows else 0,
        }

    def _analyze_destinations(self, flows, role='src'):
        """
        目的地分析（根據角色動態調整）

        Args:
            flows: 流量記錄列表
            role: 'src' 表示分析目的地，'dst' 表示分析來源
        """
        # 根據角色選擇要分析的 IP 欄位
        if role == 'src':
            # IP 作為源：分析它連到哪些目的地
            target_ips = [f['dst_ip'] for f in flows if 'dst_ip' in f]
            label = 'destinations'
        else:  # role == 'dst'
            # IP 作為目的地：分析誰連到它（來源分析）
            target_ips = [f['src_ip'] for f in flows if 'src_ip' in f]
            label = 'sources'

        target_counter = Counter(target_ips)
        unique_targets = len(target_counter)

        # 找出最常見的目標（顯示所有，最多50個）
        top_targets = target_counter.most_common(50)

        # 計算分布熵（衡量多樣性）
        total = len(target_ips)
        entropy = 0
        if total > 0:
            for count in target_counter.values():
                p = count / total
                entropy -= p * (math.log(p) if p > 0 else 0)

        return {
            'role': role,
            'label': label,
            'unique_destinations': unique_targets,
            'total_connections': len(target_ips),
            'dst_diversity_ratio': unique_targets / len(target_ips) if target_ips else 0,
            'top_destinations': [{'ip': ip, 'count': count, 'percentage': count/total*100}
                                for ip, count in top_targets],
            'is_highly_distributed': unique_targets > 50,  # 高度分散
            'is_concentrated': unique_targets < 5 and len(target_ips) > 100,  # 高度集中
        }

    def _analyze_ports(self, flows, role='src'):
        """
        通訊埠分析（根據角色動態調整）

        Args:
            flows: 流量記錄列表
            role: 'src' 表示分析目的埠，'dst' 表示分析來源埠
        """
        # 根據角色選擇要分析的通訊埠欄位
        if role == 'src':
            # IP 作為源：分析目的通訊埠
            target_ports = [f['dst_port'] for f in flows if 'dst_port' in f and f['dst_port'] > 0]
            label = 'destination_ports'
        else:  # role == 'dst'
            # IP 作為目的地：分析來源通訊埠
            target_ports = [f['src_port'] for f in flows if 'src_port' in f and f['src_port'] > 0]
            label = 'source_ports'

        port_counter = Counter(target_ports)
        unique_ports = len(port_counter)

        # 分類常見通訊埠
        well_known_ports = {
            80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 22: 'SSH',
            25: 'SMTP', 3389: 'RDP', 21: 'FTP', 23: 'Telnet',
            445: 'SMB', 3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis'
        }

        port_distribution = defaultdict(int)
        for port in target_ports:
            if port < 1024:
                port_distribution['well_known'] += 1
            elif port < 49152:
                port_distribution['registered'] += 1
            else:
                port_distribution['dynamic'] += 1

        top_ports = port_counter.most_common(10)

        # 檢測掃描模式
        is_scanning = unique_ports > 20 and len(target_ports) > 100
        is_sequential_scan = self._check_sequential_ports(list(port_counter.keys()))

        return {
            'role': role,
            'label': label,
            'unique_ports': unique_ports,
            'total_connections': len(target_ports),
            'port_diversity_ratio': unique_ports / len(target_ports) if target_ports else 0,
            'top_ports': [{'port': port,
                          'service': well_known_ports.get(port, 'Unknown'),
                          'count': count,
                          'percentage': count/len(target_ports)*100}
                         for port, count in top_ports],
            'port_distribution': dict(port_distribution),
            'is_scanning': is_scanning,
            'is_sequential_scan': is_sequential_scan,
        }

    def _check_sequential_ports(self, ports):
        """檢查是否為連續通訊埠掃描"""
        if len(ports) < 10:
            return False

        sorted_ports = sorted(ports)
        sequential_count = 0

        for i in range(len(sorted_ports) - 1):
            if sorted_ports[i+1] - sorted_ports[i] == 1:
                sequential_count += 1

        return sequential_count / len(sorted_ports) > 0.3  # 30% 以上連續

    def _analyze_protocols(self, flows):
        """協定分析"""
        protocols = [f.get('protocol', 0) for f in flows]
        proto_counter = Counter(protocols)

        proto_names = {
            1: 'ICMP', 6: 'TCP', 17: 'UDP'
        }

        proto_distribution = [
            {
                'protocol': proto_names.get(proto, f'Unknown({proto})'),
                'count': count,
                'percentage': count/len(protocols)*100
            }
            for proto, count in proto_counter.most_common()
        ]

        return {
            'protocol_distribution': proto_distribution,
            'is_icmp_heavy': proto_counter.get(1, 0) / len(protocols) > 0.5 if protocols else False,
            'is_udp_heavy': proto_counter.get(17, 0) / len(protocols) > 0.5 if protocols else False,
        }

    def _analyze_temporal_pattern(self, flows):
        """時間模式分析"""
        timestamps = []
        for f in flows:
            ts = f.get('@timestamp', f.get('timestamp', ''))
            if ts:
                try:
                    # 如果是毫秒時間戳（數字）
                    if isinstance(ts, (int, float)):
                        ts_dt = datetime.fromtimestamp(ts / 1000.0)
                    else:
                        # 如果是 ISO 字串
                        ts_dt = datetime.fromisoformat(str(ts).replace('Z', '+00:00'))
                    timestamps.append(ts_dt)
                except:
                    continue

        if len(timestamps) < 2:
            return {'insufficient_data': True}

        timestamps.sort()

        # 計算時間間隔
        intervals = [(timestamps[i+1] - timestamps[i]).total_seconds()
                    for i in range(len(timestamps) - 1)]

        avg_interval = sum(intervals) / len(intervals) if intervals else 0

        # 檢測突發流量
        burst_threshold = 1  # 1 秒內
        burst_count = sum(1 for interval in intervals if interval < burst_threshold)
        burst_ratio = burst_count / len(intervals) if intervals else 0

        return {
            'time_span_seconds': (timestamps[-1] - timestamps[0]).total_seconds(),
            'average_interval_seconds': avg_interval,
            'is_burst_traffic': burst_ratio > 0.5,
            'is_periodic': self._check_periodicity(intervals),
        }

    def _check_periodicity(self, intervals):
        """檢查是否為週期性流量"""
        if len(intervals) < 10:
            return False

        # 簡單的週期性檢測：看間隔的標準差
        import numpy as np
        std = np.std(intervals)
        mean = np.mean(intervals)

        # 如果標準差很小，表示很規律
        cv = std / mean if mean > 0 else float('inf')
        return cv < 0.3  # 變異係數 < 0.3 表示週期性

    def _analyze_traffic_pattern(self, flows):
        """流量模式分析"""
        bytes_list = [f.get('in_bytes', 0) + f.get('out_bytes', 0) for f in flows]
        packets_list = [f.get('in_pkts', 0) + f.get('out_pkts', 0) for f in flows]

        if not bytes_list:
            return {'insufficient_data': True}

        import numpy as np

        return {
            'mean_bytes': np.mean(bytes_list),
            'std_bytes': np.std(bytes_list),
            'max_bytes': np.max(bytes_list),
            'min_bytes': np.min(bytes_list),
            'median_bytes': np.median(bytes_list),
            'bytes_cv': np.std(bytes_list) / np.mean(bytes_list) if np.mean(bytes_list) > 0 else 0,
            'is_uniform_size': np.std(bytes_list) / np.mean(bytes_list) < 0.3 if np.mean(bytes_list) > 0 else False,
        }

    def _analyze_behavior(self, flows, role='src'):
        """
        行為分析（根據角色動態調整）

        Args:
            flows: 流量記錄列表
            role: 'src' 或 'dst'
        """
        dst_analysis = self._analyze_destinations(flows, role)
        port_analysis = self._analyze_ports(flows, role)
        proto_analysis = self._analyze_protocols(flows)
        traffic_analysis = self._analyze_traffic_pattern(flows)

        behaviors = []

        # 檢查是否為常見服務回應流量（只在作為源時檢查）
        if role == 'src':
            src_ports = [f.get('src_port', f.get('dst_port', 0)) for f in flows if 'src_port' in f or 'dst_port' in f]
            src_port_counter = Counter(src_ports)
            most_common_src_port = src_port_counter.most_common(1)[0] if src_port_counter else (0, 0)

            # DNS 服務器回應（源通訊埠 53，目的通訊埠多樣化是正常的）
            if most_common_src_port[0] == 53 and most_common_src_port[1] > len(flows) * 0.8:
                behaviors.append({
                    'type': 'DNS_SERVER_RESPONSE',
                    'severity': 'LOW',
                    'description': f"DNS 伺服器回應流量（源通訊埠 53）",
                    'evidence': {
                        'dns_responses': most_common_src_port[1],
                        'percentage': most_common_src_port[1] / len(flows) * 100
                    }
                })
                # DNS 服務器不應該被標記為通訊埠掃描
                return behaviors

            # Web 服務器回應（源通訊埠 80/443）
            if most_common_src_port[0] in [80, 443] and most_common_src_port[1] > len(flows) * 0.5:
                behaviors.append({
                    'type': 'WEB_SERVER_RESPONSE',
                    'severity': 'LOW',
                    'description': f"Web 伺服器回應流量（源通訊埠 {most_common_src_port[0]}）",
                    'evidence': {
                        'responses': most_common_src_port[1],
                        'percentage': most_common_src_port[1] / len(flows) * 100
                    }
                })
                return behaviors

        # 掃描行為檢測
        if port_analysis['is_scanning'] or port_analysis['is_sequential_scan']:
            if role == 'src':
                behaviors.append({
                    'type': 'PORT_SCANNING',
                    'severity': 'HIGH',
                    'description': f"檢測到通訊埠掃描：{port_analysis['unique_ports']} 個不同目的埠",
                    'evidence': {
                        'unique_ports': port_analysis['unique_ports'],
                        'is_sequential': port_analysis['is_sequential_scan']
                    }
                })
            else:  # role == 'dst'
                behaviors.append({
                    'type': 'UNDER_PORT_SCAN',
                    'severity': 'HIGH',
                    'description': f"檢測到被掃描：來自 {port_analysis['unique_ports']} 個不同來源埠",
                    'evidence': {
                        'unique_ports': port_analysis['unique_ports'],
                        'is_sequential': port_analysis['is_sequential_scan']
                    }
                })

        if dst_analysis['is_highly_distributed']:
            if role == 'src':
                behaviors.append({
                    'type': 'NETWORK_SCANNING',
                    'severity': 'HIGH',
                    'description': f"檢測到網路掃描：{dst_analysis['unique_destinations']} 個目的地",
                    'evidence': {
                        'unique_destinations': dst_analysis['unique_destinations'],
                        'dst_diversity': dst_analysis['dst_diversity_ratio']
                    }
                })
            else:  # role == 'dst'
                behaviors.append({
                    'type': 'UNDER_ATTACK',
                    'severity': 'HIGH',
                    'description': f"檢測到遭受攻擊：來自 {dst_analysis['unique_destinations']} 個不同來源",
                    'evidence': {
                        'unique_sources': dst_analysis['unique_destinations'],
                        'source_diversity': dst_analysis['dst_diversity_ratio']
                    }
                })

        # DNS 濫用（只在作為源時檢查）
        if role == 'src':
            dns_flows = [f for f in flows if f.get('dst_port') == 53]
            if len(dns_flows) > 1000 and traffic_analysis.get('mean_bytes', 0) < 500:
                behaviors.append({
                    'type': 'DNS_ABUSE',
                    'severity': 'MEDIUM',
                    'description': f"疑似 DNS 濫用：{len(dns_flows)} 個 DNS 查詢",
                    'evidence': {
                        'dns_query_count': len(dns_flows),
                        'avg_bytes': traffic_analysis.get('mean_bytes', 0)
                    }
                })

        # 數據外洩/內流
        total_bytes = sum(f.get('in_bytes', 0) + f.get('out_bytes', 0) for f in flows)
        if total_bytes > 1_000_000_000 and dst_analysis['unique_destinations'] < 5:  # 1GB+
            if role == 'src':
                behaviors.append({
                    'type': 'DATA_EXFILTRATION',
                    'severity': 'HIGH',
                    'description': f"疑似數據外洩：{total_bytes/1024/1024/1024:.2f} GB 到少數目的地",
                    'evidence': {
                        'total_bytes': total_bytes,
                        'unique_destinations': dst_analysis['unique_destinations']
                    }
                })
            else:  # role == 'dst'
                behaviors.append({
                    'type': 'LARGE_DATA_RECEIVE',
                    'severity': 'MEDIUM',
                    'description': f"接收大量數據：{total_bytes/1024/1024/1024:.2f} GB 來自少數來源",
                    'evidence': {
                        'total_bytes': total_bytes,
                        'unique_sources': dst_analysis['unique_destinations']
                    }
                })

        # ICMP 濫用
        if proto_analysis['is_icmp_heavy']:
            behaviors.append({
                'type': 'ICMP_ABUSE',
                'severity': 'MEDIUM',
                'description': "大量 ICMP 流量（可能為 ping 掃描或 DDoS）",
                'evidence': proto_analysis['protocol_distribution']
            })

        # 正常行為模式
        if not behaviors:
            # 檢查是否為正常服務
            top_ports = [p['port'] for p in port_analysis['top_ports'][:3]]
            if set(top_ports).intersection({80, 443, 53, 22}):
                behaviors.append({
                    'type': 'NORMAL_SERVICE',
                    'severity': 'LOW',
                    'description': "看起來像正常服務流量",
                    'evidence': {
                        'top_ports': port_analysis['top_ports'][:3]
                    }
                })

        return behaviors

    def _generate_verdict(self, analysis):
        """生成最終判斷"""
        behaviors = analysis['behavioral_analysis']

        high_severity = sum(1 for b in behaviors if b['severity'] == 'HIGH')
        medium_severity = sum(1 for b in behaviors if b['severity'] == 'MEDIUM')
        low_severity_types = [b['type'] for b in behaviors if b['severity'] == 'LOW']

        # 服務器回應流量應該被視為誤報
        if any(t in ['DNS_SERVER_RESPONSE', 'WEB_SERVER_RESPONSE', 'NORMAL_SERVICE'] for t in low_severity_types):
            verdict = 'FALSE_POSITIVE'
            confidence = 'HIGH'
            if 'DNS_SERVER_RESPONSE' in low_severity_types:
                recommendation = '這是 DNS 服務器回應流量，建議調整 Transform 或特徵工程來排除服務器回應'
            elif 'WEB_SERVER_RESPONSE' in low_severity_types:
                recommendation = '這是 Web 服務器回應流量，建議調整 Transform 或特徵工程來排除服務器回應'
            else:
                recommendation = '建議調整特徵閾值，降低此類誤報'
        elif high_severity > 0:
            verdict = 'TRUE_ANOMALY'
            confidence = 'HIGH'
            recommendation = '建議立即調查'
        elif medium_severity > 0:
            verdict = 'SUSPICIOUS'
            confidence = 'MEDIUM'
            recommendation = '建議持續觀察'
        else:
            verdict = 'UNCLEAR'
            confidence = 'LOW'
            recommendation = '需要更多數據或人工判斷'

        return {
            'verdict': verdict,
            'confidence': confidence,
            'recommendation': recommendation,
            'detected_behaviors': len(behaviors),
        }

    def _generate_bidirectional_verdict(self, analysis_result):
        """生成雙向分析的綜合判斷"""
        src_analysis = analysis_result.get('as_source')
        dst_analysis = analysis_result.get('as_destination')

        all_behaviors = []
        high_severity_count = 0
        medium_severity_count = 0
        low_severity_types = []

        # 收集兩個方向的行為
        if src_analysis:
            src_behaviors = src_analysis.get('behavioral_analysis', [])
            all_behaviors.extend([{**b, 'direction': 'as_source'} for b in src_behaviors])
            high_severity_count += sum(1 for b in src_behaviors if b['severity'] == 'HIGH')
            medium_severity_count += sum(1 for b in src_behaviors if b['severity'] == 'MEDIUM')
            low_severity_types.extend([b['type'] for b in src_behaviors if b['severity'] == 'LOW'])

        if dst_analysis:
            dst_behaviors = dst_analysis.get('behavioral_analysis', [])
            all_behaviors.extend([{**b, 'direction': 'as_destination'} for b in dst_behaviors])
            high_severity_count += sum(1 for b in dst_behaviors if b['severity'] == 'HIGH')
            medium_severity_count += sum(1 for b in dst_behaviors if b['severity'] == 'MEDIUM')
            low_severity_types.extend([b['type'] for b in dst_behaviors if b['severity'] == 'LOW'])

        # 綜合判斷
        if high_severity_count > 0:
            verdict = 'TRUE_ANOMALY'
            confidence = 'HIGH'
            if high_severity_count > 1:
                recommendation = f'檢測到 {high_severity_count} 個高危異常行為，建議立即調查'
            else:
                recommendation = '檢測到高危異常行為，建議立即調查'
        elif any(t in ['DNS_SERVER_RESPONSE', 'WEB_SERVER_RESPONSE', 'NORMAL_SERVICE'] for t in low_severity_types):
            # 如果有高危行為，不應該被服務器回應掩蓋
            if high_severity_count == 0:
                verdict = 'FALSE_POSITIVE'
                confidence = 'HIGH'
                recommendation = '主要為正常服務流量，建議調整特徵閾值'
            else:
                verdict = 'MIXED'
                confidence = 'MEDIUM'
                recommendation = '同時檢測到正常服務和異常行為，需進一步分析'
        elif medium_severity_count > 0:
            verdict = 'SUSPICIOUS'
            confidence = 'MEDIUM'
            recommendation = '檢測到可疑行為，建議持續觀察'
        elif all_behaviors:
            verdict = 'UNCLEAR'
            confidence = 'LOW'
            recommendation = '行為模式不明確，需要更多數據或人工判斷'
        else:
            verdict = 'NORMAL'
            confidence = 'MEDIUM'
            recommendation = '未檢測到明顯異常行為'

        return {
            'verdict': verdict,
            'confidence': confidence,
            'recommendation': recommendation,
            'total_behaviors': len(all_behaviors),
            'high_severity': high_severity_count,
            'medium_severity': medium_severity_count,
            'behaviors': all_behaviors,
        }

    def _print_bidirectional_report(self, analysis_result):
        """列印雙向分析報告"""
        print(f"\n{'='*100}")
        print(f"📋 雙向分析報告")
        print(f"{'='*100}\n")

        target_ip = analysis_result['target_ip']
        src_analysis = analysis_result.get('as_source')
        dst_analysis = analysis_result.get('as_destination')

        # 報告作為源 IP 的分析
        if src_analysis:
            print(f"{'─'*100}")
            print(f"📤 作為源 IP 的行為分析")
            print(f"{'─'*100}\n")
            self._print_single_direction_report(src_analysis)

        # 報告作為目的地 IP 的分析
        if dst_analysis:
            print(f"\n{'─'*100}")
            print(f"📥 作為目的地 IP 的行為分析")
            print(f"{'─'*100}\n")
            self._print_single_direction_report(dst_analysis)

        # 綜合判斷
        verdict = analysis_result['verdict']
        print(f"\n{'='*100}")
        print(f"🎯 綜合判斷")
        print(f"{'='*100}\n")

        verdict_icons = {
            'TRUE_ANOMALY': '🚨',
            'SUSPICIOUS': '⚠️',
            'FALSE_POSITIVE': '✅',
            'MIXED': '🔀',
            'UNCLEAR': '❓',
            'NORMAL': '✔️'
        }
        verdict_names = {
            'TRUE_ANOMALY': '真實異常',
            'SUSPICIOUS': '可疑行為',
            'FALSE_POSITIVE': '誤報（正常流量）',
            'MIXED': '混合情況',
            'UNCLEAR': '無法確定',
            'NORMAL': '正常流量'
        }

        icon = verdict_icons.get(verdict['verdict'], '❓')
        name = verdict_names.get(verdict['verdict'], verdict['verdict'])

        print(f"{icon} 判斷結果: {name}")
        print(f"📊 置信度: {verdict['confidence']}")
        print(f"📝 檢測到的行為數量: {verdict['total_behaviors']}")
        if verdict['high_severity'] > 0:
            print(f"   🔴 高危行為: {verdict['high_severity']}")
        if verdict['medium_severity'] > 0:
            print(f"   🟡 可疑行為: {verdict['medium_severity']}")
        print(f"\n💡 建議: {verdict['recommendation']}\n")

    def _print_single_direction_report(self, analysis):
        """列印單一方向的分析報告（簡化版）"""
        role = analysis.get('role', 'src')

        # 基本統計
        stats = analysis['basic_stats']
        print(f"📊 基本統計:")
        print(f"   • 總連線數: {stats['total_flows']:,}")
        print(f"   • 總流量: {stats['total_bytes']/1024/1024:.2f} MB")
        print(f"   • 平均每連線: {stats['avg_bytes_per_flow']:,.0f} bytes\n")

        # 目的地/來源分析
        dst = analysis['destination_analysis']
        if role == 'src':
            print(f"🎯 目的地分析:")
            print(f"   • 不同目的地數量: {dst['unique_destinations']}")
            print(f"   • 分散度: {dst['dst_diversity_ratio']:.3f}")
            # 顯示 TOP 5 目的地
            if dst['top_destinations']:
                num_to_display = min(5, len(dst['top_destinations']))
                if num_to_display == len(dst['top_destinations']) and num_to_display < 5:
                    print(f"\n   連線次數最多的前 {num_to_display} 個目的地:")
                else:
                    print(f"\n   TOP 5 連線目的地:")
                for i, dst_info in enumerate(dst['top_destinations'][:5], 1):
                    ip = dst_info['ip']
                    if ip in ['0.0.0.0', '::']:
                        ip_display = f"{ip} (數據缺失)"
                    else:
                        ip_display = self._format_ip_with_name(ip)
                    print(f"      {i}. {ip_display:50s} → {dst_info['count']:5,} 次 ({dst_info['percentage']:.1f}%)")
            print()
        else:
            print(f"🎯 來源分析:")
            print(f"   • 不同來源數量: {dst['unique_destinations']}")
            print(f"   • 分散度: {dst['dst_diversity_ratio']:.3f}")
            # 顯示 TOP 5 來源
            if dst['top_destinations']:
                num_to_display = min(5, len(dst['top_destinations']))
                if num_to_display == len(dst['top_destinations']) and num_to_display < 5:
                    print(f"\n   連線次數最多的前 {num_to_display} 個來源:")
                else:
                    print(f"\n   TOP 5 連線來源:")
                for i, src_info in enumerate(dst['top_destinations'][:5], 1):
                    ip = src_info['ip']
                    if ip in ['0.0.0.0', '::']:
                        ip_display = f"{ip} (數據缺失)"
                    else:
                        ip_display = self._format_ip_with_name(ip)
                    print(f"      {i}. {ip_display:50s} → {src_info['count']:5,} 次 ({src_info['percentage']:.1f}%)")
            print()

        # 通訊埠分析
        port = analysis['port_analysis']
        if role == 'src':
            print(f"🔌 目的通訊埠分析:")
        else:
            print(f"🔌 來源通訊埠分析:")
        print(f"   • 不同通訊埠數量: {port['unique_ports']}")

        # 顯示 TOP 5 通訊埠
        if port['top_ports']:
            if role == 'src':
                print(f"\n   TOP 5 目的通訊埠:")
            else:
                print(f"\n   TOP 5 來源通訊埠:")
            for i, port_info in enumerate(port['top_ports'][:5], 1):
                print(f"      {i}. {port_info['port']:5d} ({port_info['service']:15s}) → {port_info['count']:5,} 次 ({port_info['percentage']:.1f}%)")
            print()
        else:
            print()

        # 行為分析
        behaviors = analysis['behavioral_analysis']
        if behaviors:
            print(f"🔍 檢測到的行為:")
            for behavior in behaviors:
                severity_icon = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(behavior['severity'], '⚪')
                print(f"   {severity_icon} [{behavior['severity']}] {behavior['type']}")
                print(f"      {behavior['description']}")
        else:
            print(f"🔍 未檢測到明顯異常行為")

    def _print_report(self, analysis):
        """列印分析報告"""
        print(f"📋 分析報告\n")

        role = analysis.get('role', 'src')

        # 基本統計
        stats = analysis['basic_stats']
        print(f"📊 基本統計:")
        print(f"   • 總連線數: {stats['total_flows']:,}")
        print(f"   • 總流量: {stats['total_bytes']/1024/1024:.2f} MB")
        print(f"   • 平均每連線: {stats['avg_bytes_per_flow']:,.0f} bytes")
        print()

        # 目的地/來源分析（根據角色動態標籤）
        dst = analysis['destination_analysis']
        if role == 'src':
            title = "🎯 目的地分析:"
            count_label = "不同目的地數量"
            diversity_label = "目的地分散度"
            top_label = "目的地"
        else:  # role == 'dst'
            title = "🎯 來源分析:"
            count_label = "不同來源數量"
            diversity_label = "來源分散度"
            top_label = "來源"

        print(title)
        print(f"   • {count_label}: {dst['unique_destinations']}")
        print(f"   • {diversity_label}: {dst['dst_diversity_ratio']:.3f}")

        # 檢查是否為數據質量問題
        has_zero_ip = any(d['ip'] == '0.0.0.0' or d['ip'] == '::' for d in dst['top_destinations'])
        if has_zero_ip:
            print(f"   ⚠️  注意：{top_label}包含 0.0.0.0，這是數據採集問題（單向流量記錄）")
        elif dst['is_highly_distributed']:
            if role == 'src':
                print(f"   ⚠️  連線高度分散（疑似掃描行為）")
            else:
                print(f"   ⚠️  來源高度分散（疑似遭受攻擊）")
        elif dst['is_concentrated']:
            if role == 'src':
                print(f"   ⚠️  連線高度集中（疑似定向攻擊）")
            else:
                print(f"   ⚠️  來源高度集中（被少數來源大量連線）")

        # 顯示 TOP 5 目的地/來源（突出顯示）
        if dst['top_destinations']:
            # 動態調整標題：如果少於5個，顯示實際數量
            num_to_display = min(5, len(dst['top_destinations']))
            if num_to_display == len(dst['top_destinations']) and num_to_display < 5:
                # 如果總數少於5個，顯示實際數量
                print(f"\n   連線次數最多的前 {num_to_display} 個{top_label}:")
            else:
                # 如果有5個以上，顯示 TOP 5
                print(f"\n   🔝 TOP 5 連線{top_label}:")

            for i, dst_info in enumerate(dst['top_destinations'][:5], 1):
                ip = dst_info['ip']
                if ip in ['0.0.0.0', '::']:
                    ip_display = f"{ip} (數據缺失)"
                else:
                    ip_display = self._format_ip_with_name(ip)
                print(f"      {i}. {ip_display:50s} → {dst_info['count']:5,} 次 ({dst_info['percentage']:.1f}%)")

        # 顯示額外的目的地/來源（6-20名）
        if len(dst['top_destinations']) > 5:
            num_to_show = min(20, len(dst['top_destinations']))
            remaining_to_show = num_to_show - 5
            if remaining_to_show > 0:
                print(f"\n   其他高頻{top_label}（6-{num_to_show}名）:")
                for i, dst_info in enumerate(dst['top_destinations'][5:num_to_show], 6):
                    ip = dst_info['ip']
                    if ip in ['0.0.0.0', '::']:
                        ip_display = f"{ip} (數據缺失)"
                    else:
                        ip_display = self._format_ip_with_name(ip)
                    print(f"      {i}. {ip_display:50s} → {dst_info['count']:5,} 次 ({dst_info['percentage']:.1f}%)")

            # 如果還有更多，提示用戶
            if len(dst['top_destinations']) > num_to_show:
                remaining = len(dst['top_destinations']) - num_to_show
                print(f"      ... 還有 {remaining} 個{top_label}")
        print()

        # 通訊埠分析（根據角色動態標籤）
        port = analysis['port_analysis']
        if role == 'src':
            port_title = "🔌 目的通訊埠分析:"
            port_label = "目的通訊埠"
        else:  # role == 'dst'
            port_title = "🔌 來源通訊埠分析:"
            port_label = "來源通訊埠"

        print(port_title)
        print(f"   • 不同{port_label}數量: {port['unique_ports']}")
        print(f"   • {port_label}分散度: {port['port_diversity_ratio']:.3f}")
        if port['is_scanning']:
            if role == 'src':
                print(f"   ⚠️  疑似通訊埠掃描")
            else:
                print(f"   ⚠️  疑似被通訊埠掃描")
        if port['is_sequential_scan']:
            print(f"   ⚠️  檢測到連續通訊埠模式")

        # 顯示 TOP 5 通訊埠
        if port['top_ports']:
            print(f"\n   🔝 TOP 5 {port_label}:")
            for i, port_info in enumerate(port['top_ports'][:5], 1):
                print(f"      {i}. {port_info['port']:5d} ({port_info['service']:15s}) → {port_info['count']:5,} 次 ({port_info['percentage']:.1f}%)")
        print()

        # 協定分析
        proto = analysis['protocol_analysis']
        print(f"📡 協定分析:")
        for proto_info in proto['protocol_distribution']:
            print(f"   • {proto_info['protocol']:10s}: {proto_info['count']:5,} ({proto_info['percentage']:.1f}%)")
        print()

        # 行為分析
        behaviors = analysis['behavioral_analysis']
        print(f"🔍 行為分析:")
        if behaviors:
            for behavior in behaviors:
                severity_icon = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(behavior['severity'], '⚪')
                print(f"   {severity_icon} [{behavior['severity']}] {behavior['type']}")
                print(f"      {behavior['description']}")
            print()
        else:
            print(f"   ✓ 未檢測到明顯異常行為")
            print()

        # 最終判斷
        verdict = analysis['verdict']
        verdict_icons = {
            'TRUE_ANOMALY': '🚨',
            'SUSPICIOUS': '⚠️',
            'FALSE_POSITIVE': '✅',
            'UNCLEAR': '❓'
        }
        verdict_names = {
            'TRUE_ANOMALY': '真實異常',
            'SUSPICIOUS': '可疑行為',
            'FALSE_POSITIVE': '誤報（正常流量）',
            'UNCLEAR': '無法確定'
        }

        print(f"{'='*100}")
        icon = verdict_icons.get(verdict['verdict'], '❓')
        name = verdict_names.get(verdict['verdict'], verdict['verdict'])
        print(f"{icon} 最終判斷: {name} (置信度: {verdict['confidence']})")
        print(f"{'='*100}")
        print(f"💡 建議: {verdict['recommendation']}\n")


def main():
    parser = argparse.ArgumentParser(description='驗證 Isolation Forest 檢測出的異常')
    parser.add_argument('--ip', type=str, help='要分析的 IP 地址')
    parser.add_argument('--minutes', type=int, default=30, help='分析時間範圍（分鐘，默認 30）')
    parser.add_argument('--auto', action='store_true', help='自動分析最近檢測到的異常')
    parser.add_argument('--top', type=int, default=5, help='自動模式下分析前 N 個異常（默認 5）')

    args = parser.parse_args()

    # 載入配置
    config = load_config()

    # 連接 Elasticsearch
    es_host = config.get('elasticsearch', {}).get('host', 'http://localhost:9200')
    es = Elasticsearch([es_host], timeout=30)

    if not es.ping():
        print(f"❌ 無法連接到 Elasticsearch: {es_host}")
        sys.exit(1)

    print(f"✓ 已連接到 Elasticsearch: {es_host}")

    verifier = AnomalyVerifier(es, config)

    # 顯示 MySQL 連線狀態
    if verifier.mysql_connected:
        mysql_cfg = config.get('mysql', {})
        print(f"✓ 已連接到 MySQL: {mysql_cfg.get('host')}:{mysql_cfg.get('port')} (設備名稱查詢已啟用)")
    else:
        print(f"○ MySQL 未連接 (設備名稱查詢功能停用)")
    print()

    if args.auto:
        print(f"🤖 自動模式：分析最近檢測到的前 {args.top} 個異常\n")
        print("💡 提示：先運行 realtime_detection.py 來檢測異常\n")

        # 這裡可以從檢測結果中自動讀取異常 IP
        # 暫時提示用戶手動指定
        print("請先運行：python3 realtime_detection.py --minutes 30")
        print("然後使用 --ip 參數指定要分析的 IP\n")

    elif args.ip:
        verifier.verify_ip(args.ip, args.minutes)
    else:
        print("用法:")
        print("  python3 verify_anomaly.py --ip 192.168.1.100 --minutes 30")
        print("  python3 verify_anomaly.py --auto --top 5")
        print()


if __name__ == '__main__':
    main()
