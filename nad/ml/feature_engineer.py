#!/usr/bin/env python3
"""
特徵工程模組

從 netflow_stats_5m 聚合數據提取 ML 特徵
"""

import numpy as np
import requests
from typing import Dict, List
from datetime import datetime
from ..device_classifier import DeviceClassifier


class FeatureEngineer:
    """
    特徵工程器

    從聚合數據提取特徵向量
    """

    def __init__(self, config=None):
        self.config = config

        # 初始化设备分类器
        self.device_classifier = DeviceClassifier()

        # 特徵名稱（順序很重要！）
        self.feature_names = self._build_feature_names()
        
        # 定義檢測用特徵和分類用特徵
        self.detection_feature_names = self.feature_names  # 默認與 feature_names 相同
        self.classification_feature_names = self._build_classification_feature_names()

    def _build_feature_names(self):
        """構建特徵名稱列表"""
        if self.config:
            features_config = self.config.features_config

            names = []
            # 基礎特徵
            names.extend(features_config['basic'])
            # 衍生特徵
            names.extend(features_config['derived'])
            # 二值特徵
            names.extend(features_config['binary'])
            # 對數特徵
            names.extend(features_config['log_transform'])
            # 設備類型特徵
            if 'device_type' in features_config:
                names.extend(features_config['device_type'])
            # 時間序列特徵
            if 'time_series' in features_config:
                names.extend(features_config['time_series'])

            return names
        else:
            # 默認特徵集
            return [
                # 基礎特徵 (9個) - 新增 unique_src_ports, unique_dst_ports
                'flow_count', 'total_bytes', 'total_packets',
                'unique_dsts', 'unique_src_ports', 'unique_dst_ports',
                'avg_bytes', 'max_bytes',

                # 衍生特徵 (5個) - 新增 src_port_diversity
                'dst_diversity', 'src_port_diversity', 'dst_port_diversity',
                'traffic_concentration', 'bytes_per_packet',

                # 二值特徵 (5個)
                'is_high_connection', 'is_scanning_pattern',
                'is_small_packet', 'is_large_flow', 'is_likely_server_response',

                # 對數特徵 (2個)
                'log_flow_count', 'log_total_bytes',

                # 設備類型特徵 (1個) - 新增
                'device_type'
            ]

    def _build_classification_feature_names(self):
        """構建分類特徵名稱列表（包含檢測特徵和額外特徵）"""
        # 基礎特徵集（檢測用）
        names = list(self.feature_names)
        
        # 如果配置中有定義分類特徵，則使用配置
        if self.config and hasattr(self.config, 'classification_features_config') and self.config.classification_features_config:
            extra_features = self.config.classification_features_config
            names.extend(extra_features)
            return names

        # 默認額外分類特徵
        extra_features = [
            # 端口分析
            'common_ports_ratio',      # 常用端口比例 (0-1023)
            'dynamic_ports_ratio',     # 動態端口比例 (49152-65535)
            'registered_ports_ratio',  # 註冊端口比例 (1024-49151)
            
            # 流量方向性 (如果有雙向數據)
            # 'upload_download_ratio',
            
            # 協議分析 (如果有協議數據)
            # 'tcp_ratio', 'udp_ratio', 'icmp_ratio'
            
            # 更細粒度的時間特徵
            'flow_rate',               # 每秒連線數
            'byte_rate'                # 每秒字節數
        ]
        
        names.extend(extra_features)
        return names

    def extract_features(self, agg_record: Dict) -> Dict:
        """
        從單筆聚合記錄提取特徵

        Args:
            agg_record: netflow_stats_5m 的一筆記錄

        Returns:
            特徵字典
        """
        features = {}

        # 1. 基礎特徵（直接從聚合數據獲取）
        features['flow_count'] = agg_record.get('flow_count', 0)
        features['total_bytes'] = agg_record.get('total_bytes', 0)
        features['total_packets'] = agg_record.get('total_packets', 0)
        features['unique_dsts'] = agg_record.get('unique_dsts', 0)
        features['unique_src_ports'] = agg_record.get('unique_src_ports', 0)
        features['unique_dst_ports'] = agg_record.get('unique_dst_ports', 0)
        features['avg_bytes'] = agg_record.get('avg_bytes', 0)
        features['max_bytes'] = agg_record.get('max_bytes', 0)

        # 2. 衍生特徵（簡單計算）
        flow_count = max(features['flow_count'], 1)  # 避免除以0

        features['dst_diversity'] = features['unique_dsts'] / flow_count
        features['src_port_diversity'] = features['unique_src_ports'] / flow_count
        features['dst_port_diversity'] = features['unique_dst_ports'] / flow_count

        total_bytes = max(features['total_bytes'], 1)
        features['traffic_concentration'] = features['max_bytes'] / total_bytes

        total_packets = max(features['total_packets'], 1)
        features['bytes_per_packet'] = features['total_bytes'] / total_packets

        # 3. 二值特徵（行為標記）
        thresholds = self.config.thresholds if self.config else {
            'high_connection': 1000,
            'scanning_dsts': 30,
            'scanning_avg_bytes': 10000,
            'small_packet': 1000,
            'large_flow': 104857600
        }

        features['is_high_connection'] = 1 if features['flow_count'] > thresholds['high_connection'] else 0

        features['is_scanning_pattern'] = 1 if (
            features['unique_dsts'] > thresholds['scanning_dsts'] and
            features['avg_bytes'] < thresholds['scanning_avg_bytes']
        ) else 0

        features['is_small_packet'] = 1 if features['avg_bytes'] < thresholds['small_packet'] else 0
        features['is_large_flow'] = 1 if features['max_bytes'] > thresholds['large_flow'] else 0

        # 新增：檢測可能的服務器回應流量
        # 改進的特徵：低源通訊埠多樣性（固定服務埠）+ 高目的通訊埠多樣性（客戶端隨機埠）
        # 使用可配置的閾值（支援自定義）
        features['is_likely_server_response'] = 1 if (
            features['src_port_diversity'] < thresholds.get('server_response_src_port_diversity_max', 0.1) and
            features['dst_port_diversity'] > thresholds.get('server_response_dst_port_diversity_min', 0.3) and
            features['unique_src_ports'] <= thresholds.get('server_response_unique_src_ports_max', 100) and
            features['flow_count'] > thresholds.get('server_response_flow_count_min', 100) and
            features['avg_bytes'] < thresholds.get('server_response_avg_bytes_max', 50000)
        ) else 0

        # 4. 對數變換（處理偏態分布）
        features['log_flow_count'] = np.log1p(features['flow_count'])
        features['log_total_bytes'] = np.log1p(features['total_bytes'])

        # 5. 設備類型特徵（新增）
        src_ip = agg_record.get('src_ip', '')
        features['device_type'] = self.device_classifier.get_device_type_code(src_ip)

        # 6. 時間序列特徵（可選，從 time_bucket 提取）
        # 只有在配置中啟用時才提取
        if self.config and 'time_series' in self.config.features_config:
            time_features = self._extract_time_features(agg_record.get('time_bucket'))
            features.update(time_features)

        return features

    def extract_classification_features(self, agg_record: Dict) -> Dict:
        """
        提取用於分類的完整特徵集（包含檢測特徵和額外特徵）

        Args:
            agg_record: netflow_stats_3m 的一筆記錄

        Returns:
            擴展的特徵字典
        """
        # 1. 獲取基礎特徵
        features = self.extract_features(agg_record)

        # 2. 計算基於 top_ports 的端口分析特徵
        port_features = self._extract_port_features(agg_record)
        features.update(port_features)

        # 3. 速率特徵 (窗口為 3 分鐘 = 180 秒)
        duration = 180
        features['flow_rate'] = features['flow_count'] / duration
        features['byte_rate'] = features['total_bytes'] / duration

        return features

    def _extract_port_features(self, agg_record: Dict) -> Dict:
        """
        從 top_src_ports 和 top_dst_ports 提取端口特徵

        Args:
            agg_record: 聚合記錄，包含 top_src_ports 和 top_dst_ports

        Returns:
            端口特徵字典
        """
        port_features = {}

        # 獲取 top ports 數據（flattened 格式: {"port": count}）
        top_src_ports = agg_record.get('top_src_ports', {})
        top_dst_ports = agg_record.get('top_dst_ports', {})
        flow_count = max(agg_record.get('flow_count', 1), 1)  # 避免除以0

        # 轉換為列表格式 [(port_int, count), ...]
        src_ports_list = [(int(port), count) for port, count in top_src_ports.items()]
        dst_ports_list = [(int(port), count) for port, count in top_dst_ports.items()]

        # === 1. Port 集中度特徵 (P0) ===
        port_features['top_src_port_concentration'] = self._calculate_port_concentration(
            src_ports_list, flow_count
        )
        port_features['top_dst_port_concentration'] = self._calculate_port_concentration(
            dst_ports_list, flow_count
        )

        # === 2. Well-known/Ephemeral Port 比例 (P0) ===
        src_port_ratios = self._calculate_port_type_ratios(src_ports_list, flow_count)
        dst_port_ratios = self._calculate_port_type_ratios(dst_ports_list, flow_count)

        port_features['src_well_known_ratio'] = src_port_ratios['well_known']
        port_features['src_ephemeral_ratio'] = src_port_ratios['ephemeral']
        port_features['src_registered_ratio'] = src_port_ratios['registered']

        port_features['dst_well_known_ratio'] = dst_port_ratios['well_known']
        port_features['dst_ephemeral_ratio'] = dst_port_ratios['ephemeral']
        port_features['dst_registered_ratio'] = dst_port_ratios['registered']

        # 保留舊的命名以兼容現有代碼
        port_features['common_ports_ratio'] = dst_port_ratios['well_known']
        port_features['dynamic_ports_ratio'] = dst_port_ratios['ephemeral']
        port_features['registered_ports_ratio'] = dst_port_ratios['registered']

        # === 3. Server 角色識別特徵 (P0) ===
        port_features['is_likely_web_server'] = self._is_web_server(src_ports_list, dst_ports_list)
        port_features['is_likely_db_server'] = self._is_db_server(src_ports_list)
        port_features['is_likely_dns_server'] = self._is_dns_server(src_ports_list)
        port_features['is_likely_mail_server'] = self._is_mail_server(src_ports_list)

        # === 4. Port Entropy (P1) ===
        port_features['src_port_entropy'] = self._calculate_port_entropy(src_ports_list)
        port_features['dst_port_entropy'] = self._calculate_port_entropy(dst_ports_list)

        # === 5. Sequential Ports 檢測 (P1) ===
        port_features['has_sequential_dst_ports'] = self._has_sequential_ports(dst_ports_list)

        # === 6. High-risk Ports (P1) ===
        port_features['high_risk_ports_count'] = self._count_high_risk_ports(
            src_ports_list + dst_ports_list
        )

        return port_features

    def _calculate_port_concentration(self, ports_list: List[tuple], flow_count: int) -> float:
        """
        計算最常用端口的集中度

        Args:
            ports_list: [(port, count), ...]
            flow_count: 總連線數

        Returns:
            集中度 (0-1)，值越大表示流量越集中在少數端口
        """
        if not ports_list or flow_count == 0:
            return 0.0

        # 找出使用最多的端口
        max_count = max(count for _, count in ports_list)
        return max_count / flow_count

    def _calculate_port_type_ratios(self, ports_list: List[tuple], flow_count: int) -> Dict:
        """
        計算不同類型端口的比例

        Port 範圍:
        - Well-known: 0-1023 (系統/知名服務)
        - Registered: 1024-49151 (註冊服務)
        - Ephemeral: 49152-65535 (臨時/客戶端)

        Args:
            ports_list: [(port, count), ...]
            flow_count: 總連線數

        Returns:
            {'well_known': ratio, 'registered': ratio, 'ephemeral': ratio}
        """
        if not ports_list or flow_count == 0:
            return {'well_known': 0.0, 'registered': 0.0, 'ephemeral': 0.0}

        well_known_count = 0
        registered_count = 0
        ephemeral_count = 0

        for port, count in ports_list:
            if port <= 1023:
                well_known_count += count
            elif port <= 49151:
                registered_count += count
            else:  # 49152-65535
                ephemeral_count += count

        return {
            'well_known': well_known_count / flow_count,
            'registered': registered_count / flow_count,
            'ephemeral': ephemeral_count / flow_count
        }

    def _is_web_server(self, src_ports: List[tuple], dst_ports: List[tuple]) -> int:
        """檢測是否為 Web Server (HTTP/HTTPS)"""
        if not src_ports:
            return 0

        web_ports = {80, 443, 8080, 8443}
        top_src_port = src_ports[0][0] if src_ports else None

        # Web Server 模式: src_port 在 80/443, dst_port 為隨機高位端口
        if top_src_port in web_ports:
            # 檢查 dst_ports 是否為隨機端口
            if dst_ports:
                avg_dst_port = sum(port * count for port, count in dst_ports) / sum(count for _, count in dst_ports)
                if avg_dst_port > 10000:  # 客戶端隨機端口
                    return 1

        return 0

    def _is_db_server(self, src_ports: List[tuple]) -> int:
        """檢測是否為資料庫 Server"""
        if not src_ports:
            return 0

        db_ports = {3306, 5432, 1521, 1433, 27017, 6379}  # MySQL, PostgreSQL, Oracle, MSSQL, MongoDB, Redis
        top_src_port = src_ports[0][0] if src_ports else None

        return 1 if top_src_port in db_ports else 0

    def _is_dns_server(self, src_ports: List[tuple]) -> int:
        """檢測是否為 DNS Server"""
        if not src_ports:
            return 0

        top_src_port = src_ports[0][0] if src_ports else None
        return 1 if top_src_port == 53 else 0

    def _is_mail_server(self, src_ports: List[tuple]) -> int:
        """檢測是否為郵件 Server"""
        if not src_ports:
            return 0

        mail_ports = {25, 587, 465, 110, 143, 993, 995}  # SMTP, POP3, IMAP
        top_src_port = src_ports[0][0] if src_ports else None

        return 1 if top_src_port in mail_ports else 0

    def _calculate_port_entropy(self, ports_list: List[tuple]) -> float:
        """
        計算端口分布的熵值

        熵值越高表示端口分布越分散（可能是掃描）
        熵值越低表示端口分布越集中（正常服務）

        Args:
            ports_list: [(port, count), ...]

        Returns:
            熵值 (0-log2(n))
        """
        if not ports_list:
            return 0.0

        total = sum(count for _, count in ports_list)
        if total == 0:
            return 0.0

        entropy = 0.0
        for _, count in ports_list:
            if count > 0:
                p = count / total
                entropy -= p * np.log2(p)

        return entropy

    def _has_sequential_ports(self, ports_list: List[tuple]) -> int:
        """
        檢測是否存在連續端口（掃描工具特徵）

        Args:
            ports_list: [(port, count), ...]

        Returns:
            1 if 有連續端口, 0 otherwise
        """
        if len(ports_list) < 3:
            return 0

        ports = sorted([port for port, _ in ports_list])

        # 檢查是否有連續的端口序列 (至少3個連續)
        consecutive_count = 1
        for i in range(1, len(ports)):
            if ports[i] == ports[i-1] + 1:
                consecutive_count += 1
                if consecutive_count >= 3:
                    return 1
            else:
                consecutive_count = 1

        return 0

    def _count_high_risk_ports(self, ports_list: List[tuple]) -> int:
        """
        計算高風險端口數量

        高風險端口: RDP, SMB, Telnet, FTP 等常被攻擊的服務

        Args:
            ports_list: [(port, count), ...]

        Returns:
            高風險端口數量
        """
        high_risk_ports = {
            21,    # FTP
            23,    # Telnet
            135,   # MS RPC
            139,   # NetBIOS
            445,   # SMB
            3389,  # RDP
            5900,  # VNC
            1433,  # MSSQL (如果對外開放)
        }

        ports = {port for port, _ in ports_list}
        return len(ports & high_risk_ports)

    def _extract_time_features(self, time_bucket: str) -> Dict:
        """
        從 time_bucket 提取簡單時間特徵（不需要查詢歷史數據）

        Args:
            time_bucket: 時間戳字符串（ISO 8601 格式）

        Returns:
            時間特徵字典
        """
        time_features = {}

        try:
            # 解析時間
            dt = datetime.fromisoformat(time_bucket.replace('Z', '+00:00'))

            # 1. 小時（0-23）- 循環編碼
            hour = dt.hour
            time_features['hour_of_day'] = hour
            time_features['hour_sin'] = np.sin(2 * np.pi * hour / 24)
            time_features['hour_cos'] = np.cos(2 * np.pi * hour / 24)

            # 2. 星期幾（0-6，0=Monday）
            day_of_week = dt.weekday()
            time_features['day_of_week'] = day_of_week

            # 3. 是否週末（Saturday=5, Sunday=6）
            time_features['is_weekend'] = 1 if day_of_week >= 5 else 0

            # 4. 是否工作時間（週一到週五 9:00-18:00）
            is_weekday = day_of_week < 5
            is_work_hours = 9 <= hour < 18
            time_features['is_business_hours'] = 1 if (is_weekday and is_work_hours) else 0

            # 5. 是否深夜時段（22:00-06:00）
            is_late_night = hour >= 22 or hour < 6
            time_features['is_late_night'] = 1 if is_late_night else 0

        except Exception as e:
            # 如果解析失敗，返回默認值
            time_features = {
                'hour_of_day': 0,
                'hour_sin': 0,
                'hour_cos': 1,
                'day_of_week': 0,
                'is_weekend': 0,
                'is_business_hours': 0,
                'is_late_night': 0
            }

        return time_features

    def extract_features_batch(self, agg_records: List[Dict]) -> np.ndarray:
        """
        批量提取特徵

        Args:
            agg_records: 多筆聚合記錄

        Returns:
            特徵矩陣 (n_samples, n_features)
        """
        features_list = []

        for record in agg_records:
            features = self.extract_features(record)
            features = self.extract_features(record)
            # 按照 detection_feature_names 的順序構建特徵向量
            feature_vector = [features[name] for name in self.detection_feature_names]
            features_list.append(feature_vector)

        return np.array(features_list)

    def get_feature_vector(self, features_dict: Dict) -> np.ndarray:
        """
        將特徵字典轉換為向量

        Args:
            features_dict: 特徵字典

        Returns:
            特徵向量
        """
        return np.array([features_dict[name] for name in self.detection_feature_names])

    def extract_time_series_features(self, es_client, src_ip: str, hours: int = 24) -> Dict:
        """
        提取時間序列特徵（可選）

        Args:
            es_client: Elasticsearch 客戶端
            src_ip: 源 IP
            hours: 查詢小時數

        Returns:
            時間序列特徵字典
        """
        # 查詢該 IP 的歷史數據
        query = {
            "size": 288,  # 24小時 × 12個5分鐘
            "query": {
                "bool": {
                    "must": [
                        {"term": {"src_ip": src_ip}},
                        {"range": {"time_bucket": {"gte": f"now-{hours}h"}}}
                    ]
                }
            },
            "sort": [{"time_bucket": "asc"}]
        }

        index = self.config.es_aggregated_index if self.config else "netflow_stats_5m"

        try:
            response = es_client.search(index=index, body=query)
            hits = response['hits']['hits']

            if len(hits) < 2:
                return None

            # 提取時間序列
            flow_counts = [h['_source']['flow_count'] for h in hits]
            unique_dsts = [h['_source']['unique_dsts'] for h in hits]
            total_bytes = [h['_source']['total_bytes'] for h in hits]

            # 統計特徵
            ts_features = {
                # 基本統計
                'mean_flow_count': np.mean(flow_counts),
                'std_flow_count': np.std(flow_counts),
                'max_flow_count': np.max(flow_counts),
                'min_flow_count': np.min(flow_counts),

                # 變異性
                'cv_flow_count': np.std(flow_counts) / (np.mean(flow_counts) + 1),

                # 趨勢
                'flow_count_trend': self._calculate_trend(flow_counts),
                'bytes_trend': self._calculate_trend(total_bytes),

                # 突變檢測
                'recent_spike': self._detect_spike(flow_counts),

                # 時間特徵
                'hour_of_day': datetime.fromisoformat(
                    hits[-1]['_source']['time_bucket'].replace('Z', '+00:00')
                ).hour,

                # 穩定性
                'dst_stability': 1 - (np.std(unique_dsts) / (np.mean(unique_dsts) + 1))
            }

            return ts_features

        except Exception as e:
            print(f"警告: 提取時間序列特徵失敗: {e}")
            return None

    def _calculate_trend(self, values: List[float]) -> float:
        """
        計算簡單線性趨勢

        Args:
            values: 時間序列值

        Returns:
            趨勢斜率（標準化）
        """
        if len(values) < 2:
            return 0.0

        x = np.arange(len(values))
        y = np.array(values)

        # 簡單線性回歸
        if len(values) > 2:
            correlation = np.corrcoef(x, y)[0, 1]
            return correlation if not np.isnan(correlation) else 0.0
        else:
            return 0.0

    def _detect_spike(self, values: List[float]) -> int:
        """
        檢測最近是否有突增

        Args:
            values: 時間序列值

        Returns:
            1 表示有突增，0 表示無
        """
        if len(values) < 3:
            return 0

        recent = values[-1]
        baseline = np.mean(values[:-1])
        std = np.std(values[:-1])

        # Z-score 檢測
        z_score = (recent - baseline) / (std + 1)

        return 1 if z_score > 3 else 0

    def get_feature_importance_names(self) -> List[str]:
        """
        獲取特徵名稱（用於特徵重要性分析）

        Returns:
            特徵名稱列表
        """
        return self.detection_feature_names.copy()

    def describe_features(self, features_dict: Dict) -> str:
        """
        生成特徵描述（用於報告）

        Args:
            features_dict: 特徵字典

        Returns:
            可讀的特徵描述
        """
        desc = []
        desc.append(f"連線數: {features_dict['flow_count']:,}")
        desc.append(f"不同目的地數量: {features_dict['unique_dsts']}")
        desc.append(f"不同源通訊埠數量: {features_dict['unique_src_ports']}")
        desc.append(f"不同目的通訊埠數量: {features_dict['unique_dst_ports']}")
        desc.append(f"總流量: {features_dict['total_bytes'] / 1024 / 1024:.2f} MB")
        desc.append(f"平均流量: {features_dict['avg_bytes']:,.0f} bytes")
        desc.append(f"目的地分散度: {features_dict['dst_diversity']:.3f}")
        desc.append(f"源通訊埠分散度: {features_dict['src_port_diversity']:.3f}")
        desc.append(f"目的通訊埠分散度: {features_dict['dst_port_diversity']:.3f}")

        # 行為標記
        behaviors = []
        if features_dict['is_high_connection']:
            behaviors.append("高連線數")
        if features_dict['is_scanning_pattern']:
            behaviors.append("掃描模式")
        if features_dict['is_small_packet']:
            behaviors.append("小封包")
        if features_dict['is_large_flow']:
            behaviors.append("大流量")

        if behaviors:
            desc.append(f"行為特徵: {', '.join(behaviors)}")

        return " | ".join(desc)
