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
        features['is_likely_server_response'] = 1 if (
            features['src_port_diversity'] < 0.1 and     # 源通訊埠很集中（服務器固定埠如 53, 389, 443）
            features['dst_port_diversity'] > 0.3 and     # 目的通訊埠很分散（客戶端隨機埠）
            features['unique_src_ports'] <= 100 and      # 源通訊埠數量少（服務埠，放寬到 100）
            features['flow_count'] > 100 and             # 連線數足夠多
            features['avg_bytes'] < 50000                # 平均流量不大（DNS/LDAP/Web 回應）
        ) else 0

        # 4. 對數變換（處理偏態分布）
        features['log_flow_count'] = np.log1p(features['flow_count'])
        features['log_total_bytes'] = np.log1p(features['total_bytes'])

        # 5. 設備類型特徵（新增）
        src_ip = agg_record.get('src_ip', '')
        features['device_type'] = self.device_classifier.get_device_type_code(src_ip)

        return features

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
            # 按照 feature_names 的順序構建特徵向量
            feature_vector = [features[name] for name in self.feature_names]
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
        return np.array([features_dict[name] for name in self.feature_names])

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
        return self.feature_names.copy()

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
