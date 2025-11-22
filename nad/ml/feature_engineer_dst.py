#!/usr/bin/env python3
"""
Dst 視角的特徵工程模組

從 netflow_stats_5m_by_dst 提取特徵，用於 Isolation Forest (by_dst) 訓練。

關鍵差異：
- 聚合 key: dst_ip（而非 src_ip）
- 關鍵特徵: unique_srcs, unique_src_ports（而非 unique_dsts, unique_dst_ports）
- 用途: 偵測 DDoS、被掃描目標、資料外洩目標端
"""

import numpy as np
from typing import Dict, List
from datetime import datetime


class FeatureEngineerDst:
    """
    Dst 視角的特徵工程器

    從 netflow_stats_5m_by_dst 提取特徵
    """

    def __init__(self, config=None):
        self.config = config

        # 特徵名稱列表（動態構建）
        self.feature_names = self._build_feature_names()

    def _build_feature_names(self):
        """構建特徵名稱列表（從配置或使用預設值）"""
        if self.config:
            features_config = self.config.features_by_dst_config

            names = []
            # 基礎特徵
            if 'basic' in features_config:
                names.extend(features_config['basic'])
            # 衍生特徵
            if 'derived' in features_config:
                names.extend(features_config['derived'])
            # 二值特徵
            if 'binary' in features_config:
                names.extend(features_config['binary'])
            # 對數特徵
            if 'log_transform' in features_config:
                names.extend(features_config['log_transform'])
            # 時間序列特徵
            if 'time_series' in features_config:
                names.extend(features_config['time_series'])

            return names
        else:
            # 默認特徵集（向後兼容）
            return [
                # 基礎特徵
                'unique_srcs', 'unique_src_ports', 'unique_dst_ports',
                'flow_count', 'total_bytes', 'total_packets',
                'avg_bytes', 'max_bytes',
                # 衍生特徵
                'flows_per_src', 'bytes_per_src', 'packets_per_src',
                'bytes_per_flow', 'packets_per_flow',
                'src_port_diversity', 'dst_port_diversity',
                'traffic_concentration', 'port_attack_breadth',
                'avg_src_activity', 'bytes_per_packet',
                # 二值特徵
                'is_ddos_target', 'is_scan_target', 'is_high_receiver',
                'is_likely_server', 'is_abnormal_pattern',
                'is_port_concentrated', 'is_multi_port_attack',
                # 對數特徵
                'log_unique_srcs', 'log_flow_count', 'log_total_bytes',
            ]

    def _get_default_thresholds(self):
        """獲取預設閾值"""
        return {
            'ddos_min_srcs': 100,
            'ddos_max_flows_per_src': 5,
            'ddos_max_avg_bytes': 1000,
            'scan_min_dst_ports': 50,
            'scan_max_avg_bytes': 5000,
            'scan_max_packets_per_flow': 10,
            'high_receiver_min_bytes': 100_000_000,
            'high_receiver_min_bytes_per_src': 1_000_000,
            'server_min_srcs': 10,
            'server_max_dst_ports': 5,
            'server_max_dst_port_diversity': 0.1,
            'server_min_flows_per_src': 5,
            'abnormal_max_srcs': 5,
            'abnormal_min_flow_count': 1000,
            'abnormal_min_src_port_diversity': 0.8,
            'port_concentrated_max_dst_ports': 3,
            'multi_port_min_dst_ports': 20,
            'multi_port_min_flow_count': 500
        }

    def extract_features(self, record: Dict) -> np.ndarray:
        """
        從單筆 by_dst 聚合記錄提取特徵

        Args:
            record: netflow_stats_5m_by_dst 的單筆記錄

        Returns:
            特徵向量
        """
        # 基礎特徵
        unique_srcs = record.get('unique_srcs', 0)
        unique_src_ports = record.get('unique_src_ports', 0)
        unique_dst_ports = record.get('unique_dst_ports', 0)
        flow_count = record.get('flow_count', 0)
        total_bytes = record.get('total_bytes', 0)
        total_packets = record.get('total_packets', 0)
        avg_bytes = record.get('avg_bytes', 0)
        max_bytes = record.get('max_bytes', 0)

        # 防止除以零
        unique_srcs_safe = max(unique_srcs, 1)
        flow_count_safe = max(flow_count, 1)

        # 衍生特徵
        flows_per_src = flow_count / unique_srcs_safe
        bytes_per_src = total_bytes / unique_srcs_safe
        packets_per_src = total_packets / unique_srcs_safe
        bytes_per_flow = total_bytes / flow_count_safe
        packets_per_flow = total_packets / flow_count_safe
        src_port_diversity = unique_src_ports / unique_srcs_safe
        dst_port_diversity = unique_dst_ports / unique_srcs_safe
        traffic_concentration = total_bytes / unique_srcs_safe

        # 進階衍生特徵
        total_packets_safe = max(total_packets, 1)
        port_attack_breadth = unique_dst_ports / flow_count_safe
        avg_src_activity = flow_count / unique_srcs_safe
        bytes_per_packet = total_bytes / total_packets_safe

        # 取得閾值設定（優先使用 thresholds_by_dst，否則使用預設值）
        if self.config and hasattr(self.config, 'thresholds_by_dst'):
            thresholds = self.config.thresholds_by_dst
            # 如果 thresholds_by_dst 為空，使用預設值
            if not thresholds:
                thresholds = self._get_default_thresholds()
        else:
            thresholds = self._get_default_thresholds()

        # 二值行為特徵
        # 1. DDoS 攻擊目標檢測
        is_ddos_target = 1 if (
            unique_srcs > thresholds['ddos_min_srcs'] and
            flows_per_src < thresholds['ddos_max_flows_per_src'] and
            avg_bytes < thresholds['ddos_max_avg_bytes']
        ) else 0

        # 2. 被掃描目標檢測
        is_scan_target = 1 if (
            unique_dst_ports > thresholds['scan_min_dst_ports'] and
            avg_bytes < thresholds['scan_max_avg_bytes'] and
            packets_per_flow < thresholds['scan_max_packets_per_flow']
        ) else 0

        # 3. 高流量接收檢測（可能的資料下載/外洩接收端）
        is_high_receiver = 1 if (
            total_bytes > thresholds['high_receiver_min_bytes'] and
            bytes_per_src > thresholds['high_receiver_min_bytes_per_src']
        ) else 0

        # 4. 服務器行為檢測（正常）
        is_likely_server = 1 if (
            unique_srcs > thresholds['server_min_srcs'] and
            unique_dst_ports <= thresholds['server_max_dst_ports'] and
            dst_port_diversity < thresholds['server_max_dst_port_diversity'] and
            flows_per_src > thresholds['server_min_flows_per_src']
        ) else 0

        # 5. 異常連線模式檢測（來源集中但流量分散）
        is_abnormal_pattern = 1 if (
            unique_srcs < thresholds['abnormal_max_srcs'] and
            flow_count > thresholds['abnormal_min_flow_count'] and
            src_port_diversity > thresholds['abnormal_min_src_port_diversity']
        ) else 0

        # 6. 端口集中檢測（正常服務）
        is_port_concentrated = 1 if (
            unique_dst_ports <= thresholds['port_concentrated_max_dst_ports']
        ) else 0

        # 7. 多端口攻擊檢測
        is_multi_port_attack = 1 if (
            unique_dst_ports > thresholds['multi_port_min_dst_ports'] and
            flow_count > thresholds['multi_port_min_flow_count'] and
            avg_bytes < thresholds['scan_max_avg_bytes']
        ) else 0

        # 對數特徵
        log_unique_srcs = np.log1p(unique_srcs)
        log_flow_count = np.log1p(flow_count)
        log_total_bytes = np.log1p(total_bytes)

        # 所有可能的特徵值（放在字典中）
        all_features = {
            # 基礎特徵
            'unique_srcs': unique_srcs,
            'unique_src_ports': unique_src_ports,
            'unique_dst_ports': unique_dst_ports,
            'flow_count': flow_count,
            'total_bytes': total_bytes,
            'total_packets': total_packets,
            'avg_bytes': avg_bytes,
            'max_bytes': max_bytes,
            # 衍生特徵
            'flows_per_src': flows_per_src,
            'bytes_per_src': bytes_per_src,
            'packets_per_src': packets_per_src,
            'bytes_per_flow': bytes_per_flow,
            'packets_per_flow': packets_per_flow,
            'src_port_diversity': src_port_diversity,
            'dst_port_diversity': dst_port_diversity,
            'traffic_concentration': traffic_concentration,
            'port_attack_breadth': port_attack_breadth,
            'avg_src_activity': avg_src_activity,
            'bytes_per_packet': bytes_per_packet,
            # 二值特徵
            'is_ddos_target': is_ddos_target,
            'is_scan_target': is_scan_target,
            'is_high_receiver': is_high_receiver,
            'is_likely_server': is_likely_server,
            'is_abnormal_pattern': is_abnormal_pattern,
            'is_port_concentrated': is_port_concentrated,
            'is_multi_port_attack': is_multi_port_attack,
            # 對數特徵
            'log_unique_srcs': log_unique_srcs,
            'log_flow_count': log_flow_count,
            'log_total_bytes': log_total_bytes,
        }

        # 根據 feature_names 構建特徵向量
        feature_vector = [all_features.get(name, 0) for name in self.feature_names]

        return np.array(feature_vector, dtype=np.float64)

    def extract_classification_features(self, record: Dict) -> Dict:
        """
        提取用於分類的完整特徵集（包含 port 特徵）

        Args:
            record: netflow_stats_3m_by_dst 記錄

        Returns:
            擴展的特徵字典
        """
        # 1. 獲取基礎特徵（轉換為字典）
        feature_vector = self.extract_features(record)
        features = {name: value for name, value in zip(self.feature_names, feature_vector)}

        # 2. 添加 top_ports 特徵
        port_features = self._extract_port_features(record)
        features.update(port_features)

        # 3. 速率特徵
        duration = 180  # 3 分鐘窗口
        features['flow_rate'] = features.get('flow_count', 0) / duration
        features['byte_rate'] = features.get('total_bytes', 0) / duration

        return features

    def _extract_port_features(self, record: Dict) -> Dict:
        """
        從 top_src_ports 和 top_dst_ports 提取端口特徵（DST 視角）

        Args:
            record: 聚合記錄，包含 top_src_ports 和 top_dst_ports

        Returns:
            端口特徵字典
        """
        port_features = {}

        # 獲取 top ports 數據
        top_src_ports = record.get('top_src_ports', {})
        top_dst_ports = record.get('top_dst_ports', {})
        flow_count = max(record.get('flow_count', 1), 1)

        # 轉換為列表格式
        src_ports_list = [(int(port), count) for port, count in top_src_ports.items()]
        dst_ports_list = [(int(port), count) for port, count in top_dst_ports.items()]

        # === 1. Port 集中度特徵 ===
        port_features['top_src_port_concentration'] = self._calculate_port_concentration(
            src_ports_list, flow_count
        )
        port_features['top_dst_port_concentration'] = self._calculate_port_concentration(
            dst_ports_list, flow_count
        )

        # === 2. Well-known/Ephemeral Port 比例 ===
        src_port_ratios = self._calculate_port_type_ratios(src_ports_list, flow_count)
        dst_port_ratios = self._calculate_port_type_ratios(dst_ports_list, flow_count)

        port_features['src_well_known_ratio'] = src_port_ratios['well_known']
        port_features['src_ephemeral_ratio'] = src_port_ratios['ephemeral']
        port_features['dst_well_known_ratio'] = dst_port_ratios['well_known']
        port_features['dst_ephemeral_ratio'] = dst_port_ratios['ephemeral']

        # === 3. Server 識別（DST 視角：作為接收端）===
        # 如果 dst_port 集中在 well-known ports，這個 IP 可能是 server
        port_features['is_likely_web_server'] = self._is_web_server_dst(dst_ports_list)
        port_features['is_likely_db_server'] = self._is_db_server_dst(dst_ports_list)
        port_features['is_likely_dns_server'] = self._is_dns_server_dst(dst_ports_list)

        # === 4. Port Entropy ===
        port_features['src_port_entropy'] = self._calculate_port_entropy(src_ports_list)
        port_features['dst_port_entropy'] = self._calculate_port_entropy(dst_ports_list)

        # === 5. 攻擊模式檢測 ===
        port_features['has_sequential_src_ports'] = self._has_sequential_ports(src_ports_list)
        port_features['high_risk_dst_ports_count'] = self._count_high_risk_ports(dst_ports_list)

        return port_features

    def _calculate_port_concentration(self, ports_list: List[tuple], flow_count: int) -> float:
        """計算端口集中度"""
        if not ports_list or flow_count == 0:
            return 0.0
        max_count = max(count for _, count in ports_list)
        return max_count / flow_count

    def _calculate_port_type_ratios(self, ports_list: List[tuple], flow_count: int) -> Dict:
        """計算不同類型端口的比例"""
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
            else:
                ephemeral_count += count

        return {
            'well_known': well_known_count / flow_count,
            'registered': registered_count / flow_count,
            'ephemeral': ephemeral_count / flow_count
        }

    def _is_web_server_dst(self, dst_ports: List[tuple]) -> int:
        """檢測是否為 Web Server（DST 視角：接收端）"""
        if not dst_ports:
            return 0
        web_ports = {80, 443, 8080, 8443}
        top_dst_port = dst_ports[0][0] if dst_ports else None
        return 1 if top_dst_port in web_ports else 0

    def _is_db_server_dst(self, dst_ports: List[tuple]) -> int:
        """檢測是否為資料庫 Server（DST 視角）"""
        if not dst_ports:
            return 0
        db_ports = {3306, 5432, 1521, 1433, 27017, 6379}
        top_dst_port = dst_ports[0][0] if dst_ports else None
        return 1 if top_dst_port in db_ports else 0

    def _is_dns_server_dst(self, dst_ports: List[tuple]) -> int:
        """檢測是否為 DNS Server（DST 視角）"""
        if not dst_ports:
            return 0
        top_dst_port = dst_ports[0][0] if dst_ports else None
        return 1 if top_dst_port == 53 else 0

    def _calculate_port_entropy(self, ports_list: List[tuple]) -> float:
        """計算端口熵值"""
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
        """檢測連續端口（掃描特徵）"""
        if len(ports_list) < 3:
            return 0
        ports = sorted([port for port, _ in ports_list])
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
        """計算高風險端口數量"""
        high_risk_ports = {21, 23, 135, 139, 445, 3389, 5900, 1433}
        ports = {port for port, _ in ports_list}
        return len(ports & high_risk_ports)

    def extract_features_batch(self, records: List[Dict]) -> np.ndarray:
        """
        批量提取特徵

        Args:
            records: netflow_stats_5m_by_dst 記錄列表

        Returns:
            特徵矩陣 (n_samples, n_features)
        """
        if not records:
            return np.array([])

        features_list = []
        for record in records:
            try:
                features = self.extract_features(record)
                features_list.append(features)
            except Exception as e:
                # 記錄錯誤但繼續處理
                print(f"Warning: Failed to extract features from record: {e}")
                continue

        if not features_list:
            return np.array([])

        return np.array(features_list, dtype=np.float64)

    def get_feature_names(self) -> List[str]:
        """返回特徵名稱列表"""
        return self.feature_names.copy()

    def get_n_features(self) -> int:
        """返回特徵數量"""
        return len(self.feature_names)


# ========== 測試 ==========

def test_feature_extraction():
    """測試特徵提取"""
    print("=" * 70)
    print("測試 Dst 視角特徵提取")
    print("=" * 70)

    engineer = FeatureEngineerDst()

    # 測試樣本 1: 正常 Web 服務器
    normal_server = {
        'dst_ip': '192.168.10.100',
        'time_bucket': '2025-11-17T10:00:00.000Z',
        'unique_srcs': 50,
        'unique_src_ports': 150,
        'unique_dst_ports': 2,  # 只開放 80, 443
        'flow_count': 500,
        'total_bytes': 5000000,
        'total_packets': 3500,
        'avg_bytes': 10000,
        'max_bytes': 50000
    }

    # 測試樣本 2: DDoS 目標
    ddos_target = {
        'dst_ip': '192.168.10.200',
        'time_bucket': '2025-11-17T10:00:00.000Z',
        'unique_srcs': 500,      # 大量來源
        'unique_src_ports': 800,
        'unique_dst_ports': 5,
        'flow_count': 50000,     # 大量連線
        'total_bytes': 1000000,  # 小流量
        'total_packets': 50000,
        'avg_bytes': 20,         # 小封包（SYN flood）
        'max_bytes': 100
    }

    # 測試樣本 3: 被掃描目標
    scan_target = {
        'dst_ip': '192.168.10.150',
        'time_bucket': '2025-11-17T10:00:00.000Z',
        'unique_srcs': 1,
        'unique_src_ports': 500,  # 大量來源端口（掃描特徵）
        'unique_dst_ports': 1000, # 大量目標端口被探測
        'flow_count': 1000,
        'total_bytes': 500000,
        'total_packets': 1000,
        'avg_bytes': 500,         # 小封包
        'max_bytes': 1000
    }

    print("\n1. 正常 Web 服務器:")
    features = engineer.extract_features(normal_server)
    print(f"   unique_srcs: {features[0]:.0f}")
    print(f"   unique_src_ports: {features[1]:.0f}")
    print(f"   flow_count: {features[3]:.0f}")
    print(f"   avg_bytes: {features[6]:.0f}")
    print(f"   flows_per_src: {features[8]:.2f}")
    print(f"   bytes_per_src: {features[9]:.0f}")

    print("\n2. DDoS 目標:")
    features = engineer.extract_features(ddos_target)
    print(f"   unique_srcs: {features[0]:.0f} ⚠️ 異常高")
    print(f"   unique_src_ports: {features[1]:.0f}")
    print(f"   flow_count: {features[3]:.0f} ⚠️ 異常高")
    print(f"   avg_bytes: {features[6]:.0f} ⚠️ 異常低（小封包）")
    print(f"   flows_per_src: {features[8]:.2f}")
    print(f"   bytes_per_src: {features[9]:.0f} ⚠️ 異常低")

    print("\n3. 被掃描目標:")
    features = engineer.extract_features(scan_target)
    print(f"   unique_srcs: {features[0]:.0f}")
    print(f"   unique_src_ports: {features[1]:.0f} ⚠️ 異常高（掃描特徵）")
    print(f"   unique_dst_ports: {features[2]:.0f} ⚠️ 異常高（被掃描）")
    print(f"   flow_count: {features[3]:.0f}")
    print(f"   avg_bytes: {features[6]:.0f}")

    print("\n批量提取測試:")
    records = [normal_server, ddos_target, scan_target]
    batch_features = engineer.extract_features_batch(records)
    print(f"✓ 成功提取 {batch_features.shape[0]} 筆記錄的特徵")
    print(f"✓ 特徵維度: {batch_features.shape[1]}")
    print(f"✓ 特徵數量與定義一致: {batch_features.shape[1] == engineer.get_n_features()}")

    print("\n特徵名稱:")
    for i, name in enumerate(engineer.get_feature_names()[:8]):
        print(f"  {i+1}. {name}")
    print("  ...")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    test_feature_extraction()
