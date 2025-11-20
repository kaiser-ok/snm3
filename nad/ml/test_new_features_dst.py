#!/usr/bin/env python3
"""
測試新增的 Dest IP 特徵
"""

import numpy as np
from feature_engineer_dst import FeatureEngineerDst


def test_new_features():
    """測試新增的特徵是否正確計算"""
    print("=" * 80)
    print("詳細測試 Dest IP 新增特徵")
    print("=" * 80)

    engineer = FeatureEngineerDst()

    # 測試樣本 1: 正常 Web 服務器
    print("\n【測試 1】正常 Web 服務器:")
    print("-" * 80)
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

    features = engineer.extract_features(normal_server)
    feature_names = engineer.get_feature_names()

    print(f"基礎特徵:")
    print(f"  unique_srcs: {features[0]:.0f}")
    print(f"  flow_count: {features[3]:.0f}")
    print(f"  unique_dst_ports: {features[2]:.0f}")
    print(f"\n進階衍生特徵:")
    print(f"  port_attack_breadth: {features[16]:.4f}")
    print(f"  avg_src_activity: {features[17]:.2f}")
    print(f"  bytes_per_packet: {features[18]:.2f}")
    print(f"\n二值行為特徵:")
    print(f"  is_ddos_target: {int(features[19])} {'⚠️ DDoS' if features[19] else '✓ 正常'}")
    print(f"  is_scan_target: {int(features[20])} {'⚠️ 被掃描' if features[20] else '✓ 正常'}")
    print(f"  is_high_receiver: {int(features[21])} {'⚠️ 高流量' if features[21] else '✓ 正常'}")
    print(f"  is_likely_server: {int(features[22])} {'✓ 服務器' if features[22] else '✗ 非服務器'}")
    print(f"  is_abnormal_pattern: {int(features[23])} {'⚠️ 異常' if features[23] else '✓ 正常'}")
    print(f"  is_port_concentrated: {int(features[24])} {'✓ 端口集中' if features[24] else '✗ 端口分散'}")
    print(f"  is_multi_port_attack: {int(features[25])} {'⚠️ 多端口攻擊' if features[25] else '✓ 正常'}")
    print(f"\n對數特徵:")
    print(f"  log_unique_srcs: {features[26]:.4f}")
    print(f"  log_flow_count: {features[27]:.4f}")
    print(f"  log_total_bytes: {features[28]:.4f}")

    # 測試樣本 2: DDoS 目標
    print("\n\n【測試 2】DDoS 攻擊目標:")
    print("-" * 80)
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

    features = engineer.extract_features(ddos_target)
    print(f"基礎特徵:")
    print(f"  unique_srcs: {features[0]:.0f} ⚠️ 異常高")
    print(f"  flow_count: {features[3]:.0f} ⚠️ 異常高")
    print(f"  avg_bytes: {features[6]:.0f} ⚠️ 異常低（小封包）")
    print(f"\n衍生特徵:")
    print(f"  flows_per_src: {features[8]:.2f} ⚠️ 每個來源連線數")
    print(f"  bytes_per_src: {features[9]:.0f} ⚠️ 異常低")
    print(f"\n二值行為特徵:")
    print(f"  is_ddos_target: {int(features[19])} {'⚠️ DDoS 目標！' if features[19] else '✓ 正常'}")
    print(f"  is_scan_target: {int(features[20])} {'⚠️ 被掃描' if features[20] else '✓ 正常'}")
    print(f"  is_high_receiver: {int(features[21])} {'⚠️ 高流量' if features[21] else '✓ 正常'}")
    print(f"  is_likely_server: {int(features[22])} {'✓ 服務器' if features[22] else '✗ 非服務器'}")
    print(f"  is_abnormal_pattern: {int(features[23])} {'⚠️ 異常' if features[23] else '✓ 正常'}")

    # 測試樣本 3: 被掃描目標
    print("\n\n【測試 3】被掃描目標:")
    print("-" * 80)
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

    features = engineer.extract_features(scan_target)
    print(f"基礎特徵:")
    print(f"  unique_srcs: {features[0]:.0f}")
    print(f"  unique_src_ports: {features[1]:.0f} ⚠️ 異常高（掃描特徵）")
    print(f"  unique_dst_ports: {features[2]:.0f} ⚠️ 異常高（被掃描）")
    print(f"\n進階特徵:")
    print(f"  port_attack_breadth: {features[16]:.4f} ⚠️ 端口攻擊廣度高")
    print(f"  src_port_diversity: {features[13]:.2f} ⚠️ 來源端口分散")
    print(f"\n二值行為特徵:")
    print(f"  is_ddos_target: {int(features[19])} {'⚠️ DDoS' if features[19] else '✓ 正常'}")
    print(f"  is_scan_target: {int(features[20])} {'⚠️ 被掃描目標！' if features[20] else '✓ 正常'}")
    print(f"  is_multi_port_attack: {int(features[25])} {'⚠️ 多端口攻擊！' if features[25] else '✓ 正常'}")
    print(f"  is_port_concentrated: {int(features[24])} {'✓ 端口集中' if features[24] else '✗ 端口分散'}")

    # 測試樣本 4: 高流量接收（資料外洩接收端）
    print("\n\n【測試 4】高流量接收目標（可能的資料外洩）:")
    print("-" * 80)
    high_receiver = {
        'dst_ip': '203.0.113.50',
        'time_bucket': '2025-11-17T10:00:00.000Z',
        'unique_srcs': 5,
        'unique_src_ports': 10,
        'unique_dst_ports': 1,
        'flow_count': 100,
        'total_bytes': 500_000_000,  # 500 MB
        'total_packets': 400000,
        'avg_bytes': 5000000,
        'max_bytes': 10000000
    }

    features = engineer.extract_features(high_receiver)
    print(f"基礎特徵:")
    print(f"  unique_srcs: {features[0]:.0f}")
    print(f"  total_bytes: {features[4]/1024/1024:.2f} MB ⚠️ 高流量")
    print(f"\n衍生特徵:")
    print(f"  bytes_per_src: {features[9]/1024/1024:.2f} MB ⚠️ 每個來源流量大")
    print(f"\n二值行為特徵:")
    print(f"  is_ddos_target: {int(features[19])} {'⚠️ DDoS' if features[19] else '✓ 正常'}")
    print(f"  is_high_receiver: {int(features[21])} {'⚠️ 高流量接收！' if features[21] else '✓ 正常'}")
    print(f"  is_abnormal_pattern: {int(features[23])} {'⚠️ 異常模式' if features[23] else '✓ 正常'}")

    # 特徵數量驗證
    print("\n\n" + "=" * 80)
    print("特徵數量統計:")
    print("=" * 80)
    print(f"總特徵數: {len(features)} (預期: 29)")
    print(f"特徵名稱數: {len(feature_names)}")
    print(f"一致性檢查: {'✓ 通過' if len(features) == len(feature_names) == 29 else '✗ 失敗'}")

    print("\n完整特徵列表:")
    for i, name in enumerate(feature_names):
        category = ""
        if i < 8:
            category = "基礎"
        elif i < 16:
            category = "衍生"
        elif i < 19:
            category = "進階"
        elif i < 26:
            category = "二值"
        else:
            category = "對數"
        print(f"  {i+1:2d}. [{category}] {name}")

    print("\n" + "=" * 80)
    print("測試完成！")
    print("=" * 80)


if __name__ == "__main__":
    test_new_features()
