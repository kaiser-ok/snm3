#!/usr/bin/env python3
"""
實時異常檢測腳本（聚合版）

將同一 IP 的多個異常時間桶聚合顯示
"""

import sys
import argparse
import time
import warnings
from datetime import datetime
from collections import defaultdict

# 忽略 Elasticsearch 安全警告
warnings.filterwarnings('ignore', message='.*Elasticsearch built-in security features.*')

from nad.utils import load_config
from nad.ml import OptimizedIsolationForest


def aggregate_anomalies_by_ip(anomalies):
    """將異常按 IP 聚合"""
    ip_anomalies = defaultdict(list)

    for anomaly in anomalies:
        ip = anomaly['src_ip']
        ip_anomalies[ip].append(anomaly)

    # 為每個 IP 計算聚合統計
    aggregated = []
    for ip, records in ip_anomalies.items():
        # 使用最高異常分數
        max_score_record = max(records, key=lambda x: x['anomaly_score'])

        agg = {
            'src_ip': ip,
            'occurrence_count': len(records),  # 異常出現次數
            'max_anomaly_score': max(r['anomaly_score'] for r in records),
            'avg_anomaly_score': sum(r['anomaly_score'] for r in records) / len(records),
            'total_flow_count': sum(r['flow_count'] for r in records),
            'avg_flow_count': sum(r['flow_count'] for r in records) / len(records),
            'max_unique_dsts': max(r['unique_dsts'] for r in records),
            'avg_bytes': sum(r['avg_bytes'] for r in records) / len(records),
            'total_bytes': sum(r['total_bytes'] for r in records),
            'time_buckets': [r['time_bucket'] for r in records],
            'confidence': max_score_record['confidence'],
            'features': max_score_record['features']
        }
        aggregated.append(agg)

    # 按最高異常分數排序
    aggregated.sort(key=lambda x: x['max_anomaly_score'], reverse=True)

    return aggregated


def print_aggregated_anomalies(anomalies, top_n=20):
    """打印聚合後的異常結果"""
    if not anomalies:
        print("✅ 未發現異常\n")
        return

    print(f"\n⚠️  發現 {len(anomalies)} 個異常 IP\n")
    print(f"{'='*120}")
    print(f"{'排名':<6} {'IP地址':<17} {'出現次數':<10} {'最高分數':<12} {'平均分數':<12} {'總連線數':<12} {'目的地':<10} {'總流量(MB)':<15}")
    print(f"{'='*120}")

    for i, anomaly in enumerate(anomalies[:top_n], 1):
        total_mb = anomaly['total_bytes'] / 1024 / 1024
        print(f"{i:<6} "
              f"{anomaly['src_ip']:<17} "
              f"{anomaly['occurrence_count']:<10} "
              f"{anomaly['max_anomaly_score']:< 12.4f} "
              f"{anomaly['avg_anomaly_score']:< 12.4f} "
              f"{anomaly['total_flow_count']:< 12,} "
              f"{anomaly['max_unique_dsts']:< 10} "
              f"{total_mb:< 15.2f}")

    print(f"{'='*120}\n")


def analyze_aggregated_anomalies(anomalies):
    """分析聚合後的異常模式"""
    if not anomalies:
        return

    print("📊 異常模式分析\n")

    # 統計行為模式
    high_conn = sum(1 for a in anomalies if a['features']['is_high_connection'])
    scanning = sum(1 for a in anomalies if a['features']['is_scanning_pattern'])
    small_packet = sum(1 for a in anomalies if a['features']['is_small_packet'])
    large_flow = sum(1 for a in anomalies if a['features']['is_large_flow'])
    persistent = sum(1 for a in anomalies if a['occurrence_count'] >= 3)

    print(f"行為統計:")
    print(f"  高連線數: {high_conn} 個IP")
    print(f"  掃描模式: {scanning} 個IP")
    print(f"  小封包: {small_packet} 個IP")
    print(f"  大流量: {large_flow} 個IP")
    print(f"  持續異常 (≥3次): {persistent} 個IP\n")

    # Top 異常詳細分析
    print("🔍 Top 5 異常 IP 詳細分析:\n")

    for i, anomaly in enumerate(anomalies[:5], 1):
        print(f"{i}. {anomaly['src_ip']}")
        print(f"   異常出現: {anomaly['occurrence_count']} 次")
        print(f"   時間範圍: {anomaly['time_buckets'][0]} → {anomaly['time_buckets'][-1]}")
        print(f"   最高異常分數: {anomaly['max_anomaly_score']:.4f}")
        print(f"   平均異常分數: {anomaly['avg_anomaly_score']:.4f}")
        print(f"   總連線數: {anomaly['total_flow_count']:,}")
        print(f"   平均每次連線數: {anomaly['avg_flow_count']:.0f}")
        print(f"   最大目的地數: {anomaly['max_unique_dsts']}")
        print(f"   總流量: {anomaly['total_bytes'] / 1024 / 1024:.2f} MB")
        print(f"   平均流量/連線: {anomaly['avg_bytes']:.0f} bytes")

        # 行為特徵
        features = []
        if anomaly['features']['is_high_connection']:
            features.append('高連線數')
        if anomaly['features']['is_scanning_pattern']:
            features.append('掃描模式')
        if anomaly['features']['is_small_packet']:
            features.append('小封包')
        if anomaly['features']['is_large_flow']:
            features.append('大流量')
        if anomaly['occurrence_count'] >= 3:
            features.append('持續異常')

        if features:
            print(f"   行為特徵: {', '.join(features)}")

        print()


def main():
    parser = argparse.ArgumentParser(
        description='實時異常檢測 - IP 聚合版'
    )
    parser.add_argument(
        '--minutes',
        type=int,
        default=10,
        help='檢測最近 N 分鐘的數據（默認: 10）'
    )
    parser.add_argument(
        '--config',
        type=str,
        default='nad/config.yaml',
        help='配置文件路徑'
    )
    parser.add_argument(
        '--top',
        type=int,
        default=20,
        help='顯示前 N 個異常 IP（默認: 20）'
    )
    parser.add_argument(
        '--loop',
        action='store_true',
        help='持續運行檢測'
    )
    parser.add_argument(
        '--interval',
        type=int,
        default=60,
        help='循環檢測間隔（秒，默認: 60）'
    )

    args = parser.parse_args()

    # 加載配置
    print("📋 加載配置...")
    try:
        config = load_config(args.config)
        print("✓ 配置加載成功")
    except Exception as e:
        print(f"❌ 配置加載失敗: {e}")
        sys.exit(1)

    # 創建檢測器
    print("🤖 加載模型...")
    detector = OptimizedIsolationForest(config)

    # 檢查模型狀態
    model_info = detector.get_model_info()
    if model_info['status'] != 'trained':
        print("❌ 模型尚未訓練")
        print("   請先執行: python3 train_isolation_forest.py --days 7")
        sys.exit(1)

    print("✓ 模型加載成功\n")
    print("模型信息:")
    print(f"  樹的數量: {model_info['n_estimators']}")
    print(f"  特徵數量: {model_info['n_features']}")
    print(f"  污染率: {model_info['contamination']}\n")

    # 執行檢測
    detection_num = 0
    try:
        while True:
            detection_num += 1

            print("=" * 100)
            print(f"實時異常檢測（IP聚合） - 分析最近 {args.minutes} 分鐘")
            print("=" * 100)

            if args.loop:
                print(f"🔍 檢測 #{detection_num} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print("-" * 100)

            # 檢測異常
            start_time = time.time()
            raw_anomalies = detector.detect_realtime(minutes=args.minutes)
            elapsed = time.time() - start_time

            print(f"\n⏱️  檢測耗時: {elapsed:.2f} 秒")

            if raw_anomalies:
                # 聚合異常
                aggregated_anomalies = aggregate_anomalies_by_ip(raw_anomalies)

                # 顯示結果
                print_aggregated_anomalies(aggregated_anomalies, args.top)
                analyze_aggregated_anomalies(aggregated_anomalies)
            else:
                print("\n✅ 未發現異常\n")

            # 如果不是循環模式，結束
            if not args.loop:
                break

            # 等待下次檢測
            print(f"⏳ {args.interval} 秒後執行下次檢測...\n")
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n\n⏹️  檢測已停止")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ 檢測失敗: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
