#!/usr/bin/env python3
"""
實時異常檢測腳本

使用訓練好的 Isolation Forest 進行實時異常檢測
並使用分類器判斷異常類型
"""

import sys
import argparse
import time
import warnings
from datetime import datetime, timezone

# 忽略 Elasticsearch 安全警告
warnings.filterwarnings('ignore', message='.*Elasticsearch built-in security features.*')

from nad.utils import load_config
from nad.ml import OptimizedIsolationForest
from nad.ml.anomaly_classifier import AnomalyClassifier
from nad.device_classifier import DeviceClassifier
from nad.anomaly_logger import AnomalyLogger


def print_anomalies(anomalies, top_n=20):
    """打印異常結果"""
    if not anomalies:
        print("✅ 未發現異常\n")
        return

    # 初始化设备分类器
    device_classifier = DeviceClassifier()

    print(f"\n⚠️  發現 {len(anomalies)} 個異常\n")
    print(f"{'='*100}")
    print(f"{'排名':<6} {'設備':<6} {'IP地址':<17} {'異常分數':<12} {'置信度':<10} {'連線數':<10} {'目的地':<8} {'平均流量':<15}")
    print(f"{'='*100}")

    for i, anomaly in enumerate(anomalies[:top_n], 1):
        # 获取设备类型
        device_type = device_classifier.classify(anomaly['src_ip'])
        device_emoji = device_classifier.get_type_emoji(device_type)

        print(f"{i:<6} "
              f"{device_emoji:<6} "
              f"{anomaly['src_ip']:<17} "
              f"{anomaly['anomaly_score']:< 12.4f} "
              f"{anomaly['confidence']:< 10.2f} "
              f"{anomaly['flow_count']:< 10,} "
              f"{anomaly['unique_dsts']:< 8} "
              f"{anomaly['avg_bytes']:< 15,.0f}")

    print(f"{'='*100}\n")


def analyze_anomalies(anomalies):
    """分析異常模式"""
    if not anomalies:
        return

    print("📊 異常模式分析\n")

    # 統計行為模式
    high_conn = sum(1 for a in anomalies if a['features']['is_high_connection'])
    scanning = sum(1 for a in anomalies if a['features']['is_scanning_pattern'])
    small_packet = sum(1 for a in anomalies if a['features']['is_small_packet'])
    large_flow = sum(1 for a in anomalies if a['features']['is_large_flow'])

    print(f"行為統計:")
    print(f"  高連線數: {high_conn} 個IP")
    print(f"  掃描模式: {scanning} 個IP")
    print(f"  小封包: {small_packet} 個IP")
    print(f"  大流量: {large_flow} 個IP\n")

    # Top 異常詳細分析（加入分類）
    print("🔍 Top 5 異常詳細分析:\n")

    # 創建分類器
    classifier = AnomalyClassifier()

    for i, anomaly in enumerate(anomalies[:5], 1):
        # 計算時間差並轉換為本地時間
        from datetime import timedelta
        anomaly_dt_utc = datetime.fromisoformat(anomaly['time_bucket'].replace('Z', '+00:00'))
        local_tz = timezone(timedelta(hours=8))
        anomaly_dt_local = anomaly_dt_utc.astimezone(local_tz)

        now = datetime.now(timezone.utc)
        time_diff_minutes = (now - anomaly_dt_utc).total_seconds() / 60

        print(f"{i}. {anomaly['src_ip']}")
        print(f"   時間: {anomaly_dt_local.strftime('%Y-%m-%d %H:%M:%S')} (本地時間, {time_diff_minutes:.1f} 分鐘前)")
        print(f"   異常分數: {anomaly['anomaly_score']:.4f} (置信度: {anomaly['confidence']:.2f})")
        print(f"   連線數: {anomaly['flow_count']:,}")
        print(f"   不同目的地數量: {anomaly['unique_dsts']}")
        print(f"   不同源通訊埠數量: {anomaly.get('unique_src_ports', 'N/A')}")
        print(f"   不同目的通訊埠數量: {anomaly.get('unique_dst_ports', 'N/A')}")
        print(f"   總流量: {anomaly['total_bytes'] / 1024 / 1024:.2f} MB")
        print(f"   平均流量: {anomaly['avg_bytes']:,.0f} bytes")

        # 行為標記（保留，作為輔助信息）
        behaviors = []
        if anomaly['features']['is_high_connection']:
            behaviors.append("高連線數")
        if anomaly['features']['is_scanning_pattern']:
            behaviors.append("掃描模式")
        if anomaly['features']['is_small_packet']:
            behaviors.append("小封包")
        if anomaly['features']['is_large_flow']:
            behaviors.append("大流量")

        if behaviors:
            print(f"   行為特徵: {', '.join(behaviors)}")

        # ========== 新增：威脅分類 ==========
        try:
            # 準備上下文
            context = {
                'timestamp': datetime.fromisoformat(anomaly['time_bucket'].replace('Z', '+00:00')),
                'src_ip': anomaly['src_ip'],
                'anomaly_score': anomaly['anomaly_score']
            }

            # 進行分類
            classification = classifier.classify(anomaly['features'], context)

            # 顯示分類結果
            severity_emoji = classifier.get_severity_emoji(classification['severity'])
            print(f"\n   {severity_emoji} 威脅分類: {classification['class_name']} ({classification['class_name_en']})")
            print(f"      置信度: {classification['confidence']:.0%}")
            print(f"      嚴重性: {classification['severity']} | 優先級: {classification['priority']}")
            print(f"      描述: {classification['description']}")

            # 關鍵指標
            if classification['indicators']:
                print(f"      關鍵指標:")
                for indicator in classification['indicators'][:3]:  # 最多顯示3個
                    print(f"         • {indicator}")

            # 響應建議（簡化顯示）
            if classification['response']:
                print(f"      建議行動: {classification['response'][0]}")  # 只顯示第一個

        except Exception as e:
            print(f"   ⚠️  分類失敗: {e}")

        print()


def single_detection(detector, minutes, exclude_servers=False):
    """單次檢測"""
    # 計算並顯示查詢時間範圍
    from datetime import datetime, timedelta, timezone

    end_time_utc = datetime.now(timezone.utc)
    start_time_utc = end_time_utc - timedelta(minutes=minutes)

    # 轉換為本地時間 (UTC+8)
    local_tz = timezone(timedelta(hours=8))
    end_time_local = end_time_utc.astimezone(local_tz)
    start_time_local = start_time_utc.astimezone(local_tz)

    print(f"\n{'='*100}")
    print(f"實時異常檢測 - 分析最近 {minutes} 分鐘")
    if exclude_servers:
        print("(過濾服務器回應流量)")
    print(f"{'='*100}")
    print(f"\n查詢時間範圍:")
    print(f"  開始: {start_time_local.strftime('%Y-%m-%d %H:%M:%S')} (本地時間 UTC+8)")
    print(f"  結束: {end_time_local.strftime('%Y-%m-%d %H:%M:%S')} (本地時間 UTC+8)")
    print(f"  當前: {end_time_local.strftime('%Y-%m-%d %H:%M:%S')} (本地時間 UTC+8)\n")

    start_time = time.time()

    try:
        # 檢查數據可用性
        from elasticsearch import Elasticsearch
        es = Elasticsearch([detector.config.es_host], request_timeout=30)
        count_query = {
            'query': {
                'range': {
                    'time_bucket': {
                        'gte': start_time_utc.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                        'lte': end_time_utc.strftime('%Y-%m-%dT%H:%M:%S.000Z')
                    }
                }
            }
        }
        count_response = es.count(index=detector.config.es_aggregated_index, body=count_query)
        available_records = count_response['count']

        if available_records == 0:
            print(f"⚠️  警告: 在指定時間範圍內沒有可用數據")
            print(f"   原因: 聚合索引是 5 分鐘一個時間桶，最新數據可能還在處理中")
            print(f"   建議: 使用 --minutes 10 或更長的時間窗口\n")
        else:
            print(f"📊 可用數據: {available_records:,} 筆記錄\n")

        anomalies = detector.predict_realtime(recent_minutes=minutes)

        # 過濾服務器回應（如果啟用）
        if exclude_servers:
            original_count = len(anomalies)
            anomalies = [a for a in anomalies if not a.get('is_likely_server_response', 0)]
            filtered_count = original_count - len(anomalies)
            if filtered_count > 0:
                print(f"🚫 過濾掉 {filtered_count} 個服務器回應流量\n")

        elapsed = time.time() - start_time
        print(f"⏱️  檢測耗時: {elapsed:.2f} 秒\n")

        # 顯示結果
        print_anomalies(anomalies)

        # 分析異常
        analyze_anomalies(anomalies)

        return anomalies

    except Exception as e:
        print(f"❌ 檢測失敗: {e}")
        import traceback
        traceback.print_exc()
        return []


def continuous_monitoring(detector, interval_minutes, window_minutes, exclude_servers=False):
    """持續監控模式"""
    print(f"\n{'='*100}")
    print(f"持續監控模式")
    if exclude_servers:
        print("(過濾服務器回應流量)")
    print(f"{'='*100}\n")
    print(f"檢測間隔: 每 {interval_minutes} 分鐘")
    print(f"分析窗口: 最近 {window_minutes} 分鐘")
    print(f"異常記錄: 自動寫入 Elasticsearch")
    print(f"按 Ctrl+C 停止\n")
    print(f"{'='*100}\n")

    iteration = 0

    # 創建分類器（用於威脅分類）
    classifier = AnomalyClassifier()
    device_classifier = DeviceClassifier()

    # 創建異常記錄日誌器
    anomaly_logger = AnomalyLogger(
        es_host=detector.config.es_host if detector.config else 'localhost:9200'
    )

    try:
        while True:
            iteration += 1
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            print(f"\n🔍 檢測 #{iteration} - {current_time}")
            print(f"{'-'*100}")

            anomalies = detector.predict_realtime(recent_minutes=window_minutes)

            # 過濾服務器回應（如果啟用）
            if exclude_servers and anomalies:
                anomalies = [a for a in anomalies if not a.get('is_likely_server_response', 0)]

            if anomalies:
                # 只顯示高置信度異常
                high_conf = [a for a in anomalies if a['confidence'] > 0.6]
                low_conf_count = len(anomalies) - len(high_conf)

                if high_conf:
                    print(f"\n⚠️  發現 {len(high_conf)} 個高置信度異常:\n")

                    # 顯示前 10 個異常，包含分類信息
                    for i, anomaly in enumerate(high_conf[:10], 1):
                        # 获取设备类型
                        device_type = device_classifier.classify(anomaly['src_ip'])
                        device_emoji = device_classifier.get_type_emoji(device_type)

                        # 基本信息
                        print(f"  {i:2}. {device_emoji} {anomaly['src_ip']:15} | "
                              f"分數: {anomaly['anomaly_score']:.4f} | "
                              f"置信度: {anomaly['confidence']:.2f} | "
                              f"{anomaly['flow_count']:,} 連線 | "
                              f"{anomaly['unique_dsts']:3} 目的地", end='')

                        # 威脅分類
                        try:
                            context = {
                                'timestamp': datetime.fromisoformat(anomaly['time_bucket'].replace('Z', '+00:00')),
                                'src_ip': anomaly['src_ip'],
                                'anomaly_score': anomaly['anomaly_score']
                            }
                            classification = classifier.classify(anomaly['features'], context)

                            # 簡短的分類信息（單行顯示）
                            severity_emoji = classifier.get_severity_emoji(classification['severity'])
                            print(f" | {severity_emoji} {classification['class_name']:10} ({classification['confidence']:.0%})")
                        except:
                            print()  # 如果分類失敗，只換行

                    # 如果有超過 10 個異常，顯示還有多少個
                    if len(high_conf) > 10:
                        print(f"\n  ... 還有 {len(high_conf) - 10} 個異常未顯示")

                    # 顯示被過濾的低置信度異常數量
                    if low_conf_count > 0:
                        print(f"\n  🔍 [Debug] 過濾掉 {low_conf_count} 個低置信度異常 (≤ 0.6)")

                    # 📝 自動記錄高置信度異常到 ES
                    try:
                        anomaly_logger.log_anomalies_batch(
                            high_conf,
                            device_classifier=device_classifier,
                            classifier=classifier
                        )
                        print(f"\n  💾 已記錄 {len(high_conf)} 筆異常到 Elasticsearch")
                    except Exception as e:
                        print(f"\n  ⚠️  記錄異常失敗: {e}")

                else:
                    print(f"  ✓ 檢測到 {len(anomalies)} 個異常，但置信度較低 (≤ 0.6)")
            else:
                print("  ✅ 未發現異常")

            # 等待下一次檢測
            print(f"\n⏰ 下次檢測: {interval_minutes} 分鐘後...")
            time.sleep(interval_minutes * 60)

    except KeyboardInterrupt:
        print(f"\n\n{'='*100}")
        print("監控已停止")
        print(f"{'='*100}\n")


def main():
    parser = argparse.ArgumentParser(
        description='實時異常檢測'
    )
    parser.add_argument(
        '--minutes',
        type=int,
        default=10,
        help='分析最近 N 分鐘的數據（默認: 10）'
    )
    parser.add_argument(
        '--config',
        type=str,
        default='nad/config.yaml',
        help='配置文件路徑'
    )
    parser.add_argument(
        '--continuous',
        action='store_true',
        help='持續監控模式'
    )
    parser.add_argument(
        '--interval',
        type=int,
        default=5,
        help='持續監控時的檢測間隔（分鐘，默認: 5）'
    )
    parser.add_argument(
        '--exclude-servers',
        action='store_true',
        help='過濾掉可能的服務器回應流量（推薦使用）'
    )

    args = parser.parse_args()

    # 加載配置
    print(f"\n📋 加載配置...")
    try:
        config = load_config(args.config)
        print(f"✓ 配置加載成功")
    except Exception as e:
        print(f"❌ 配置加載失敗: {e}")
        sys.exit(1)

    # 創建檢測器並加載模型
    print(f"🤖 加載模型...")
    try:
        detector = OptimizedIsolationForest(config)
        detector._load_model()
        print(f"✓ 模型加載成功")

        model_info = detector.get_model_info()
        print(f"\n模型信息:")
        print(f"  樹的數量: {model_info['n_estimators']}")
        print(f"  特徵數量: {model_info['n_features']}")
        print(f"  污染率: {model_info['contamination']}")

    except FileNotFoundError as e:
        print(f"\n❌ 模型文件不存在")
        print(f"   請先運行訓練: python3 train_isolation_forest.py --days 7\n")
        sys.exit(1)
    except Exception as e:
        print(f"❌ 模型加載失敗: {e}")
        sys.exit(1)

    # 執行檢測
    if args.continuous:
        continuous_monitoring(detector, args.interval, args.minutes, args.exclude_servers)
    else:
        single_detection(detector, args.minutes, args.exclude_servers)


if __name__ == "__main__":
    main()
