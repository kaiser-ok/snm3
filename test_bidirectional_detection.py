#!/usr/bin/env python3
"""
測試雙向偵測改進效果

對比：
1. 舊方法（只基於 src 視角）的誤報情況
2. 新方法（雙向分析）的改進效果
"""

import requests
import json
from nad.ml.bidirectional_analyzer import BidirectionalAnalyzer
from datetime import datetime


ES_HOST = "http://localhost:9200"
SRC_INDEX = f"{ES_HOST}/netflow_stats_5m/_search"


def test_old_method_false_positives():
    """
    測試舊方法的誤報

    舊方法：只看 unique_dst_ports > 100 就判定為 Port Scan
    """
    print("=" * 80)
    print("測試 1: 舊方法的 Port Scan 誤報")
    print("=" * 80)

    # 查詢 unique_dst_ports > 100 的 IP（舊方法會判定為掃描）
    query = {
        "size": 20,
        "query": {
            "bool": {
                "must": [
                    {"range": {"time_bucket": {"gte": "now-1h"}}},
                    {"range": {"unique_dst_ports": {"gte": 100}}},
                    {"range": {"avg_bytes": {"lt": 5000}}}  # 舊方法的條件
                ]
            }
        },
        "sort": [{"unique_dst_ports": "desc"}]
    }

    response = requests.post(SRC_INDEX, json=query,
                            headers={'Content-Type': 'application/json'})
    data = response.json()

    old_method_alerts = []

    for hit in data.get('hits', {}).get('hits', []):
        src_data = hit['_source']
        src_ip = src_data['src_ip']

        old_method_alerts.append({
            'src_ip': src_ip,
            'unique_dst_ports': src_data['unique_dst_ports'],
            'unique_dsts': src_data['unique_dsts'],
            'flow_count': src_data['flow_count'],
            'avg_bytes': src_data['avg_bytes']
        })

    print(f"\n舊方法告警數量: {len(old_method_alerts)}")
    print("\n前 10 個告警:")
    print(f"{'IP':<16} {'目的端口數':>10} {'目的IP數':>10} {'連線數':>10} {'平均封包':>12}")
    print("-" * 70)

    for alert in old_method_alerts[:10]:
        print(f"{alert['src_ip']:<16} "
              f"{alert['unique_dst_ports']:>10} "
              f"{alert['unique_dsts']:>10} "
              f"{alert['flow_count']:>10,} "
              f"{alert['avg_bytes']:>12.0f}")

    return old_method_alerts


def test_new_method_improvements(old_alerts):
    """
    測試新方法的改進

    新方法：使用雙向分析，識別微服務、負載均衡等正常模式
    """
    print("\n" + "=" * 80)
    print("測試 2: 新方法的改進（雙向分析）")
    print("=" * 80)

    analyzer = BidirectionalAnalyzer()

    false_positives_reduced = 0
    true_positives_kept = 0

    print("\n分析結果:")
    print(f"{'IP':<16} {'舊方法':^12} {'新方法':^20} {'原因':^30}")
    print("-" * 85)

    for alert in old_alerts[:10]:  # 只測試前 10 個
        src_ip = alert['src_ip']

        # 使用新方法重新分析
        result = analyzer.detect_port_scan_improved(src_ip, time_range="now-1h")

        old_result = "🔴 Port Scan"
        new_result = ""
        reason = ""

        if result.get('is_port_scan'):
            new_result = f"🔴 {result['scan_type']}"
            reason = f"置信度 {result['confidence']:.0%}"
            true_positives_kept += 1
        else:
            pattern = result.get('pattern', 'UNKNOWN')
            if pattern == 'MICROSERVICE':
                new_result = "✅ 微服務"
                reason = "微服務架構模式"
            elif pattern == 'LOAD_BALANCER':
                new_result = "✅ 負載均衡"
                reason = "負載均衡模式"
            elif pattern == 'LEGITIMATE_HIGH_PORT_DIVERSITY':
                new_result = "⚠️  合法高端口"
                reason = result.get('reason', '')
            else:
                new_result = "✅ 正常"
                reason = result.get('reason', 'Unknown')

            false_positives_reduced += 1

        print(f"{src_ip:<16} {old_result:^12} {new_result:^20} {reason:<30}")

    print("\n" + "=" * 80)
    print("改進統計:")
    print(f"  舊方法告警數: {len(old_alerts[:10])}")
    print(f"  減少的誤報: {false_positives_reduced} ({false_positives_reduced/len(old_alerts[:10])*100:.1f}%)")
    print(f"  保留的真陽性: {true_positives_kept}")
    print("=" * 80)


def test_ddos_detection():
    """測試 DDoS 偵測（新功能）"""
    print("\n" + "=" * 80)
    print("測試 3: DDoS 偵測（基於 dst 視角 - 新功能）")
    print("=" * 80)

    analyzer = BidirectionalAnalyzer()

    ddos_list = analyzer.detect_ddos_by_dst(time_range="now-1h", threshold=50)

    print(f"\n發現 {len(ddos_list)} 個可能的 DDoS 目標")

    if ddos_list:
        print(f"\n{'目標IP':<16} {'來源數':>8} {'連線數':>10} {'平均封包':>10} {'類型':^15} {'嚴重性':^10} {'置信度':>8}")
        print("-" * 90)

        for ddos in ddos_list[:10]:
            print(f"{ddos['target_ip']:<16} "
                  f"{ddos['unique_sources']:>8} "
                  f"{ddos['total_connections']:>10,} "
                  f"{ddos['avg_packet_size']:>10.0f} "
                  f"{ddos['ddos_type']:^15} "
                  f"{ddos['severity']:^10} "
                  f"{ddos['confidence']:>7.0%}")

        print("\n說明:")
        print("  - 這些目標同時收到來自大量不同來源的流量")
        print("  - 舊方法（只看 src）無法偵測這種多對一的攻擊模式")
        print("  - 新方法通過 dst 視角可以有效識別 DDoS")
    else:
        print("\n✓ 未發現 DDoS 攻擊")


def print_summary():
    """打印總結"""
    print("\n" + "=" * 80)
    print("雙向聚合的優勢總結")
    print("=" * 80)
    print("""
1. Port Scan 偵測改進:
   ✓ 減少誤報: 識別微服務、負載均衡等正常模式
   ✓ 提高準確率: 區分真實掃描 vs 正常高端口多樣性
   ✓ 更精細分類: 區分針對性掃描 vs 水平掃描

2. DDoS 偵測（新功能）:
   ✓ 多對一攻擊偵測: 識別多個來源攻擊單一目標
   ✓ 攻擊類型分類: SYN Flood, UDP Flood, Connection Flood
   ✓ 排除正常流量: 識別高流量但合法的服務器

3. 整體改進:
   ✓ 完整視角: src 和 dst 雙向分析
   ✓ 交叉驗證: 減少單一視角的盲點
   ✓ 智能判斷: 基於模式而非簡單閾值

建議:
  - 將雙向分析整合到主要的異常偵測流程中
  - 根據實際環境調整閾值和模式識別參數
  - 建立白名單機制排除已知的微服務架構
    """)
    print("=" * 80)


def main():
    """主測試流程"""
    print("\n" + "🔍 " * 25)
    print("雙向流量分析 - 改進效果測試")
    print("🔍 " * 25 + "\n")

    # 測試 1: 舊方法的誤報
    old_alerts = test_old_method_false_positives()

    # 測試 2: 新方法的改進
    if old_alerts:
        test_new_method_improvements(old_alerts)

    # 測試 3: DDoS 偵測
    test_ddos_detection()

    # 總結
    print_summary()


if __name__ == "__main__":
    main()
