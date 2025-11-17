#!/usr/bin/env python3
"""
基於 netflow_stats_5m 聚合數據的異常分析工具

優勢:
- 查詢速度快 100+ 倍 (只需掃描聚合數據)
- 數據量小 99%
- 可進行快速異常偵測
"""

import requests
import json
from datetime import datetime, timedelta
from collections import defaultdict
import sys

# ES 配置
ES_HOST = "http://localhost:9200"
AGG_INDEX = "netflow_stats_5m"

class AggregatedDataAnalyzer:
    """基於聚合數據的分析器"""

    def __init__(self):
        self.es_url = f"{ES_HOST}/{AGG_INDEX}/_search"

    def analyze_recent(self, hours=1):
        """分析最近 N 小時的聚合數據"""
        print(f"\n{'='*70}")
        print(f"基於聚合數據的異常分析 - 過去 {hours} 小時")
        print(f"{'='*70}\n")

        # 1. 掃描偵測
        print("🔍 檢測掃描行為...")
        scanners = self.detect_scanning(hours)

        # 2. 高連線數偵測
        print("\n📊 檢測異常高連線數...")
        high_conn = self.detect_high_connections(hours)

        # 3. 大流量偵測
        print("\n💾 檢測異常大流量...")
        high_traffic = self.detect_high_traffic(hours)

        # 4. 生成報告
        print(f"\n{'='*70}")
        print("異常摘要")
        print(f"{'='*70}")
        print(f"掃描行為: {len(scanners)} 個IP")
        print(f"高連線數: {len(high_conn)} 個IP")
        print(f"高流量: {len(high_traffic)} 個IP")

        return {
            'scanners': scanners,
            'high_connections': high_conn,
            'high_traffic': high_traffic
        }

    def detect_scanning(self, hours=1):
        """
        偵測掃描行為
        特徵: 連線到多個目的地且平均流量小
        """
        query = {
            "size": 100,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"time_bucket": {"gte": f"now-{hours}h"}}},
                        {"range": {"unique_dsts": {"gte": 30}}},  # 連線到30+個目的地
                        {"range": {"avg_bytes": {"lt": 10000}}},   # 平均流量小於10KB
                        {"range": {"flow_count": {"gte": 50}}}     # 至少50個連線
                    ]
                }
            },
            "sort": [{"unique_dsts": "desc"}]
        }

        response = requests.post(self.es_url, json=query, headers={'Content-Type': 'application/json'})
        data = response.json()

        scanners = []
        seen_ips = set()

        for hit in data['hits']['hits']:
            src = hit['_source']
            ip = src['src_ip']

            if ip not in seen_ips:
                seen_ips.add(ip)

                # 計算掃描評分
                scan_score = self._calculate_scan_score(src)

                scanners.append({
                    'ip': ip,
                    'unique_dsts': src['unique_dsts'],
                    'flow_count': src['flow_count'],
                    'avg_bytes': src['avg_bytes'],
                    'scan_score': scan_score,
                    'time_bucket': src['time_bucket']
                })

        # 輸出結果
        if scanners:
            print(f"\n⚠️  發現 {len(scanners)} 個可疑掃描 IP:\n")
            for i, scanner in enumerate(scanners[:10], 1):
                print(f"{i:2}. {scanner['ip']:15} | "
                      f"{scanner['unique_dsts']:3} 目的地 | "
                      f"{scanner['flow_count']:5,} 連線 | "
                      f"評分: {scanner['scan_score']}/100")
        else:
            print("✓ 未發現掃描行為")

        return scanners

    def detect_high_connections(self, hours=1):
        """偵測異常高連線數"""
        query = {
            "size": 0,
            "query": {
                "range": {"time_bucket": {"gte": f"now-{hours}h"}}
            },
            "aggs": {
                "per_ip": {
                    "terms": {
                        "field": "src_ip",
                        "size": 100,
                        "order": {"total_connections": "desc"}
                    },
                    "aggs": {
                        "total_connections": {"sum": {"field": "flow_count"}},
                        "total_traffic": {"sum": {"field": "total_bytes"}},
                        "avg_unique_dsts": {"avg": {"field": "unique_dsts"}}
                    }
                }
            }
        }

        response = requests.post(self.es_url, json=query, headers={'Content-Type': 'application/json'})
        data = response.json()

        high_conn = []
        threshold = 1000 * hours  # 每小時1000連線

        for bucket in data['aggregations']['per_ip']['buckets']:
            conns = bucket['total_connections']['value']
            if conns > threshold:
                high_conn.append({
                    'ip': bucket['key'],
                    'connections': int(conns),
                    'traffic_mb': bucket['total_traffic']['value'] / 1024 / 1024,
                    'avg_unique_dsts': bucket['avg_unique_dsts']['value']
                })

        # 輸出結果
        if high_conn:
            print(f"\n⚠️  發現 {len(high_conn)} 個高連線數 IP:\n")
            for i, item in enumerate(high_conn[:10], 1):
                print(f"{i:2}. {item['ip']:15} | "
                      f"{item['connections']:7,} 連線 | "
                      f"{item['traffic_mb']:8.2f} MB | "
                      f"平均 {item['avg_unique_dsts']:.0f} 目的地")
        else:
            print(f"✓ 未發現異常高連線數 (閾值: {threshold:,})")

        return high_conn

    def detect_high_traffic(self, hours=1):
        """偵測異常大流量"""
        query = {
            "size": 0,
            "query": {
                "range": {"time_bucket": {"gte": f"now-{hours}h"}}
            },
            "aggs": {
                "per_ip": {
                    "terms": {
                        "field": "src_ip",
                        "size": 50,
                        "order": {"total_traffic": "desc"}
                    },
                    "aggs": {
                        "total_traffic": {"sum": {"field": "total_bytes"}},
                        "total_connections": {"sum": {"field": "flow_count"}},
                        "max_single_flow": {"max": {"field": "max_bytes"}}
                    }
                }
            }
        }

        response = requests.post(self.es_url, json=query, headers={'Content-Type': 'application/json'})
        data = response.json()

        high_traffic = []
        threshold_gb = 1  # 1GB

        for bucket in data['aggregations']['per_ip']['buckets']:
            traffic = bucket['total_traffic']['value']
            traffic_gb = traffic / 1024 / 1024 / 1024

            if traffic_gb > threshold_gb:
                high_traffic.append({
                    'ip': bucket['key'],
                    'traffic_gb': traffic_gb,
                    'connections': int(bucket['total_connections']['value']),
                    'max_single_flow_mb': bucket['max_single_flow']['value'] / 1024 / 1024
                })

        # 輸出結果
        if high_traffic:
            print(f"\n⚠️  發現 {len(high_traffic)} 個大流量 IP (>{threshold_gb}GB):\n")
            for i, item in enumerate(high_traffic[:10], 1):
                print(f"{i:2}. {item['ip']:15} | "
                      f"{item['traffic_gb']:6.2f} GB | "
                      f"{item['connections']:6,} 連線 | "
                      f"最大單連線: {item['max_single_flow_mb']:.2f} MB")
        else:
            print(f"✓ 未發現異常大流量 (閾值: {threshold_gb}GB)")

        return high_traffic

    def _calculate_scan_score(self, data):
        """計算掃描評分 (0-100)"""
        score = 0

        # 目的地數量
        if data['unique_dsts'] > 100:
            score += 40
        elif data['unique_dsts'] > 50:
            score += 30
        elif data['unique_dsts'] > 30:
            score += 20

        # 平均流量小（掃描特徵）
        if data['avg_bytes'] < 1000:
            score += 30
        elif data['avg_bytes'] < 5000:
            score += 20
        elif data['avg_bytes'] < 10000:
            score += 10

        # 連線數
        if data['flow_count'] > 1000:
            score += 20
        elif data['flow_count'] > 500:
            score += 10
        elif data['flow_count'] > 100:
            score += 5

        # 端口多樣性
        if data['unique_ports'] > 50:
            score += 10

        return min(score, 100)

    def analyze_ip(self, ip, hours=24):
        """深度分析特定 IP"""
        print(f"\n{'='*70}")
        print(f"IP 深度分析: {ip}")
        print(f"{'='*70}\n")

        query = {
            "size": 500,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"src_ip": ip}},
                        {"range": {"time_bucket": {"gte": f"now-{hours}h"}}}
                    ]
                }
            },
            "sort": [{"time_bucket": "asc"}]
        }

        response = requests.post(self.es_url, json=query, headers={'Content-Type': 'application/json'})
        data = response.json()

        if not data['hits']['hits']:
            print(f"❌ 未找到 {ip} 在過去 {hours} 小時的數據")
            return

        # 統計分析
        total_connections = 0
        total_traffic = 0
        max_unique_dsts = 0
        time_series = []

        print(f"時間序列數據 (每5分鐘):")
        print(f"{'-'*70}")
        print(f"{'時間':<20} {'連線數':>8} {'流量(MB)':>10} {'目的地':>8} {'平均流量':>12}")
        print(f"{'-'*70}")

        for hit in data['hits']['hits'][:20]:  # 只顯示前20筆
            src = hit['_source']
            time = datetime.fromisoformat(src['time_bucket'].replace('Z', '+00:00'))
            conns = src['flow_count']
            traffic = src['total_bytes'] / 1024 / 1024
            dsts = src['unique_dsts']
            avg = src['avg_bytes']

            total_connections += conns
            total_traffic += traffic
            max_unique_dsts = max(max_unique_dsts, dsts)

            print(f"{time.strftime('%Y-%m-%d %H:%M'):<20} "
                  f"{conns:8,} {traffic:10.2f} {dsts:8} {avg:12,.0f}")

        print(f"{'-'*70}")
        print(f"\n統計摘要:")
        print(f"  總連線數: {total_connections:,}")
        print(f"  總流量: {total_traffic:.2f} MB")
        print(f"  最大目的地數: {max_unique_dsts}")
        print(f"  平均連線/5分鐘: {total_connections / len(data['hits']['hits']):.0f}")

        # 異常判斷
        print(f"\n異常指標:")
        is_scanning = max_unique_dsts > 50 and total_connections > 500
        is_high_conn = total_connections > 10000
        is_high_traffic = total_traffic > 1000  # 1GB

        if is_scanning:
            print(f"  🔴 掃描行為: 是 (最大目的地: {max_unique_dsts})")
        else:
            print(f"  ✅ 掃描行為: 否")

        if is_high_conn:
            print(f"  🔴 高連線數: 是 ({total_connections:,})")
        else:
            print(f"  ✅ 高連線數: 否")

        if is_high_traffic:
            print(f"  🔴 高流量: 是 ({total_traffic:.2f} MB)")
        else:
            print(f"  ✅ 高流量: 否")

    def compare_with_baseline(self, ip, baseline_days=7):
        """與基準線比較（未來實作）"""
        # TODO: 實作基準線比較功能
        pass


def main():
    analyzer = AggregatedDataAnalyzer()

    if len(sys.argv) > 1:
        # 指定 IP 分析
        ip = sys.argv[1]
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        analyzer.analyze_ip(ip, hours)
    else:
        # 一般異常分析
        hours = 1
        result = analyzer.analyze_recent(hours)

        # 可選：保存結果
        # with open(f'anomaly_report_{datetime.now().strftime("%Y%m%d_%H%M")}.json', 'w') as f:
        #     json.dump(result, f, indent=2)


if __name__ == "__main__":
    main()
