#!/usr/bin/env python3
"""
調試覆蓋率問題 - 精確比較原始數據和聚合數據
"""

import requests
from datetime import datetime, timedelta

ES_HOST = "http://localhost:9200"

def compare_time_aligned():
    """使用時間對齊的方式比較"""

    # 計算對齊到5分鐘邊界的時間範圍
    now = datetime.now()

    # 往回推1小時，並對齊到5分鐘邊界
    end_time = now.replace(second=0, microsecond=0)
    end_time = end_time.replace(minute=(end_time.minute // 5) * 5)

    start_time = end_time - timedelta(hours=1)

    start_ms = int(start_time.timestamp() * 1000)
    end_ms = int(end_time.timestamp() * 1000)

    print("=" * 70)
    print("時間對齊覆蓋率驗證")
    print("=" * 70)
    print(f"開始時間: {start_time}")
    print(f"結束時間: {end_time}")
    print(f"時間範圍: {(end_time - start_time).total_seconds() / 3600:.1f} 小時")
    print()

    # 1. 查詢原始索引
    print("🔍 查詢原始索引...")
    raw_query = {
        "size": 0,
        "query": {
            "range": {
                "FLOW_START_MILLISECONDS": {
                    "gte": start_ms,
                    "lt": end_ms
                }
            }
        },
        "aggs": {
            "unique_ips": {
                "cardinality": {
                    "field": "IPV4_SRC_ADDR",
                    "precision_threshold": 10000
                }
            },
            "total_flows": {
                "value_count": {"field": "IPV4_SRC_ADDR"}
            },
            "time_range": {
                "stats": {"field": "FLOW_START_MILLISECONDS"}
            }
        }
    }

    resp = requests.post(
        f"{ES_HOST}/radar_flow_collector-*/_search",
        json=raw_query,
        headers={'Content-Type': 'application/json'}
    )

    raw_data = resp.json()
    raw_unique_ips = int(raw_data['aggregations']['unique_ips']['value'])
    raw_total = int(raw_data['aggregations']['total_flows']['value'])

    time_stats = raw_data['aggregations']['time_range']
    actual_min = datetime.fromtimestamp(time_stats['min'] / 1000)
    actual_max = datetime.fromtimestamp(time_stats['max'] / 1000)

    print(f"  唯一 IP: {raw_unique_ips:,}")
    print(f"  總流記錄: {raw_total:,}")
    print(f"  實際時間範圍: {actual_min} 到 {actual_max}")
    print()

    # 2. 查詢聚合索引 (使用 time_bucket)
    print("🔍 查詢聚合索引...")

    # 轉換為 ISO 格式給 time_bucket
    start_iso = start_time.isoformat() + "Z"
    end_iso = end_time.isoformat() + "Z"

    agg_query = {
        "size": 0,
        "query": {
            "range": {
                "time_bucket": {
                    "gte": start_iso,
                    "lt": end_iso
                }
            }
        },
        "aggs": {
            "unique_ips": {
                "cardinality": {
                    "field": "src_ip",
                    "precision_threshold": 10000
                }
            },
            "total_buckets": {
                "value_count": {"field": "src_ip"}
            },
            "time_buckets": {
                "cardinality": {
                    "field": "time_bucket"
                }
            }
        }
    }

    resp = requests.post(
        f"{ES_HOST}/netflow_stats_5m/_search",
        json=agg_query,
        headers={'Content-Type': 'application/json'}
    )

    agg_data = resp.json()
    agg_unique_ips = int(agg_data['aggregations']['unique_ips']['value'])
    agg_total = int(agg_data['aggregations']['total_buckets']['value'])
    agg_time_buckets = int(agg_data['aggregations']['time_buckets']['value'])

    print(f"  唯一 IP: {agg_unique_ips:,}")
    print(f"  聚合記錄數: {agg_total:,}")
    expected_buckets = 60 // 5
    print(f"  時間桶數: {agg_time_buckets} (預期: {expected_buckets})")
    print()

    # 3. 計算覆蓋率
    print("=" * 70)
    print("覆蓋率分析")
    print("=" * 70)

    if raw_unique_ips > 0:
        coverage = (agg_unique_ips / raw_unique_ips) * 100
        missing = raw_unique_ips - agg_unique_ips

        print(f"原始索引唯一 IP:    {raw_unique_ips:>8,}")
        print(f"聚合索引唯一 IP:    {agg_unique_ips:>8,}")
        print(f"遺漏 IP 數:         {missing:>8,}")
        print(f"覆蓋率:            {coverage:>8.2f}%")
        print()

        # 數據壓縮比
        compression = (1 - agg_total / raw_total) * 100 if raw_total > 0 else 0
        reduction_ratio = raw_total / agg_total if agg_total > 0 else 0

        print(f"數據壓縮:")
        print(f"  原始: {raw_total:,} 筆")
        print(f"  聚合: {agg_total:,} 筆")
        print(f"  壓縮率: {compression:.2f}%")
        print(f"  縮減比例: {reduction_ratio:.1f}x")
        print()

        # 每個時間桶的平均 IP 數
        if agg_time_buckets > 0:
            avg_ips_per_bucket = agg_total / agg_time_buckets
            print(f"平均每個時間桶: {avg_ips_per_bucket:.0f} 條聚合記錄")
            print()

        # 診斷
        print("=" * 70)
        print("診斷")
        print("=" * 70)

        if coverage >= 95:
            print("✅ 覆蓋率優秀")
        elif coverage >= 80:
            print("⚠️  覆蓋率可接受但有改進空間")
            print()
            print("可能原因:")
            if agg_time_buckets < 12:
                print(f"  - Transform 數據不完整 (只有 {agg_time_buckets}/12 個時間桶)")
            if avg_ips_per_bucket < 100:
                print(f"  - 每個時間桶平均 IP 數過少 ({avg_ips_per_bucket:.0f})")
                print("    可能是 Transform group_by terms 的默認 size 限制")
        else:
            print("🔴 覆蓋率嚴重不足")
            print()
            print("主要問題:")

            if agg_time_buckets < 12:
                print(f"  1. 時間桶不完整: {agg_time_buckets}/12")
                print("     → Transform 可能尚未處理所有數據")
                print("     → 解決方案: 等待 Transform 完成同步")

            if coverage < 50 and agg_time_buckets >= 10:
                print(f"  2. 覆蓋率過低但時間桶完整")
                print("     → Transform group_by 的 terms aggregation 默認只返回 Top 10")
                print("     → 問題: ES 7.17 Transform 不支援在 group_by 中設置 size")
                print("     → 這是 ES Transform 的已知限制")
                print()
                print("     可能的解決方案:")
                print("     a) 使用 Python 腳本直接聚合 (最靈活)")
                print("     b) 使用 Logstash聚合 (可控制 terms size)")
                print("     c) 升級到 ES 8.x (支援 group_by terms size)")

    return {
        'raw_ips': raw_unique_ips,
        'agg_ips': agg_unique_ips,
        'coverage': coverage if raw_unique_ips > 0 else 0,
        'time_buckets': agg_time_buckets
    }


def check_terms_limit():
    """檢查 terms aggregation 是否受到 size 限制"""

    print("\n" + "=" * 70)
    print("檢查 Terms Aggregation 限制")
    print("=" * 70)

    # 選擇最近的一個完整時間桶
    query = {
        "size": 0,
        "query": {
            "range": {
                "time_bucket": {
                    "gte": "now-30m"
                }
            }
        },
        "aggs": {
            "by_time_bucket": {
                "terms": {
                    "field": "time_bucket",
                    "size": 1,
                    "order": {"_key": "desc"}
                },
                "aggs": {
                    "ip_count": {
                        "cardinality": {
                            "field": "src_ip",
                            "precision_threshold": 5000
                        }
                    },
                    "doc_count_stat": {
                        "value_count": {"field": "src_ip"}
                    }
                }
            }
        }
    }

    resp = requests.post(
        f"{ES_HOST}/netflow_stats_5m/_search",
        json=query,
        headers={'Content-Type': 'application/json'}
    )

    data = resp.json()

    if 'aggregations' in data and data['aggregations']['by_time_bucket']['buckets']:
        bucket = data['aggregations']['by_time_bucket']['buckets'][0]
        time_bucket = bucket['key_as_string']
        ip_count = int(bucket['ip_count']['value'])
        doc_count = int(bucket['doc_count'])

        print(f"最近時間桶: {time_bucket}")
        print(f"  該桶中的唯一 IP 數: {ip_count:,}")
        print(f"  該桶中的文檔數: {doc_count:,}")
        print()

        # 現在查詢原始數據中這個時間桶應該有多少 IP
        bucket_time = datetime.fromisoformat(time_bucket.replace('Z', '+00:00'))
        bucket_start_ms = int(bucket_time.timestamp() * 1000)
        bucket_end_ms = bucket_start_ms + (5 * 60 * 1000)

        raw_query = {
            "size": 0,
            "query": {
                "range": {
                    "FLOW_START_MILLISECONDS": {
                        "gte": bucket_start_ms,
                        "lt": bucket_end_ms
                    }
                }
            },
            "aggs": {
                "unique_ips": {
                    "cardinality": {
                        "field": "IPV4_SRC_ADDR",
                        "precision_threshold": 5000
                    }
                }
            }
        }

        resp = requests.post(
            f"{ES_HOST}/radar_flow_collector-*/_search",
            json=raw_query,
            headers={'Content-Type': 'application/json'}
        )

        raw_data = resp.json()
        raw_ip_count = int(raw_data['aggregations']['unique_ips']['value'])

        print(f"原始數據中該時間桶的唯一 IP: {raw_ip_count:,}")
        print()

        if raw_ip_count > 0:
            bucket_coverage = (ip_count / raw_ip_count) * 100
            print(f"該時間桶的覆蓋率: {bucket_coverage:.2f}%")
            print()

            if bucket_coverage < 50:
                print("🔴 問題確認: Transform 的 group_by terms 限制導致大量 IP 遺漏")
                print(f"   預期: {raw_ip_count:,} 個 IP")
                print(f"   實際: {ip_count:,} 個 IP")
                print(f"   遺漏: {raw_ip_count - ip_count:,} 個 IP")
            elif bucket_coverage < 95:
                print("⚠️  有部分 IP 未被記錄")
            else:
                print("✅ 該時間桶覆蓋率良好")


if __name__ == "__main__":
    result = compare_time_aligned()
    check_terms_limit()

    print("\n" + "=" * 70)
    print("結論")
    print("=" * 70)

    if result['coverage'] < 80:
        print("Transform 配置存在根本性問題，無法用於全面的異常偵測")
        print()
        print("建議替代方案:")
        print("1. 使用 Python 腳本進行聚合 (完全可控)")
        print("2. 改用 Logstash pipeline 進行聚合")
        print("3. 直接對原始數據進行異常分析 (analyze_from_aggregated.py 已驗證可行)")
    elif result['coverage'] >= 95:
        print("Transform 配置良好，可用於異常偵測")
    else:
        print("Transform 可用，但建議優化以提高覆蓋率")

    print("=" * 70)
