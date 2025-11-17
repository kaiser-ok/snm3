#!/usr/bin/env python3
"""
回填資料覆蓋率驗證工具

驗證回填的歷史資料是否完整，比對原始索引和聚合索引的 IP 數量
"""

import requests
import json
from datetime import datetime, timedelta

ES_HOST = "http://localhost:9200"

def verify_backfill_coverage(start_date=None, end_date=None):
    """
    驗證特定時間範圍的回填覆蓋率

    Args:
        start_date: 開始時間 (ISO format 或 None 表示自動計算)
        end_date: 結束時間 (ISO format 或 None 表示自動計算)
    """
    print("=" * 80)
    print("回填資料覆蓋率驗證")
    print("=" * 80)

    # 如果沒指定時間，先查詢聚合索引的時間範圍
    if not start_date or not end_date:
        print("\n🔍 查詢聚合索引的時間範圍...")
        query = {
            "size": 0,
            "aggs": {
                "time_range": {
                    "stats": {"field": "time_bucket"}
                }
            }
        }

        try:
            resp = requests.post(
                f"{ES_HOST}/netflow_stats_5m/_search",
                json=query,
                headers={'Content-Type': 'application/json'}
            )
            resp.raise_for_status()
            data = resp.json()

            stats = data['aggregations']['time_range']
            min_ts = int(stats['min'])
            max_ts = int(stats['max'])

            start_date = datetime.fromtimestamp(min_ts / 1000).isoformat()
            end_date = datetime.fromtimestamp(max_ts / 1000).isoformat()

            print(f"✓ 聚合索引時間範圍:")
            print(f"  開始: {stats['min_as_string']}")
            print(f"  結束: {stats['max_as_string']}")

        except Exception as e:
            print(f"❌ 查詢失敗: {e}")
            return

    print(f"\n分析時間範圍:")
    print(f"  開始: {start_date}")
    print(f"  結束: {end_date}")
    print()

    # 1. 查詢原始索引的統計
    print("🔍 查詢原始索引 (radar_flow_collector-*)...")
    raw_query = {
        "size": 0,
        "query": {
            "range": {
                "FLOW_START_MILLISECONDS": {
                    "gte": start_date,
                    "lte": end_date,
                    "format": "strict_date_optional_time"
                }
            }
        },
        "aggs": {
            "unique_ips": {
                "cardinality": {
                    "field": "IPV4_SRC_ADDR",
                    "precision_threshold": 40000
                }
            },
            "total_docs": {
                "value_count": {
                    "field": "IPV4_SRC_ADDR"
                }
            },
            "time_range": {
                "stats": {
                    "field": "FLOW_START_MILLISECONDS"
                }
            }
        }
    }

    try:
        resp1 = requests.post(
            f"{ES_HOST}/radar_flow_collector-*/_search",
            json=raw_query,
            headers={'Content-Type': 'application/json'},
            timeout=120
        )
        resp1.raise_for_status()
        raw_data = resp1.json()

        raw_unique_ips = raw_data['aggregations']['unique_ips']['value']
        raw_total_docs = raw_data['aggregations']['total_docs']['value']
        raw_time_range = raw_data['aggregations']['time_range']

        print(f"✓ 原始索引統計:")
        print(f"  唯一 IP 數: {raw_unique_ips:,}")
        print(f"  總文檔數: {raw_total_docs:,}")
        print(f"  實際時間範圍:")
        print(f"    {raw_time_range['min_as_string']} → {raw_time_range['max_as_string']}")
        print()

    except Exception as e:
        print(f"❌ 查詢原始索引失敗: {e}")
        return

    # 2. 查詢聚合索引的統計
    print("🔍 查詢聚合索引 (netflow_stats_5m)...")
    agg_query = {
        "size": 0,
        "query": {
            "range": {
                "time_bucket": {
                    "gte": start_date,
                    "lte": end_date,
                    "format": "strict_date_optional_time"
                }
            }
        },
        "aggs": {
            "unique_ips": {
                "cardinality": {
                    "field": "src_ip",
                    "precision_threshold": 40000
                }
            },
            "total_docs": {
                "value_count": {
                    "field": "src_ip"
                }
            },
            "time_buckets": {
                "cardinality": {
                    "field": "time_bucket",
                    "precision_threshold": 10000
                }
            }
        }
    }

    try:
        resp2 = requests.post(
            f"{ES_HOST}/netflow_stats_5m/_search",
            json=agg_query,
            headers={'Content-Type': 'application/json'},
            timeout=120
        )
        resp2.raise_for_status()
        agg_data = resp2.json()

        agg_unique_ips = agg_data['aggregations']['unique_ips']['value']
        agg_total_docs = agg_data['aggregations']['total_docs']['value']
        agg_time_buckets = agg_data['aggregations']['time_buckets']['value']

        print(f"✓ 聚合索引統計:")
        print(f"  唯一 IP 數: {agg_unique_ips:,}")
        print(f"  總文檔數: {agg_total_docs:,}")
        print(f"  時間桶數: {agg_time_buckets:,} 個")
        print(f"  平均每桶 IP 數: {agg_total_docs / agg_time_buckets:.0f}")
        print()

    except Exception as e:
        print(f"❌ 查詢聚合索引失敗: {e}")
        return

    # 3. 計算覆蓋率
    print("=" * 80)
    print("覆蓋率分析")
    print("=" * 80)

    if raw_unique_ips > 0:
        coverage_rate = (agg_unique_ips / raw_unique_ips) * 100

        print(f"原始數據唯一 IP:   {raw_unique_ips:>10,}")
        print(f"聚合數據唯一 IP:   {agg_unique_ips:>10,}")
        print(f"覆蓋率:            {coverage_rate:>9.2f}%")
        print()

        # 數據壓縮率
        if raw_total_docs > 0 and agg_total_docs > 0:
            compression_rate = (1 - agg_total_docs / raw_total_docs) * 100
            reduction_ratio = raw_total_docs / agg_total_docs

            print(f"原始文檔數:        {raw_total_docs:>10,}")
            print(f"聚合文檔數:        {agg_total_docs:>10,}")
            print(f"數據壓縮率:        {compression_rate:>9.1f}%")
            print(f"壓縮比例:          {reduction_ratio:>9.0f}x")
            print()

        # 評估結果
        print("=" * 80)
        print("評估結果")
        print("=" * 80)

        if coverage_rate >= 99:
            print("✅ 覆蓋率優秀 (≥99%)")
            print("   回填資料完整，幾乎捕獲所有 IP")
        elif coverage_rate >= 95:
            print("✅ 覆蓋率良好 (95-99%)")
            print("   回填資料品質優良，略有遺漏屬正常")
        elif coverage_rate >= 90:
            print("⚠️  覆蓋率可接受 (90-95%)")
            print("   有少量 IP 未被記錄")
        else:
            print("🔴 覆蓋率不足 (<90%)")
            print("   大量 IP 未被記錄，建議檢查:")
            print("   - 回填腳本的 size 參數是否足夠")
            print("   - 時間範圍是否對齊")
            print("   - ES 是否有處理限制")

        # 顯示遺漏情況
        if coverage_rate < 100:
            missing_ips = int(raw_unique_ips - agg_unique_ips)
            missing_rate = ((raw_unique_ips - agg_unique_ips) / raw_unique_ips) * 100

            print(f"\n📊 遺漏統計:")
            print(f"  遺漏 IP 數量: {missing_ips:,} 個")
            print(f"  遺漏比例: {missing_rate:.2f}%")

            if missing_ips < 10:
                print(f"  可能原因: cardinality 聚合的近似誤差（正常）")
            elif missing_ips < 100:
                print(f"  可能原因: 極低流量 IP 或邊緣時間點的資料")
            else:
                print(f"  可能原因: 回填腳本的處理限制（檢查 size 參數）")

        # 效能評估
        print(f"\n📈 效能評估:")
        print(f"  時間桶數: {agg_time_buckets:,} 個 (每5分鐘一個)")
        print(f"  資料縮減: 原始 {raw_total_docs:,} → 聚合 {agg_total_docs:,}")
        print(f"  查詢加速: 約 {reduction_ratio:.0f}x 倍")

    else:
        print("❌ 原始數據中沒有 IP，無法計算覆蓋率")

    print("=" * 80)


def verify_specific_time_bucket(time_bucket):
    """驗證特定時間桶的覆蓋率（精確驗證）"""
    print("=" * 80)
    print(f"單一時間桶精確驗證")
    print("=" * 80)
    print(f"時間桶: {time_bucket}")
    print()

    # 解析時間桶（假設是 ISO 格式）
    try:
        bucket_dt = datetime.fromisoformat(time_bucket.replace('Z', '+00:00'))
        start_time = bucket_dt.isoformat()
        end_time = (bucket_dt + timedelta(minutes=5)).isoformat()
    except:
        print("❌ 時間格式錯誤，請使用 ISO 格式（例如：2025-11-11T12:00:00.000Z）")
        return

    print(f"查詢範圍: {start_time} → {end_time}")
    print()

    # 查詢原始索引
    print("🔍 查詢原始索引...")
    raw_query = {
        "size": 0,
        "query": {
            "range": {
                "FLOW_START_MILLISECONDS": {
                    "gte": start_time,
                    "lt": end_time,
                    "format": "strict_date_optional_time"
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
            "all_ips": {
                "terms": {
                    "field": "IPV4_SRC_ADDR",
                    "size": 10000
                }
            }
        }
    }

    try:
        resp = requests.post(
            f"{ES_HOST}/radar_flow_collector-*/_search",
            json=raw_query,
            headers={'Content-Type': 'application/json'}
        )
        resp.raise_for_status()
        raw_data = resp.json()

        raw_unique_ips = raw_data['aggregations']['unique_ips']['value']
        raw_ip_set = set([b['key'] for b in raw_data['aggregations']['all_ips']['buckets']])

        print(f"✓ 原始索引唯一 IP: {raw_unique_ips:,}")
        print(f"✓ 實際取得 IP 數: {len(raw_ip_set):,}")

    except Exception as e:
        print(f"❌ 查詢失敗: {e}")
        return

    # 查詢聚合索引
    print("\n🔍 查詢聚合索引...")
    agg_query = {
        "size": 10000,
        "query": {
            "term": {
                "time_bucket": time_bucket
            }
        },
        "_source": ["src_ip", "time_bucket"]
    }

    try:
        resp = requests.post(
            f"{ES_HOST}/netflow_stats_5m/_search",
            json=agg_query,
            headers={'Content-Type': 'application/json'}
        )
        resp.raise_for_status()
        agg_data = resp.json()

        agg_ip_set = set([hit['_source']['src_ip'] for hit in agg_data['hits']['hits']])

        print(f"✓ 聚合索引唯一 IP: {len(agg_ip_set):,}")

    except Exception as e:
        print(f"❌ 查詢失敗: {e}")
        return

    # 比對
    print("\n" + "=" * 80)
    print("精確比對結果")
    print("=" * 80)

    coverage = len(agg_ip_set) / len(raw_ip_set) * 100 if raw_ip_set else 0

    print(f"原始 IP 數: {len(raw_ip_set):,}")
    print(f"聚合 IP 數: {len(agg_ip_set):,}")
    print(f"覆蓋率: {coverage:.2f}%")

    # 找出遺漏和多餘的 IP
    missing_ips = raw_ip_set - agg_ip_set
    extra_ips = agg_ip_set - raw_ip_set

    if missing_ips:
        print(f"\n⚠️  遺漏 IP ({len(missing_ips)} 個):")
        for ip in list(missing_ips)[:10]:
            print(f"  - {ip}")
        if len(missing_ips) > 10:
            print(f"  ... 還有 {len(missing_ips) - 10} 個")

    if extra_ips:
        print(f"\n⚠️  多餘 IP ({len(extra_ips)} 個):")
        for ip in list(extra_ips)[:10]:
            print(f"  - {ip}")
        if len(extra_ips) > 10:
            print(f"  ... 還有 {len(extra_ips) - 10} 個")

    if not missing_ips and not extra_ips:
        print("\n✅ 完美匹配！所有 IP 都已正確回填")

    print("=" * 80)


if __name__ == "__main__":
    import sys

    if '--help' in sys.argv or '-h' in sys.argv:
        print("""
回填資料覆蓋率驗證工具

用法:
    # 驗證整個回填範圍的覆蓋率
    python3 verify_backfill_coverage.py

    # 驗證特定時間範圍
    python3 verify_backfill_coverage.py --start 2025-11-09T00:00:00 --end 2025-11-12T00:00:00

    # 精確驗證單一時間桶
    python3 verify_backfill_coverage.py --bucket 2025-11-11T12:00:00.000Z

參數說明:
    --start DATETIME    開始時間 (ISO format)
    --end DATETIME      結束時間 (ISO format)
    --bucket DATETIME   精確驗證單一時間桶
    --help, -h          顯示此說明

範例:
    # 自動偵測並驗證整個回填範圍
    python3 verify_backfill_coverage.py

    # 驗證特定3天
    python3 verify_backfill_coverage.py --start 2025-11-09T00:00:00 --end 2025-11-12T00:00:00

    # 精確驗證特定時間桶
    python3 verify_backfill_coverage.py --bucket 2025-11-11T12:00:00.000Z
        """)
        sys.exit(0)

    # 單一時間桶驗證
    if '--bucket' in sys.argv:
        bucket_idx = sys.argv.index('--bucket')
        if bucket_idx + 1 < len(sys.argv):
            time_bucket = sys.argv[bucket_idx + 1]
            verify_specific_time_bucket(time_bucket)
        else:
            print("❌ 請指定時間桶")
        sys.exit(0)

    # 時間範圍驗證
    start_date = None
    end_date = None

    if '--start' in sys.argv:
        start_idx = sys.argv.index('--start')
        if start_idx + 1 < len(sys.argv):
            start_date = sys.argv[start_idx + 1]

    if '--end' in sys.argv:
        end_idx = sys.argv.index('--end')
        if end_idx + 1 < len(sys.argv):
            end_date = sys.argv[end_idx + 1]

    verify_backfill_coverage(start_date, end_date)
