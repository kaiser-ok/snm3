#!/usr/bin/env python3
"""
IP 覆蓋率驗證工具

比較原始索引和聚合索引的唯一 IP 數量，確保 Transform 沒有遺漏數據
"""

import requests
import json
from datetime import datetime

ES_HOST = "http://localhost:9200"

def verify_coverage(hours=1):
    """驗證聚合數據的 IP 覆蓋率"""

    print("=" * 60)
    print("IP 覆蓋率驗證")
    print("=" * 60)
    print(f"分析時間範圍: 過去 {hours} 小時\n")

    # 1. 查詢原始數據的唯一 IP 數
    print("🔍 查詢原始索引 (radar_flow_collector-*)...")
    raw_query = {
        "size": 0,
        "query": {
            "range": {
                "FLOW_START_MILLISECONDS": {
                    "gte": f"now-{hours}h"
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
            "total_docs": {
                "value_count": {
                    "field": "IPV4_SRC_ADDR"
                }
            }
        }
    }

    try:
        resp1 = requests.post(
            f"{ES_HOST}/radar_flow_collector-*/_search",
            json=raw_query,
            headers={'Content-Type': 'application/json'}
        )
        resp1.raise_for_status()
        raw_data = resp1.json()

        raw_unique_ips = raw_data['aggregations']['unique_ips']['value']
        raw_total_docs = raw_data['aggregations']['total_docs']['value']

        print(f"✓ 原始索引唯一 IP 數: {raw_unique_ips:,}")
        print(f"✓ 原始索引總文檔數: {raw_total_docs:,}\n")

    except Exception as e:
        print(f"❌ 查詢原始索引失敗: {e}")
        return

    # 2. 查詢聚合數據的唯一 IP 數
    print("🔍 查詢聚合索引 (netflow_stats_5m)...")
    agg_query = {
        "size": 0,
        "query": {
            "range": {
                "time_bucket": {
                    "gte": f"now-{hours}h"
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
            "total_docs": {
                "value_count": {
                    "field": "src_ip"
                }
            }
        }
    }

    try:
        resp2 = requests.post(
            f"{ES_HOST}/netflow_stats_5m/_search",
            json=agg_query,
            headers={'Content-Type': 'application/json'}
        )
        resp2.raise_for_status()
        agg_data = resp2.json()

        agg_unique_ips = agg_data['aggregations']['unique_ips']['value']
        agg_total_docs = agg_data['aggregations']['total_docs']['value']

        print(f"✓ 聚合索引唯一 IP 數: {agg_unique_ips:,}")
        print(f"✓ 聚合索引總文檔數: {agg_total_docs:,}\n")

    except Exception as e:
        print(f"❌ 查詢聚合索引失敗: {e}")
        return

    # 3. 計算覆蓋率
    print("=" * 60)
    print("覆蓋率分析")
    print("=" * 60)

    if raw_unique_ips > 0:
        coverage_rate = (agg_unique_ips / raw_unique_ips) * 100

        print(f"原始數據唯一 IP:   {raw_unique_ips:>8,}")
        print(f"聚合數據唯一 IP:   {agg_unique_ips:>8,}")
        print(f"覆蓋率:            {coverage_rate:>7.1f}%")
        print()

        # 數據壓縮率
        if raw_total_docs > 0:
            compression_rate = (1 - agg_total_docs / raw_total_docs) * 100
            print(f"數據壓縮率:        {compression_rate:>7.1f}%")
            print(f"(從 {raw_total_docs:,} 筆壓縮到 {agg_total_docs:,} 筆)")
            print()

        # 評估結果
        print("=" * 60)
        print("評估結果")
        print("=" * 60)

        if coverage_rate >= 99:
            print("✅ 覆蓋率優秀 (≥99%)")
            print("   Transform 正確處理了幾乎所有 IP")
        elif coverage_rate >= 95:
            print("✅ 覆蓋率良好 (95-99%)")
            print("   Transform 處理了絕大部分 IP，略有遺漏屬正常")
        elif coverage_rate >= 90:
            print("⚠️  覆蓋率可接受 (90-95%)")
            print("   有少量 IP 未被記錄，可能需要檢查配置")
        else:
            print("🔴 覆蓋率不足 (<90%)")
            print("   大量 IP 未被記錄，需要調整 Transform 配置")
            print("   建議檢查:")
            print("   - max_page_search_size 是否足夠")
            print("   - Transform 是否正常運行")
            print("   - 查詢時間範圍是否正確")

        # 如果覆蓋率不是 100%，分析可能原因
        if coverage_rate < 100:
            missing_ips = raw_unique_ips - agg_unique_ips
            print(f"\n📊 遺漏 IP 數量: {missing_ips:,} 個")

            if missing_ips < 10:
                print("   可能原因: cardinality 聚合的近似誤差")
            elif missing_ips < 100:
                print("   可能原因: Transform 尚未完全同步最新數據")
            else:
                print("   可能原因: Transform 配置問題或處理限制")
    else:
        print("❌ 原始數據中沒有 IP，無法計算覆蓋率")

    print("=" * 60)


def check_transform_status():
    """檢查 Transform 狀態"""
    print("\n" + "=" * 60)
    print("Transform 狀態檢查")
    print("=" * 60)

    try:
        resp = requests.get(
            f"{ES_HOST}/_transform/netflow_production/_stats",
            headers={'Content-Type': 'application/json'}
        )
        resp.raise_for_status()
        stats = resp.json()

        if 'transforms' in stats and len(stats['transforms']) > 0:
            t = stats['transforms'][0]
            state = t['state']

            print(f"Transform ID: netflow_production")
            print(f"狀態: {state}")

            if 'stats' in t:
                s = t['stats']
                print(f"已處理文檔: {s.get('documents_processed', 0):,}")
                print(f"已索引文檔: {s.get('documents_indexed', 0):,}")
                print(f"觸發次數: {s.get('trigger_count', 0):,}")

                if 'checkpointing' in t:
                    cp = t['checkpointing']
                    if 'last' in cp:
                        last_checkpoint = cp['last'].get('checkpoint', 0)
                        print(f"最後檢查點: {last_checkpoint}")

            if state != 'started':
                print(f"\n⚠️  Transform 未在運行狀態 (當前: {state})")
                print("   這可能影響數據同步")
        else:
            print("❌ 未找到 Transform: netflow_production")

    except Exception as e:
        print(f"❌ 查詢 Transform 狀態失敗: {e}")

    print("=" * 60)


if __name__ == "__main__":
    # 檢查 Transform 狀態
    check_transform_status()

    # 驗證覆蓋率
    print("\n")
    verify_coverage(hours=1)

    print("\n💡 建議:")
    print("   - 如果覆蓋率 ≥95%，當前配置良好")
    print("   - 如果覆蓋率 <90%，考慮增加 max_page_search_size")
    print("   - 定期執行此腳本以監控數據品質")
    print()
