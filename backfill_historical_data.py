#!/usr/bin/env python3
"""
歷史資料回填工具

將過去 N 天的原始 NetFlow 資料聚合並寫入 netflow_stats_5m 索引
模擬 Transform 的聚合邏輯，但處理歷史資料
"""

import requests
import json
from datetime import datetime, timedelta
import time
import sys

# ES 配置
ES_HOST = "http://localhost:9200"
SOURCE_INDEX = "radar_flow_collector-*"
DEST_INDEX = "netflow_stats_5m"

class HistoricalDataBackfill:
    """歷史資料回填處理器"""

    def __init__(self):
        self.es_url = ES_HOST
        self.processed_buckets = 0
        self.processed_docs = 0
        self.errors = []

    def backfill(self, days=3, batch_hours=1, dry_run=False, auto_confirm=False):
        """
        回填過去 N 天的歷史資料

        Args:
            days: 回填天數
            batch_hours: 每批處理的小時數 (建議1-6小時，避免單次查詢過大)
            dry_run: 是否僅測試不實際寫入
            auto_confirm: 自動確認執行（用於背景執行）
        """
        print("=" * 80)
        print(f"NetFlow 歷史資料回填工具")
        print("=" * 80)
        print(f"回填範圍: 過去 {days} 天")
        print(f"批次大小: {batch_hours} 小時/批")
        print(f"模式: {'測試模式 (不寫入)' if dry_run else '正式模式 (寫入數據)'}")
        print("=" * 80)
        print()

        # 計算時間範圍
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days)

        print(f"開始時間: {start_time.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        print(f"結束時間: {end_time.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        print()

        # 確認是否繼續
        if not dry_run and not auto_confirm:
            try:
                response = input("⚠️  這將寫入實際數據，是否繼續? (yes/no): ")
                if response.lower() != 'yes':
                    print("已取消")
                    return
            except EOFError:
                print("⚠️  無法讀取輸入（可能在背景執行），請使用 --auto-confirm 參數")
                print("已取消")
                return
        elif not dry_run and auto_confirm:
            print("✅ 自動確認模式，開始執行...")
            print()

        # 分批處理
        current_time = start_time
        batch_num = 0

        while current_time < end_time:
            batch_end = min(current_time + timedelta(hours=batch_hours), end_time)
            batch_num += 1

            print(f"\n{'='*80}")
            print(f"批次 #{batch_num}: {current_time.strftime('%Y-%m-%d %H:%M')} - {batch_end.strftime('%Y-%m-%d %H:%M')}")
            print(f"{'='*80}")

            try:
                self._process_time_range(current_time, batch_end, dry_run)
            except Exception as e:
                error_msg = f"批次 #{batch_num} 處理失敗: {e}"
                print(f"❌ {error_msg}")
                self.errors.append(error_msg)

            current_time = batch_end

            # 避免過度負載 ES
            if not dry_run and batch_num % 5 == 0:
                print("\n⏸️  暫停 5 秒以避免 ES 過載...")
                time.sleep(5)

        # 輸出總結
        self._print_summary(dry_run)

    def _process_time_range(self, start_time, end_time, dry_run=False):
        """處理指定時間範圍的資料"""

        # 計算時間範圍內有多少個5分鐘桶
        num_5m_buckets = int((end_time - start_time).total_seconds() / 300)

        print(f"🔍 查詢原始資料...")
        print(f"   預計包含 {num_5m_buckets} 個5分鐘時間桶")

        # 構建聚合查詢 (完全模擬 Transform 配置)
        query = {
            "size": 0,
            "query": {
                "range": {
                    "FLOW_START_MILLISECONDS": {
                        "gte": start_time.isoformat(),
                        "lt": end_time.isoformat(),
                        "format": "strict_date_optional_time"
                    }
                }
            },
            "aggs": {
                "time_buckets": {
                    "date_histogram": {
                        "field": "FLOW_START_MILLISECONDS",
                        "fixed_interval": "5m",
                        "min_doc_count": 1
                    },
                    "aggs": {
                        "by_src_ip": {
                            "terms": {
                                "field": "IPV4_SRC_ADDR",
                                "size": 10000  # 處理大量 IP
                            },
                            "aggs": {
                                "total_bytes": {
                                    "sum": {"field": "IN_BYTES"}
                                },
                                "total_packets": {
                                    "sum": {"field": "IN_PKTS"}
                                },
                                "flow_count": {
                                    "value_count": {"field": "IPV4_SRC_ADDR"}
                                },
                                "unique_dsts": {
                                    "cardinality": {
                                        "field": "IPV4_DST_ADDR",
                                        "precision_threshold": 3000
                                    }
                                },
                                "unique_src_ports": {
                                    "cardinality": {
                                        "field": "L4_SRC_PORT",
                                        "precision_threshold": 1000
                                    }
                                },
                                "unique_dst_ports": {
                                    "cardinality": {
                                        "field": "L4_DST_PORT",
                                        "precision_threshold": 1000
                                    }
                                },
                                "avg_bytes": {
                                    "avg": {"field": "IN_BYTES"}
                                },
                                "max_bytes": {
                                    "max": {"field": "IN_BYTES"}
                                }
                            }
                        }
                    }
                }
            }
        }

        # 執行查詢
        response = requests.post(
            f"{self.es_url}/{SOURCE_INDEX}/_search",
            json=query,
            headers={'Content-Type': 'application/json'},
            timeout=300  # 5分鐘超時
        )
        response.raise_for_status()
        data = response.json()

        # 檢查是否有數據
        time_buckets = data['aggregations']['time_buckets']['buckets']

        if not time_buckets:
            print(f"   ⚠️  此時間範圍內無數據")
            return

        print(f"   ✓ 找到 {len(time_buckets)} 個時間桶")

        # 準備批次寫入的文檔
        docs_to_index = []
        total_ips = 0

        for time_bucket in time_buckets:
            bucket_time = time_bucket['key_as_string']
            ip_buckets = time_bucket['by_src_ip']['buckets']
            total_ips += len(ip_buckets)

            for ip_bucket in ip_buckets:
                doc = {
                    "time_bucket": bucket_time,
                    "src_ip": ip_bucket['key'],
                    "total_bytes": ip_bucket['total_bytes']['value'],
                    "total_packets": ip_bucket['total_packets']['value'],
                    "flow_count": ip_bucket['flow_count']['value'],
                    "unique_dsts": ip_bucket['unique_dsts']['value'],
                    "unique_src_ports": ip_bucket['unique_src_ports']['value'],
                    "unique_dst_ports": ip_bucket['unique_dst_ports']['value'],
                    "avg_bytes": ip_bucket['avg_bytes']['value'],
                    "max_bytes": ip_bucket['max_bytes']['value']
                }
                docs_to_index.append(doc)

        print(f"   📊 聚合結果: {total_ips} 個唯一 IP")

        if dry_run:
            print(f"   🔍 [測試模式] 跳過寫入，共 {len(docs_to_index)} 筆文檔")
            # 顯示範例文檔
            if docs_to_index:
                print(f"\n   範例文檔:")
                print(f"   {json.dumps(docs_to_index[0], indent=4)}")
        else:
            # 批次寫入到目標索引
            self._bulk_index(docs_to_index)

        self.processed_buckets += len(time_buckets)
        self.processed_docs += len(docs_to_index)

    def _bulk_index(self, docs):
        """批次寫入文檔到 ES"""
        if not docs:
            return

        print(f"   💾 寫入 {len(docs)} 筆文檔到 {DEST_INDEX}...")

        # 構建 bulk 請求
        bulk_body = []
        for doc in docs:
            # 使用 time_bucket + src_ip 作為文檔 ID，避免重複
            doc_id = f"{doc['time_bucket']}_{doc['src_ip']}"

            # Index action
            bulk_body.append(json.dumps({
                "index": {
                    "_index": DEST_INDEX,
                    "_id": doc_id
                }
            }))
            # Document
            bulk_body.append(json.dumps(doc))

        bulk_data = "\n".join(bulk_body) + "\n"

        # 執行 bulk 寫入
        response = requests.post(
            f"{self.es_url}/_bulk",
            data=bulk_data,
            headers={'Content-Type': 'application/x-ndjson'},
            timeout=120
        )
        response.raise_for_status()
        result = response.json()

        # 檢查錯誤
        if result.get('errors'):
            error_count = sum(1 for item in result['items'] if 'error' in item.get('index', {}))
            print(f"   ⚠️  寫入時發生 {error_count} 個錯誤")

            # 顯示第一個錯誤範例
            for item in result['items']:
                if 'error' in item.get('index', {}):
                    print(f"   錯誤範例: {item['index']['error']}")
                    break
        else:
            print(f"   ✓ 成功寫入 {len(docs)} 筆文檔")

    def _print_summary(self, dry_run):
        """輸出執行總結"""
        print("\n" + "=" * 80)
        print("執行總結")
        print("=" * 80)
        print(f"處理的時間桶數: {self.processed_buckets}")
        print(f"生成的文檔數: {self.processed_docs:,}")

        if self.errors:
            print(f"\n❌ 錯誤數量: {len(self.errors)}")
            for error in self.errors[:5]:  # 只顯示前5個錯誤
                print(f"   - {error}")
        else:
            print(f"\n✅ 無錯誤")

        if dry_run:
            print(f"\n⚠️  這是測試運行，未實際寫入數據")
            print(f"   若要實際寫入，請執行: python3 {sys.argv[0]} --execute")
        else:
            print(f"\n✅ 回填完成！")
            print(f"\n建議執行以下命令驗證:")
            print(f"   python3 verify_coverage.py")

        print("=" * 80)

    def check_existing_data(self, days=3):
        """檢查目標索引中已有的歷史資料範圍"""
        print("\n" + "=" * 80)
        print("檢查現有資料")
        print("=" * 80)

        query = {
            "size": 0,
            "query": {
                "range": {
                    "time_bucket": {
                        "gte": f"now-{days}d"
                    }
                }
            },
            "aggs": {
                "time_range": {
                    "stats": {
                        "field": "time_bucket"
                    }
                },
                "doc_count": {
                    "value_count": {
                        "field": "time_bucket"
                    }
                }
            }
        }

        try:
            response = requests.post(
                f"{self.es_url}/{DEST_INDEX}/_search",
                json=query,
                headers={'Content-Type': 'application/json'}
            )
            response.raise_for_status()
            data = response.json()

            total_docs = data['hits']['total']['value']

            if total_docs > 0:
                stats = data['aggregations']['time_range']
                min_time = datetime.fromtimestamp(stats['min'] / 1000)
                max_time = datetime.fromtimestamp(stats['max'] / 1000)

                print(f"現有文檔數: {total_docs:,}")
                print(f"時間範圍: {min_time.strftime('%Y-%m-%d %H:%M')} - {max_time.strftime('%Y-%m-%d %H:%M')}")
            else:
                print("索引中目前無資料")

        except Exception as e:
            print(f"❌ 查詢失敗: {e}")

        print("=" * 80)


def main():
    backfill = HistoricalDataBackfill()

    # 解析命令行參數
    if '--check' in sys.argv:
        # 只檢查現有資料
        days = int(sys.argv[sys.argv.index('--check') + 1]) if len(sys.argv) > sys.argv.index('--check') + 1 else 7
        backfill.check_existing_data(days)
        return

    # 回填模式
    dry_run = '--execute' not in sys.argv
    auto_confirm = '--auto-confirm' in sys.argv

    # 獲取天數參數
    days = 3
    if '--days' in sys.argv:
        days = int(sys.argv[sys.argv.index('--days') + 1])

    # 獲取批次大小
    batch_hours = 1
    if '--batch-hours' in sys.argv:
        batch_hours = int(sys.argv[sys.argv.index('--batch-hours') + 1])

    # 先檢查現有資料
    backfill.check_existing_data(days)

    # 執行回填
    backfill.backfill(days=days, batch_hours=batch_hours, dry_run=dry_run, auto_confirm=auto_confirm)


if __name__ == "__main__":
    if len(sys.argv) == 1 or '--help' in sys.argv or '-h' in sys.argv:
        print("""
NetFlow 歷史資料回填工具

用法:
    # 測試模式 (不實際寫入，僅顯示會處理的資料)
    python3 backfill_historical_data.py
    python3 backfill_historical_data.py --days 3

    # 正式執行 (實際寫入資料)
    python3 backfill_historical_data.py --execute
    python3 backfill_historical_data.py --execute --days 3

    # 背景執行（自動確認，不需要輸入 yes/no）
    python3 backfill_historical_data.py --execute --auto-confirm --days 3

    # 自訂批次大小 (每批處理幾小時)
    python3 backfill_historical_data.py --execute --days 7 --batch-hours 2

    # 檢查現有資料
    python3 backfill_historical_data.py --check
    python3 backfill_historical_data.py --check 7

參數說明:
    --execute        正式執行模式 (會實際寫入資料)
    --auto-confirm   自動確認執行（用於 nohup 背景執行）
    --days N         回填過去 N 天的資料 (預設: 3)
    --batch-hours N  每批處理 N 小時 (預設: 1，建議 1-6)
    --check [N]      檢查索引中現有資料 (可選擇天數)
    --help, -h       顯示此說明

注意事項:
    1. 首次執行建議使用測試模式，確認資料範圍無誤
    2. 批次大小建議 1-6 小時，避免單次查詢過大
    3. 回填會自動跳過已存在的文檔 (使用 time_bucket + src_ip 作為 ID)
    4. 大量回填可能需要較長時間，請耐心等待

範例:
    # 回填過去3天，測試模式
    python3 backfill_historical_data.py --days 3

    # 確認無誤後，正式執行
    python3 backfill_historical_data.py --execute --days 3

    # 回填過去7天，每批處理2小時
    python3 backfill_historical_data.py --execute --days 7 --batch-hours 2
        """)
        sys.exit(0)

    main()
