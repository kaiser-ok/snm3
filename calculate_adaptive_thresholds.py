#!/usr/bin/env python3
"""
自適應閾值計算器

基於歷史數據統計自動計算特徵閾值
使用百分位數方法確保閾值適應網路流量的實際分布
"""

import sys
import argparse
import numpy as np
import yaml
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from nad.utils.config_loader import load_config


class AdaptiveThresholdCalculator:
    """
    自適應閾值計算器

    基於歷史數據的統計分析來計算最優閾值
    """

    def __init__(self, es_client, config):
        self.es = es_client
        self.config = config
        self.index = config.get('elasticsearch', {}).get('indices', {}).get('aggregated', 'netflow_stats_5m')

    def calculate_thresholds(self, days=7, percentiles=None):
        """
        基於歷史數據計算自適應閾值

        Args:
            days: 分析天數
            percentiles: 百分位數字典 (特徵名 -> 百分位數)
                       例如: {'high_connection': 95, 'scanning_dsts': 90}

        Returns:
            閾值字典
        """
        if percentiles is None:
            # 默認百分位數設置
            # 95% 表示只有 5% 的數據會被標記為異常
            percentiles = {
                'high_connection': 95,      # 高連線數：95百分位
                'scanning_dsts': 90,        # 掃描目的地：90百分位
                'scanning_avg_bytes': 50,   # 掃描平均流量：50百分位（中位數）
                'small_packet': 25,         # 小封包：25百分位
                'large_flow': 99,           # 大流量：99百分位
            }

        print(f"\n{'='*100}")
        print(f"📊 基於歷史數據計算自適應閾值")
        print(f"{'='*100}\n")
        print(f"分析期間: 過去 {days} 天")
        print(f"數據源: {self.index}")
        print()

        # Step 1: 收集歷史數據
        print("📚 Step 1: 收集歷史聚合數據...")
        agg_data = self._fetch_historical_data(days)

        if not agg_data:
            print("❌ 沒有找到歷史數據！")
            return None

        print(f"✓ 收集到 {len(agg_data):,} 筆聚合記錄\n")

        # Step 2: 提取特徵值
        print("🔍 Step 2: 提取特徵值分布...")
        features = self._extract_features(agg_data)

        # Step 3: 計算統計量
        print("📈 Step 3: 計算統計量和百分位數...\n")
        statistics = self._calculate_statistics(features)

        # Step 4: 基於百分位數計算閾值
        print("🎯 Step 4: 計算自適應閾值...\n")
        thresholds = self._calculate_thresholds_from_percentiles(features, percentiles, statistics)

        # Step 5: 顯示結果
        self._display_results(thresholds, statistics, percentiles)

        return thresholds

    def _fetch_historical_data(self, days):
        """從 ES 獲取歷史聚合數據"""
        start_time = datetime.utcnow() - timedelta(days=days)

        query = {
            "size": 10000,  # 每次獲取上限
            "query": {
                "range": {
                    "time_bucket": {
                        "gte": start_time.isoformat()
                    }
                }
            },
            "_source": [
                "src_ip", "flow_count", "total_bytes", "total_packets",
                "unique_dsts", "unique_src_ports", "unique_dst_ports",
                "avg_bytes", "max_bytes"
            ]
        }

        all_data = []

        try:
            # 使用 scroll API 獲取所有數據
            response = self.es.search(
                index=self.index,
                body=query,
                scroll='5m'
            )

            scroll_id = response['_scroll_id']
            hits = response['hits']['hits']
            all_data.extend([hit['_source'] for hit in hits])

            # 繼續滾動獲取
            while len(hits) > 0:
                response = self.es.scroll(scroll_id=scroll_id, scroll='5m')
                scroll_id = response['_scroll_id']
                hits = response['hits']['hits']
                all_data.extend([hit['_source'] for hit in hits])

                if len(all_data) % 50000 == 0:
                    print(f"   已收集 {len(all_data):,} 筆...")

            # 清理 scroll
            self.es.clear_scroll(scroll_id=scroll_id)

        except Exception as e:
            print(f"❌ 查詢失敗: {e}")
            return []

        return all_data

    def _extract_features(self, agg_data):
        """從聚合數據中提取特徵值"""
        features = {
            'flow_count': [],
            'unique_dsts': [],
            'avg_bytes': [],
            'max_bytes': [],
            'total_bytes': [],
            'unique_src_ports': [],
            'unique_dst_ports': [],
            'dst_diversity': [],
            'src_port_diversity': [],
            'dst_port_diversity': [],
        }

        for record in agg_data:
            flow_count = record.get('flow_count', 0)
            total_bytes = record.get('total_bytes', 0)

            if flow_count == 0:
                continue

            # 基礎特徵
            features['flow_count'].append(flow_count)
            features['unique_dsts'].append(record.get('unique_dsts', 0))
            features['avg_bytes'].append(record.get('avg_bytes', 0))
            features['max_bytes'].append(record.get('max_bytes', 0))
            features['total_bytes'].append(total_bytes)
            features['unique_src_ports'].append(record.get('unique_src_ports', 0))
            features['unique_dst_ports'].append(record.get('unique_dst_ports', 0))

            # 衍生特徵
            features['dst_diversity'].append(record.get('unique_dsts', 0) / flow_count)
            features['src_port_diversity'].append(record.get('unique_src_ports', 0) / flow_count)
            features['dst_port_diversity'].append(record.get('unique_dst_ports', 0) / flow_count)

        # 轉換為 numpy arrays
        for key in features:
            features[key] = np.array(features[key])

        print(f"✓ 提取特徵: {', '.join(features.keys())}\n")

        return features

    def _calculate_statistics(self, features):
        """計算特徵的統計量"""
        statistics = {}

        print(f"{'特徵名稱':<25} {'最小值':>12} {'中位數':>12} {'平均值':>12} {'95%位':>12} {'99%位':>12} {'最大值':>12}")
        print(f"{'-'*100}")

        for feature_name, values in features.items():
            if len(values) == 0:
                continue

            stats = {
                'min': np.min(values),
                'p25': np.percentile(values, 25),
                'median': np.median(values),
                'p75': np.percentile(values, 75),
                'p90': np.percentile(values, 90),
                'p95': np.percentile(values, 95),
                'p99': np.percentile(values, 99),
                'max': np.max(values),
                'mean': np.mean(values),
                'std': np.std(values),
            }

            statistics[feature_name] = stats

            # 格式化輸出
            print(f"{feature_name:<25} "
                  f"{stats['min']:>12,.1f} "
                  f"{stats['median']:>12,.1f} "
                  f"{stats['mean']:>12,.1f} "
                  f"{stats['p95']:>12,.1f} "
                  f"{stats['p99']:>12,.1f} "
                  f"{stats['max']:>12,.1f}")

        print()
        return statistics

    def _calculate_thresholds_from_percentiles(self, features, percentiles, statistics):
        """基於百分位數計算閾值"""
        thresholds = {}

        # 1. high_connection: 基於 flow_count
        p = percentiles['high_connection']
        thresholds['high_connection'] = int(np.percentile(features['flow_count'], p))

        # 2. scanning_dsts: 基於 unique_dsts
        p = percentiles['scanning_dsts']
        thresholds['scanning_dsts'] = int(np.percentile(features['unique_dsts'], p))

        # 3. scanning_avg_bytes: 基於 avg_bytes 的較低百分位（掃描通常是小流量）
        p = percentiles['scanning_avg_bytes']
        thresholds['scanning_avg_bytes'] = int(np.percentile(features['avg_bytes'], p))

        # 4. small_packet: 基於 avg_bytes 的低百分位
        p = percentiles['small_packet']
        thresholds['small_packet'] = int(np.percentile(features['avg_bytes'], p))

        # 5. large_flow: 基於 max_bytes 的高百分位
        p = percentiles['large_flow']
        thresholds['large_flow'] = int(np.percentile(features['max_bytes'], p))

        return thresholds

    def _display_results(self, thresholds, statistics, percentiles):
        """顯示結果對比"""
        print(f"{'='*100}")
        print(f"🎯 自適應閾值計算結果")
        print(f"{'='*100}\n")

        # 獲取當前配置的閾值
        current_thresholds = self.config.get('thresholds', {})

        print(f"{'參數':<30} {'當前值':>15} {'建議值':>15} {'百分位':>10} {'變化':>15}")
        print(f"{'-'*100}")

        for param, new_value in thresholds.items():
            current_value = current_thresholds.get(param, 'N/A')
            percentile = percentiles.get(param, 'N/A')

            # 計算變化
            if isinstance(current_value, (int, float)):
                change = ((new_value - current_value) / current_value * 100)
                change_str = f"{change:+.1f}%"

                # 用顏色標記顯著變化
                if abs(change) > 50:
                    change_str = f"🔴 {change_str}"
                elif abs(change) > 20:
                    change_str = f"🟡 {change_str}"
                else:
                    change_str = f"🟢 {change_str}"
            else:
                change_str = "新增"

            # 格式化數值
            if isinstance(current_value, (int, float)):
                current_str = f"{current_value:,}"
            else:
                current_str = str(current_value)

            print(f"{param:<30} "
                  f"{current_str:>15} "
                  f"{new_value:>15,} "
                  f"P{percentile:>9} "
                  f"{change_str:>15}")

        print(f"\n{'='*100}")
        print(f"💡 應用建議")
        print(f"{'='*100}\n")

        print("1️⃣  自動更新配置文件:")
        print(f"   python3 {sys.argv[0]} --days 7 --apply\n")

        print("2️⃣  手動更新 nad/config.yaml:")
        print("   編輯 thresholds 部分:\n")
        print("   thresholds:")
        for param, value in thresholds.items():
            print(f"     {param}: {value}")
        print()

        print("3️⃣  重新訓練模型:")
        print("   python3 train_isolation_forest.py --days 7\n")

        print("4️⃣  驗證效果:")
        print("   python3 realtime_detection.py --minutes 30\n")

    def apply_thresholds(self, thresholds, config_path='nad/config.yaml'):
        """
        應用閾值到配置文件

        Args:
            thresholds: 計算出的閾值字典
            config_path: 配置文件路徑
        """
        print(f"\n{'='*100}")
        print(f"💾 應用閾值到配置文件")
        print(f"{'='*100}\n")

        try:
            # 讀取現有配置
            with open(config_path, 'r', encoding='utf-8') as f:
                original_config = f.read()

            config = yaml.safe_load(original_config)

            # 備份原配置（在修改之前）
            backup_path = f"{config_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(original_config)
            print(f"✓ 已備份原配置: {backup_path}")
            print()

            # 更新閾值
            if 'thresholds' not in config:
                config['thresholds'] = {}

            print("📝 更新閾值:")
            for param, value in thresholds.items():
                old_value = config['thresholds'].get(param, 'N/A')
                config['thresholds'][param] = value

                # 格式化顯示
                if isinstance(old_value, (int, float)):
                    change = ((value - old_value) / old_value * 100) if old_value != 0 else 0
                    print(f"   {param:<25} {old_value:>15,} → {value:>15,}  ({change:+.1f}%)")
                else:
                    print(f"   {param:<25} {old_value:>15} → {value:>15,}  (新增)")

            # 寫入新配置
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

            print(f"\n✓ 已更新配置文件: {config_path}")
            print(f"\n💡 如需回滾，執行:")
            print(f"   cp {backup_path} {config_path}")
            print(f"\n{'='*100}\n")

            return True

        except Exception as e:
            print(f"❌ 更新配置失敗: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description='基於歷史數據計算自適應閾值',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 分析過去 7 天的數據
  python3 calculate_adaptive_thresholds.py --days 7

  # 分析並自動應用到配置文件
  python3 calculate_adaptive_thresholds.py --days 7 --apply

  # 使用自定義百分位數
  python3 calculate_adaptive_thresholds.py --days 14 --percentile high_connection=98

  # 只計算特定參數
  python3 calculate_adaptive_thresholds.py --days 7 --params high_connection,scanning_dsts
        """
    )

    parser.add_argument('--days', type=int, default=7,
                       help='分析天數 (默認: 7)')
    parser.add_argument('--apply', action='store_true',
                       help='自動應用到配置文件')
    parser.add_argument('--config', type=str, default='nad/config.yaml',
                       help='配置文件路徑 (默認: nad/config.yaml)')
    parser.add_argument('--percentile', action='append',
                       help='自定義百分位數 (格式: param=value, 例如: high_connection=98)')
    parser.add_argument('--params', type=str,
                       help='只計算指定參數 (逗號分隔)')

    args = parser.parse_args()

    # 載入配置
    config = load_config()

    # 連接 Elasticsearch
    es_host = config.get('elasticsearch', {}).get('host', 'http://localhost:9200')
    es = Elasticsearch([es_host], timeout=30)

    if not es.ping():
        print(f"❌ 無法連接到 Elasticsearch: {es_host}")
        sys.exit(1)

    print(f"✓ 已連接到 Elasticsearch: {es_host}")

    # 創建計算器
    calculator = AdaptiveThresholdCalculator(es, config)

    # 解析自定義百分位數
    percentiles = None
    if args.percentile:
        percentiles = {}
        for item in args.percentile:
            param, value = item.split('=')
            percentiles[param.strip()] = float(value.strip())

    # 計算閾值
    thresholds = calculator.calculate_thresholds(
        days=args.days,
        percentiles=percentiles
    )

    if not thresholds:
        print("❌ 閾值計算失敗")
        sys.exit(1)

    # 如果指定了特定參數，只保留這些
    if args.params:
        param_list = [p.strip() for p in args.params.split(',')]
        thresholds = {k: v for k, v in thresholds.items() if k in param_list}

    # 應用閾值
    if args.apply:
        success = calculator.apply_thresholds(thresholds, args.config)
        if success:
            print("✅ 閾值已成功應用！")
            print("⚠️  請記得重新訓練模型: python3 train_isolation_forest.py --days 7")
        else:
            sys.exit(1)


if __name__ == '__main__':
    main()
