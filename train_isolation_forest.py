#!/usr/bin/env python3
"""
Isolation Forest 訓練腳本

使用聚合數據訓練無監督異常檢測模型
"""

import sys
import argparse
import warnings
from datetime import datetime

# 忽略 Elasticsearch 安全警告
warnings.filterwarnings('ignore', message='.*Elasticsearch built-in security features.*')

from nad.utils import load_config
from nad.ml import OptimizedIsolationForest


def main():
    parser = argparse.ArgumentParser(
        description='訓練 Isolation Forest 異常檢測模型'
    )
    parser.add_argument(
        '--days',
        type=int,
        default=7,
        help='訓練數據天數（默認: 7）'
    )
    parser.add_argument(
        '--config',
        type=str,
        default='nad/config.yaml',
        help='配置文件路徑'
    )
    parser.add_argument(
        '--evaluate',
        action='store_true',
        help='訓練後進行評估'
    )
    parser.add_argument(
        '--exclude-servers',
        action='store_true',
        help='訓練時排除可能的服務器回應流量（is_likely_server_response=1）'
    )

    args = parser.parse_args()

    # 加載配置
    print(f"\n📋 加載配置文件: {args.config}")
    try:
        config = load_config(args.config)
        print(f"✓ 配置加載成功\n")
    except Exception as e:
        print(f"❌ 配置加載失敗: {e}")
        sys.exit(1)

    # 創建檢測器
    detector = OptimizedIsolationForest(config)

    # 訓練
    try:
        start_time = datetime.now()

        detector.train_on_aggregated_data(
            days=args.days,
            exclude_servers=args.exclude_servers
        )

        elapsed = (datetime.now() - start_time).total_seconds()
        print(f"⏱️  總訓練時間: {elapsed:.2f} 秒\n")

    except Exception as e:
        print(f"\n❌ 訓練失敗: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # 顯示模型信息
    model_info = detector.get_model_info()
    print(f"📊 模型信息:")
    print(f"  狀態: {model_info['status']}")
    print(f"  樹的數量: {model_info['n_estimators']}")
    print(f"  污染率: {model_info['contamination']}")
    print(f"  特徵數量: {model_info['n_features']}")
    print(f"  模型路徑: {model_info['model_path']}\n")

    # 評估（可選）
    if args.evaluate:
        print(f"{'='*70}")
        print("開始評估模型...")
        print(f"{'='*70}\n")

        try:
            eval_result = detector.evaluate(days=1)

            print("\n✅ 評估完成")
            print(f"\n建議下一步:")
            print(f"  1. 運行實時檢測: python3 realtime_detection.py")
            print(f"  2. 查看檢測結果")
            print(f"  3. 根據結果調整配置\n")

        except Exception as e:
            print(f"⚠️  評估失敗: {e}")

    else:
        print(f"💡 提示:")
        print(f"  使用 --evaluate 參數進行模型評估")
        print(f"  例如: python3 train_isolation_forest.py --days 7 --evaluate\n")


if __name__ == "__main__":
    main()
