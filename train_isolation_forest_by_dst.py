#!/usr/bin/env python3
"""
訓練 Isolation Forest (by_dst) 模型

使用 netflow_stats_5m_by_dst 聚合數據訓練模型，用於偵測：
- DDoS 攻擊目標
- 被掃描的目標
- 資料外洩目標端
- 惡意軟體分發服務器
"""

import sys
import os
import argparse

# 添加專案根目錄到 Python 路徑
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nad.ml.isolation_forest_by_dst import IsolationForestByDst


def main():
    """主函數"""
    parser = argparse.ArgumentParser(
        description='訓練 Isolation Forest (by_dst) 模型'
    )
    parser.add_argument(
        '--days',
        type=int,
        default=7,
        help='訓練數據天數（默認 7 天）'
    )

    args = parser.parse_args()

    print("\n" + "🤖 " * 25)
    print("Isolation Forest (by_dst) 訓練")
    print("🤖 " * 25 + "\n")

    # 初始化檢測器
    detector = IsolationForestByDst()

    try:
        # 訓練模型
        detector.train_on_aggregated_data(days=args.days)

        # 顯示模型信息
        info = detector.get_model_info()
        print(f"\n✓ 訓練成功完成")
        print(f"\n模型信息:")
        print(f"  - 視角: {info['perspective']}")
        print(f"  - 特徵數: {info['n_features']}")
        print(f"  - 污染率: {info['contamination']}")
        print(f"  - 估計器數: {info['n_estimators']}")
        print(f"  - 模型路徑: {info['model_path']}")

        print(f"\n下一步:")
        print(f"  1. 測試模型: python3 nad/ml/isolation_forest_by_dst.py --predict")
        print(f"  2. 整合到實時偵測: python3 realtime_detection_integrated.py --enable-dst-model")

    except Exception as e:
        print(f"\n❌ 訓練失敗: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
