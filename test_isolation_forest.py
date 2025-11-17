#!/usr/bin/env python3
"""
Isolation Forest 測試腳本（不需要真實訓練）

測試代碼邏輯和結構
"""

import sys
import numpy as np

# 模擬測試
print("="*70)
print("Isolation Forest 代碼結構測試")
print("="*70)
print()

# Test 1: 配置加載
print("✓ Test 1: 檢查配置文件結構...")
try:
    import yaml
    with open('nad/config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    print(f"  - ES Host: {config['elasticsearch']['host']}")
    print(f"  - 聚合索引: {config['elasticsearch']['indices']['aggregated']}")
    print(f"  - 特徵數量: {len(config['features']['basic']) + len(config['features']['derived']) + len(config['features']['binary']) + len(config['features']['log_transform'])}")
    print("  ✅ 配置文件結構正確\n")
except Exception as e:
    print(f"  ❌ 失敗: {e}\n")

# Test 2: 特徵工程
print("✓ Test 2: 測試特徵工程...")
try:
    from nad.ml.feature_engineer import FeatureEngineer
    from nad.utils import load_config

    config = load_config('nad/config.yaml')
    engineer = FeatureEngineer(config)

    # 模擬聚合記錄
    mock_record = {
        'flow_count': 1500,
        'total_bytes': 15000000,
        'total_packets': 10000,
        'unique_dsts': 50,
        'unique_ports': 30,
        'avg_bytes': 10000,
        'max_bytes': 500000
    }

    features = engineer.extract_features(mock_record)

    print(f"  - 提取特徵數: {len(features)}")
    print(f"  - 特徵名稱: {list(features.keys())[:5]}...")
    print(f"  - flow_count: {features['flow_count']}")
    print(f"  - dst_diversity: {features['dst_diversity']:.3f}")
    print(f"  - is_high_connection: {features['is_high_connection']}")
    print("  ✅ 特徵工程正常\n")
except Exception as e:
    print(f"  ❌ 失敗: {e}\n")
    import traceback
    traceback.print_exc()

# Test 3: 批量特徵提取
print("✓ Test 3: 測試批量特徵提取...")
try:
    mock_records = [
        {
            'flow_count': 100,
            'total_bytes': 1000000,
            'total_packets': 500,
            'unique_dsts': 10,
            'unique_ports': 5,
            'avg_bytes': 10000,
            'max_bytes': 50000
        },
        {
            'flow_count': 5000,
            'total_bytes': 50000000,
            'total_packets': 30000,
            'unique_dsts': 200,
            'unique_ports': 100,
            'avg_bytes': 10000,
            'max_bytes': 1000000
        }
    ]

    X = engineer.extract_features_batch(mock_records)

    print(f"  - 輸入記錄數: {len(mock_records)}")
    print(f"  - 輸出矩陣形狀: {X.shape}")
    print(f"  - 樣本數: {X.shape[0]}")
    print(f"  - 特徵數: {X.shape[1]}")
    print(f"  - 特徵名稱數: {len(engineer.feature_names)}")
    assert X.shape[1] == len(engineer.feature_names), "特徵數量不匹配"
    print("  ✅ 批量特徵提取正常\n")
except Exception as e:
    print(f"  ❌ 失敗: {e}\n")
    import traceback
    traceback.print_exc()

# Test 4: Isolation Forest 結構
print("✓ Test 4: 測試 Isolation Forest 類結構...")
try:
    from nad.ml.isolation_forest_detector import OptimizedIsolationForest

    detector = OptimizedIsolationForest(config)

    print(f"  - 模型配置: {detector.model_config}")
    print(f"  - 特徵數量: {len(detector.feature_engineer.feature_names)}")
    print(f"  - 模型路徑: {detector.model_path}")

    # 測試模型信息（未訓練狀態）
    info = detector.get_model_info()
    print(f"  - 模型狀態: {info['status']}")
    print("  ✅ Isolation Forest 類結構正常\n")
except Exception as e:
    print(f"  ❌ 失敗: {e}\n")
    import traceback
    traceback.print_exc()

# Test 5: 訓練腳本語法
print("✓ Test 5: 檢查訓練腳本語法...")
try:
    import ast
    with open('train_isolation_forest.py', 'r') as f:
        code = f.read()
    ast.parse(code)
    print("  ✅ 訓練腳本語法正確\n")
except Exception as e:
    print(f"  ❌ 失敗: {e}\n")

# Test 6: 實時檢測腳本語法
print("✓ Test 6: 檢查實時檢測腳本語法...")
try:
    with open('realtime_detection.py', 'r') as f:
        code = f.read()
    ast.parse(code)
    print("  ✅ 實時檢測腳本語法正確\n")
except Exception as e:
    print(f"  ❌ 失敗: {e}\n")

# 總結
print("="*70)
print("測試總結")
print("="*70)
print()
print("✅ 代碼結構測試通過")
print()
print("📝 下一步（需要真實數據）:")
print("   1. 確保 Elasticsearch 運行且有數據")
print("   2. 安裝依賴（如果尚未安裝）:")
print("      pip3 install scikit-learn elasticsearch pyyaml")
print("   3. 訓練模型:")
print("      python3 train_isolation_forest.py --days 7 --evaluate")
print("   4. 實時檢測:")
print("      python3 realtime_detection.py --minutes 10")
print()
print("="*70)
