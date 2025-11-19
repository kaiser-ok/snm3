#!/usr/bin/env python3
"""
測試 Feature Drift 檢測機制

測試場景：
1. 舊模型向後兼容性測試（無元數據）
2. 新模型正常載入測試（有元數據，特徵一致）
3. Feature Drift 檢測測試（特徵不一致）
"""

import sys
import os
sys.path.insert(0, '/home/kaisermac/snm_flow')

import pickle
from datetime import datetime


def test_old_model_compatibility():
    """
    測試 1: 舊模型向後兼容性

    模擬載入舊格式模型（直接保存 model 對象，無特徵元數據）
    """
    print("\n" + "="*70)
    print("測試 1: 舊模型向後兼容性")
    print("="*70 + "\n")

    from nad.ml.isolation_forest_detector import OptimizedIsolationForest
    from nad.utils.config_loader import Config

    try:
        config = Config('/home/kaisermac/snm_flow/nad/config.yaml')
        detector = OptimizedIsolationForest(config)

        # 嘗試載入現有的舊格式模型
        print("載入現有模型...")
        detector._load_model()

        print("\n✓ 測試通過：舊格式模型可以正常載入")
        print("  （會顯示警告訊息，提示缺少特徵元數據）\n")

    except Exception as e:
        print(f"\n✗ 測試失敗: {e}\n")


def test_new_model_format():
    """
    測試 2: 新模型格式保存與載入

    測試新格式模型的保存和載入（包含特徵元數據）
    """
    print("\n" + "="*70)
    print("測試 2: 新模型格式保存與載入")
    print("="*70 + "\n")

    from nad.ml.isolation_forest_detector import OptimizedIsolationForest
    from nad.utils.config_loader import Config
    from sklearn.ensemble import IsolationForest

    try:
        config = Config('/home/kaisermac/snm_flow/nad/config.yaml')
        detector = OptimizedIsolationForest(config)

        # 模擬訓練（創建一個簡單的模型）
        print("創建測試模型...")
        detector.model = IsolationForest(n_estimators=10, random_state=42)

        # 保存模型（新格式，包含元數據）
        test_model_path = '/home/kaisermac/snm_flow/nad/models/test_model.pkl'
        test_scaler_path = '/home/kaisermac/snm_flow/nad/models/test_scaler.pkl'

        original_model_path = detector.model_path
        original_scaler_path = detector.scaler_path

        detector.model_path = test_model_path
        detector.scaler_path = test_scaler_path

        print("保存模型（新格式）...")
        detector._save_model()

        # 讀取並檢查模型文件內容
        print("\n檢查保存的模型結構...")
        with open(test_model_path, 'rb') as f:
            model_state = pickle.load(f)

        if isinstance(model_state, dict):
            print("✓ 模型使用新格式（字典結構）")
            print(f"  - 包含 model: {('model' in model_state)}")
            print(f"  - 包含 feature_names: {('feature_names' in model_state)}")
            print(f"  - 包含 n_features: {('n_features' in model_state)}")
            print(f"  - 包含 trained_at: {('trained_at' in model_state)}")
            print(f"  - 特徵數量: {model_state.get('n_features')}")
            print(f"  - 訓練時間: {model_state.get('trained_at')}")
        else:
            print("✗ 模型使用舊格式")

        # 重新載入測試
        print("\n重新載入模型...")
        detector2 = OptimizedIsolationForest(config)
        detector2.model_path = test_model_path
        detector2.scaler_path = test_scaler_path
        detector2._load_model()

        print("✓ 模型載入成功，特徵一致性驗證通過\n")

        # 清理測試文件
        os.remove(test_model_path)
        os.remove(test_scaler_path)

    except Exception as e:
        print(f"\n✗ 測試失敗: {e}\n")


def test_feature_drift_detection():
    """
    測試 3: Feature Drift 檢測

    模擬特徵配置變更，測試 drift 檢測機制
    """
    print("\n" + "="*70)
    print("測試 3: Feature Drift 檢測")
    print("="*70 + "\n")

    from nad.ml.isolation_forest_detector import OptimizedIsolationForest
    from nad.utils.config_loader import Config
    from sklearn.ensemble import IsolationForest

    try:
        config = Config('/home/kaisermac/snm_flow/nad/config.yaml')
        detector = OptimizedIsolationForest(config)

        # 保存當前特徵列表
        original_features = detector.feature_engineer.feature_names.copy()
        print(f"原始特徵列表 ({len(original_features)} 個):")
        print(f"  {original_features[:5]}...\n")

        # 創建測試模型（使用原始特徵）
        detector.model = IsolationForest(n_estimators=10, random_state=42)

        test_model_path = '/home/kaisermac/snm_flow/nad/models/test_drift_model.pkl'
        test_scaler_path = '/home/kaisermac/snm_flow/nad/models/test_drift_scaler.pkl'

        detector.model_path = test_model_path
        detector.scaler_path = test_scaler_path

        print("保存模型（使用原始特徵配置）...")
        detector._save_model()

        # 模擬修改特徵配置（改變順序）
        print("\n模擬修改特徵配置...")
        print("（將前兩個特徵順序對調）\n")

        # 修改 feature_engineer 的特徵列表
        modified_features = original_features.copy()
        modified_features[0], modified_features[1] = modified_features[1], modified_features[0]
        detector.feature_engineer.feature_names = modified_features

        print(f"修改後特徵列表 ({len(modified_features)} 個):")
        print(f"  {modified_features[:5]}...\n")

        # 嘗試載入模型（應該檢測到 drift）
        print("嘗試載入模型...")
        detector2 = OptimizedIsolationForest(config)
        detector2.model_path = test_model_path
        detector2.scaler_path = test_scaler_path

        # 手動設置修改後的特徵列表
        detector2.feature_engineer.feature_names = modified_features

        try:
            detector2._load_model()
            print("\n✗ Feature Drift 檢測失敗：沒有拋出異常\n")
        except ValueError as e:
            print("✓ Feature Drift 檢測成功！")
            print("  系統正確檢測到特徵不一致並拋出異常\n")
            print("異常訊息片段:")
            print("-" * 70)
            error_lines = str(e).split('\n')[:8]
            for line in error_lines:
                print(line)
            print("-" * 70)
            print()

        # 清理測試文件
        os.remove(test_model_path)
        os.remove(test_scaler_path)

    except Exception as e:
        print(f"\n✗ 測試異常: {e}\n")


def main():
    """執行所有測試"""
    print("\n" + "="*70)
    print("Feature Drift 檢測機制測試")
    print("="*70)

    # 測試 1: 舊模型向後兼容性
    test_old_model_compatibility()

    # 測試 2: 新模型格式
    test_new_model_format()

    # 測試 3: Feature Drift 檢測
    test_feature_drift_detection()

    print("\n" + "="*70)
    print("測試完成")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
