#!/usr/bin/env python3
"""
測試特徵分離功能
"""

import unittest
import numpy as np
from nad.ml.feature_engineer import FeatureEngineer
from nad.ml.isolation_forest_detector import OptimizedIsolationForest
from nad.ml.anomaly_classifier import AnomalyClassifier
from unittest.mock import MagicMock

class MockConfig:
    def __init__(self):
        self.features_config = {
            'basic': ['flow_count', 'total_bytes'],
            'derived': ['dst_diversity'],
            'binary': ['is_high_connection'],
            'log_transform': ['log_flow_count'],
            'device_type': ['device_type']
        }
        self.thresholds = {
            'high_connection': 1000,
            'scanning_dsts': 30,
            'scanning_avg_bytes': 10000,
            'small_packet': 1000,
            'large_flow': 104857600
        }
        self.isolation_forest_config = {
            'n_estimators': 100,
            'contamination': 0.05,
            'max_samples': 256,
            'max_features': 1.0,
            'random_state': 42
        }
        self.output_config = {
            'models_dir': '/tmp/models'
        }
        # Test custom classification features
        self.classification_features_config = [
            'flow_rate', 
            'byte_rate'
            # Intentionally omitting 'common_ports_ratio' to test config respect
        ]

class TestClassificationFeatures(unittest.TestCase):
    def setUp(self):
        self.config = MockConfig()
        self.feature_engineer = FeatureEngineer(self.config)
        
        # Mock device classifier
        self.feature_engineer.device_classifier = MagicMock()
        self.feature_engineer.device_classifier.get_device_type_code.return_value = 0
        
        # Create models dir if not exists
        import os
        if not os.path.exists('/tmp/models'):
            os.makedirs('/tmp/models')

    def test_feature_names_separation(self):
        """測試檢測特徵和分類特徵是否正確分離"""
        detection_features = self.feature_engineer.detection_feature_names
        classification_features = self.feature_engineer.classification_feature_names
        
        print(f"Detection features count: {len(detection_features)}")
        print(f"Classification features count: {len(classification_features)}")
        
        # 驗證分類特徵包含檢測特徵
        self.assertTrue(set(detection_features).issubset(set(classification_features)))
        
        # 驗證分類特徵比檢測特徵多
        self.assertTrue(len(classification_features) > len(detection_features))
        
        # 驗證新增的分類特徵存在
        self.assertIn('flow_rate', classification_features)
        self.assertIn('byte_rate', classification_features)
        
        # Verify that omitted feature is NOT present (proving config is used)
        self.assertNotIn('common_ports_ratio', classification_features)
        
        print("Feature separation test passed!")

    def test_extract_classification_features(self):
        """測試提取分類特徵"""
        # 模擬聚合記錄
        record = {
            'src_ip': '192.168.1.100',
            'flow_count': 100,
            'total_bytes': 10000,
            'total_packets': 500,
            'unique_dsts': 5,
            'unique_src_ports': 50,
            'unique_dst_ports': 10,
            'avg_bytes': 100,
            'max_bytes': 1000,
            'time_bucket': '2023-01-01T12:00:00'
        }
        
        # 提取檢測特徵
        det_features = self.feature_engineer.extract_features(record)
        
        # 提取分類特徵
        cls_features = self.feature_engineer.extract_classification_features(record)
        
        # 驗證 extract_features 返回的結果包含所有檢測特徵
        for name in self.feature_engineer.detection_feature_names:
            self.assertIn(name, det_features)
            
        # 驗證 extract_classification_features 返回的結果包含所有分類特徵
        # 注意：extract_classification_features 會計算並返回所有分類特徵
        for name in self.feature_engineer.classification_feature_names:
            self.assertIn(name, cls_features)
        
        # 驗證新增特徵的值
        self.assertIn('flow_rate', cls_features)
        self.assertIn('byte_rate', cls_features)
        
        # flow_rate = flow_count / 300 (5 mins) = 100 / 300 = 0.333
        self.assertAlmostEqual(cls_features['flow_rate'], 100/300)
        
        print("Classification feature extraction test passed!")

    def test_model_uses_detection_features(self):
        """測試模型只使用檢測特徵"""
        model = OptimizedIsolationForest(self.config)
        
        # 檢查模型使用的特徵名稱
        self.assertEqual(model.feature_engineer.detection_feature_names, 
                         self.feature_engineer.detection_feature_names)
        
        print("Model feature usage test passed!")

if __name__ == '__main__':
    unittest.main()
