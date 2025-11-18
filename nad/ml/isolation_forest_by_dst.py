#!/usr/bin/env python3
"""
基於 Dst 視角的 Isolation Forest 異常檢測器

使用 netflow_stats_5m_by_dst 聚合數據訓練，偵測：
1. DDoS 攻擊目標（unique_srcs 很高）
2. 被掃描的目標（unique_src_ports 很高）
3. 資料外洩目標端（大量內部 IP 向外部 IP 傳輸數據）
4. 惡意軟體分發服務器（大量內部 IP 下載）
"""

import numpy as np
import pickle
import os
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from elasticsearch import Elasticsearch
from typing import Dict, List, Tuple

try:
    from .feature_engineer_dst import FeatureEngineerDst
except ImportError:
    # 如果作為腳本直接運行
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))
    from nad.ml.feature_engineer_dst import FeatureEngineerDst


class IsolationForestByDst:
    """
    基於 Dst 視角的 Isolation Forest 檢測器

    特點：
    - 使用 netflow_stats_5m_by_dst 聚合數據
    - 偵測 dst 視角的異常（DDoS, 被掃描, 資料外洩目標端等）
    - 與 by_src 模型互補
    """

    def __init__(self, config=None):
        self.config = config
        self.model = None
        self.scaler = StandardScaler()
        self.feature_engineer = FeatureEngineerDst(config)

        # 模型配置
        if config:
            iso_config = config.isolation_forest_config
            self.model_config = iso_config
            self.model_path = os.path.join(
                config.output_config['models_dir'],
                'isolation_forest_by_dst.pkl'
            )
            self.scaler_path = os.path.join(
                config.output_config['models_dir'],
                'scaler_by_dst.pkl'
            )
        else:
            self.model_config = {
                'contamination': 0.05,
                'n_estimators': 150,
                'max_samples': 512,
                'max_features': 0.8,
                'random_state': 42,
                'n_jobs': -1
            }
            self.model_path = 'nad/models/isolation_forest_by_dst.pkl'
            self.scaler_path = 'nad/models/scaler_by_dst.pkl'

        # Elasticsearch 客戶端
        self.es = None

    def _init_es_client(self):
        """初始化 Elasticsearch 客戶端"""
        if self.es is None:
            es_host = self.config.es_host if self.config else "http://localhost:9200"
            self.es = Elasticsearch([es_host], timeout=30)

    def train_on_aggregated_data(self, days: int = 7, exclude_servers: bool = False) -> 'IsolationForestByDst':
        """
        使用 by_dst 聚合數據訓練模型

        Args:
            days: 訓練數據天數（默認7天）
            exclude_servers: 是否排除伺服器回應流量（預留參數，by_dst 模式下此參數無效）

        Returns:
            self

        Note:
            exclude_servers 參數在 by_dst 模式下不適用，因為目標 IP 視角
            主要關注被連接的目標，而非發起連接的來源
        """
        print(f"\n{'='*70}")
        print(f"Isolation Forest (by_dst) 訓練 - 使用過去 {days} 天的聚合數據")
        print(f"{'='*70}\n")

        self._init_es_client()

        # Step 1: 收集訓練數據
        print(f"📚 Step 1: 收集過去 {days} 天的聚合數據...")
        training_records = self._fetch_training_data(days)

        if len(training_records) == 0:
            raise ValueError("沒有找到訓練數據！請檢查 netflow_stats_5m_by_dst 索引。")

        print(f"✓ 收集到 {len(training_records):,} 筆聚合記錄\n")

        # Step 2: 特徵提取
        print("🔧 Step 2: 提取特徵...")
        X = self.feature_engineer.extract_features_batch(training_records)

        if len(X) == 0:
            raise ValueError("特徵提取失敗！")

        print(f"✓ 提取到 {X.shape[1]} 個特徵")
        print(f"✓ 訓練樣本數: {X.shape[0]:,}\n")

        # Step 3: 標準化
        print("📊 Step 3: 特徵標準化...")
        X_scaled = self.scaler.fit_transform(X)
        print(f"✓ 標準化完成\n")

        # Step 4: 訓練 Isolation Forest
        print("🤖 Step 4: 訓練 Isolation Forest...")
        self.model = IsolationForest(**self.model_config)
        self.model.fit(X_scaled)
        print(f"✓ 模型訓練完成\n")

        # Step 5: 評估
        print("📈 Step 5: 訓練集評估...")
        predictions = self.model.predict(X_scaled)
        scores = self.model.score_samples(X_scaled)

        n_anomalies = np.sum(predictions == -1)
        anomaly_rate = n_anomalies / len(predictions)

        print(f"✓ 訓練集異常數: {n_anomalies:,} ({anomaly_rate*100:.2f}%)")
        print(f"✓ 異常分數範圍: [{scores.min():.3f}, {scores.max():.3f}]")
        print(f"✓ 異常分數平均: {scores.mean():.3f}\n")

        # Step 6: 保存模型
        print("💾 Step 6: 保存模型...")
        self._save_model()
        print(f"✓ 模型已保存: {self.model_path}")
        print(f"✓ Scaler 已保存: {self.scaler_path}\n")

        print("=" * 70)
        print("訓練完成！")
        print("=" * 70)

        return self

    def _fetch_training_data(self, days: int) -> List[Dict]:
        """
        從 netflow_stats_5m_by_dst 獲取訓練數據

        Args:
            days: 過去 N 天

        Returns:
            記錄列表
        """
        end_time = datetime.now()
        start_time = end_time - timedelta(days=days)

        query = {
            "size": 10000,
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "time_bucket": {
                                    "gte": start_time.isoformat(),
                                    "lte": end_time.isoformat()
                                }
                            }
                        }
                    ]
                }
            },
            "sort": [{"time_bucket": "desc"}]
        }

        records = []
        scroll_size = 10000

        # 使用 scroll API 獲取大量數據
        result = self.es.search(
            index='netflow_stats_5m_by_dst',
            body=query,
            scroll='5m',
            size=scroll_size
        )

        scroll_id = result['_scroll_id']
        hits = result['hits']['hits']

        while hits:
            for hit in hits:
                records.append(hit['_source'])

            # 獲取下一批
            result = self.es.scroll(scroll_id=scroll_id, scroll='5m')
            hits = result['hits']['hits']

        # 清理 scroll
        self.es.clear_scroll(scroll_id=scroll_id)

        return records

    def predict_realtime(self, recent_minutes: int = 10) -> List[Dict]:
        """
        實時異常偵測（dst 視角）

        Args:
            recent_minutes: 分析最近 N 分鐘的數據

        Returns:
            異常列表
        """
        if self.model is None:
            raise ValueError("模型尚未訓練或加載！請先調用 train_on_aggregated_data() 或 _load_model()")

        self._init_es_client()

        # 查詢最近的數據
        records = self._fetch_recent_data(recent_minutes)

        if not records:
            return []

        # 提取特徵
        X = self.feature_engineer.extract_features_batch(records)

        if len(X) == 0:
            return []

        # 標準化
        X_scaled = self.scaler.transform(X)

        # 預測
        predictions = self.model.predict(X_scaled)
        scores = self.model.score_samples(X_scaled)

        # 收集異常
        anomalies = []
        for i, pred in enumerate(predictions):
            if pred == -1:  # 異常
                record = records[i]

                # 計算置信度（基於異常分數）
                confidence = self._calculate_confidence(scores[i])

                # 提取特徵（用於後續分類）
                features = self.feature_engineer.extract_features(record)

                anomaly = {
                    'dst_ip': record['dst_ip'],
                    'time_bucket': record['time_bucket'],
                    'anomaly_score': abs(scores[i]),
                    'confidence': confidence,
                    'perspective': 'DST',  # 標記視角

                    # Dst 視角的關鍵指標
                    'unique_srcs': record.get('unique_srcs', 0),
                    'unique_src_ports': record.get('unique_src_ports', 0),
                    'unique_dst_ports': record.get('unique_dst_ports', 0),
                    'flow_count': record.get('flow_count', 0),
                    'total_bytes': record.get('total_bytes', 0),
                    'avg_bytes': record.get('avg_bytes', 0),

                    # 特徵向量（用於分類）
                    'features': {
                        'unique_srcs': record.get('unique_srcs', 0),
                        'unique_src_ports': record.get('unique_src_ports', 0),
                        'unique_dst_ports': record.get('unique_dst_ports', 0),
                        'flow_count': record.get('flow_count', 0),
                        'total_bytes': record.get('total_bytes', 0),
                        'avg_bytes': record.get('avg_bytes', 0),
                        'flows_per_src': features[8] if len(features) > 8 else 0,
                        'bytes_per_src': features[9] if len(features) > 9 else 0,
                    }
                }

                anomalies.append(anomaly)

        return anomalies

    def _fetch_recent_data(self, recent_minutes: int) -> List[Dict]:
        """
        查詢最近的 by_dst 數據

        Args:
            recent_minutes: 最近 N 分鐘

        Returns:
            記錄列表
        """
        query = {
            "size": 10000,
            "query": {
                "range": {
                    "time_bucket": {
                        "gte": f"now-{recent_minutes}m"
                    }
                }
            },
            "sort": [{"time_bucket": "desc"}]
        }

        result = self.es.search(index='netflow_stats_5m_by_dst', body=query)
        hits = result['hits']['hits']

        records = [hit['_source'] for hit in hits]
        return records

    def _calculate_confidence(self, score: float) -> float:
        """
        計算異常置信度

        Args:
            score: Isolation Forest 分數（越負越異常）

        Returns:
            置信度（0-1）
        """
        # 將分數映射到 0-1 範圍
        # score 範圍通常是 [-0.5, 0.5]
        # 異常分數 < 0，越負越異常
        if score >= 0:
            return 0.5

        # 使用 sigmoid 映射
        confidence = 1 / (1 + np.exp(score * 10))
        return min(max(confidence, 0.5), 1.0)

    def _save_model(self):
        """保存模型和 scaler"""
        # 確保目錄存在
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)

        # 保存模型
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)

        # 保存 scaler
        with open(self.scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)

    def _load_model(self):
        """加載模型和 scaler"""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"模型文件不存在: {self.model_path}\n"
                f"請先訓練模型: python3 train_isolation_forest_by_dst.py"
            )

        with open(self.model_path, 'rb') as f:
            self.model = pickle.load(f)

        with open(self.scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)

    def get_model_info(self) -> Dict:
        """獲取模型信息"""
        if self.model is None:
            return {'status': 'not_trained'}

        return {
            'status': 'trained',
            'n_features': self.feature_engineer.get_n_features(),
            'contamination': self.model_config['contamination'],
            'n_estimators': self.model_config['n_estimators'],
            'model_path': self.model_path,
            'perspective': 'DST'
        }


# ========== 測試 ==========

def test_training():
    """測試訓練"""
    print("測試 Isolation Forest (by_dst) 訓練\n")

    detector = IsolationForestByDst()

    try:
        detector.train_on_aggregated_data(days=7)
        print("\n✓ 訓練成功")

        # 顯示模型信息
        info = detector.get_model_info()
        print(f"\n模型信息:")
        print(f"  - 特徵數: {info['n_features']}")
        print(f"  - 污染率: {info['contamination']}")
        print(f"  - 視角: {info['perspective']}")

    except Exception as e:
        print(f"\n✗ 訓練失敗: {e}")


def test_prediction():
    """測試預測"""
    print("\n" + "=" * 70)
    print("測試 Isolation Forest (by_dst) 實時偵測")
    print("=" * 70 + "\n")

    detector = IsolationForestByDst()

    try:
        # 加載模型
        detector._load_model()
        print("✓ 模型已加載\n")

        # 實時偵測
        anomalies = detector.predict_realtime(recent_minutes=30)
        print(f"✓ 偵測到 {len(anomalies)} 個 dst 視角異常\n")

        if anomalies:
            print("前 5 個異常:")
            for i, anomaly in enumerate(anomalies[:5], 1):
                print(f"\n{i}. {anomaly['dst_ip']}")
                print(f"   異常分數: {anomaly['anomaly_score']:.4f}")
                print(f"   置信度: {anomaly['confidence']:.0%}")
                print(f"   unique_srcs: {anomaly['unique_srcs']}")
                print(f"   unique_src_ports: {anomaly['unique_src_ports']}")
                print(f"   flow_count: {anomaly['flow_count']:,}")
                print(f"   avg_bytes: {anomaly['avg_bytes']:.0f}")

    except FileNotFoundError as e:
        print(f"✗ {e}")
    except Exception as e:
        print(f"✗ 預測失敗: {e}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == '--train':
        test_training()
    elif len(sys.argv) > 1 and sys.argv[1] == '--predict':
        test_prediction()
    else:
        print("用法:")
        print("  訓練: python3 nad/ml/isolation_forest_by_dst.py --train")
        print("  預測: python3 nad/ml/isolation_forest_by_dst.py --predict")
