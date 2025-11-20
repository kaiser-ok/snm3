#!/usr/bin/env python3
"""
優化的 Isolation Forest 異常檢測器

基於 netflow_stats_5m 聚合數據的無監督異常檢測
"""

import numpy as np
import pickle
import os
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from elasticsearch import Elasticsearch
from typing import Dict, List, Tuple

from .feature_engineer import FeatureEngineer


class OptimizedIsolationForest:
    """
    優化的 Isolation Forest 檢測器

    特點：
    - 直接使用聚合數據訓練
    - 99.57% 數據覆蓋率
    - 訓練速度快（5-10分鐘）
    - 推論延遲低（< 1秒）
    """

    def __init__(self, config=None):
        self.config = config
        self.model = None
        self.scaler = StandardScaler()
        self.feature_engineer = FeatureEngineer(config)

        # 模型配置
        if config:
            iso_config = config.isolation_forest_config
            self.model_config = iso_config
            self.model_path = os.path.join(
                config.output_config['models_dir'],
                'isolation_forest.pkl'
            )
            self.scaler_path = os.path.join(
                config.output_config['models_dir'],
                'scaler.pkl'
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
            self.model_path = 'nad/models/isolation_forest.pkl'
            self.scaler_path = 'nad/models/scaler.pkl'

        # Elasticsearch 客戶端
        self.es = None

    def _init_es_client(self):
        """初始化 Elasticsearch 客戶端"""
        if self.es is None:
            es_host = self.config.es_host if self.config else "http://localhost:9200"
            self.es = Elasticsearch([es_host], timeout=30)

    def train_on_aggregated_data(self, days: int = 7, exclude_servers: bool = False) -> 'OptimizedIsolationForest':
        """
        使用聚合數據訓練模型

        Args:
            days: 訓練數據天數（默認7天）
            exclude_servers: 是否排除可能的服務器回應流量（默認False）

        Returns:
            self
        """
        print(f"\n{'='*70}")
        print(f"Isolation Forest 訓練 - 使用過去 {days} 天的聚合數據")
        if exclude_servers:
            print("(排除服務器回應流量)")
        print(f"{'='*70}\n")

        self._init_es_client()

        # Step 1: 收集訓練數據
        print(f"📚 Step 1: 收集過去 {days} 天的聚合數據...")
        training_records = self._fetch_training_data(days)

        if len(training_records) == 0:
            raise ValueError("沒有找到訓練數據！請檢查 Elasticsearch 索引。")

        print(f"✓ 收集到 {len(training_records):,} 筆聚合記錄\n")

        # Step 2: 特徵提取
        print("🔧 Step 2: 提取特徵...")
        X = self.feature_engineer.extract_features_batch(training_records)
        print(f"✓ 提取特徵矩陣: {X.shape}")
        print(f"  樣本數: {X.shape[0]:,}")
        print(f"  特徵數: {X.shape[1]}\n")

        # Step 2.5: 過濾服務器回應（如果啟用）
        if exclude_servers:
            print("🚫 Step 2.5: 過濾服務器回應流量...")
            # is_likely_server_response 是倒數第3個特徵（log_flow_count, log_total_bytes 之前）
            server_response_idx = self.feature_engineer.detection_feature_names.index('is_likely_server_response')

            # 找出不是服務器回應的樣本
            not_server_mask = X[:, server_response_idx] == 0
            X_filtered = X[not_server_mask]
            training_records_filtered = [training_records[i] for i in range(len(training_records)) if not_server_mask[i]]

            n_excluded = len(training_records) - len(training_records_filtered)
            print(f"✓ 排除 {n_excluded:,} 筆服務器回應記錄 ({n_excluded/len(training_records)*100:.2f}%)")
            print(f"  剩餘訓練樣本: {len(training_records_filtered):,}\n")

            X = X_filtered
            training_records = training_records_filtered

        # Step 3: 標準化
        print("📊 Step 3: 標準化特徵...")
        X_scaled = self.scaler.fit_transform(X)
        print(f"✓ 特徵已標準化\n")

        # Step 4: 訓練模型
        print("🏋️  Step 4: 訓練 Isolation Forest...")
        print(f"  配置: {self.model_config}")

        self.model = IsolationForest(**self.model_config)
        self.model.fit(X_scaled)

        print(f"✓ 訓練完成\n")

        # Step 5: 評估訓練結果
        print("📈 Step 5: 評估訓練結果...")
        predictions = self.model.predict(X_scaled)
        n_anomalies = np.sum(predictions == -1)
        anomaly_rate = n_anomalies / len(predictions) * 100

        print(f"  訓練集異常比例: {anomaly_rate:.2f}%")
        print(f"  異常樣本數: {n_anomalies:,} / {len(predictions):,}\n")

        # Step 6: 保存模型
        print("💾 Step 6: 保存模型...")
        self._save_model()
        print(f"✓ 模型已保存到: {self.model_path}\n")

        print(f"{'='*70}")
        print("✅ 訓練完成！")
        print(f"{'='*70}\n")

        return self

    def _fetch_training_data(self, days: int) -> List[Dict]:
        """
        從 ES 獲取訓練數據

        Args:
            days: 天數

        Returns:
            聚合記錄列表
        """
        index = self.config.es_aggregated_index if self.config else "netflow_stats_5m"

        query = {
            "size": 10000,
            "query": {
                "range": {
                    "time_bucket": {
                        "gte": f"now-{days}d",
                        "lt": "now"
                    }
                }
            }
        }

        # 使用 scroll API 獲取所有數據
        records = []
        response = self.es.search(index=index, body=query, scroll='5m')

        scroll_id = response['_scroll_id']
        hits = response['hits']['hits']

        while hits:
            for hit in hits:
                records.append(hit['_source'])

            # 繼續 scroll
            response = self.es.scroll(scroll_id=scroll_id, scroll='5m')
            hits = response['hits']['hits']

        # 清理 scroll
        self.es.clear_scroll(scroll_id=scroll_id)

        return records

    def predict_realtime(self, recent_minutes: int = 10) -> List[Dict]:
        """
        對最近的數據進行實時異常檢測

        Args:
            recent_minutes: 分析最近 N 分鐘

        Returns:
            異常列表
        """
        if self.model is None:
            self._load_model()

        self._init_es_client()

        # 計算明確的時間範圍
        from datetime import datetime, timedelta, timezone

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=recent_minutes)

        # 轉換為 ISO 8601 格式
        start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%S.000Z')

        # 查詢最近數據
        index = self.config.es_aggregated_index if self.config else "netflow_stats_5m"

        query = {
            "size": 1000,
            "query": {
                "range": {
                    "time_bucket": {
                        "gte": start_time_str,
                        "lte": end_time_str
                    }
                }
            }
        }

        response = self.es.search(index=index, body=query)
        records = [hit['_source'] for hit in response['hits']['hits']]

        if len(records) == 0:
            return []

        # 預測
        return self._predict_batch(records)

    def predict_batch(self, records: List[Dict]) -> List[Dict]:
        """
        批量預測

        Args:
            records: 聚合記錄列表

        Returns:
            預測結果列表
        """
        if self.model is None:
            self._load_model()

        return self._predict_batch(records)

    def _predict_batch(self, records: List[Dict]) -> List[Dict]:
        """
        內部批量預測方法

        Args:
            records: 聚合記錄

        Returns:
            異常結果
        """
        # 提取特徵
        X = self.feature_engineer.extract_features_batch(records)
        X_scaled = self.scaler.transform(X)

        # 預測
        predictions = self.model.predict(X_scaled)
        scores = self.model.score_samples(X_scaled)

        # 組裝結果
        results = []
        for i, (record, pred, score) in enumerate(zip(records, predictions, scores)):
            if pred == -1:  # 異常
                # 使用分類特徵提取器獲取更豐富的特徵
                features = self.feature_engineer.extract_classification_features(record)

                results.append({
                    'src_ip': record['src_ip'],
                    'time_bucket': record['time_bucket'],
                    'is_anomaly': True,
                    'anomaly_score': -score,  # 轉為正值，越大越異常
                    'confidence': self._score_to_confidence(-score),
                    'features': features,
                    'is_likely_server_response': features.get('is_likely_server_response', 0),  # 新增
                    'flow_count': record['flow_count'],
                    'unique_dsts': record['unique_dsts'],
                    'unique_src_ports': record.get('unique_src_ports', 0),
                    'unique_dst_ports': record.get('unique_dst_ports', 0),
                    'avg_bytes': record['avg_bytes'],
                    'total_bytes': record['total_bytes']
                })

        # 按異常分數排序
        results.sort(key=lambda x: x['anomaly_score'], reverse=True)

        return results

    def _score_to_confidence(self, score: float) -> float:
        """
        將異常分數轉換為置信度 (0-1)

        使用基於分佈的 Sigmoid 映射，避免早飽和問題

        Args:
            score: Isolation Forest 分數（已取反，正值）

        Returns:
            置信度 (0-1)
        """
        # 基於實際異常分數分佈的參數（通過校準數據得出）
        # 中位數約 0.57, 90分位約 0.66, 95分位約 0.68

        # 使用 Sigmoid 函數進行平滑映射
        # 參數設計:
        #   - midpoint (中點): 0.60 → 對應 50% 置信度
        #   - steepness (陡度): 20 → 控制曲線的平滑度
        midpoint = 0.60
        steepness = 20

        # Sigmoid 函數: 1 / (1 + exp(-steepness * (score - midpoint)))
        confidence = 1 / (1 + np.exp(-steepness * (score - midpoint)))

        # 確保在 [0, 1] 範圍內
        confidence = max(0.0, min(1.0, confidence))

        return confidence

    def _save_model(self):
        """保存模型、scaler 和特徵元數據"""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)

        # 準備模型狀態（包含特徵元數據）
        model_state = {
            'model': self.model,
            'feature_names': self.feature_engineer.detection_feature_names,
            'n_features': len(self.feature_engineer.detection_feature_names),
            'trained_at': datetime.now().isoformat(),
            'model_config': self.model_config
        }

        # 保存模型狀態
        with open(self.model_path, 'wb') as f:
            pickle.dump(model_state, f)

        # 保存 scaler（獨立文件）
        with open(self.scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)

    def _load_model(self):
        """加載模型和 scaler，並驗證特徵一致性"""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"模型文件不存在: {self.model_path}\n"
                f"請先運行訓練: detector.train_on_aggregated_data()"
            )

        with open(self.model_path, 'rb') as f:
            model_state = pickle.load(f)

        # 向後兼容：如果是舊格式（直接保存 model），轉換為新格式
        if isinstance(model_state, dict) and 'model' in model_state:
            # 新格式：包含元數據
            self.model = model_state['model']
            saved_feature_names = model_state.get('feature_names')
            saved_n_features = model_state.get('n_features')
            trained_at = model_state.get('trained_at', 'Unknown')

            # 驗證特徵一致性
            current_feature_names = self.feature_engineer.detection_feature_names

            if saved_feature_names is not None:
                if saved_feature_names != current_feature_names:
                    # 特徵漂移檢測
                    raise ValueError(
                        f"\n{'='*70}\n"
                        f"⚠️  Feature Drift 檢測到特徵不一致！\n"
                        f"{'='*70}\n\n"
                        f"模型訓練時的特徵 ({saved_n_features} 個):\n  {saved_feature_names}\n\n"
                        f"當前配置的特徵 ({len(current_feature_names)} 個):\n  {current_feature_names}\n\n"
                        f"模型訓練時間: {trained_at}\n\n"
                        f"可能原因:\n"
                        f"  1. config.yaml 中的 features 配置已被修改\n"
                        f"  2. 特徵順序發生變化\n"
                        f"  3. 新增或刪除了特徵\n\n"
                        f"解決方案:\n"
                        f"  1. 恢復 config.yaml 中的特徵配置為訓練時的設定\n"
                        f"  2. 或重新訓練模型以使用新的特徵配置\n"
                        f"{'='*70}\n"
                    )

                print(f"✓ 特徵一致性驗證通過 ({saved_n_features} 個特徵)")
            else:
                print("⚠️  警告：模型缺少特徵元數據（可能是舊版本訓練），無法進行特徵一致性檢查")
        else:
            # 舊格式：直接保存的 model 對象
            self.model = model_state
            print("⚠️  警告：載入舊格式模型（無特徵元數據），建議重新訓練")

        # 載入 scaler
        with open(self.scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)

    def evaluate(self, test_records: List[Dict] = None, days: int = 1) -> Dict:
        """
        評估模型性能

        Args:
            test_records: 測試數據（可選）
            days: 如果沒有提供測試數據，從最近 N 天獲取

        Returns:
            評估結果
        """
        if test_records is None:
            self._init_es_client()
            test_records = self._fetch_training_data(days)

        if len(test_records) == 0:
            raise ValueError("沒有測試數據")

        print(f"\n{'='*70}")
        print("模型評估")
        print(f"{'='*70}\n")

        # 預測
        results = self._predict_batch(test_records)

        # 統計
        n_total = len(test_records)
        n_anomalies = len(results)
        anomaly_rate = n_anomalies / n_total * 100

        print(f"測試樣本數: {n_total:,}")
        print(f"檢測到異常: {n_anomalies:,}")
        print(f"異常比例: {anomaly_rate:.2f}%\n")

        # 異常分數分布
        if n_anomalies > 0:
            scores = [r['anomaly_score'] for r in results]
            print(f"異常分數統計:")
            print(f"  最小值: {np.min(scores):.4f}")
            print(f"  最大值: {np.max(scores):.4f}")
            print(f"  平均值: {np.mean(scores):.4f}")
            print(f"  中位數: {np.median(scores):.4f}\n")

        # Top 異常
        if n_anomalies > 0:
            print("Top 10 異常:")
            print(f"{'-'*70}")
            for i, anomaly in enumerate(results[:10], 1):
                print(f"{i:2}. {anomaly['src_ip']:15} | "
                      f"分數: {anomaly['anomaly_score']:.4f} | "
                      f"{anomaly['flow_count']:5,} 連線 | "
                      f"{anomaly['unique_dsts']:3} 目的地")

        print(f"\n{'='*70}\n")

        return {
            'n_total': n_total,
            'n_anomalies': n_anomalies,
            'anomaly_rate': anomaly_rate,
            'top_anomalies': results[:20]
        }

    def get_model_info(self) -> Dict:
        """
        獲取模型信息

        Returns:
            模型信息字典
        """
        if self.model is None:
            return {'status': 'not_trained'}

        return {
            'status': 'trained',
            'n_estimators': self.model.n_estimators,
            'contamination': self.model.contamination,
            'max_samples': self.model.max_samples,
            'max_samples': self.model.max_samples,
            'n_features': len(self.feature_engineer.detection_feature_names),
            'feature_names': self.feature_engineer.detection_feature_names,
            'model_path': self.model_path
        }
