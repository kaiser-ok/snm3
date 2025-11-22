#!/usr/bin/env python3
"""
檢測服務 - 處理異常檢測相關業務邏輯
"""
import sys
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

# 動態添加 NAD 模組路徑
sys.path.insert(0, '/home/kaisermac/snm_flow')

from nad.ml import OptimizedIsolationForest
from nad.ml.anomaly_classifier import AnomalyClassifier
from nad.device_classifier import DeviceClassifier
from nad.utils import load_config


class DetectorService:
    """異常檢測服務"""

    def __init__(self, nad_config_path: str):
        """
        初始化檢測服務

        Args:
            nad_config_path: NAD 配置檔案路徑
        """
        self.config = load_config(nad_config_path)
        self.detector = OptimizedIsolationForest(self.config)
        self.classifier = AnomalyClassifier()
        self.device_classifier = DeviceClassifier()

        # 在記憶體中快取檢測任務
        self.jobs: Dict[str, Dict] = {}

    def get_model_info(self) -> Dict:
        """
        獲取模型資訊

        Returns:
            模型資訊字典
        """
        try:
            info = self.detector.get_model_info()
            return {
                'status': 'ready',
                'model_info': info
            }
        except Exception as e:
            return {
                'status': 'not_ready',
                'error': str(e)
            }

    def run_detection_sync(self, minutes: int = 60) -> Dict:
        """
        同步執行異常檢測並直接返回結果

        Args:
            minutes: 檢測時間範圍（分鐘）

        Returns:
            檢測結果字典
        """
        try:
            # 檢查 netflow_stats_3m_by_src 數據新鮮度
            data_health = self._check_netflow_data_health()

            # 從 ES 讀取預存的異常檢測結果
            anomalies = self._fetch_anomalies_from_es(minutes)
            print(f"DEBUG: 從 ES 讀取到 {len(anomalies)} 條異常記錄")

            # 按時間 bucket 分組（填充完整時間範圍）
            buckets = self._group_by_bucket(anomalies, minutes=minutes)
            print(f"DEBUG: 生成了 {len(buckets)} 個時間 bucket")

            # 計算總異常 IP 數（不重複）並補充 device_emoji
            all_unique_ips = set()
            for bucket in buckets:
                for anomaly in bucket['anomalies']:
                    # 補充 device_emoji 和 device_type
                    device_type = anomaly.get('device_type', 'unknown')

                    # 如果 device_type 是 src_anomaly/dst_anomaly，重新分類
                    if device_type in ['src_anomaly', 'dst_anomaly']:
                        # 對於來源異常，使用 src_ip 分類
                        if anomaly.get('src_ip'):
                            device_type = self.device_classifier.classify(anomaly['src_ip'])
                            anomaly['device_type'] = device_type
                        # 對於目的地異常，保持 dst_anomaly
                        elif device_type == 'dst_anomaly':
                            pass  # 保持 dst_anomaly

                    anomaly['device_emoji'] = self.device_classifier.get_type_emoji(device_type)

                    # 計算 confidence（基於 anomaly_score）
                    if 'confidence' not in anomaly:
                        anomaly['confidence'] = min(anomaly.get('anomaly_score', 0.5) * 1.2, 1.0)

                    # 追蹤不重複 IP
                    if anomaly.get('src_ip'):
                        all_unique_ips.add(anomaly['src_ip'])

            total_anomalies = len(all_unique_ips)

            return {
                'buckets': buckets,
                'total_anomalies': total_anomalies,
                'query_range': {
                    'minutes': minutes
                },
                'data_health': data_health
            }

        except Exception as e:
            raise Exception(f"檢測失敗: {str(e)}")

    def run_detection(self, minutes: int = 60) -> str:
        """
        讀取預存的異常檢測結果

        Args:
            minutes: 檢測時間範圍（分鐘）

        Returns:
            任務 ID
        """
        job_id = str(uuid.uuid4())

        # 建立任務記錄
        job = {
            'job_id': job_id,
            'status': 'running',
            'created_at': datetime.now(timezone.utc).isoformat(),
            'params': {'minutes': minutes},
            'results': None,
            'error': None
        }
        self.jobs[job_id] = job

        try:
            # 從 ES 讀取預存的異常檢測結果
            anomalies = self._fetch_anomalies_from_es(minutes)
            print(f"DEBUG: 從 ES 讀取到 {len(anomalies)} 條異常記錄")

            # 按時間 bucket 分組（填充完整時間範圍）
            buckets = self._group_by_bucket(anomalies, minutes=minutes)
            print(f"DEBUG: 生成了 {len(buckets)} 個時間 bucket")

            # 計算總異常 IP 數（不重複）並補充 device_emoji
            all_unique_ips = set()
            for bucket in buckets:
                for anomaly in bucket['anomalies']:
                    # 補充 device_emoji 和 device_type
                    device_type = anomaly.get('device_type', 'unknown')

                    # 如果 device_type 是 src_anomaly/dst_anomaly，重新分類
                    if device_type in ['src_anomaly', 'dst_anomaly']:
                        # 對於來源異常，使用 src_ip 分類
                        if anomaly.get('src_ip'):
                            device_type = self.device_classifier.classify(anomaly['src_ip'])
                            anomaly['device_type'] = device_type
                        # 對於目的地異常，保持 dst_anomaly
                        elif device_type == 'dst_anomaly':
                            pass  # 保持 dst_anomaly

                    anomaly['device_emoji'] = self.device_classifier.get_type_emoji(device_type)

                    # 計算 confidence（基於 anomaly_score）
                    if 'confidence' not in anomaly:
                        anomaly['confidence'] = min(anomaly.get('anomaly_score', 0.5) * 1.2, 1.0)

                    # 追蹤不重複 IP
                    if anomaly.get('src_ip'):
                        all_unique_ips.add(anomaly['src_ip'])

            total_anomalies = len(all_unique_ips)

            # 更新任務狀態
            job['status'] = 'completed'
            job['results'] = {
                'buckets': buckets,
                'total_anomalies': total_anomalies,
                'query_range': {
                    'minutes': minutes
                }
            }

        except Exception as e:
            job['status'] = 'failed'
            job['error'] = str(e)

        job['completed_at'] = datetime.now(timezone.utc).isoformat()
        return job_id

    def get_results(self, job_id: str) -> Optional[Dict]:
        """
        獲取檢測結果

        Args:
            job_id: 任務 ID

        Returns:
            任務結果或 None
        """
        return self.jobs.get(job_id)

    def _fetch_anomalies_from_es(self, minutes: int = 60) -> List[Dict]:
        """
        從 ES 的 anomaly_detection-* 索引讀取預存的異常檢測結果

        Args:
            minutes: 查詢的時間範圍（分鐘）

        Returns:
            異常記錄列表
        """
        from datetime import timedelta
        from elasticsearch import Elasticsearch

        # 初始化 ES 客戶端
        es_host = self.config.get('elasticsearch', {}).get('host', 'http://localhost:9200')
        es = Elasticsearch([es_host], timeout=30)

        # 計算時間範圍
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=minutes)

        # 轉換為 ISO 8601 格式
        start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%S.000Z')

        # 查詢 anomaly_detection-* 索引（包含 src_ip 異常和 dst_anomaly）
        query = {
            "size": 10000,  # 最多返回 10000 條異常記錄
            "query": {
                "range": {
                    "time_bucket": {
                        "gte": start_time_str,
                        "lte": end_time_str
                    }
                }
            },
            "sort": [
                {"time_bucket": {"order": "asc"}},
                {"anomaly_score": {"order": "desc"}}
            ]
        }

        try:
            response = es.search(index="anomaly_detection-*", body=query)
            anomalies = [hit['_source'] for hit in response['hits']['hits']]
            return anomalies
        except Exception as e:
            print(f"從 ES 讀取異常數據失敗: {e}")
            return []

    def _group_by_bucket(self, anomalies: List[Dict], minutes: int = 60) -> List[Dict]:
        """
        按 10 分鐘時間 bucket 分組異常，填充完整時間範圍

        Args:
            anomalies: 異常列表
            minutes: 查詢的時間範圍（分鐘）

        Returns:
            分組後的 bucket 列表（包含空的時間段）
        """
        from datetime import datetime, timedelta, timezone

        # 首先按 time_bucket 分組異常，並計算不重複 IP
        buckets_dict = {}
        for anomaly in anomalies:
            bucket_time = anomaly.get('time_bucket')
            src_ip = anomaly.get('src_ip')

            if bucket_time not in buckets_dict:
                buckets_dict[bucket_time] = {
                    'time_bucket': bucket_time,
                    'anomaly_count': 0,
                    'anomalies': [],
                    'unique_ips': set()
                }

            buckets_dict[bucket_time]['anomalies'].append(anomaly)
            buckets_dict[bucket_time]['unique_ips'].add(src_ip)

        # 計算每個 bucket 的不重複 IP 數量
        for bucket_data in buckets_dict.values():
            bucket_data['anomaly_count'] = len(bucket_data['unique_ips'])
            del bucket_data['unique_ips']  # 移除 set（無法 JSON 序列化）

        # 轉換為排序列表
        buckets = sorted(buckets_dict.values(), key=lambda x: x['time_bucket'])

        return buckets

    def get_anomaly_stats(self, days: int = 7) -> Dict:
        """
        獲取異常統計資訊（從 ES anomaly_detection-* 索引）

        Args:
            days: 統計天數

        Returns:
            統計資訊
        """
        from nad.anomaly_logger import AnomalyLogger

        try:
            logger = AnomalyLogger()
            stats = logger.get_anomaly_stats(days=days)
            return {
                'status': 'success',
                'stats': stats
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def _check_netflow_data_health(self) -> Dict:
        """
        檢查 netflow_stats_3m_by_src 索引的數據新鮮度

        Returns:
            健康狀態字典，包含 status, message, last_data_time, lag_minutes
        """
        from datetime import datetime, timezone, timedelta
        from elasticsearch import Elasticsearch

        try:
            # 初始化 ES 客戶端
            es_host = self.config.get('elasticsearch', {}).get('host', 'http://localhost:9200')
            es = Elasticsearch([es_host], timeout=30)

            # 查詢 netflow_stats_3m_by_src 索引的最新數據時間
            query = {
                "size": 0,
                "aggs": {
                    "max_time": {
                        "max": {
                            "field": "time_bucket"
                        }
                    }
                }
            }

            response = es.search(index="netflow_stats_3m_by_src", body=query)

            # 檢查是否有數據
            max_time_value = response.get('aggregations', {}).get('max_time', {}).get('value')

            if max_time_value is None:
                return {
                    'status': 'error',
                    'message': 'netflow 異常：索引無資料',
                    'last_data_time': None,
                    'lag_minutes': None
                }

            # 轉換時間戳（毫秒）為 datetime
            last_data_time = datetime.fromtimestamp(max_time_value / 1000, tz=timezone.utc)
            current_time = datetime.now(timezone.utc)

            # 計算延遲（分鐘）
            lag = current_time - last_data_time
            lag_minutes = int(lag.total_seconds() / 60)

            # 判斷健康狀態（超過 30 分鐘視為異常）
            if lag_minutes > 30:
                return {
                    'status': 'error',
                    'message': f'netflow 異常：資料已延遲 {lag_minutes} 分鐘',
                    'last_data_time': last_data_time.isoformat(),
                    'lag_minutes': lag_minutes
                }
            elif lag_minutes > 15:
                return {
                    'status': 'warning',
                    'message': f'netflow 警告：資料延遲 {lag_minutes} 分鐘',
                    'last_data_time': last_data_time.isoformat(),
                    'lag_minutes': lag_minutes
                }
            else:
                return {
                    'status': 'healthy',
                    'message': 'netflow 數據正常',
                    'last_data_time': last_data_time.isoformat(),
                    'lag_minutes': lag_minutes
                }

        except Exception as e:
            return {
                'status': 'error',
                'message': f'netflow 檢查失敗：{str(e)}',
                'last_data_time': None,
                'lag_minutes': None
            }
