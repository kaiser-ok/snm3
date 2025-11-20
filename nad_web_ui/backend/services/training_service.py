#!/usr/bin/env python3
"""
訓練服務 - 處理模型訓練相關業務邏輯
"""
import sys
import uuid
import threading
import yaml
import shutil
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, List

# 動態添加 NAD 模組路徑
sys.path.insert(0, '/home/kaisermac/snm_flow')

from nad.ml import OptimizedIsolationForest
from nad.ml.isolation_forest_by_dst import IsolationForestByDst
from nad.utils import load_config


class TrainingService:
    """模型訓練服務"""

    def __init__(self, nad_config_path: str):
        """
        初始化訓練服務

        Args:
            nad_config_path: NAD 配置檔案路徑
        """
        self.nad_config_path = nad_config_path
        self.config = load_config(nad_config_path)

        # 訓練任務狀態
        self.jobs: Dict[str, Dict] = {}
        self.training_threads: Dict[str, threading.Thread] = {}

    def _get_model_info_for_mode(self, config, mode: str = 'by_src') -> Dict:
        """
        獲取指定模式的模型資訊

        Args:
            config: NAD 配置
            mode: 'by_src' 或 'by_dst'

        Returns:
            模型資訊字典
        """
        # 根據模式選擇檢測器
        if mode == 'by_dst':
            detector = IsolationForestByDst(config)
        else:
            detector = OptimizedIsolationForest(config)

        model_info = detector.get_model_info()

        # 如果記憶體中沒有模型，但磁碟上存在已訓練的模型檔案
        if model_info.get('status') == 'not_trained' and os.path.exists(detector.model_path):
            # 載入模型以獲取完整資訊
            try:
                detector._load_model()
                model_info = detector.get_model_info()
            except Exception as e:
                # 如果載入失敗，至少標記檔案存在
                model_info['status'] = 'file_exists_but_load_failed'
                model_info['error'] = str(e)

        # 補充特徵數量資訊（從 feature_engineer 獲取）
        if 'n_features' not in model_info and hasattr(detector, 'feature_engineer'):
            model_info['n_features'] = len(detector.feature_engineer.feature_names)

        # 添加模型訓練日期（從檔案修改時間獲取）
        if os.path.exists(detector.model_path):
            model_mtime = os.path.getmtime(detector.model_path)
            model_info['trained_at'] = datetime.fromtimestamp(model_mtime, tz=timezone.utc).isoformat()

        return model_info

    def get_config(self, mode: str = None) -> Dict:
        """
        獲取當前訓練配置

        Args:
            mode: 'by_src', 'by_dst', 或 None (返回兩者)

        Returns:
            配置資訊
        """
        try:
            # 重新載入配置以確保最新
            config = load_config(self.nad_config_path)

            base_result = {
                'status': 'success',
                'training_config': {
                    'contamination': config.isolation_forest_config.get('contamination', 0.05),
                    'n_estimators': config.isolation_forest_config.get('n_estimators', 150),
                    'max_samples': config.isolation_forest_config.get('max_samples', 512),
                    'max_features': config.isolation_forest_config.get('max_features', 0.8),
                    'random_state': config.isolation_forest_config.get('random_state', 42),
                    'anomaly_threshold': config.realtime_config.get('anomaly_threshold', 0.6),
                },
                'config_path': self.nad_config_path
            }

            # 如果指定模式，只返回該模式的資訊
            if mode in ['by_src', 'by_dst']:
                model_info = self._get_model_info_for_mode(config, mode)
                base_result['model_info'] = model_info
                base_result['mode'] = mode
            else:
                # 返回兩個模式的資訊
                base_result['models'] = {
                    'by_src': self._get_model_info_for_mode(config, 'by_src'),
                    'by_dst': self._get_model_info_for_mode(config, 'by_dst')
                }

            return base_result
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def update_config(self, new_config: Dict) -> Dict:
        """
        更新訓練配置

        Args:
            new_config: 新配置（只包含要更新的項目）

        Returns:
            更新結果
        """
        try:
            # 建立備份
            backup_path = f"{self.nad_config_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(self.nad_config_path, backup_path)

            # 讀取現有配置
            with open(self.nad_config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)

            # 更新 isolation_forest 配置
            if 'isolation_forest' not in config_data:
                config_data['isolation_forest'] = {}

            for key, value in new_config.items():
                if key in ['contamination', 'n_estimators', 'max_samples', 'max_features', 'random_state']:
                    config_data['isolation_forest'][key] = value
                elif key == 'anomaly_threshold':
                    # 更新 realtime.anomaly_threshold
                    if 'realtime' not in config_data:
                        config_data['realtime'] = {}
                    config_data['realtime']['anomaly_threshold'] = value

            # 寫回檔案
            with open(self.nad_config_path, 'w', encoding='utf-8') as f:
                yaml.dump(config_data, f, allow_unicode=True, default_flow_style=False)

            # 重新載入配置
            self.config = load_config(self.nad_config_path)

            return {
                'status': 'success',
                'message': 'Configuration updated successfully',
                'backup_path': backup_path
            }

        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def start_training(self, days: int = 3, n_estimators: int = 150, contamination: float = 0.05, anomaly_threshold: float = 0.6, mode: str = 'by_src') -> str:
        """
        開始模型訓練（背景執行）

        Args:
            days: 訓練資料天數
            n_estimators: 決策樹數量
            contamination: 污染率
            anomaly_threshold: 異常偵測閾值
            mode: 訓練模式 ('by_src' 或 'by_dst')

        Returns:
            任務 ID
        """
        job_id = str(uuid.uuid4())

        # 建立任務記錄
        job = {
            'job_id': job_id,
            'status': 'running',
            'created_at': datetime.now(timezone.utc).isoformat(),
            'params': {
                'days': days,
                'n_estimators': n_estimators,
                'contamination': contamination,
                'anomaly_threshold': anomaly_threshold,
                'mode': mode
            },
            'progress': {
                'step': 'initializing',
                'message': '正在初始化...',
                'percent': 0
            },
            'metrics': None,
            'error': None,
            'mode': mode
        }
        self.jobs[job_id] = job

        # 在背景執行緒中執行訓練
        thread = threading.Thread(target=self._train_worker, args=(job_id, days, n_estimators, contamination, anomaly_threshold, mode))
        thread.daemon = True
        thread.start()

        self.training_threads[job_id] = thread

        return job_id

    def _train_worker(self, job_id: str, days: int, n_estimators: int, contamination: float, anomaly_threshold: float = 0.6, mode: str = 'by_src'):
        """
        訓練工作執行緒

        Args:
            job_id: 任務 ID
            days: 訓練天數
            n_estimators: 決策樹數量
            contamination: 污染率
            anomaly_threshold: 異常偵測閾值
            mode: 訓練模式 ('by_src' 或 'by_dst')
        """
        job = self.jobs[job_id]

        try:
            mode_desc = '來源 IP 視角 (by_src)' if mode == 'by_src' else '目標 IP 視角 (by_dst)'

            # Step 1: 更新配置檔案中的訓練參數 (0-5%)
            job['progress'] = {
                'step': 'updating_config',
                'message': f'正在更新配置... ({mode_desc})',
                'percent': 2
            }

            # 將訓練參數寫入配置檔案（持久化儲存）
            update_result = self.update_config({
                'n_estimators': n_estimators,
                'contamination': contamination,
                'anomaly_threshold': anomaly_threshold
            })

            if update_result['status'] == 'error':
                raise Exception(f"配置更新失敗: {update_result['error']}")

            # Step 2: 載入配置 (5-10%)
            job['progress'] = {
                'step': 'loading_config',
                'message': f'正在載入配置... ({mode_desc})',
                'percent': 5
            }

            config = load_config(self.nad_config_path)

            job['progress'] = {
                'step': 'initializing_detector',
                'message': f'正在初始化檢測器... ({mode_desc})',
                'percent': 8
            }

            # 根據模式選擇檢測器
            if mode == 'by_dst':
                detector = IsolationForestByDst(config)
            else:
                detector = OptimizedIsolationForest(config)

            # Step 3: 準備訓練資料 (10-20%)
            job['progress'] = {
                'step': 'preparing_data',
                'message': f'正在從 Elasticsearch 載入 {days} 天的訓練資料...',
                'percent': 10
            }

            # 模擬資料載入階段的進度更新
            import time
            for i in range(3):
                time.sleep(0.5)
                job['progress']['percent'] = 10 + (i + 1) * 3
                job['progress']['message'] = f'正在從 Elasticsearch 載入 {days} 天的訓練資料... ({job["progress"]["percent"]}%)'

            # Step 4: 特徵工程 (20-30%)
            job['progress'] = {
                'step': 'feature_engineering',
                'message': '正在進行特徵工程...',
                'percent': 20
            }

            for i in range(2):
                time.sleep(0.3)
                job['progress']['percent'] = 20 + (i + 1) * 5

            # Step 5: 開始訓練模型 (30-95%)
            job['progress'] = {
                'step': 'training',
                'message': f'正在訓練模型 ({n_estimators} 棵決策樹, 污染率 {contamination})...',
                'percent': 30
            }

            start_time = datetime.now()

            # 在背景執行緒中模擬訓練進度
            def simulate_training_progress():
                # 訓練階段從 30% 到 95%，共 65% 的進度
                # 根據實際參數估算訓練時間並調整進度速度

                # 估算總訓練時間（秒）
                # 基於經驗：每棵樹每天資料約需 0.6-0.8 秒
                estimated_total_time = days * n_estimators * 0.7
                # 最小 15 秒，最大 300 秒
                estimated_total_time = max(15, min(300, estimated_total_time))

                # 計算每次更新應該增加的進度（65% / 總秒數）
                total_progress = 65  # 30% -> 95%
                update_interval = 0.5  # 每 0.5 秒更新一次
                progress_per_update = (total_progress / estimated_total_time) * update_interval

                current_percent = 30.0
                elapsed_time = 0

                while current_percent < 95 and job['status'] == 'running':
                    time.sleep(update_interval)
                    elapsed_time += update_interval

                    # 動態調整進度增長速度（隨時間遞減，避免太快到達上限）
                    # 30-50%: 正常速度
                    # 50-70%: 稍慢
                    # 70-85%: 更慢
                    # 85-95%: 最慢
                    if current_percent < 50:
                        increment = progress_per_update * 1.2
                    elif current_percent < 70:
                        increment = progress_per_update * 1.0
                    elif current_percent < 85:
                        increment = progress_per_update * 0.7
                    else:
                        increment = progress_per_update * 0.4

                    current_percent = min(95, current_percent + increment)
                    job['progress']['percent'] = int(current_percent)
                    job['progress']['message'] = f'正在訓練模型 ({n_estimators} 棵決策樹)... {int(current_percent)}%'

            # 啟動進度模擬執行緒
            import threading
            progress_thread = threading.Thread(target=simulate_training_progress)
            progress_thread.daemon = True
            progress_thread.start()

            # 實際執行訓練
            detector.train_on_aggregated_data(days=days)
            training_time = (datetime.now() - start_time).total_seconds()

            # Step 6: 保存模型 (95-98%)
            job['progress'] = {
                'step': 'saving_model',
                'message': '正在保存模型...',
                'percent': 95
            }

            time.sleep(0.3)

            job['progress'] = {
                'step': 'saving_model',
                'message': '正在保存模型...',
                'percent': 97
            }

            # Step 7: 完成 (98-100%)
            job['progress'] = {
                'step': 'finalizing',
                'message': '正在完成訓練...',
                'percent': 98
            }

            time.sleep(0.2)

            job['progress'] = {
                'step': 'completed',
                'message': '訓練完成！',
                'percent': 100
            }

            model_info = detector.get_model_info()

            job['status'] = 'completed'
            job['metrics'] = {
                'training_time_seconds': training_time,
                'model_info': model_info
            }

        except Exception as e:
            job['status'] = 'failed'
            job['error'] = str(e)
            job['progress'] = {
                'step': 'failed',
                'message': f'訓練失敗: {str(e)}',
                'percent': 0
            }

        job['completed_at'] = datetime.now(timezone.utc).isoformat()

    def get_progress(self, job_id: str) -> Optional[Dict]:
        """
        獲取訓練進度

        Args:
            job_id: 任務 ID

        Returns:
            進度資訊或 None
        """
        job = self.jobs.get(job_id)
        if not job:
            return None

        return {
            'job_id': job_id,
            'status': job['status'],
            'progress': job.get('progress', {}),
            'metrics': job.get('metrics'),
            'error': job.get('error'),
            'created_at': job.get('created_at'),
            'completed_at': job.get('completed_at')
        }

    def get_training_history(self) -> List[Dict]:
        """
        獲取訓練歷史（簡單版本，從記憶體中的已完成任務）

        Returns:
            歷史記錄列表
        """
        history = []
        for job_id, job in self.jobs.items():
            if job['status'] in ['completed', 'failed']:
                history.append({
                    'job_id': job_id,
                    'status': job['status'],
                    'created_at': job.get('created_at'),
                    'completed_at': job.get('completed_at'),
                    'params': job.get('params'),
                    'metrics': job.get('metrics')
                })

        # 按完成時間排序（最新在前）
        history.sort(key=lambda x: x.get('completed_at', ''), reverse=True)
        return history

    def get_available_features(self, mode: str = 'by_src') -> Dict:
        """
        獲取可用特徵列表（按類別分組）

        Args:
            mode: 'by_src' 或 'by_dst'

        Returns:
            可用特徵列表和當前選擇狀態
        """
        try:
            # 讀取配置
            with open(self.nad_config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)

            # 根據模式選擇特徵集合
            if mode == 'by_dst':
                # By Dst 特徵列表
                available_features = {
                    'basic': {
                        'unique_srcs': {'name': '不同來源數', 'description': '唯一來源 IP 數量'},
                        'unique_src_ports': {'name': '不同源埠數', 'description': '唯一源通訊埠數量'},
                        'unique_dst_ports': {'name': '不同目的埠數', 'description': '唯一目的通訊埠數量'},
                        'flow_count': {'name': '連線數', 'description': '5分鐘內的總連線數'},
                        'total_bytes': {'name': '總流量', 'description': '總傳輸位元組數'},
                        'total_packets': {'name': '總封包數', 'description': '總封包數量'},
                        'avg_bytes': {'name': '平均流量', 'description': '每連線平均位元組數'},
                        'max_bytes': {'name': '最大流量', 'description': '單一連線最大位元組數'},
                    },
                    'derived': {
                        'flows_per_src': {'name': '每來源連線數', 'description': '連線數 / 來源數'},
                        'bytes_per_src': {'name': '每來源流量', 'description': '總流量 / 來源數'},
                        'packets_per_src': {'name': '每來源封包數', 'description': '總封包數 / 來源數'},
                        'bytes_per_flow': {'name': '每連線流量', 'description': '總流量 / 連線數'},
                        'packets_per_flow': {'name': '每連線封包數', 'description': '總封包數 / 連線數'},
                        'src_port_diversity': {'name': '源埠分散度', 'description': '源埠數 / 來源數'},
                        'dst_port_diversity': {'name': '目的埠分散度', 'description': '目的埠數 / 來源數'},
                        'traffic_concentration': {'name': '流量集中度', 'description': '總流量 / 來源數'},
                        'port_attack_breadth': {'name': '端口攻擊廣度', 'description': '目的埠數 / 連線數'},
                        'avg_src_activity': {'name': '平均來源活躍度', 'description': '連線數 / 來源數'},
                        'bytes_per_packet': {'name': '每封包位元組數', 'description': '總流量 / 總封包數'},
                    },
                    'binary': {
                        'is_ddos_target': {'name': 'DDoS 目標標記', 'description': '疑似 DDoS 攻擊目標'},
                        'is_scan_target': {'name': '掃描目標標記', 'description': '疑似被掃描目標'},
                        'is_high_receiver': {'name': '高流量接收標記', 'description': '接收大量流量'},
                        'is_likely_server': {'name': '伺服器標記', 'description': '疑似伺服器行為'},
                        'is_abnormal_pattern': {'name': '異常模式標記', 'description': '異常連線模式'},
                        'is_port_concentrated': {'name': '端口集中標記', 'description': '端口使用集中'},
                        'is_multi_port_attack': {'name': '多端口攻擊標記', 'description': '多端口被攻擊'},
                    },
                    'log_transform': {
                        'log_unique_srcs': {'name': '來源數對數', 'description': 'log(來源數 + 1)'},
                        'log_flow_count': {'name': '連線數對數', 'description': 'log(連線數 + 1)'},
                        'log_total_bytes': {'name': '總流量對數', 'description': 'log(總流量 + 1)'},
                    },
                    'time_series': {
                        'hour_of_day': {'name': '小時（原始）', 'description': '一天中的小時（0-23）'},
                        'hour_sin': {'name': '小時（正弦）', 'description': '小時的正弦編碼（循環特徵）'},
                        'hour_cos': {'name': '小時（餘弦）', 'description': '小時的餘弦編碼（循環特徵）'},
                        'day_of_week': {'name': '星期幾', 'description': '週一到週日（0-6）'},
                        'is_weekend': {'name': '週末標記', 'description': '是否為週末'},
                        'is_business_hours': {'name': '工作時間標記', 'description': '是否為工作時間（週一至五 9-18點）'},
                        'is_late_night': {'name': '深夜標記', 'description': '是否為深夜時段（22-6點）'},
                    },
                    'classification': {
                        'flow_rate': {'name': '連線速率', 'description': '每秒連線數'},
                        'byte_rate': {'name': '傳輸速率', 'description': '每秒傳輸位元組數'},
                        'common_ports_ratio': {'name': '常用端口比例', 'description': '端口 0-1023 的比例'},
                        'dynamic_ports_ratio': {'name': '動態端口比例', 'description': '端口 49152-65535 的比例'},
                        'registered_ports_ratio': {'name': '註冊端口比例', 'description': '端口 1024-49151 的比例'},
                    }
                }
                
                # 從 features_by_dst 讀取當前配置
                current_features = config_data.get('features_by_dst', {})
                current_classification_features = config_data.get('classification_features_by_dst', [])
            else:
                # By Src 特徵列表
                available_features = {
                    'basic': {
                        'flow_count': {'name': '連線數', 'description': '5分鐘內的總連線數'},
                        'total_bytes': {'name': '總流量', 'description': '總傳輸位元組數'},
                        'total_packets': {'name': '總封包數', 'description': '總封包數量'},
                        'unique_dsts': {'name': '不同目的地數', 'description': '唯一目的 IP 數量'},
                        'unique_src_ports': {'name': '不同源埠數', 'description': '唯一源通訊埠數量'},
                        'unique_dst_ports': {'name': '不同目的埠數', 'description': '唯一目的通訊埠數量'},
                        'avg_bytes': {'name': '平均流量', 'description': '每連線平均位元組數'},
                        'max_bytes': {'name': '最大流量', 'description': '單一連線最大位元組數'},
                    },
                    'derived': {
                        'dst_diversity': {'name': '目的地分散度', 'description': '目的地數 / 連線數'},
                        'src_port_diversity': {'name': '源埠分散度', 'description': '源埠數 / 連線數'},
                        'dst_port_diversity': {'name': '目的埠分散度', 'description': '目的埠數 / 連線數'},
                        'traffic_concentration': {'name': '流量集中度', 'description': '最大流量 / 總流量'},
                        'bytes_per_packet': {'name': '每封包位元組數', 'description': '總流量 / 總封包數'},
                    },
                    'binary': {
                        'is_high_connection': {'name': '高連線數標記', 'description': '連線數超過閾值'},
                        'is_scanning_pattern': {'name': '掃描模式標記', 'description': '符合掃描行為特徵'},
                        'is_small_packet': {'name': '小封包標記', 'description': '平均封包大小較小'},
                        'is_large_flow': {'name': '大流量標記', 'description': '最大流量超過閾值'},
                        'is_likely_server_response': {'name': '伺服器回應標記', 'description': '可能是伺服器回應流量'},
                    },
                    'log_transform': {
                        'log_flow_count': {'name': '連線數對數', 'description': 'log(連線數 + 1)'},
                        'log_total_bytes': {'name': '總流量對數', 'description': 'log(總流量 + 1)'},
                    },
                    'device_type': {
                        'device_type': {'name': '設備類型', 'description': 'IP 設備類型編碼'},
                    },
                    'time_series': {
                        'hour_of_day': {'name': '小時（原始）', 'description': '一天中的小時（0-23）'},
                        'hour_sin': {'name': '小時（正弦）', 'description': '小時的正弦編碼（循環特徵）'},
                        'hour_cos': {'name': '小時（餘弦）', 'description': '小時的餘弦編碼（循環特徵）'},
                        'day_of_week': {'name': '星期幾', 'description': '週一到週日（0-6）'},
                        'is_weekend': {'name': '週末標記', 'description': '是否為週末'},
                        'is_business_hours': {'name': '工作時間標記', 'description': '是否為工作時間（週一至五 9-18點）'},
                        'is_late_night': {'name': '深夜標記', 'description': '是否為深夜時段（22-6點）'},
                    },
                    'classification': {
                        'flow_rate': {'name': '連線速率', 'description': '每秒連線數'},
                        'byte_rate': {'name': '傳輸速率', 'description': '每秒傳輸位元組數'},
                        'common_ports_ratio': {'name': '常用端口比例', 'description': '端口 0-1023 的比例'},
                        'dynamic_ports_ratio': {'name': '動態端口比例', 'description': '端口 49152-65535 的比例'},
                        'registered_ports_ratio': {'name': '註冊端口比例', 'description': '端口 1024-49151 的比例'},
                    }
                }
                
                # 從 features 讀取當前配置
                current_features = config_data.get('features', {})
                current_classification_features = config_data.get('classification_features', [])

            # 如果配置中沒有特徵設定，使用所有可用特徵作為預設值
            if not current_features:
                current_features = {
                    category: list(features.keys())
                    for category, features in available_features.items()
                }
                # 時間序列特徵預設不啟用
                current_features['time_series'] = []
            
            # 處理分類特徵
            if not current_classification_features:
                # 預設啟用所有分類特徵
                current_classification_features = list(available_features['classification'].keys())
            
            # 將分類特徵加入 current_features (為了前端統一處理)
            current_features['classification'] = current_classification_features

            # 確保所有類別都存在（向後兼容）
            if 'time_series' not in current_features:
                current_features['time_series'] = []

            # 計算總數
            total_available = sum(len(features) for features in available_features.values())
            total_selected = sum(len(features) for features in current_features.values())

            return {
                'status': 'success',
                'available_features': available_features,
                'current_selection': current_features,
                'total_available': total_available,
                'total_selected': total_selected,
                'mode': mode
            }

        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def update_feature_selection(self, mode: str, selected_features: Dict) -> Dict:
        """
        更新特徵選擇配置

        Args:
            mode: 'by_src' 或 'by_dst'
            selected_features: 選中的特徵字典，格式如：
                {
                    "basic": ["flow_count", "total_bytes", ...],
                    "derived": [...],
                    ...
                }

        Returns:
            更新結果
        """
        try:
            # 建立備份
            backup_path = f"{self.nad_config_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(self.nad_config_path, backup_path)

            # 讀取現有配置
            with open(self.nad_config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)

            # 根據模式更新對應的特徵配置
            
            # 分離分類特徵
            classification_features = selected_features.pop('classification', [])
            
            if mode == 'by_dst':
                config_data['features_by_dst'] = selected_features
                config_data['classification_features_by_dst'] = classification_features
            else:
                config_data['features'] = selected_features
                config_data['classification_features'] = classification_features

            # 寫回檔案
            with open(self.nad_config_path, 'w', encoding='utf-8') as f:
                yaml.dump(config_data, f, allow_unicode=True, default_flow_style=False)

            # 重新載入配置
            self.config = load_config(self.nad_config_path)

            # 統計選中的特徵數
            total_selected = sum(len(features) for features in selected_features.values())

            return {
                'status': 'success',
                'message': f'特徵選擇已更新（共 {total_selected} 個特徵）',
                'backup_path': backup_path,
                'selected_features': selected_features,
                'total_selected': total_selected,
                'mode': mode
            }

        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def get_thresholds(self) -> Dict:
        """
        獲取當前閾值配置

        Returns:
            閾值配置字典
        """
        try:
            with open(self.nad_config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)

            thresholds = config_data.get('thresholds', {})

            return {
                'status': 'success',
                'thresholds': thresholds
            }

        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def update_thresholds(self, new_thresholds: Dict) -> Dict:
        """
        更新閾值配置

        Args:
            new_thresholds: 新的閾值配置

        Returns:
            更新結果
        """
        try:
            # 建立備份
            backup_path = f"{self.nad_config_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(self.nad_config_path, backup_path)

            # 讀取現有配置
            with open(self.nad_config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)

            # 更新 thresholds 配置
            if 'thresholds' not in config_data:
                config_data['thresholds'] = {}

            # 只更新提供的閾值
            for key, value in new_thresholds.items():
                config_data['thresholds'][key] = value

            # 寫回檔案
            with open(self.nad_config_path, 'w', encoding='utf-8') as f:
                yaml.dump(config_data, f, allow_unicode=True, default_flow_style=False)

            # 重新載入配置
            self.config = load_config(self.nad_config_path)

            return {
                'status': 'success',
                'message': '閾值配置已更新',
                'backup_path': backup_path,
                'thresholds': config_data['thresholds']
            }

        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
