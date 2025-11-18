#!/usr/bin/env python3
"""
訓練 API 端點
"""
from flask import Blueprint, jsonify, request, Response
from services.training_service import TrainingService
from config import Config
import json
import time

training_bp = Blueprint('training', __name__)

# 初始化訓練服務（單例）
training_service = None


def init_training_service():
    """初始化訓練服務"""
    global training_service
    if training_service is None:
        training_service = TrainingService(Config.NAD_CONFIG_PATH)
    return training_service


@training_bp.route('/api/training/config', methods=['GET'])
def get_config():
    """
    獲取訓練配置

    Query Parameters:
        mode: 'by_src', 'by_dst', 或不指定（返回兩者）
    """
    mode = request.args.get('mode')
    service = init_training_service()
    result = service.get_config(mode=mode)
    return jsonify(result)


@training_bp.route('/api/training/config', methods=['PUT'])
def update_config():
    """更新訓練配置"""
    try:
        data = request.get_json()

        # 驗證輸入
        if 'contamination' in data:
            if not (0.01 <= data['contamination'] <= 0.10):
                return jsonify({
                    'status': 'error',
                    'error': 'contamination must be between 0.01 and 0.10'
                }), 400

        if 'n_estimators' in data:
            if not (50 <= data['n_estimators'] <= 300):
                return jsonify({
                    'status': 'error',
                    'error': 'n_estimators must be between 50 and 300'
                }), 400

        if 'max_samples' in data:
            if not (256 <= data['max_samples'] <= 2048):
                return jsonify({
                    'status': 'error',
                    'error': 'max_samples must be between 256 and 2048'
                }), 400

        service = init_training_service()
        result = service.update_config(data)

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@training_bp.route('/api/training/start', methods=['POST'])
def start_training():
    """開始訓練"""
    try:
        data = request.get_json() or {}
        days = data.get('days', 3)
        n_estimators = data.get('n_estimators', 150)
        contamination = data.get('contamination', 0.05)
        exclude_servers = data.get('exclude_servers', False)
        anomaly_threshold = data.get('anomaly_threshold', 0.6)
        mode = data.get('mode', 'by_src')  # 新增模式參數

        # 驗證輸入
        if not (1 <= days <= 14):
            return jsonify({
                'status': 'error',
                'error': 'days must be between 1 and 14'
            }), 400

        if not (50 <= n_estimators <= 300):
            return jsonify({
                'status': 'error',
                'error': 'n_estimators must be between 50 and 300'
            }), 400

        if not (0.01 <= contamination <= 0.10):
            return jsonify({
                'status': 'error',
                'error': 'contamination must be between 0.01 and 0.10'
            }), 400

        if not (0.1 <= anomaly_threshold <= 1.0):
            return jsonify({
                'status': 'error',
                'error': 'anomaly_threshold must be between 0.1 and 1.0'
            }), 400

        if mode not in ['by_src', 'by_dst']:
            return jsonify({
                'status': 'error',
                'error': 'mode must be either "by_src" or "by_dst"'
            }), 400

        service = init_training_service()
        job_id = service.start_training(
            days=days,
            n_estimators=n_estimators,
            contamination=contamination,
            exclude_servers=exclude_servers,
            anomaly_threshold=anomaly_threshold,
            mode=mode
        )

        return jsonify({
            'status': 'success',
            'job_id': job_id,
            'mode': mode
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@training_bp.route('/api/training/status/<job_id>')
def training_status(job_id):
    """
    SSE 端點 - 串流訓練進度
    """
    service = init_training_service()

    def generate():
        """SSE 事件產生器"""
        last_progress_data = None

        while True:
            progress = service.get_progress(job_id)

            if progress is None:
                # 任務不存在
                yield f"data: {json.dumps({'type': 'error', 'message': 'Job not found'})}\n\n"
                break

            # 取得當前進度資料的字串表示（用於比較是否變化）
            current_progress_data = json.dumps(progress.get('progress', {}), sort_keys=True)

            # 只要進度資料有變化就發送更新（不僅僅是 status）
            if current_progress_data != last_progress_data:
                yield f"data: {json.dumps({'type': 'progress', **progress})}\n\n"
                last_progress_data = current_progress_data

            # 如果完成或失敗，停止串流
            current_status = progress['status']
            if current_status in ['completed', 'failed']:
                yield f"data: {json.dumps({'type': current_status, **progress})}\n\n"
                break

            time.sleep(1)  # 每秒輪詢一次

    return Response(generate(), mimetype='text/event-stream')


@training_bp.route('/api/training/history', methods=['GET'])
def get_history():
    """獲取訓練歷史"""
    service = init_training_service()
    history = service.get_training_history()

    return jsonify({
        'status': 'success',
        'history': history
    })
