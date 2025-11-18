#!/usr/bin/env python3
"""
檢測 API 端點
"""
from flask import Blueprint, jsonify, request
from services.detector_service import DetectorService
from config import Config

detection_bp = Blueprint('detection', __name__)

# 初始化檢測服務（單例）
detector_service = None


def init_detector_service():
    """初始化檢測服務"""
    global detector_service
    if detector_service is None:
        detector_service = DetectorService(Config.NAD_CONFIG_PATH)
    return detector_service


@detection_bp.route('/api/detection/status', methods=['GET'])
def get_status():
    """獲取模型狀態"""
    service = init_detector_service()
    result = service.get_model_info()
    return jsonify(result)


@detection_bp.route('/api/detection/run', methods=['POST'])
def run_detection():
    """執行異常檢測（同步返回結果）"""
    try:
        data = request.get_json()
        minutes = data.get('minutes', 60)

        # 驗證輸入
        if not isinstance(minutes, int) or minutes < 5 or minutes > 1440:
            return jsonify({
                'status': 'error',
                'error': 'minutes must be between 5 and 1440'
            }), 400

        service = init_detector_service()

        # 直接執行檢測並返回結果（不需要 job_id）
        results = service.run_detection_sync(minutes=minutes)

        return jsonify({
            'status': 'success',
            'results': results
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@detection_bp.route('/api/detection/results/<job_id>', methods=['GET'])
def get_results(job_id):
    """獲取檢測結果"""
    service = init_detector_service()
    results = service.get_results(job_id)

    if results is None:
        return jsonify({
            'status': 'error',
            'error': 'Job not found'
        }), 404

    return jsonify(results)


@detection_bp.route('/api/detection/stats', methods=['GET'])
def get_stats():
    """獲取異常統計"""
    try:
        days = request.args.get('days', default=7, type=int)

        if days < 1 or days > 30:
            return jsonify({
                'status': 'error',
                'error': 'days must be between 1 and 30'
            }), 400

        service = init_detector_service()
        result = service.get_anomaly_stats(days=days)

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500
