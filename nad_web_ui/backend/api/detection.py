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
    """執行異常檢測（同步返回結果）
    支援兩種模式：
    1. 使用 minutes 參數：查詢最近 N 分鐘的資料
    2. 使用 start_time 和 end_time 參數：查詢指定時間範圍的資料
    """
    try:
        data = request.get_json()

        # 檢查使用哪種模式
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        minutes = data.get('minutes')

        service = init_detector_service()

        # 模式 1: 自訂時間範圍
        if start_time and end_time:
            # 直接傳遞 ISO 格式時間字串給服務層
            results = service.run_detection_sync(
                start_time=start_time,
                end_time=end_time
            )
        # 模式 2: 使用分鐘數
        elif minutes:
            # 驗證輸入
            if not isinstance(minutes, int) or minutes < 5 or minutes > 10080:  # 最多 7 天
                return jsonify({
                    'status': 'error',
                    'error': 'minutes must be between 5 and 10080 (7 days)'
                }), 400

            results = service.run_detection_sync(minutes=minutes)
        else:
            return jsonify({
                'status': 'error',
                'error': 'Either minutes or (start_time and end_time) must be provided'
            }), 400

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
