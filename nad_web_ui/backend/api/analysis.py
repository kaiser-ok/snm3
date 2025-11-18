#!/usr/bin/env python3
"""
分析 API 端點
"""
from flask import Blueprint, jsonify, request
from services.analysis_service import AnalysisService
from services.llm_service import LLMService
from services.multi_llm_service import MultiLLMService
from config import Config
import ipaddress

analysis_bp = Blueprint('analysis', __name__)

# 初始化分析服務（單例）
analysis_service = None
llm_service = None
multi_llm_service = None


def init_analysis_service():
    """初始化分析服務"""
    global analysis_service
    if analysis_service is None:
        analysis_service = AnalysisService(Config.NAD_CONFIG_PATH, Config.ES_HOST)
    return analysis_service


def init_llm_service():
    """初始化 LLM 服務"""
    global llm_service
    if llm_service is None:
        llm_service = LLMService()
    return llm_service


def init_multi_llm_service():
    """初始化多 LLM 服務"""
    global multi_llm_service
    if multi_llm_service is None:
        multi_llm_service = MultiLLMService()
    return multi_llm_service


@analysis_bp.route('/api/analysis/ip', methods=['POST'])
def analyze_ip():
    """分析特定 IP"""
    try:
        data = request.get_json()
        ip = data.get('ip')

        # 驗證 IP 地址
        if not ip:
            return jsonify({
                'status': 'error',
                'error': 'IP address is required'
            }), 400

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({
                'status': 'error',
                'error': 'Invalid IP address format'
            }), 400

        # 時間範圍（可選）
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        minutes = data.get('minutes', 1440)  # 預設 24 小時 = 1440 分鐘
        top_n = data.get('top_n')  # top_n 參數，如果未提供則為 None（自動模式）

        # 驗證 minutes（最少 5 分鐘，最多 7 天 = 10080 分鐘）
        if not (5 <= minutes <= 10080):
            return jsonify({
                'status': 'error',
                'error': 'minutes must be between 5 and 10080 (7 days)'
            }), 400

        # 驗證 top_n（如果有提供）
        if top_n is not None and not (1 <= top_n <= 100):  # 自動模式最多 100 筆
            return jsonify({
                'status': 'error',
                'error': 'top_n must be between 1 and 100'
            }), 400

        service = init_analysis_service()
        result = service.analyze_ip(
            ip=ip,
            start_time=start_time,
            end_time=end_time,
            minutes=minutes,
            top_n=top_n
        )

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@analysis_bp.route('/api/analysis/top-talkers', methods=['GET'])
def get_top_talkers():
    """獲取 Top 流量 IP"""
    try:
        minutes = request.args.get('minutes', default=60, type=int)
        limit = request.args.get('limit', default=20, type=int)

        # 驗證輸入
        if not (5 <= minutes <= 1440):
            return jsonify({
                'status': 'error',
                'error': 'minutes must be between 5 and 1440'
            }), 400

        if not (1 <= limit <= 100):
            return jsonify({
                'status': 'error',
                'error': 'limit must be between 1 and 100'
            }), 400

        service = init_analysis_service()
        result = service.get_top_talkers(minutes=minutes, limit=limit)

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@analysis_bp.route('/api/analysis/llm-security-report', methods=['POST'])
def get_llm_security_report():
    """使用 LLM 生成安全分析報告（支援多模型和 OpenRouter）"""
    try:
        data = request.get_json()

        # 驗證必要欄位（analysis_data 或 custom_prompt 至少需要一個）
        if not data or ('analysis_data' not in data and 'custom_prompt' not in data):
            return jsonify({
                'status': 'error',
                'error': 'Missing analysis_data or custom_prompt in request body'
            }), 400

        service = init_llm_service()
        # 將整個 data 傳遞給服務，讓服務處理所有參數
        result = service.analyze_ip_security(data)

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500
