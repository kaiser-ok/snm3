#!/usr/bin/env python3
"""
設備映射 API 端點
"""
from flask import Blueprint, jsonify, request
from services.device_mapping_service import DeviceMappingService
from config import Config
import os

device_mapping_bp = Blueprint('device_mapping', __name__)

# 初始化設備映射服務
device_mapping_service = None


def init_device_mapping_service():
    """初始化設備映射服務"""
    global device_mapping_service
    if device_mapping_service is None:
        # 設備映射檔案路徑
        device_mapping_path = os.path.join(
            os.path.dirname(Config.NAD_CONFIG_PATH),
            'device_mapping.yaml'
        )
        device_mapping_service = DeviceMappingService(device_mapping_path)
    return device_mapping_service


@device_mapping_bp.route('/api/device-mapping', methods=['GET'])
def get_device_mapping():
    """獲取設備映射配置"""
    service = init_device_mapping_service()
    result = service.get_device_mapping()
    return jsonify(result)


@device_mapping_bp.route('/api/device-mapping/<device_type>', methods=['PUT'])
def update_device_type(device_type):
    """更新設備類型配置"""
    try:
        data = request.get_json()

        # 驗證設備類型名稱格式（只允許字母、數字、底線）
        import re
        if not re.match(r'^[a-z0-9_]+$', device_type):
            return jsonify({
                'status': 'error',
                'error': '無效的設備類型名稱。只允許小寫字母、數字和底線'
            }), 400

        service = init_device_mapping_service()
        result = service.update_device_type(device_type, data)

        if result['status'] == 'error':
            return jsonify(result), 400

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@device_mapping_bp.route('/api/device-mapping/<device_type>/ip-ranges', methods=['POST'])
def add_ip_range(device_type):
    """添加 IP 網段到設備類型"""
    try:
        data = request.get_json()
        ip_range = data.get('ip_range')

        if not ip_range:
            return jsonify({
                'status': 'error',
                'error': 'ip_range 參數是必需的'
            }), 400

        # 簡單的 IP 網段格式驗證
        import re
        cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
        if not re.match(cidr_pattern, ip_range):
            return jsonify({
                'status': 'error',
                'error': 'IP 網段格式不正確，應為 CIDR 格式 (例如: 192.168.1.0/24)'
            }), 400

        service = init_device_mapping_service()
        result = service.add_ip_range(device_type, ip_range)

        if result['status'] == 'error':
            return jsonify(result), 400

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@device_mapping_bp.route('/api/device-mapping/<device_type>/ip-ranges', methods=['DELETE'])
def remove_ip_range(device_type):
    """從設備類型中移除 IP 網段"""
    try:
        data = request.get_json()
        ip_range = data.get('ip_range')

        if not ip_range:
            return jsonify({
                'status': 'error',
                'error': 'ip_range 參數是必需的'
            }), 400

        service = init_device_mapping_service()
        result = service.remove_ip_range(device_type, ip_range)

        if result['status'] == 'error':
            return jsonify(result), 400

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@device_mapping_bp.route('/api/device-mapping/special/<category>', methods=['PUT'])
def update_special_device(category):
    """更新特殊設備配置"""
    try:
        data = request.get_json()
        device_type = data.get('device_type')
        ips = data.get('ips', [])

        if not device_type:
            return jsonify({
                'status': 'error',
                'error': 'device_type 參數是必需的'
            }), 400

        if not isinstance(ips, list):
            return jsonify({
                'status': 'error',
                'error': 'ips 必須是陣列'
            }), 400

        service = init_device_mapping_service()
        result = service.update_special_device(category, device_type, ips)

        if result['status'] == 'error':
            return jsonify(result), 400

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@device_mapping_bp.route('/api/device-mapping/types', methods=['POST'])
def create_device_type():
    """新增設備類型"""
    try:
        data = request.get_json()
        type_key = data.get('type_key')
        display_name = data.get('display_name')
        icon = data.get('icon')
        description = data.get('description')
        characteristics = data.get('characteristics', [])

        # 驗證必要參數
        if not type_key:
            return jsonify({
                'status': 'error',
                'error': 'type_key 參數是必需的'
            }), 400

        if not display_name:
            return jsonify({
                'status': 'error',
                'error': 'display_name 參數是必需的'
            }), 400

        # 驗證 type_key 格式（只允許英文、數字、底線）
        import re
        if not re.match(r'^[a-z0-9_]+$', type_key):
            return jsonify({
                'status': 'error',
                'error': 'type_key 只能包含小寫英文、數字和底線'
            }), 400

        service = init_device_mapping_service()
        result = service.create_device_type(
            type_key=type_key,
            display_name=display_name,
            icon=icon or '📦',
            description=description or '',
            characteristics=characteristics
        )

        if result['status'] == 'error':
            return jsonify(result), 400

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@device_mapping_bp.route('/api/device-mapping/types/<type_key>/rename', methods=['PUT'])
def rename_device_type(type_key):
    """重命名設備類型"""
    try:
        data = request.get_json()
        new_key = data.get('new_key', type_key)
        display_name = data.get('display_name')

        # 驗證 new_key 格式
        import re
        if not re.match(r'^[a-z0-9_]+$', new_key):
            return jsonify({
                'status': 'error',
                'error': 'new_key 只能包含小寫英文、數字和底線'
            }), 400

        service = init_device_mapping_service()
        result = service.rename_device_type(type_key, new_key, display_name)

        if result['status'] == 'error':
            return jsonify(result), 400

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@device_mapping_bp.route('/api/device-mapping/types/<type_key>', methods=['DELETE'])
def delete_device_type(type_key):
    """刪除設備類型"""
    try:
        data = request.get_json() or {}
        force = data.get('force', False)

        service = init_device_mapping_service()
        result = service.delete_device_type(type_key, force)

        if result['status'] == 'error':
            return jsonify(result), 400

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500
