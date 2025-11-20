#!/usr/bin/env python3
"""
Classifier 閾值配置 API
"""
from flask import Blueprint, jsonify, request
import yaml
import os
from pathlib import Path

classifier_thresholds_bp = Blueprint('classifier_thresholds', __name__)

# 配置文件路徑
THRESHOLDS_CONFIG_PATH = '/home/kaisermac/snm_flow/nad/config/classifier_thresholds.yaml'


def load_thresholds_config():
    """載入閾值配置"""
    try:
        with open(THRESHOLDS_CONFIG_PATH, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except Exception as e:
        return None


def save_thresholds_config(config):
    """儲存閾值配置"""
    try:
        # 備份原配置
        if os.path.exists(THRESHOLDS_CONFIG_PATH):
            from datetime import datetime
            backup_path = f"{THRESHOLDS_CONFIG_PATH}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            import shutil
            shutil.copy2(THRESHOLDS_CONFIG_PATH, backup_path)

        # 寫入新配置
        with open(THRESHOLDS_CONFIG_PATH, 'w', encoding='utf-8') as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)
        return True
    except Exception as e:
        print(f"Error saving thresholds config: {e}")
        return False


@classifier_thresholds_bp.route('/api/classifier-thresholds', methods=['GET'])
def get_thresholds():
    """獲取所有閾值配置"""
    try:
        config = load_thresholds_config()
        if config is None:
            return jsonify({
                'status': 'error',
                'error': '無法載入配置文件'
            }), 500

        return jsonify({
            'status': 'success',
            'config': config
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@classifier_thresholds_bp.route('/api/classifier-thresholds', methods=['PUT'])
def update_thresholds():
    """更新閾值配置"""
    try:
        data = request.get_json()

        if not data or 'config' not in data:
            return jsonify({
                'status': 'error',
                'error': '缺少配置數據'
            }), 400

        # 儲存配置
        if save_thresholds_config(data['config']):
            return jsonify({
                'status': 'success',
                'message': '配置已更新'
            })
        else:
            return jsonify({
                'status': 'error',
                'error': '儲存配置失敗'
            }), 500

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@classifier_thresholds_bp.route('/api/classifier-thresholds/reset', methods=['POST'])
def reset_thresholds():
    """重置為預設值"""
    try:
        # 預設配置（與 classifier_thresholds.yaml 初始值相同）
        default_config = {
            'src_threats': {
                'PORT_SCAN': {
                    'name': '埠掃描',
                    'enabled': True,
                    'thresholds': {
                        'unique_dst_ports': 100,
                        'avg_bytes': 5000,
                        'dst_port_diversity': 0.5
                    }
                },
                'NETWORK_SCAN': {
                    'name': '網路掃描',
                    'enabled': True,
                    'thresholds': {
                        'unique_dsts': 50,
                        'dst_diversity': 0.3,
                        'flow_count': 1000,
                        'avg_bytes': 50000
                    }
                },
                'DNS_TUNNELING': {
                    'name': 'DNS 隧道',
                    'enabled': True,
                    'thresholds': {
                        'flow_count': 1000,
                        'unique_dst_ports': 2,
                        'avg_bytes': 1000,
                        'unique_dsts': 5
                    }
                },
                'DDOS': {
                    'name': 'DDoS 攻擊',
                    'enabled': True,
                    'thresholds': {
                        'flow_count': 10000,
                        'flow_rate': 30,
                        'avg_bytes': 500,
                        'unique_dsts': 20
                    }
                },
                'DATA_EXFILTRATION': {
                    'name': '數據外洩',
                    'enabled': True,
                    'thresholds': {
                        'total_bytes': 1000000000,
                        'byte_rate': 3000000,
                        'unique_dsts': 5,
                        'dst_diversity': 0.1
                    }
                },
                'C2_COMMUNICATION': {
                    'name': 'C&C 通訊',
                    'enabled': True,
                    'thresholds': {
                        'unique_dsts': 1,
                        'flow_count_min': 100,
                        'flow_count_max': 1000,
                        'avg_bytes_min': 1000,
                        'avg_bytes_max': 100000
                    }
                },
                'NORMAL_HIGH_TRAFFIC': {
                    'name': '正常高流量',
                    'enabled': True,
                    'thresholds': {
                        'total_bytes': 1000000000,
                        'unique_dsts_min': 10,
                        'unique_dsts_max': 100
                    }
                }
            },
            'dst_threats': {
                'DDOS_TARGET': {
                    'name': 'DDoS 攻擊目標',
                    'enabled': True,
                    'thresholds': {
                        'unique_srcs': 100,
                        'flow_count': 1000,
                        'avg_bytes': 500
                    }
                },
                'SCAN_TARGET': {
                    'name': '掃描目標',
                    'enabled': True,
                    'thresholds': {
                        'unique_src_ports': 100,
                        'unique_dst_ports': 50,
                        'avg_bytes': 2000
                    }
                },
                'DATA_SINK': {
                    'name': '資料外洩目標端',
                    'enabled': True,
                    'thresholds': {
                        'unique_srcs': 10,
                        'total_bytes': 100000000,
                        'avg_bytes': 10000
                    }
                },
                'MALWARE_DISTRIBUTION': {
                    'name': '惡意軟體分發',
                    'enabled': True,
                    'thresholds': {
                        'unique_srcs': 5,
                        'total_bytes': 50000000,
                        'flows_per_src': 10
                    }
                },
                'POPULAR_SERVER': {
                    'name': '熱門服務器',
                    'enabled': True,
                    'thresholds': {
                        'unique_srcs': 20,
                        'avg_bytes_min': 500,
                        'avg_bytes_max': 50000
                    }
                }
            },
            'global': {
                'backup_hours': [1, 2, 3, 4, 5]
            }
        }

        if save_thresholds_config(default_config):
            return jsonify({
                'status': 'success',
                'message': '已重置為預設值',
                'config': default_config
            })
        else:
            return jsonify({
                'status': 'error',
                'error': '重置失敗'
            }), 500

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500
