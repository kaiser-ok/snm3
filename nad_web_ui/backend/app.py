#!/usr/bin/env python3
"""
NAD Web UI - Flask Backend

網路異常檢測系統的 Web 管理介面後端
"""
import os
from flask import Flask, jsonify
from flask_cors import CORS
from config import config
import logging
from logging.handlers import RotatingFileHandler

# 導入 API blueprints
from api.detection import detection_bp
from api.training import training_bp
from api.analysis import analysis_bp
from api.device_mapping import device_mapping_bp
from api.classifier_thresholds import classifier_thresholds_bp


def create_app(config_name='default'):
    """
    應用工廠函數

    Args:
        config_name: 配置名稱 (development, production)

    Returns:
        Flask 應用實例
    """
    app = Flask(__name__)

    # 載入配置
    app.config.from_object(config[config_name])

    # 設置 CORS
    CORS(app, resources={
        r"/api/*": {
            "origins": app.config['CORS_ORIGINS'],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })

    # 設置日誌
    setup_logging(app)

    # 註冊 blueprints
    app.register_blueprint(detection_bp)
    app.register_blueprint(training_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(device_mapping_bp)
    app.register_blueprint(classifier_thresholds_bp)

    # 健康檢查端點
    @app.route('/api/health', methods=['GET'])
    def health_check():
        """健康檢查"""
        return jsonify({
            'status': 'healthy',
            'service': 'NAD Web UI Backend',
            'version': '1.0.0'
        })

    # 根端點
    @app.route('/')
    def index():
        """根端點"""
        return jsonify({
            'service': 'NAD Web UI Backend',
            'version': '1.0.0',
            'endpoints': {
                'health': '/api/health',
                'detection': {
                    'status': 'GET /api/detection/status',
                    'run': 'POST /api/detection/run',
                    'results': 'GET /api/detection/results/<job_id>',
                    'stats': 'GET /api/detection/stats'
                },
                'training': {
                    'config': 'GET/PUT /api/training/config',
                    'start': 'POST /api/training/start',
                    'status': 'GET /api/training/status/<job_id> (SSE)',
                    'history': 'GET /api/training/history'
                },
                'analysis': {
                    'ip': 'POST /api/analysis/ip',
                    'top_talkers': 'GET /api/analysis/top-talkers'
                }
            }
        })

    # 錯誤處理
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'status': 'error', 'error': 'Not found'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f'Internal error: {error}')
        return jsonify({'status': 'error', 'error': 'Internal server error'}), 500

    return app


def setup_logging(app):
    """設置應用日誌"""
    if not app.debug:
        # 創建日誌目錄
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'logs')
        os.makedirs(log_dir, exist_ok=True)

        # 文件處理器
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, 'backend.log'),
            maxBytes=10485760,  # 10MB
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)

        app.logger.setLevel(logging.INFO)
        app.logger.info('NAD Web UI Backend startup')


if __name__ == '__main__':
    # 獲取環境變數
    env = os.getenv('FLASK_ENV', 'development')

    # 創建應用
    app = create_app(env)

    # 運行應用
    app.run(
        host=app.config['BACKEND_HOST'],
        port=app.config['BACKEND_PORT'],
        debug=app.config['DEBUG']
    )
