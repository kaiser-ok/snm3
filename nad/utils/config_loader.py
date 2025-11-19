#!/usr/bin/env python3
"""
配置加載器
"""

import yaml
import os
from pathlib import Path


class Config:
    """配置管理類"""

    def __init__(self, config_path=None):
        if config_path is None:
            # 默認配置文件路徑
            config_path = Path(__file__).parent.parent / "config.yaml"

        with open(config_path, 'r', encoding='utf-8') as f:
            self._config = yaml.safe_load(f)

        # 創建必要的目錄
        self._create_directories()

    def _create_directories(self):
        """創建必要的目錄"""
        for dir_key in ['reports_dir', 'models_dir', 'logs_dir']:
            dir_path = self._config['output'].get(dir_key)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)

    @property
    def es_host(self):
        return self._config['elasticsearch']['host']

    @property
    def es_aggregated_index(self):
        return self._config['elasticsearch']['indices']['aggregated']

    @property
    def es_raw_index(self):
        return self._config['elasticsearch']['indices']['raw']

    @property
    def mysql_config(self):
        return self._config['mysql']

    @property
    def isolation_forest_config(self):
        return self._config['isolation_forest']

    @property
    def training_config(self):
        return self._config['training']

    @property
    def features_config(self):
        return self._config['features']

    @property
    def realtime_config(self):
        return self._config['realtime']

    @property
    def thresholds(self):
        return self._config['thresholds']

    @property
    def features_by_dst_config(self):
        """By Dst 特徵配置"""
        return self._config.get('features_by_dst', self._config['features'])  # 向後兼容

    @property
    def thresholds_by_dst(self):
        """By Dst 閾值配置"""
        return self._config.get('thresholds_by_dst', {})

    @property
    def output_config(self):
        return self._config['output']

    @property
    def logging_config(self):
        return self._config['logging']

    def get(self, key, default=None):
        """獲取配置值"""
        keys = key.split('.')
        value = self._config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default
        return value


def load_config(config_path=None):
    """加載配置文件"""
    return Config(config_path)
