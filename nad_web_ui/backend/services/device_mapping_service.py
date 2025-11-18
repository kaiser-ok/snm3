#!/usr/bin/env python3
"""
設備映射服務 - 處理設備 IP 映射配置
"""
import yaml
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class DeviceMappingService:
    """設備映射管理服務"""

    def __init__(self, device_mapping_path: str):
        """
        初始化設備映射服務

        Args:
            device_mapping_path: 設備映射 YAML 檔案路徑
        """
        self.device_mapping_path = device_mapping_path
        self.device_type_icons = {
            'server_farm': '🏭',
            'station': '💻',
            'iot': '🛠️',
            'external': '🌐'
        }

    def get_device_mapping(self) -> Dict:
        """
        獲取設備映射配置

        Returns:
            設備映射配置
        """
        try:
            with open(self.device_mapping_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            # 添加圖示資訊（優先使用 YAML 中的 icon，否則使用預設）
            if 'device_types' in config:
                for device_type, data in config['device_types'].items():
                    if 'icon' not in data:
                        data['icon'] = self.device_type_icons.get(device_type, '❓')

            return {
                'status': 'success',
                'data': config,
                'config_path': self.device_mapping_path
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def update_device_type(self, device_type: str, updates: Dict) -> Dict:
        """
        更新設備類型配置

        Args:
            device_type: 設備類型名稱 (server_farm, station, iot, external)
            updates: 更新內容 (description, ip_ranges, characteristics)

        Returns:
            更新結果
        """
        try:
            # 建立備份
            backup_path = f"{self.device_mapping_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(self.device_mapping_path, backup_path)

            # 讀取現有配置
            with open(self.device_mapping_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            # 確保設備類型存在
            if 'device_types' not in config:
                config['device_types'] = {}

            if device_type not in config['device_types']:
                config['device_types'][device_type] = {}

            # 更新配置
            for key, value in updates.items():
                if key in ['description', 'ip_ranges', 'characteristics', 'icon', 'display_name']:
                    config['device_types'][device_type][key] = value

            # 寫回檔案
            with open(self.device_mapping_path, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, allow_unicode=True, default_flow_style=False)

            return {
                'status': 'success',
                'message': f'設備類型 {device_type} 更新成功',
                'backup_path': backup_path
            }

        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def add_ip_range(self, device_type: str, ip_range: str) -> Dict:
        """
        添加 IP 網段到設備類型

        Args:
            device_type: 設備類型
            ip_range: IP 網段 (例如: 192.168.1.0/24)

        Returns:
            操作結果
        """
        try:
            # 建立備份
            backup_path = f"{self.device_mapping_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(self.device_mapping_path, backup_path)

            # 讀取配置
            with open(self.device_mapping_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            # 驗證設備類型存在
            if 'device_types' not in config or device_type not in config['device_types']:
                return {
                    'status': 'error',
                    'error': f'設備類型 {device_type} 不存在'
                }

            # 初始化 ip_ranges 列表（如果不存在）
            if 'ip_ranges' not in config['device_types'][device_type]:
                config['device_types'][device_type]['ip_ranges'] = []

            # 檢查 IP 網段是否已存在
            if ip_range in config['device_types'][device_type]['ip_ranges']:
                return {
                    'status': 'error',
                    'error': f'IP 網段 {ip_range} 已存在於 {device_type}'
                }

            # 添加 IP 網段
            config['device_types'][device_type]['ip_ranges'].append(ip_range)

            # 寫回檔案
            with open(self.device_mapping_path, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, allow_unicode=True, default_flow_style=False)

            return {
                'status': 'success',
                'message': f'已將 {ip_range} 添加到 {device_type}',
                'backup_path': backup_path
            }

        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def remove_ip_range(self, device_type: str, ip_range: str) -> Dict:
        """
        從設備類型中移除 IP 網段

        Args:
            device_type: 設備類型
            ip_range: 要移除的 IP 網段

        Returns:
            操作結果
        """
        try:
            # 建立備份
            backup_path = f"{self.device_mapping_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(self.device_mapping_path, backup_path)

            # 讀取配置
            with open(self.device_mapping_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            # 驗證設備類型和 IP 網段
            if 'device_types' not in config or device_type not in config['device_types']:
                return {
                    'status': 'error',
                    'error': f'設備類型 {device_type} 不存在'
                }

            if 'ip_ranges' not in config['device_types'][device_type]:
                return {
                    'status': 'error',
                    'error': f'{device_type} 沒有 IP 網段配置'
                }

            if ip_range not in config['device_types'][device_type]['ip_ranges']:
                return {
                    'status': 'error',
                    'error': f'IP 網段 {ip_range} 不存在於 {device_type}'
                }

            # 移除 IP 網段
            config['device_types'][device_type]['ip_ranges'].remove(ip_range)

            # 寫回檔案
            with open(self.device_mapping_path, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, allow_unicode=True, default_flow_style=False)

            return {
                'status': 'success',
                'message': f'已從 {device_type} 移除 {ip_range}',
                'backup_path': backup_path
            }

        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def update_special_device(self, category: str, device_type: str, ips: List[str]) -> Dict:
        """
        更新特殊設備配置

        Args:
            category: 特殊設備分類 (如 dns_servers, critical_servers)
            device_type: 設備類型
            ips: IP 列表

        Returns:
            操作結果
        """
        try:
            # 建立備份
            backup_path = f"{self.device_mapping_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(self.device_mapping_path, backup_path)

            # 讀取配置
            with open(self.device_mapping_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            # 初始化 special_devices
            if 'special_devices' not in config:
                config['special_devices'] = {}

            # 更新特殊設備
            config['special_devices'][category] = {
                'device_type': device_type,
                'ips': ips
            }

            # 寫回檔案
            with open(self.device_mapping_path, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, allow_unicode=True, default_flow_style=False)

            return {
                'status': 'success',
                'message': f'特殊設備 {category} 更新成功',
                'backup_path': backup_path
            }

        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def create_device_type(self, type_key: str, display_name: str, icon: str, description: str, characteristics: List[str] = None) -> Dict:
        """
        新增設備類型

        Args:
            type_key: 設備類型 key (英文，用於程式識別)
            display_name: 顯示名稱 (中文)
            icon: 圖示 emoji
            description: 說明
            characteristics: 特徵列表

        Returns:
            操作結果
        """
        try:
            # 建立備份
            backup_path = f"{self.device_mapping_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(self.device_mapping_path, backup_path)

            # 讀取配置
            with open(self.device_mapping_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            # 確保 device_types 存在
            if 'device_types' not in config:
                config['device_types'] = {}

            # 檢查是否已存在
            if type_key in config['device_types']:
                return {
                    'status': 'error',
                    'error': f'設備類型 {type_key} 已存在'
                }

            # 新增設備類型
            config['device_types'][type_key] = {
                'display_name': display_name,
                'icon': icon,
                'description': description,
                'ip_ranges': [],
                'characteristics': characteristics or []
            }

            # 寫回檔案
            with open(self.device_mapping_path, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, allow_unicode=True, default_flow_style=False)

            return {
                'status': 'success',
                'message': f'設備類型 {display_name} 新增成功',
                'backup_path': backup_path
            }

        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def rename_device_type(self, old_key: str, new_key: str, display_name: str = None) -> Dict:
        """
        重命名設備類型（修改 key）

        Args:
            old_key: 原設備類型 key
            new_key: 新設備類型 key
            display_name: 新的顯示名稱（可選）

        Returns:
            操作結果
        """
        try:
            # 建立備份
            backup_path = f"{self.device_mapping_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(self.device_mapping_path, backup_path)

            # 讀取配置
            with open(self.device_mapping_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            # 驗證
            if 'device_types' not in config or old_key not in config['device_types']:
                return {
                    'status': 'error',
                    'error': f'設備類型 {old_key} 不存在'
                }

            if new_key != old_key and new_key in config['device_types']:
                return {
                    'status': 'error',
                    'error': f'設備類型 {new_key} 已存在'
                }

            # 取得舊資料
            old_data = config['device_types'][old_key]

            # 更新顯示名稱（如果提供）
            if display_name:
                old_data['display_name'] = display_name

            # 如果 key 有變化，進行重命名
            if new_key != old_key:
                # 刪除舊 key
                del config['device_types'][old_key]
                # 新增新 key
                config['device_types'][new_key] = old_data

            # 寫回檔案
            with open(self.device_mapping_path, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, allow_unicode=True, default_flow_style=False)

            return {
                'status': 'success',
                'message': f'設備類型已更新',
                'backup_path': backup_path
            }

        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def delete_device_type(self, type_key: str, force: bool = False) -> Dict:
        """
        刪除設備類型

        Args:
            type_key: 設備類型 key
            force: 是否強制刪除（即使有 IP 網段）

        Returns:
            操作結果
        """
        try:
            # 保護預設類別
            protected_types = ['server_farm', 'station', 'iot', 'external']
            if type_key in protected_types and not force:
                return {
                    'status': 'error',
                    'error': f'預設設備類型 {type_key} 受到保護，無法刪除'
                }

            # 建立備份
            backup_path = f"{self.device_mapping_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(self.device_mapping_path, backup_path)

            # 讀取配置
            with open(self.device_mapping_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            # 驗證
            if 'device_types' not in config or type_key not in config['device_types']:
                return {
                    'status': 'error',
                    'error': f'設備類型 {type_key} 不存在'
                }

            # 檢查是否有 IP 網段
            device_data = config['device_types'][type_key]
            ip_count = len(device_data.get('ip_ranges', []))

            if ip_count > 0 and not force:
                return {
                    'status': 'error',
                    'error': f'設備類型 {type_key} 還有 {ip_count} 個 IP 網段，無法刪除',
                    'ip_count': ip_count
                }

            # 刪除設備類型
            del config['device_types'][type_key]

            # 寫回檔案
            with open(self.device_mapping_path, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, allow_unicode=True, default_flow_style=False)

            return {
                'status': 'success',
                'message': f'設備類型 {type_key} 已刪除',
                'backup_path': backup_path
            }

        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
