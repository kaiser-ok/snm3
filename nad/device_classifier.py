#!/usr/bin/env python3
"""
设备类型分类器
根据 IP 地址判断设备类型
"""

import yaml
import ipaddress
from pathlib import Path
from typing import Dict, Optional


class DeviceClassifier:
    """
    设备类型分类器

    根据 device_mapping.yaml 配置判断 IP 地址所属的设备类型
    """

    def __init__(self, config_path: str = None):
        """
        初始化设备分类器

        Args:
            config_path: device_mapping.yaml 的路径
        """
        if config_path is None:
            # 默认路径：与当前文件同目录
            config_path = Path(__file__).parent / 'device_mapping.yaml'

        self.config_path = config_path
        self.device_types = {}
        self.special_devices = {}
        self._load_config()

    def _load_config(self):
        """加载配置文件"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            # 加载设备类型配置
            self.device_types = config.get('device_types', {})

            # 加载特殊设备配置
            special_config = config.get('special_devices', {})
            for group_name, group_config in special_config.items():
                device_type = group_config.get('device_type', 'external')
                # 将列表转换为字典
                for ip in group_config:
                    if ip not in ['device_type']:
                        self.special_devices[ip] = device_type

        except Exception as e:
            print(f"警告: 无法加载设备映射配置 {self.config_path}: {e}")
            # 使用默认配置
            self._use_default_config()

    def _use_default_config(self):
        """使用默认配置"""
        self.device_types = {
            'server_farm': {
                'ip_ranges': ['192.168.10.0/24', '10.10.10.0/24']
            },
            'station': {
                'ip_ranges': ['192.168.20.0/24', '192.168.30.0/24']
            },
            'iot': {
                'ip_ranges': ['192.168.0.0/24']
            },
            'external': {
                'ip_ranges': []
            }
        }

    def classify(self, ip: str) -> str:
        """
        判断 IP 地址的设备类型

        Args:
            ip: IP 地址字符串

        Returns:
            设备类型: 'server_farm', 'station', 'iot', 'external'
        """
        # 首先检查特殊设备列表
        if ip in self.special_devices:
            return self.special_devices[ip]

        # 解析 IP 地址
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return 'external'

        # 检查每个设备类型的 IP 范围
        for device_type, config in self.device_types.items():
            ip_ranges = config.get('ip_ranges', [])

            for ip_range in ip_ranges:
                try:
                    network = ipaddress.ip_network(ip_range, strict=False)
                    if ip_obj in network:
                        return device_type
                except ValueError:
                    continue

        # 默认返回 external
        return 'external'

    def get_device_type_code(self, ip: str) -> int:
        """
        获取设备类型的数值编码（用于特征工程）

        Args:
            ip: IP 地址字符串

        Returns:
            数值编码: 0=server_farm, 1=station, 2=iot, 3=external
        """
        device_type = self.classify(ip)

        type_mapping = {
            'server_farm': 0,
            'station': 1,
            'iot': 2,
            'external': 3
        }

        return type_mapping.get(device_type, 3)

    def get_device_type_info(self, ip: str) -> Dict:
        """
        获取设备类型的详细信息

        Args:
            ip: IP 地址字符串

        Returns:
            包含类型、描述等信息的字典
        """
        device_type = self.classify(ip)
        config = self.device_types.get(device_type, {})

        return {
            'type': device_type,
            'type_code': self.get_device_type_code(ip),
            'description': config.get('description', ''),
            'characteristics': config.get('characteristics', [])
        }

    def get_type_display_name(self, device_type: str) -> str:
        """
        获取设备类型的显示名称

        Args:
            device_type: 设备类型代码

        Returns:
            中文显示名称
        """
        display_names = {
            'server_farm': '服务器',
            'station': '工作站',
            'iot': 'IoT设备',
            'external': '外部/其他'
        }

        return display_names.get(device_type, device_type)

    def get_type_emoji(self, device_type: str) -> str:
        """
        获取设备类型的 emoji 图标

        Args:
            device_type: 设备类型代码

        Returns:
            emoji 图标
        """
        emojis = {
            'server_farm': '🏭',
            'station': '💻',
            'iot': '🛠️',
            'external': '🌐'
        }

        return emojis.get(device_type, '❓')


# 测试代码
if __name__ == '__main__':
    classifier = DeviceClassifier()

    test_ips = [
        '192.168.10.160',
        '192.168.20.50',
        '192.168.0.4',
        '203.72.154.50',
        '8.8.8.8',
    ]

    print('设备类型分类测试:')
    print('=' * 80)

    for ip in test_ips:
        info = classifier.get_device_type_info(ip)
        emoji = classifier.get_type_emoji(info['type'])
        display_name = classifier.get_type_display_name(info['type'])

        print(f"{emoji} {ip:20} → {display_name:10} (code: {info['type_code']})")
