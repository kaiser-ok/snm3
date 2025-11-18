#!/usr/bin/env python3
"""
行為基準線管理器 (Baseline Manager)

管理每個 IP 的正常行為基準線，用於偵測異常的行為偏離。

主要功能：
1. 學習 IP 的歷史正常行為（7-30天）
2. 偵測當前行為是否偏離基準線
3. 計算偏離的嚴重程度
4. 支援多種統計指標的基準線
"""

import requests
import json
import numpy as np
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict


class BaselineManager:
    """
    行為基準線管理器

    管理每個 IP 的正常行為模式，用於偵測異常偏離。
    """

    def __init__(self, es_host="http://localhost:9200", learning_days=7):
        """
        初始化基準線管理器

        Args:
            es_host: Elasticsearch 主機地址
            learning_days: 學習期（天數），默認 7 天
        """
        self.es_host = es_host
        self.src_index = f"{es_host}/netflow_stats_5m/_search"
        self.learning_days = learning_days

        # 基準線緩存 {src_ip: baseline}
        self.baselines = {}

        # 統計信息
        self.stats = {
            'total_learned': 0,
            'total_checked': 0,
            'deviations_detected': 0
        }

    def learn_baseline(self, src_ip: str) -> Optional[Dict]:
        """
        學習某個 IP 的行為基準線

        從歷史數據中計算該 IP 的正常行為統計特徵。

        Args:
            src_ip: 源 IP

        Returns:
            基準線字典，包含各指標的統計信息
        """
        # 計算時間範圍
        end_time = datetime.now()
        start_time = end_time - timedelta(days=self.learning_days)

        # 查詢歷史數據
        historical_data = self._query_historical_data(
            src_ip,
            start_time.isoformat(),
            end_time.isoformat()
        )

        if not historical_data or len(historical_data) < 10:  # 至少需要 10 個樣本
            return None

        # 計算各指標的統計特徵
        baseline = {
            'src_ip': src_ip,
            'learning_period_days': self.learning_days,
            'sample_count': len(historical_data),
            'learned_at': datetime.now().isoformat(),

            # 各指標的統計
            'unique_dst_ports': self._calculate_metric_stats(
                historical_data, 'unique_dst_ports'
            ),
            'unique_dsts': self._calculate_metric_stats(
                historical_data, 'unique_dsts'
            ),
            'flow_count': self._calculate_metric_stats(
                historical_data, 'flow_count'
            ),
            'avg_bytes': self._calculate_metric_stats(
                historical_data, 'avg_bytes'
            ),
            'total_bytes': self._calculate_metric_stats(
                historical_data, 'total_bytes'
            ),
            'unique_src_ports': self._calculate_metric_stats(
                historical_data, 'unique_src_ports'
            )
        }

        # 緩存基準線
        self.baselines[src_ip] = baseline
        self.stats['total_learned'] += 1

        return baseline

    def check_deviation(self, src_ip: str, current_data: Dict) -> Dict:
        """
        檢查當前行為是否偏離基準線

        Args:
            src_ip: 源 IP
            current_data: 當前的行為數據（from netflow_stats_5m）

        Returns:
            {
                'has_deviation': bool,
                'deviations': {...},  # 具體偏離的指標
                'severity': str,      # CRITICAL, HIGH, MEDIUM, LOW
                'baseline': {...}     # 基準線信息
            }
        """
        self.stats['total_checked'] += 1

        # 如果沒有基準線，先學習
        if src_ip not in self.baselines:
            baseline = self.learn_baseline(src_ip)
            if not baseline:
                return {
                    'has_deviation': False,
                    'reason': 'Insufficient historical data for baseline',
                    'baseline': None
                }
        else:
            baseline = self.baselines[src_ip]

        # 檢查各指標是否偏離
        deviations = {}
        max_severity = 'NORMAL'

        # 檢查 unique_dst_ports
        deviation = self._check_metric_deviation(
            current_value=current_data.get('unique_dst_ports', 0),
            baseline_stats=baseline['unique_dst_ports'],
            metric_name='unique_dst_ports'
        )
        if deviation['has_deviation']:
            deviations['unique_dst_ports'] = deviation
            max_severity = self._max_severity(max_severity, deviation['severity'])

        # 檢查 unique_dsts
        deviation = self._check_metric_deviation(
            current_value=current_data.get('unique_dsts', 0),
            baseline_stats=baseline['unique_dsts'],
            metric_name='unique_dsts'
        )
        if deviation['has_deviation']:
            deviations['unique_dsts'] = deviation
            max_severity = self._max_severity(max_severity, deviation['severity'])

        # 檢查 flow_count
        deviation = self._check_metric_deviation(
            current_value=current_data.get('flow_count', 0),
            baseline_stats=baseline['flow_count'],
            metric_name='flow_count'
        )
        if deviation['has_deviation']:
            deviations['flow_count'] = deviation
            max_severity = self._max_severity(max_severity, deviation['severity'])

        # 檢查 avg_bytes
        deviation = self._check_metric_deviation(
            current_value=current_data.get('avg_bytes', 0),
            baseline_stats=baseline['avg_bytes'],
            metric_name='avg_bytes',
            allow_decrease=True  # avg_bytes 減少也可能是異常（DDoS）
        )
        if deviation['has_deviation']:
            deviations['avg_bytes'] = deviation
            max_severity = self._max_severity(max_severity, deviation['severity'])

        has_deviation = len(deviations) > 0

        if has_deviation:
            self.stats['deviations_detected'] += 1

        return {
            'has_deviation': has_deviation,
            'deviations': deviations,
            'severity': max_severity,
            'baseline': baseline,
            'current_data': current_data
        }

    def _query_historical_data(self, src_ip: str, start_time: str, end_time: str) -> List[Dict]:
        """
        查詢歷史數據

        Args:
            src_ip: 源 IP
            start_time: 開始時間（ISO格式）
            end_time: 結束時間（ISO格式）

        Returns:
            歷史數據列表
        """
        query = {
            "size": 10000,  # 最多獲取 10000 個樣本
            "query": {
                "bool": {
                    "must": [
                        {"term": {"src_ip": src_ip}},
                        {
                            "range": {
                                "time_bucket": {
                                    "gte": start_time,
                                    "lte": end_time
                                }
                            }
                        }
                    ]
                }
            },
            "sort": [{"time_bucket": "asc"}]
        }

        try:
            response = requests.post(self.src_index, json=query,
                                    headers={'Content-Type': 'application/json'})
            data = response.json()

            historical_data = []
            for hit in data.get('hits', {}).get('hits', []):
                historical_data.append(hit['_source'])

            return historical_data

        except Exception as e:
            print(f"Error querying historical data: {e}")
            return []

    def _calculate_metric_stats(self, data: List[Dict], metric_name: str) -> Dict:
        """
        計算某個指標的統計特徵

        Args:
            data: 歷史數據列表
            metric_name: 指標名稱

        Returns:
            統計特徵字典
        """
        values = [item.get(metric_name, 0) for item in data]
        values = [v for v in values if v is not None and v > 0]  # 過濾無效值

        if not values:
            return {
                'mean': 0,
                'std': 0,
                'min': 0,
                'max': 0,
                'p50': 0,
                'p95': 0,
                'p99': 0
            }

        return {
            'mean': float(np.mean(values)),
            'std': float(np.std(values)),
            'min': float(np.min(values)),
            'max': float(np.max(values)),
            'p50': float(np.percentile(values, 50)),
            'p95': float(np.percentile(values, 95)),
            'p99': float(np.percentile(values, 99))
        }

    def _check_metric_deviation(self, current_value: float, baseline_stats: Dict,
                                metric_name: str, allow_decrease: bool = False) -> Dict:
        """
        檢查單個指標是否偏離基準線

        Args:
            current_value: 當前值
            baseline_stats: 基準線統計
            metric_name: 指標名稱
            allow_decrease: 是否將減少也視為異常

        Returns:
            偏離檢測結果
        """
        mean = baseline_stats['mean']
        std = baseline_stats['std']
        p95 = baseline_stats['p95']
        p99 = baseline_stats['p99']
        max_val = baseline_stats['max']

        # 如果基準線太小（接近零），使用絕對閾值
        if mean < 1:
            return {'has_deviation': False}

        # 計算 Z-score（標準差倍數）
        if std > 0:
            z_score = (current_value - mean) / std
        else:
            z_score = 0

        # 計算相對於最大值的比例
        ratio_to_max = current_value / max_val if max_val > 0 else 0
        ratio_to_mean = current_value / mean if mean > 0 else 0

        # 判斷是否偏離
        has_deviation = False
        severity = 'NORMAL'
        reason = ''

        # CRITICAL: 超過歷史最大值的 10 倍
        if current_value > max_val * 10:
            has_deviation = True
            severity = 'CRITICAL'
            reason = f'超過歷史最大值 10 倍（{current_value:.0f} vs {max_val:.0f}）'

        # HIGH: 超過歷史最大值的 5 倍或 Z-score > 5
        elif current_value > max_val * 5 or z_score > 5:
            has_deviation = True
            severity = 'HIGH'
            reason = f'超過歷史最大值 5 倍或 Z-score > 5（當前: {current_value:.0f}, 最大: {max_val:.0f}, Z: {z_score:.1f}）'

        # MEDIUM: 超過 P99 的 2 倍或 Z-score > 3
        elif current_value > p99 * 2 or z_score > 3:
            has_deviation = True
            severity = 'MEDIUM'
            reason = f'超過 P99 兩倍或 Z-score > 3（當前: {current_value:.0f}, P99: {p99:.0f}, Z: {z_score:.1f}）'

        # LOW: 超過 P95 的 1.5 倍
        elif current_value > p95 * 1.5:
            has_deviation = True
            severity = 'LOW'
            reason = f'超過 P95 的 1.5 倍（當前: {current_value:.0f}, P95: {p95:.0f}）'

        # 檢查減少的情況（如果允許）
        if allow_decrease and current_value < mean * 0.1 and mean > 100:
            has_deviation = True
            severity = 'MEDIUM'
            reason = f'大幅減少（當前: {current_value:.0f}, 平均: {mean:.0f}）'

        return {
            'has_deviation': has_deviation,
            'severity': severity,
            'reason': reason,
            'current_value': current_value,
            'baseline_mean': mean,
            'baseline_max': max_val,
            'baseline_p95': p95,
            'baseline_p99': p99,
            'z_score': z_score,
            'ratio_to_max': ratio_to_max,
            'ratio_to_mean': ratio_to_mean
        }

    def _max_severity(self, s1: str, s2: str) -> str:
        """返回更嚴重的等級"""
        severity_order = ['NORMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        idx1 = severity_order.index(s1) if s1 in severity_order else 0
        idx2 = severity_order.index(s2) if s2 in severity_order else 0
        return severity_order[max(idx1, idx2)]

    def get_baseline(self, src_ip: str) -> Optional[Dict]:
        """獲取某個 IP 的基準線"""
        return self.baselines.get(src_ip)

    def refresh_baseline(self, src_ip: str) -> Optional[Dict]:
        """重新學習基準線"""
        if src_ip in self.baselines:
            del self.baselines[src_ip]
        return self.learn_baseline(src_ip)

    def get_stats(self) -> Dict:
        """獲取統計信息"""
        return {
            **self.stats,
            'baselines_cached': len(self.baselines)
        }

    def generate_deviation_report(self, deviation_result: Dict) -> str:
        """
        生成偏離報告

        Args:
            deviation_result: check_deviation 的返回結果

        Returns:
            報告文本
        """
        if not deviation_result['has_deviation']:
            return "未發現行為偏離"

        lines = []
        lines.append(f"行為偏離偵測報告")
        lines.append(f"=" * 60)
        lines.append(f"嚴重程度: {deviation_result['severity']}")
        lines.append(f"")

        baseline = deviation_result.get('baseline', {})
        if baseline:
            lines.append(f"基準線信息:")
            lines.append(f"  - 學習期: {baseline.get('learning_period_days', 0)} 天")
            lines.append(f"  - 樣本數: {baseline.get('sample_count', 0)}")
            lines.append(f"  - 學習時間: {baseline.get('learned_at', 'Unknown')}")
            lines.append(f"")

        lines.append(f"偏離指標:")
        for metric_name, deviation in deviation_result['deviations'].items():
            lines.append(f"")
            lines.append(f"  {metric_name}:")
            lines.append(f"    - 嚴重程度: {deviation['severity']}")
            lines.append(f"    - 當前值: {deviation['current_value']:.0f}")
            lines.append(f"    - 基準平均: {deviation['baseline_mean']:.0f}")
            lines.append(f"    - 基準最大: {deviation['baseline_max']:.0f}")
            lines.append(f"    - Z-score: {deviation['z_score']:.2f}")
            lines.append(f"    - 原因: {deviation['reason']}")

        return "\n".join(lines)


# ========== 測試和範例 ==========

def test_baseline_learning():
    """測試基準線學習"""
    print("=" * 70)
    print("測試基準線學習")
    print("=" * 70)

    manager = BaselineManager(learning_days=7)

    # 學習某個 IP 的基準線
    test_ip = '192.168.10.135'

    print(f"\n學習 {test_ip} 的基準線（過去 7 天）...")
    baseline = manager.learn_baseline(test_ip)

    if baseline:
        print(f"\n✓ 基準線學習成功")
        print(f"  - 樣本數: {baseline['sample_count']}")
        print(f"  - unique_dst_ports:")
        print(f"    - 平均: {baseline['unique_dst_ports']['mean']:.1f}")
        print(f"    - 最大: {baseline['unique_dst_ports']['max']:.0f}")
        print(f"    - P95: {baseline['unique_dst_ports']['p95']:.0f}")
        print(f"  - unique_dsts:")
        print(f"    - 平均: {baseline['unique_dsts']['mean']:.1f}")
        print(f"    - 最大: {baseline['unique_dsts']['max']:.0f}")
    else:
        print(f"\n✗ 基準線學習失敗（歷史數據不足）")


def test_deviation_detection():
    """測試偏離偵測"""
    print("\n" + "=" * 70)
    print("測試偏離偵測")
    print("=" * 70)

    manager = BaselineManager(learning_days=7)

    test_ip = '192.168.10.135'

    # 學習基準線
    baseline = manager.learn_baseline(test_ip)
    if not baseline:
        print("\n歷史數據不足，無法測試")
        return

    # 測試異常數據（模擬 Port Scan）
    abnormal_data = {
        'src_ip': test_ip,
        'unique_dst_ports': 1000,  # 遠超正常值
        'unique_dsts': 50,
        'flow_count': 1200,
        'avg_bytes': 800,
        'total_bytes': 960000
    }

    print(f"\n檢查異常數據...")
    result = manager.check_deviation(test_ip, abnormal_data)

    if result['has_deviation']:
        print(f"\n⚠️  偵測到行為偏離")
        print(manager.generate_deviation_report(result))
    else:
        print(f"\n✓ 行為正常，未偏離基準線")


if __name__ == "__main__":
    test_baseline_learning()
    test_deviation_detection()
