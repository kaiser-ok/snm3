#!/usr/bin/env python3
"""
分析服務 - 處理 IP 詳細分析相關業務邏輯
"""
import sys
from datetime import datetime, timedelta, timezone
from typing import Dict, List
from collections import Counter

from elasticsearch import Elasticsearch

# 動態添加 NAD 模組路徑
sys.path.insert(0, '/home/kaisermac/snm_flow')

from nad.device_classifier import DeviceClassifier
from nad.ml.anomaly_classifier import AnomalyClassifier
from nad.ml.feature_engineer import FeatureEngineer
from nad.utils import load_config


class AnalysisService:
    """IP 分析服務"""

    def __init__(self, nad_config_path: str, es_host: str):
        """
        初始化分析服務

        Args:
            nad_config_path: NAD 配置檔案路徑
            es_host: Elasticsearch 地址
        """
        self.config = load_config(nad_config_path)
        self.es = Elasticsearch([es_host], timeout=30)
        self.device_classifier = DeviceClassifier()
        self.anomaly_classifier = AnomalyClassifier()
        self.feature_engineer = FeatureEngineer(self.config)

    def analyze_ip(self, ip: str, start_time: str = None, end_time: str = None, minutes: int = 1440, top_n: int = None) -> Dict:
        """
        分析特定 IP 的 netflow 行為

        Args:
            ip: IP 地址
            start_time: 開始時間 (ISO 格式)
            end_time: 結束時間 (ISO 格式)
            minutes: 如果未提供時間範圍，則分析最近 N 分鐘（預設 1440 = 24 小時）
            top_n: 返回前 N 筆 IP 和 Port（None = 自動模式，返回所有不重複目的地）

        Returns:
            分析結果
        """
        try:
            # 確定時間範圍
            if not end_time:
                end_dt = datetime.now(timezone.utc)
            else:
                end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))

            if not start_time:
                start_dt = end_dt - timedelta(minutes=minutes)
            else:
                start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))

            start_time_str = start_dt.strftime('%Y-%m-%dT%H:%M:%S.000Z')
            end_time_str = end_dt.strftime('%Y-%m-%dT%H:%M:%S.000Z')

            # 1. 從聚合索引獲取摘要資訊
            summary = self._get_summary_from_aggregated(ip, start_time_str, end_time_str)

            # 2. 從原始索引獲取詳細資訊
            details = self._get_details_from_raw(ip, start_time_str, end_time_str, top_n)

            # 3. 獲取時間軸資料
            timeline = self._get_timeline(ip, start_time_str, end_time_str)

            # 4. 基準比較
            baseline = self._get_baseline_comparison(ip, start_dt, end_dt)

            # 5. 設備類型
            device_type = self.device_classifier.classify(ip)
            device_emoji = self.device_classifier.get_type_emoji(device_type)

            # 6. 行為特徵分析
            behavior_analysis = self._analyze_behaviors(ip, start_time_str, end_time_str, summary)

            # 7. 威脅分類（如果有異常行為）
            threat_classification = None
            if behavior_analysis['has_anomaly']:
                # 從 record 中取得實際的 time_bucket（直接使用字串，不轉換）
                time_bucket_str = behavior_analysis['record'].get('time_bucket')
                if not time_bucket_str:
                    time_bucket_str = start_dt.strftime('%Y-%m-%dT%H:%M:%S.000Z')

                threat_classification = self._classify_threat(
                    ip, behavior_analysis['features'], time_bucket_str, summary
                )

            # 計算時間範圍
            duration_seconds = (end_dt - start_dt).total_seconds()
            duration_minutes = duration_seconds / 60
            duration_hours = duration_seconds / 3600

            return {
                'status': 'success',
                'ip': ip,
                'device_type': device_type,
                'device_emoji': device_emoji,
                'time_range': {
                    'start': start_time_str,
                    'end': end_time_str,
                    'duration_minutes': duration_minutes,
                    'duration_hours': duration_hours  # 保留向後相容
                },
                'summary': summary,
                'details': details,
                'timeline': timeline,
                'baseline_comparison': baseline,
                'behavior_analysis': behavior_analysis,
                'threat_classification': threat_classification
            }

        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def _get_summary_from_aggregated(self, ip: str, start_time: str, end_time: str) -> Dict:
        """從聚合索引獲取摘要統計"""
        # 從聚合索引查詢流量、位元組、封包的總和
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"src_ip": ip}},
                        {"range": {"time_bucket": {"gte": start_time, "lte": end_time}}}
                    ]
                }
            },
            "aggs": {
                "total_flows": {"sum": {"field": "flow_count"}},
                "total_bytes": {"sum": {"field": "total_bytes"}},
                "total_packets": {"sum": {"field": "total_packets"}},
                "avg_bytes": {"avg": {"field": "avg_bytes"}}
            }
        }

        response = self.es.search(index="netflow_stats_3m_by_src", body=query)
        aggs = response['aggregations']

        # 從原始索引查詢真實的不重複目的地、埠號數量
        cardinality_query = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"match_phrase": {"IPV4_SRC_ADDR": ip}},
                        {"range": {
                            "FLOW_START_MILLISECONDS": {
                                "gte": start_time,
                                "lte": end_time,
                                "format": "strict_date_optional_time"
                            }
                        }}
                    ]
                }
            },
            "aggs": {
                "unique_dsts": {"cardinality": {"field": "IPV4_DST_ADDR"}},
                "unique_src_ports": {"cardinality": {"field": "L4_SRC_PORT"}},
                "unique_dst_ports": {"cardinality": {"field": "L4_DST_PORT"}}
            }
        }

        cardinality_resp = self.es.search(index="flow_collector-*", body=cardinality_query)
        cardinality_aggs = cardinality_resp.get('aggregations', {})

        return {
            'total_flows': int(aggs['total_flows']['value']),
            'total_bytes': int(aggs['total_bytes']['value']),
            'total_packets': int(aggs['total_packets']['value']),
            'unique_destinations': int(cardinality_aggs.get('unique_dsts', {}).get('value', 0)),
            'unique_src_ports': int(cardinality_aggs.get('unique_src_ports', {}).get('value', 0)),
            'unique_dst_ports': int(cardinality_aggs.get('unique_dst_ports', {}).get('value', 0)),
            'avg_bytes': aggs['avg_bytes']['value'] or 0
        }

    def _get_details_from_raw(self, ip: str, start_time: str, end_time: str, top_n: int = None) -> Dict:
        """從原始索引獲取詳細資訊

        Args:
            ip: IP 地址
            start_time: 開始時間
            end_time: 結束時間
            top_n: 返回前 N 筆資料（None = 返回所有）
        """
        # 如果 top_n 為 None（自動模式），設定一個較大的值來獲取所有資料
        # 然後根據實際返回的 bucket 數量來決定
        if top_n is None:
            # 使用一個較大的 size（1000）來確保能獲取所有不重複的目的地和埠號
            # Elasticsearch 的 terms aggregation 預設最多返回實際不重複的數量
            top_n = 1000  # 臨時設為較大值
            top_n_ports = 1000
        else:
            top_n_ports = top_n

        # Top 目的地
        top_dsts_query = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"match_phrase": {"IPV4_SRC_ADDR": ip}},
                        {"range": {
                            "FLOW_START_MILLISECONDS": {
                                "gte": start_time,
                                "lte": end_time,
                                "format": "strict_date_optional_time"
                            }
                        }}
                    ]
                }
            },
            "aggs": {
                "top_dsts": {
                    "terms": {"field": "IPV4_DST_ADDR", "size": top_n},
                    "aggs": {
                        "total_bytes": {"sum": {"field": "IN_BYTES"}}
                    }
                }
            }
        }

        # 埠號分佈
        port_dist_query = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"match_phrase": {"IPV4_SRC_ADDR": ip}},
                        {"range": {
                            "FLOW_START_MILLISECONDS": {
                                "gte": start_time,
                                "lte": end_time,
                                "format": "strict_date_optional_time"
                            }
                        }}
                    ]
                }
            },
            "aggs": {
                "dst_ports": {
                    "terms": {"field": "L4_DST_PORT", "size": top_n_ports},
                    "aggs": {
                        "flow_count": {"value_count": {"field": "L4_DST_PORT"}}
                    }
                },
                "protocols": {
                    "terms": {"field": "PROTOCOL", "size": 10}
                }
            }
        }

        try:
            dsts_response = self.es.search(index="flow_collector-*", body=top_dsts_query)
            port_response = self.es.search(index="flow_collector-*", body=port_dist_query)

            # 檢查是否有數據
            total_hits = dsts_response.get('hits', {}).get('total', {}).get('value', 0)
            if total_hits == 0:
                print(f"INFO: IP {ip} 在原始索引中沒有流量記錄（時間範圍: {start_time} ~ {end_time}）")
                print(f"      可能原始數據已被清理，僅保留聚合統計")

            top_destinations = [
                {
                    'dst_ip': bucket['key'],
                    'flow_count': bucket['doc_count'],
                    'total_bytes': int(bucket['total_bytes']['value'])
                }
                for bucket in dsts_response['aggregations']['top_dsts']['buckets']
            ]

            port_distribution = {
                str(bucket['key']): bucket['doc_count']
                for bucket in port_response['aggregations']['dst_ports']['buckets']
            }

            protocol_breakdown = {
                str(bucket['key']): bucket['doc_count']
                for bucket in port_response['aggregations']['protocols']['buckets']
            }

            return {
                'top_destinations': top_destinations,
                'port_distribution': port_distribution,
                'protocol_breakdown': protocol_breakdown
            }

        except Exception as e:
            # 如果原始索引查詢失敗，返回空結果
            print(f"WARNING: 原始索引查詢失敗 for IP {ip}: {e}")
            return {
                'top_destinations': [],
                'port_distribution': {},
                'protocol_breakdown': {}
            }

    def _get_timeline(self, ip: str, start_time: str, end_time: str) -> List[Dict]:
        """獲取時間軸資料（每 5 分鐘 bucket）"""
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"src_ip": ip}},
                        {"range": {"time_bucket": {"gte": start_time, "lte": end_time}}}
                    ]
                }
            },
            "aggs": {
                "timeline": {
                    "date_histogram": {
                        "field": "time_bucket",
                        "fixed_interval": "5m",
                        "min_doc_count": 0,
                        "extended_bounds": {
                            "min": start_time,
                            "max": end_time
                        }
                    },
                    "aggs": {
                        "flow_count": {"sum": {"field": "flow_count"}},
                        "total_bytes": {"sum": {"field": "total_bytes"}}
                    }
                }
            }
        }

        response = self.es.search(index="netflow_stats_3m_by_src", body=query)

        timeline = []
        for bucket in response['aggregations']['timeline']['buckets']:
            timeline.append({
                'time_bucket': bucket['key_as_string'],
                'flow_count': int(bucket['flow_count']['value']),
                'total_bytes': int(bucket['total_bytes']['value'])
            })

        return timeline

    def _get_baseline_comparison(self, ip: str, current_start: datetime, current_end: datetime) -> Dict:
        """與歷史基準比較"""
        # 獲取過去 7 天的平均值作為基準
        baseline_start = current_start - timedelta(days=7)
        baseline_end = current_start

        baseline_start_str = baseline_start.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        baseline_end_str = baseline_end.strftime('%Y-%m-%dT%H:%M:%S.000Z')

        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"src_ip": ip}},
                        {"range": {"time_bucket": {"gte": baseline_start_str, "lte": baseline_end_str}}}
                    ]
                }
            },
            "aggs": {
                "avg_flow_count": {"avg": {"field": "flow_count"}},
                "avg_bytes": {"avg": {"field": "total_bytes"}},
                "avg_unique_dsts": {"avg": {"field": "unique_dsts"}}
            }
        }

        try:
            response = self.es.search(index="netflow_stats_3m_by_src", body=query)
            aggs = response['aggregations']

            return {
                'avg_flow_count_7d': aggs['avg_flow_count']['value'] or 0,
                'avg_bytes_7d': aggs['avg_bytes']['value'] or 0,
                'avg_unique_dsts_7d': aggs['avg_unique_dsts']['value'] or 0
            }
        except:
            return {
                'avg_flow_count_7d': 0,
                'avg_bytes_7d': 0,
                'avg_unique_dsts_7d': 0
            }

    def get_top_talkers(self, minutes: int = 60, limit: int = 20) -> Dict:
        """
        獲取 Top 流量 IP

        Args:
            minutes: 時間範圍（分鐘）
            limit: 返回數量

        Returns:
            Top talkers 列表
        """
        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(minutes=minutes)

            start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%S.000Z')
            end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%S.000Z')

            query = {
                "size": 0,
                "query": {
                    "range": {"time_bucket": {"gte": start_time_str, "lte": end_time_str}}
                },
                "aggs": {
                    "top_ips": {
                        "terms": {"field": "src_ip", "size": limit, "order": {"total_flows": "desc"}},
                        "aggs": {
                            "total_flows": {"sum": {"field": "flow_count"}},
                            "total_bytes": {"sum": {"field": "total_bytes"}},
                            "unique_dsts": {"sum": {"field": "unique_dsts"}}
                        }
                    }
                }
            }

            response = self.es.search(index="netflow_stats_3m_by_src", body=query)

            top_talkers = []
            for bucket in response['aggregations']['top_ips']['buckets']:
                ip = bucket['key']
                device_type = self.device_classifier.classify(ip)

                top_talkers.append({
                    'src_ip': ip,
                    'device_type': device_type,
                    'total_flows': int(bucket['total_flows']['value']),
                    'total_bytes': int(bucket['total_bytes']['value']),
                    'unique_destinations': int(bucket['unique_dsts']['value'])
                })

            return {
                'status': 'success',
                'top_talkers': top_talkers,
                'time_range': {
                    'start': start_time_str,
                    'end': end_time_str,
                    'minutes': minutes
                }
            }

        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def _analyze_behaviors(self, ip: str, start_time: str, end_time: str, summary: Dict) -> Dict:
        """
        分析 IP 的行為特徵
        """
        query = {
            "size": 1,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"src_ip": ip}},
                        {"range": {"time_bucket": {"gte": start_time, "lte": end_time}}}
                    ]
                }
            },
            "sort": [{"time_bucket": {"order": "desc"}}]
        }

        try:
            response = self.es.search(index="netflow_stats_3m_by_src", body=query)

            if response['hits']['total']['value'] == 0:
                return {'has_anomaly': False, 'behaviors': [], 'features': {}}

            record = response['hits']['hits'][0]['_source']
            features = self.feature_engineer.extract_features(record)

            behaviors = []
            if features.get('is_high_connection', False):
                behaviors.append('高連線數')
            if features.get('is_scanning_pattern', False):
                behaviors.append('掃描模式')
            if features.get('is_small_packet', False):
                behaviors.append('小封包')
            if features.get('is_large_flow', False):
                behaviors.append('大流量')

            return {
                'has_anomaly': len(behaviors) > 0,
                'behaviors': behaviors,
                'features': features,
                'record': record
            }
        except Exception as e:
            return {'has_anomaly': False, 'behaviors': [], 'features': {}}

    def _classify_threat(self, ip: str, features: Dict, timestamp: datetime, summary: Dict) -> Dict:
        """
        對 IP 進行威脅分類
        優先從 anomaly_detection 索引讀取已存在的分類結果
        """
        try:
            # 首先嘗試從 anomaly_detection 索引讀取已存在的威脅分類
            # 查詢該 IP 最近的一筆異常記錄（不精確匹配 time_bucket，因為可能還沒處理到最新資料）
            query = {
                "size": 1,
                "query": {
                    "term": {"src_ip": ip}
                },
                "sort": [{"time_bucket": {"order": "desc"}}]
            }

            try:
                response = self.es.search(index="anomaly_detection-*", body=query)
                if response['hits']['total']['value'] > 0:
                    anomaly_record = response['hits']['hits'][0]['_source']
                    print(f"DEBUG: 從 ES 讀取到最近異常記錄，time_bucket={anomaly_record.get('time_bucket')}, confidence={anomaly_record.get('confidence')}")

                    # 使用已存在的威脅分類資訊
                    if anomaly_record.get('threat_class'):
                        severity_emoji = self.anomaly_classifier.get_severity_emoji(
                            anomaly_record.get('severity', 'MEDIUM')
                        )

                        # 解析 response_actions（可能是字串或列表）
                        response_actions = anomaly_record.get('response_actions', '')
                        if isinstance(response_actions, str):
                            response_list = [r.strip() for r in response_actions.split('\n') if r.strip()]
                        else:
                            response_list = response_actions if isinstance(response_actions, list) else []

                        # 解析 indicators（可能是字串或列表）
                        indicators = anomaly_record.get('indicators', '')
                        if isinstance(indicators, str):
                            indicators_list = [i.strip() for i in indicators.split(',') if i.strip()]
                        else:
                            indicators_list = indicators if isinstance(indicators, list) else []

                        return {
                            'class_name': anomaly_record.get('threat_class'),
                            'class_name_en': anomaly_record.get('threat_class_en'),
                            'confidence': anomaly_record.get('threat_confidence', 0.5),
                            'anomaly_confidence': anomaly_record.get('confidence', 0.0),  # Isolation Forest 置信度
                            'severity': anomaly_record.get('severity', 'MEDIUM'),
                            'severity_emoji': severity_emoji,
                            'priority': anomaly_record.get('priority', 'P2'),
                            'description': anomaly_record.get('description', ''),
                            'indicators': indicators_list,  # 返回所有 indicators（不限制）
                            'response': response_list,  # 返回所有 response（不限制）
                            'detection_time': anomaly_record.get('detection_time', timestamp.isoformat())
                        }
            except Exception as e:
                print(f"無法從 anomaly_detection 索引讀取: {str(e)}")

            # 如果無法從 ES 讀取，則重新計算
            # timestamp 可能是字串，需要轉換為 datetime 用於 context
            from dateutil import parser as date_parser
            if isinstance(timestamp, str):
                timestamp_dt = date_parser.parse(timestamp)
                detection_time_str = timestamp
            else:
                timestamp_dt = timestamp
                detection_time_str = timestamp.isoformat()

            context = {
                'timestamp': timestamp_dt,
                'src_ip': ip,
                'anomaly_score': features.get('anomaly_score', 0.5)
            }

            classification = self.anomaly_classifier.classify(features, context)
            severity_emoji = self.anomaly_classifier.get_severity_emoji(classification['severity'])

            return {
                'class_name': classification['class_name'],
                'class_name_en': classification['class_name_en'],
                'confidence': classification['confidence'],
                'anomaly_confidence': 0.0,  # fallback 時無法取得 Isolation Forest 置信度
                'severity': classification['severity'],
                'severity_emoji': severity_emoji,
                'priority': classification['priority'],
                'description': classification['description'],
                'indicators': classification.get('indicators', []),  # 返回所有 indicators（不限制）
                'response': classification.get('response', []),  # 返回所有 response（不限制）
                'detection_time': detection_time_str
            }
        except Exception as e:
            print(f"威脅分類失敗: {str(e)}")
            import traceback
            traceback.print_exc()
            return None
