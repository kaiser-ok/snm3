#!/usr/bin/env python3
"""
异常记录日志器
将检测到的异常自动写入 Elasticsearch 索引
"""

from elasticsearch import Elasticsearch
from datetime import datetime, timezone
from typing import Dict, List
import warnings

warnings.filterwarnings('ignore')


class AnomalyLogger:
    """
    异常记录日志器

    功能:
    - 将异常检测结果写入 ES 索引
    - 支持按时间分片的索引 (anomaly_detection-YYYY.MM.DD)
    - 便于后续统计和分析
    """

    def __init__(self, es_host: str = 'localhost:9200', index_prefix: str = 'anomaly_detection'):
        """
        初始化日志器

        Args:
            es_host: Elasticsearch 地址
            index_prefix: 索引前缀
        """
        self.es = Elasticsearch([es_host], request_timeout=30)
        self.index_prefix = index_prefix

        # 确保索引模板存在
        self._create_index_template()

    def _create_index_template(self):
        """创建索引模板"""
        template_name = f"{self.index_prefix}-template"

        template = {
            "index_patterns": [f"{self.index_prefix}-*"],
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "index.lifecycle.name": "anomaly_detection_policy",
                "index.lifecycle.rollover_alias": self.index_prefix
            },
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "detection_time": {"type": "date"},
                    "time_bucket": {"type": "date"},
                    "src_ip": {"type": "ip"},
                    "device_type": {"type": "keyword"},
                    "anomaly_score": {"type": "float"},
                    "confidence": {"type": "float"},
                    "flow_count": {"type": "long"},
                    "unique_dsts": {"type": "integer"},
                    "unique_src_ports": {"type": "integer"},
                    "unique_dst_ports": {"type": "integer"},
                    "total_bytes": {"type": "long"},
                    "avg_bytes": {"type": "long"},

                    # 威胁分类信息
                    "threat_class": {"type": "keyword"},
                    "threat_class_en": {"type": "keyword"},
                    "threat_confidence": {"type": "float"},
                    "severity": {"type": "keyword"},
                    "priority": {"type": "keyword"},
                    "description": {"type": "text"},

                    # 详细分析字段
                    "indicators": {"type": "text"},  # 关键指标列表（以换行符分隔）
                    "response_actions": {"type": "text"},  # 建议行动列表（以换行符分隔）
                    "behavior_features": {"type": "text"},  # 行为特征

                    # 原始特征（用于后续分析）
                    "features": {"type": "object", "enabled": False}
                }
            }
        }

        try:
            self.es.indices.put_template(name=template_name, body=template)
        except Exception as e:
            print(f"警告: 创建索引模板失败: {e}")

    def get_index_name(self, timestamp: datetime = None) -> str:
        """
        获取当天的索引名称

        Args:
            timestamp: 时间戳，默认为当前时间

        Returns:
            索引名称，如 'anomaly_detection-2025.11.15'
        """
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        return f"{self.index_prefix}-{timestamp.strftime('%Y.%m.%d')}"

    def log_anomaly(self, anomaly: Dict, device_type: str, classification: Dict = None):
        """
        记录单条异常

        Args:
            anomaly: 异常检测结果字典
            device_type: 设备类型
            classification: 威胁分类结果（可选）
        """
        # 构建文档
        doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "detection_time": datetime.now(timezone.utc).isoformat(),
            "time_bucket": anomaly.get('time_bucket'),
            "src_ip": anomaly.get('src_ip'),
            "device_type": device_type,
            "anomaly_score": anomaly.get('anomaly_score'),
            "confidence": anomaly.get('confidence'),
            "flow_count": anomaly.get('flow_count'),
            "unique_dsts": anomaly.get('unique_dsts'),
            "unique_src_ports": anomaly.get('unique_src_ports'),
            "unique_dst_ports": anomaly.get('unique_dst_ports'),
            "total_bytes": anomaly.get('total_bytes'),
            "avg_bytes": anomaly.get('avg_bytes'),
            "features": anomaly.get('features', {})
        }

        # 添加威胁分类信息（如果有）
        if classification:
            doc.update({
                "threat_class": classification.get('class_name'),
                "threat_class_en": classification.get('class_name_en'),
                "threat_confidence": classification.get('confidence'),
                "severity": classification.get('severity'),
                "priority": classification.get('priority'),
                "description": classification.get('description'),
                "indicators": ', '.join(classification.get('indicators', [])),
                "response": ', '.join(classification.get('response', []))
            })

        # 写入 ES
        try:
            index_name = self.get_index_name()
            self.es.index(index=index_name, body=doc)
        except Exception as e:
            print(f"警告: 写入异常记录失败: {e}")

    def log_anomalies_batch(self, anomalies: List[Dict], device_classifier=None, classifier=None):
        """
        批量记录异常

        Args:
            anomalies: 异常列表
            device_classifier: 设备分类器（可选）
            classifier: 威胁分类器（可选）
        """
        if not anomalies:
            return

        # 如果没有提供分类器，不尝试导入（由调用者提供）
        if device_classifier is None or classifier is None:
            print("警告: 未提供分类器，跳过分类步骤")
            return

        # 批量写入
        bulk_body = []

        for anomaly in anomalies:
            # 获取设备类型
            device_type = device_classifier.classify(anomaly['src_ip'])

            # 获取威胁分类
            classification = None
            try:
                context = {
                    'timestamp': datetime.fromisoformat(anomaly['time_bucket'].replace('Z', '+00:00')),
                    'src_ip': anomaly['src_ip'],
                    'anomaly_score': anomaly['anomaly_score']
                }
                classification = classifier.classify(anomaly['features'], context)
            except:
                pass

            # 提取行为特征
            behaviors = []
            if anomaly.get('features', {}).get('is_high_connection'):
                behaviors.append("高連線數")
            if anomaly.get('features', {}).get('is_scanning_pattern'):
                behaviors.append("掃描模式")
            if anomaly.get('features', {}).get('is_small_packet'):
                behaviors.append("小封包")
            if anomaly.get('features', {}).get('is_large_flow'):
                behaviors.append("大流量")

            # 构建文档
            doc = {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "detection_time": datetime.now(timezone.utc).isoformat(),
                "time_bucket": anomaly.get('time_bucket'),
                "src_ip": anomaly.get('src_ip'),
                "device_type": device_type,
                "anomaly_score": anomaly.get('anomaly_score'),
                "confidence": anomaly.get('confidence'),
                "flow_count": anomaly.get('flow_count'),
                "unique_dsts": anomaly.get('unique_dsts'),
                "unique_src_ports": anomaly.get('unique_src_ports'),
                "unique_dst_ports": anomaly.get('unique_dst_ports'),
                "total_bytes": anomaly.get('total_bytes'),
                "avg_bytes": anomaly.get('avg_bytes'),
                "behavior_features": ', '.join(behaviors) if behaviors else None
            }

            if classification:
                doc.update({
                    "threat_class": classification.get('class_name'),
                    "threat_class_en": classification.get('class_name_en'),
                    "threat_confidence": classification.get('confidence'),
                    "severity": classification.get('severity'),
                    "priority": classification.get('priority'),
                    "description": classification.get('description'),
                    # 保存详细的关键指标（每行一个，便于展示）
                    "indicators": '\n'.join(classification.get('indicators', [])) if classification.get('indicators') else None,
                    # 保存详细的响应建议（每行一个，便于展示）
                    "response_actions": '\n'.join(classification.get('response', [])) if classification.get('response') else None,
                })

            # 添加到批量操作
            index_name = self.get_index_name()
            bulk_body.append({"index": {"_index": index_name}})
            bulk_body.append(doc)

        # 执行批量写入
        if bulk_body:
            try:
                self.es.bulk(body=bulk_body, refresh=True)
            except Exception as e:
                print(f"警告: 批量写入异常记录失败: {e}")

    def get_anomaly_stats(self, days: int = 7) -> Dict:
        """
        获取异常统计信息

        Args:
            days: 统计最近 N 天

        Returns:
            统计信息字典
        """
        query = {
            "size": 0,
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": f"now-{days}d"
                    }
                }
            },
            "aggs": {
                "by_device_type": {
                    "terms": {"field": "device_type", "size": 10}
                },
                "by_threat_class": {
                    "terms": {"field": "threat_class", "size": 10}
                },
                "by_severity": {
                    "terms": {"field": "severity", "size": 10}
                },
                "top_ips": {
                    "terms": {"field": "src_ip", "size": 20}
                }
            }
        }

        try:
            response = self.es.search(
                index=f"{self.index_prefix}-*",
                body=query
            )

            return {
                'total': response['hits']['total']['value'],
                'by_device_type': response['aggregations']['by_device_type']['buckets'],
                'by_threat_class': response['aggregations']['by_threat_class']['buckets'],
                'by_severity': response['aggregations']['by_severity']['buckets'],
                'top_ips': response['aggregations']['top_ips']['buckets']
            }
        except Exception as e:
            print(f"警告: 获取统计信息失败: {e}")
            return {}
