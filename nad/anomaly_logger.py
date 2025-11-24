#!/usr/bin/env python3
"""
异常记录日志器
将检测到的异常自动写入 Elasticsearch 索引
"""

from elasticsearch import Elasticsearch
from datetime import datetime, timezone
from typing import Dict, List
import warnings
import pytz

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
                    "dst_ip": {"type": "ip"},
                    "perspective": {"type": "keyword"},  # SRC 或 DST
                    "device_type": {"type": "keyword"},
                    "anomaly_score": {"type": "float"},
                    "confidence": {"type": "float"},
                    "flow_count": {"type": "long"},
                    "unique_dsts": {"type": "integer"},
                    "unique_srcs": {"type": "integer"},
                    "unique_src_ports": {"type": "integer"},
                    "unique_dst_ports": {"type": "integer"},
                    "total_bytes": {"type": "long"},
                    "avg_bytes": {"type": "long"},

                    # 後處理驗證結果
                    "validation_result": {"type": "keyword"},
                    "verification_details": {"type": "object", "enabled": False},

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
            # 使用新版 put_index_template API (ES 7.8+)
            self.es.indices.put_index_template(name=template_name, body={
                "index_patterns": template["index_patterns"],
                "template": {
                    "settings": template["settings"],
                    "mappings": template["mappings"]
                }
            })
            print(f"✓ 索引模板已創建: {template_name}")
        except Exception as e:
            print(f"警告: 创建索引模板失败: {e}")

    def get_index_name(self, timestamp: datetime = None) -> str:
        """
        获取当天的索引名称（使用台北時區）

        Args:
            timestamp: 时间戳，默认为当前时间

        Returns:
            索引名称，如 'anomaly_detection-2025.11.15'
        """
        if timestamp is None:
            taipei_tz = pytz.timezone('Asia/Taipei')
            timestamp = datetime.now(taipei_tz)

        return f"{self.index_prefix}-{timestamp.strftime('%Y.%m.%d')}"

    def log_anomaly(self, anomaly: Dict, device_type: str, classification: Dict = None):
        """
        记录单条异常

        Args:
            anomaly: 异常检测结果字典
            device_type: 设备类型
            classification: 威胁分类结果（可选）
        """
        # 提取行为特征
        perspective = anomaly.get('perspective', 'SRC')
        features = anomaly.get('features', {})
        behaviors = []

        if perspective == 'SRC':
            # SRC 視角的行為特徵
            if features.get('is_high_connection'):
                behaviors.append("高連線數")
            if features.get('is_scanning_pattern'):
                behaviors.append("掃描模式")
            if features.get('is_small_packet'):
                behaviors.append("小封包")
            if features.get('is_large_flow'):
                behaviors.append("大流量")
        elif perspective == 'DST':
            # DST 視角的行為特徵（基於統計數據推斷）
            unique_srcs = features.get('unique_srcs', 0)
            flow_count = features.get('flow_count', 0)
            avg_bytes = features.get('avg_bytes', 0)
            flows_per_src = features.get('flows_per_src', 0)
            unique_dst_ports = features.get('unique_dst_ports', 0)

            # 大量來源 IP
            if unique_srcs > 100:
                behaviors.append("大量來源")

            # 高連線數
            if flow_count > 1000:
                behaviors.append("高連線數")

            # 小封包（可能是探測或攻擊）
            if avg_bytes < 500:
                behaviors.append("小封包")

            # 大流量
            if features.get('total_bytes', 0) > 10000000:  # > 10MB
                behaviors.append("大流量")

            # 掃描特徵：大量不同端口被訪問
            if unique_dst_ports > 100:
                behaviors.append("多端口訪問")

            # 每個來源連線少（掃描回應特徵）
            if flows_per_src > 0 and flows_per_src < 5:
                behaviors.append("低頻訪問")

        # 构建文档
        taipei_tz = pytz.timezone('Asia/Taipei')
        now_taipei = datetime.now(taipei_tz)
        doc = {
            "@timestamp": now_taipei.isoformat(),
            "detection_time": now_taipei.isoformat(),
            "time_bucket": anomaly.get('time_bucket'),
            "src_ip": anomaly.get('src_ip'),
            "dst_ip": anomaly.get('dst_ip'),
            "perspective": anomaly.get('perspective', 'SRC'),  # SRC 或 DST
            "device_type": device_type,
            "anomaly_score": anomaly.get('anomaly_score'),
            "confidence": anomaly.get('confidence'),
            "flow_count": anomaly.get('flow_count'),
            "unique_dsts": anomaly.get('unique_dsts'),
            "unique_srcs": anomaly.get('unique_srcs'),
            "unique_src_ports": anomaly.get('unique_src_ports'),
            "unique_dst_ports": anomaly.get('unique_dst_ports'),
            "total_bytes": anomaly.get('total_bytes'),
            "avg_bytes": anomaly.get('avg_bytes'),
            "validation_result": anomaly.get('validation_result'),  # 驗證結果
            "behavior_features": ', '.join(behaviors) if behaviors else None,
            "features": anomaly.get('features', {})
        }

        # 寫入 verification_details（即使是空字典也寫入）
        if 'verification_details' in anomaly:
            doc["verification_details"] = anomaly['verification_details']

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
            perspective = anomaly.get('perspective', 'SRC')
            features = anomaly.get('features', {})
            behaviors = []

            if perspective == 'SRC':
                # SRC 視角的行為特徵
                if features.get('is_high_connection'):
                    behaviors.append("高連線數")
                if features.get('is_scanning_pattern'):
                    behaviors.append("掃描模式")
                if features.get('is_small_packet'):
                    behaviors.append("小封包")
                if features.get('is_large_flow'):
                    behaviors.append("大流量")
            elif perspective == 'DST':
                # DST 視角的行為特徵（基於統計數據推斷）
                unique_srcs = features.get('unique_srcs', 0)
                flow_count = features.get('flow_count', 0)
                avg_bytes = features.get('avg_bytes', 0)
                flows_per_src = features.get('flows_per_src', 0)
                unique_dst_ports = features.get('unique_dst_ports', 0)

                if unique_srcs > 100:
                    behaviors.append("大量來源")
                if flow_count > 1000:
                    behaviors.append("高連線數")
                if avg_bytes < 500:
                    behaviors.append("小封包")
                if features.get('total_bytes', 0) > 10000000:
                    behaviors.append("大流量")
                if unique_dst_ports > 100:
                    behaviors.append("多端口訪問")
                if flows_per_src > 0 and flows_per_src < 5:
                    behaviors.append("低頻訪問")

            # 构建文档
            taipei_tz = pytz.timezone('Asia/Taipei')
            now_taipei = datetime.now(taipei_tz)
            doc = {
                "@timestamp": now_taipei.isoformat(),
                "detection_time": now_taipei.isoformat(),
                "time_bucket": anomaly.get('time_bucket'),
                "src_ip": anomaly.get('src_ip'),
                "dst_ip": anomaly.get('dst_ip'),
                "perspective": anomaly.get('perspective', 'SRC'),
                "device_type": device_type,
                "anomaly_score": anomaly.get('anomaly_score'),
                "confidence": anomaly.get('confidence'),
                "flow_count": anomaly.get('flow_count'),
                "unique_dsts": anomaly.get('unique_dsts'),
                "unique_srcs": anomaly.get('unique_srcs'),
                "unique_src_ports": anomaly.get('unique_src_ports'),
                "unique_dst_ports": anomaly.get('unique_dst_ports'),
                "total_bytes": anomaly.get('total_bytes'),
                "avg_bytes": anomaly.get('avg_bytes'),
                "validation_result": anomaly.get('validation_result'),
                "behavior_features": ', '.join(behaviors) if behaviors else None
            }

            # 寫入 verification_details（即使是空字典也寫入）
            if 'verification_details' in anomaly:
                doc["verification_details"] = anomaly['verification_details']

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
