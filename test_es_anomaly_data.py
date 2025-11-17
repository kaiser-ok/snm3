#!/usr/bin/env python3
"""
测试脚本：查询 Elasticsearch 中的异常检测记录
验证详细分析数据是否正确保存
"""

import warnings
warnings.filterwarnings('ignore')

from elasticsearch import Elasticsearch
from datetime import datetime, timedelta, timezone
import json


def test_anomaly_records():
    """查询并显示最新的异常记录"""

    es = Elasticsearch(['localhost:9200'], request_timeout=30)

    # 查询今天的索引
    today = datetime.now(timezone.utc)
    index_name = f"anomaly_detection-{today.strftime('%Y.%m.%d')}"

    print(f"\n{'='*100}")
    print(f"查询索引: {index_name}")
    print(f"{'='*100}\n")

    # 检查索引是否存在
    try:
        if not es.indices.exists(index=index_name):
            print(f"⚠️  索引 {index_name} 不存在")
            print(f"提示: 请先运行 'python3 realtime_detection.py --continuous' 产生数据\n")
            return
    except Exception as e:
        print(f"❌ 检查索引失败: {e}\n")
        return

    # 查询最新的 5 条记录
    query = {
        "size": 5,
        "sort": [
            {"@timestamp": {"order": "desc"}}
        ],
        "query": {
            "match_all": {}
        }
    }

    try:
        response = es.search(index=index_name, body=query)
        total = response['hits']['total']['value']

        print(f"📊 总记录数: {total:,}\n")

        if total == 0:
            print("⚠️  没有找到任何记录")
            print("提示: 请先运行 'python3 realtime_detection.py --continuous' 产生数据\n")
            return

        print(f"{'='*100}")
        print("最新的 5 条异常记录详情:")
        print(f"{'='*100}\n")

        for i, hit in enumerate(response['hits']['hits'], 1):
            doc = hit['_source']

            # 转换为本地时间
            detection_time_utc = datetime.fromisoformat(doc['detection_time'].replace('Z', '+00:00'))
            local_tz = timezone(timedelta(hours=8))
            detection_time_local = detection_time_utc.astimezone(local_tz)

            print(f"{i}. 异常记录")
            print(f"   {'─'*90}")
            print(f"   检测时间: {detection_time_local.strftime('%Y-%m-%d %H:%M:%S')} (本地时间)")
            print(f"   源IP: {doc.get('src_ip')}")
            print(f"   设备类型: {doc.get('device_type', 'N/A')}")
            print()

            print(f"   异常指标:")
            print(f"      异常分数: {doc.get('anomaly_score', 0):.4f}")
            print(f"      置信度: {doc.get('confidence', 0):.2f}")
            print(f"      连线数: {doc.get('flow_count', 0):,}")
            print(f"      不同目的地: {doc.get('unique_dsts', 0)}")
            print(f"      不同源端口: {doc.get('unique_src_ports', 0)}")
            print(f"      不同目的端口: {doc.get('unique_dst_ports', 0)}")
            print(f"      总流量: {doc.get('total_bytes', 0) / 1024 / 1024:.2f} MB")
            print(f"      平均流量: {doc.get('avg_bytes', 0):,.0f} bytes")
            print()

            # 行为特征
            if doc.get('behavior_features'):
                print(f"   行为特征: {doc['behavior_features']}")
                print()

            # 威胁分类
            if doc.get('threat_class'):
                print(f"   威胁分类:")
                print(f"      类别: {doc.get('threat_class')} ({doc.get('threat_class_en', 'N/A')})")
                print(f"      置信度: {doc.get('threat_confidence', 0):.0%}")
                print(f"      严重性: {doc.get('severity', 'N/A')}")
                print(f"      优先级: {doc.get('priority', 'N/A')}")
                print(f"      描述: {doc.get('description', 'N/A')}")
                print()

                # 关键指标
                if doc.get('indicators'):
                    print(f"      关键指标:")
                    for indicator in doc['indicators'].split('\n'):
                        if indicator.strip():
                            print(f"         • {indicator.strip()}")
                    print()

                # 响应建议
                if doc.get('response_actions'):
                    print(f"      建议行动:")
                    for action in doc['response_actions'].split('\n'):
                        if action.strip():
                            print(f"         • {action.strip()}")
                    print()

            print(f"   {'─'*90}\n")

        # 显示字段统计
        print(f"{'='*100}")
        print("字段完整性检查:")
        print(f"{'='*100}\n")

        # 统计各字段的填充率
        fields_to_check = [
            'behavior_features',
            'threat_class',
            'threat_class_en',
            'threat_confidence',
            'severity',
            'priority',
            'description',
            'indicators',
            'response_actions'
        ]

        field_stats = {}
        for field in fields_to_check:
            count_query = {
                "query": {
                    "exists": {
                        "field": field
                    }
                }
            }
            count_response = es.count(index=index_name, body=count_query)
            field_stats[field] = count_response['count']

        for field, count in field_stats.items():
            percentage = (count / total * 100) if total > 0 else 0
            status = "✓" if percentage > 80 else "⚠" if percentage > 50 else "✗"
            print(f"   {status} {field:25} : {count:5,} / {total:,} ({percentage:5.1f}%)")

        print()

    except Exception as e:
        print(f"❌ 查询失败: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    test_anomaly_records()
