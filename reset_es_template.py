#!/usr/bin/env python3
"""
重置 ES 索引模板和数据
删除旧的索引模板和索引，让新模板生效
"""

import warnings
warnings.filterwarnings('ignore')

from elasticsearch import Elasticsearch
from datetime import datetime, timezone


def reset_anomaly_detection_index():
    """删除旧索引和模板"""

    es = Elasticsearch(['localhost:9200'], request_timeout=30)

    # 删除模板
    template_name = "anomaly_detection-template"
    try:
        if es.indices.exists_template(name=template_name):
            es.indices.delete_template(name=template_name)
            print(f"✓ 已删除索引模板: {template_name}")
        else:
            print(f"  索引模板不存在: {template_name}")
    except Exception as e:
        print(f"⚠️  删除索引模板失败: {e}")

    # 删除所有异常检测索引
    index_pattern = "anomaly_detection-*"
    try:
        if es.indices.exists(index=index_pattern):
            es.indices.delete(index=index_pattern)
            print(f"✓ 已删除索引: {index_pattern}")
        else:
            print(f"  索引不存在: {index_pattern}")
    except Exception as e:
        print(f"⚠️  删除索引失败: {e}")

    print("\n重置完成！")
    print("提示: 请重新运行 'python3 realtime_detection.py --continuous' 产生新数据\n")


if __name__ == "__main__":
    print(f"\n{'='*100}")
    print("重置异常检测索引和模板")
    print(f"{'='*100}\n")

    confirm = input("确定要删除所有异常检测数据吗？(yes/no): ")
    if confirm.lower() == 'yes':
        reset_anomaly_detection_index()
    else:
        print("已取消操作\n")
