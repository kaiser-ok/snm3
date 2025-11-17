#!/usr/bin/env python3
"""
删除 Elasticsearch 中时间异常的数据

用法:
  python3 delete_invalid_time_data.py --year 2026 --dry-run  # 预览要删除的数据
  python3 delete_invalid_time_data.py --year 2026            # 实际删除
"""

import argparse
import warnings
from datetime import datetime
from nad.utils import load_config
from elasticsearch import Elasticsearch

warnings.filterwarnings('ignore')


def preview_invalid_data(es, index, cutoff_date):
    """预览要删除的数据"""
    query = {
        'size': 0,
        'query': {
            'range': {
                'time_bucket': {
                    'gte': cutoff_date
                }
            }
        },
        'aggs': {
            'sample_docs': {
                'top_hits': {
                    'size': 10,
                    'sort': [{'time_bucket': {'order': 'desc'}}],
                    '_source': ['src_ip', 'time_bucket', 'flow_count']
                }
            },
            'year_stats': {
                'date_histogram': {
                    'field': 'time_bucket',
                    'calendar_interval': 'year'
                }
            }
        }
    }

    try:
        response = es.search(index=index, body=query)
        total = response['hits']['total']['value']

        if total == 0:
            print(f'\n索引 {index}: ✅ 没有需要删除的数据')
            return 0

        print(f'\n索引 {index}: 发现 {total:,} 笔异常数据 (时间 >= {cutoff_date})')

        # 显示年份分布
        print('\n年份分布:')
        for bucket in response['aggregations']['year_stats']['buckets']:
            year = datetime.fromtimestamp(bucket['key'] / 1000).year
            print(f'  {year} 年: {bucket["doc_count"]:,} 笔')

        # 显示样本
        print('\n样本数据 (前 10 笔):')
        for hit in response['aggregations']['sample_docs']['hits']['hits']:
            src = hit['_source']
            print(f'  时间: {src.get("time_bucket", "N/A")} | '
                  f'IP: {src.get("src_ip", "N/A")} | '
                  f'连线数: {src.get("flow_count", "N/A")}')

        return total

    except Exception as e:
        print(f'\n索引 {index}: ❌ 查询失败 - {e}')
        return 0


def delete_invalid_data(es, index, cutoff_date):
    """删除时间异常的数据"""
    query = {
        'query': {
            'range': {
                'time_bucket': {
                    'gte': cutoff_date
                }
            }
        }
    }

    try:
        # 使用 delete_by_query 批量删除
        response = es.delete_by_query(
            index=index,
            body=query,
            conflicts='proceed',  # 忽略版本冲突
            refresh=True  # 删除后刷新索引
        )

        deleted = response.get('deleted', 0)
        print(f'\n索引 {index}: ✅ 成功删除 {deleted:,} 笔数据')

        # 显示详细信息
        if response.get('failures'):
            print(f'  ⚠️  失败: {len(response["failures"])} 笔')
            for failure in response['failures'][:5]:  # 只显示前 5 个失败
                print(f'    - {failure}')

        return deleted

    except Exception as e:
        print(f'\n索引 {index}: ❌ 删除失败 - {e}')
        return 0


def main():
    parser = argparse.ArgumentParser(description='删除 Elasticsearch 中时间异常的数据')
    parser.add_argument(
        '--year',
        type=int,
        default=2026,
        help='删除此年份及以后的数据 (默认: 2026)'
    )
    parser.add_argument(
        '--index',
        type=str,
        default='netflow_stats_5m',
        help='要处理的索引名称 (默认: netflow_stats_5m)'
    )
    parser.add_argument(
        '--config',
        type=str,
        default='nad/config.yaml',
        help='配置文件路径'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='预览模式，不实际删除数据'
    )

    args = parser.parse_args()

    # 构建截止日期
    cutoff_date = f'{args.year}-01-01T00:00:00.000Z'

    print('=' * 100)
    print('删除 Elasticsearch 时间异常数据')
    print('=' * 100)
    print(f'\n配置:')
    print(f'  索引: {args.index}')
    print(f'  删除条件: 时间 >= {cutoff_date}')
    print(f'  模式: {"🔍 预览模式 (不会实际删除)" if args.dry_run else "⚠️  实际删除模式"}')
    print('=' * 100)

    # 加载配置
    try:
        config = load_config(args.config)
        es = Elasticsearch([config.es_host], request_timeout=60)
    except Exception as e:
        print(f'\n❌ 初始化失败: {e}')
        return

    # 预览数据
    print('\n📊 步骤 1: 预览要删除的数据')
    total = preview_invalid_data(es, args.index, cutoff_date)

    if total == 0:
        print('\n✅ 没有需要删除的数据，退出')
        return

    # 确认删除
    if not args.dry_run:
        print('\n' + '=' * 100)
        print('⚠️  警告: 即将删除数据，此操作不可恢复！')
        print('=' * 100)

        confirm = input(f'\n确认要删除 {total:,} 笔数据吗？输入 "YES" 确认: ')

        if confirm != 'YES':
            print('\n❌ 已取消删除操作')
            return

        # 执行删除
        print('\n🗑️  步骤 2: 执行删除...')
        deleted = delete_invalid_data(es, args.index, cutoff_date)

        print('\n' + '=' * 100)
        print(f'✅ 删除完成！共删除 {deleted:,} 笔数据')
        print('=' * 100)

        # 验证
        print('\n🔍 步骤 3: 验证删除结果...')
        remaining = preview_invalid_data(es, args.index, cutoff_date)

        if remaining == 0:
            print('\n✅ 验证通过：所有异常数据已删除')
        else:
            print(f'\n⚠️  警告：仍有 {remaining:,} 笔异常数据未删除')
    else:
        print('\n💡 提示: 移除 --dry-run 参数即可实际删除数据')


if __name__ == '__main__':
    main()
