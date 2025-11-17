#!/usr/bin/env python3
"""
配置文件備份恢復工具

列出並恢復 nad/config.yaml 的備份版本
"""

import os
import sys
import argparse
import shutil
from datetime import datetime
from pathlib import Path


def list_backups(config_path='nad/config.yaml'):
    """
    列出所有備份文件

    Args:
        config_path: 配置文件路徑

    Returns:
        備份文件列表（按時間排序）
    """
    backup_dir = os.path.dirname(config_path) or '.'
    config_name = os.path.basename(config_path)

    # 查找所有備份文件
    backups = []
    for filename in os.listdir(backup_dir):
        if filename.startswith(f"{config_name}.backup."):
            backup_path = os.path.join(backup_dir, filename)

            # 提取時間戳
            timestamp_str = filename.split('.backup.')[1]
            try:
                timestamp = datetime.strptime(timestamp_str, '%Y%m%d_%H%M%S')
                size = os.path.getsize(backup_path)
                backups.append({
                    'path': backup_path,
                    'filename': filename,
                    'timestamp': timestamp,
                    'timestamp_str': timestamp_str,
                    'size': size
                })
            except ValueError:
                # 無法解析時間戳，跳過
                continue

    # 按時間倒序排列（最新的在前）
    backups.sort(key=lambda x: x['timestamp'], reverse=True)

    return backups


def display_backups(backups):
    """顯示備份列表"""
    if not backups:
        print("❌ 沒有找到備份文件")
        return

    print(f"\n{'='*100}")
    print(f"📦 可用的配置備份")
    print(f"{'='*100}\n")

    print(f"{'序號':<6} {'時間':<20} {'檔案大小':<12} {'備份文件名'}")
    print(f"{'-'*100}")

    for i, backup in enumerate(backups, 1):
        size_kb = backup['size'] / 1024
        time_str = backup['timestamp'].strftime('%Y-%m-%d %H:%M:%S')

        # 標記最新的備份
        marker = "🆕" if i == 1 else "  "

        print(f"{marker} {i:<4} {time_str:<20} {size_kb:>8.1f} KB   {backup['filename']}")

    print()


def restore_backup(backup_path, config_path='nad/config.yaml', create_backup=True):
    """
    恢復備份

    Args:
        backup_path: 要恢復的備份文件路徑
        config_path: 目標配置文件路徑
        create_backup: 是否在恢復前備份當前配置

    Returns:
        成功返回 True，失敗返回 False
    """
    print(f"\n{'='*100}")
    print(f"🔄 恢復配置備份")
    print(f"{'='*100}\n")

    try:
        # 檢查備份文件是否存在
        if not os.path.exists(backup_path):
            print(f"❌ 備份文件不存在: {backup_path}")
            return False

        # 在恢復前備份當前配置
        if create_backup and os.path.exists(config_path):
            current_backup_path = f"{config_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(config_path, current_backup_path)
            print(f"✓ 已備份當前配置: {current_backup_path}")

        # 恢復備份
        shutil.copy2(backup_path, config_path)
        print(f"✓ 已恢復配置文件: {config_path}")
        print(f"   來源: {backup_path}")

        print(f"\n{'='*100}")
        print(f"✅ 配置已成功恢復！")
        print(f"{'='*100}\n")

        print("⚠️  重要提醒:")
        print("   1. 如果閾值已改變，請重新訓練模型:")
        print("      python3 train_isolation_forest.py --days 7")
        print()
        print("   2. 驗證配置是否正確:")
        print("      python3 realtime_detection.py --minutes 10")
        print()

        return True

    except Exception as e:
        print(f"❌ 恢復失敗: {e}")
        return False


def compare_configs(backup_path, config_path='nad/config.yaml'):
    """
    比較備份與當前配置的差異

    Args:
        backup_path: 備份文件路徑
        config_path: 當前配置文件路徑
    """
    import yaml

    print(f"\n{'='*100}")
    print(f"🔍 配置差異對比")
    print(f"{'='*100}\n")

    try:
        # 讀取兩個配置
        with open(backup_path, 'r', encoding='utf-8') as f:
            backup_config = yaml.safe_load(f)

        with open(config_path, 'r', encoding='utf-8') as f:
            current_config = yaml.safe_load(f)

        # 比較 thresholds
        backup_thresholds = backup_config.get('thresholds', {})
        current_thresholds = current_config.get('thresholds', {})

        print("📊 閾值差異:\n")
        print(f"{'參數':<30} {'備份值':>15} {'當前值':>15} {'差異':>15}")
        print(f"{'-'*100}")

        all_params = set(list(backup_thresholds.keys()) + list(current_thresholds.keys()))
        has_diff = False

        for param in sorted(all_params):
            backup_val = backup_thresholds.get(param, 'N/A')
            current_val = current_thresholds.get(param, 'N/A')

            if backup_val != current_val:
                has_diff = True
                if isinstance(backup_val, (int, float)) and isinstance(current_val, (int, float)):
                    if backup_val != 0:
                        change = ((current_val - backup_val) / backup_val * 100)
                        diff_str = f"{change:+.1f}%"
                    else:
                        diff_str = "N/A"
                    backup_str = f"{backup_val:,}"
                    current_str = f"{current_val:,}"
                else:
                    diff_str = "不同"
                    backup_str = str(backup_val)
                    current_str = str(current_val)

                print(f"🔴 {param:<27} {backup_str:>15} {current_str:>15} {diff_str:>15}")
            else:
                if isinstance(backup_val, (int, float)):
                    val_str = f"{backup_val:,}"
                else:
                    val_str = str(backup_val)
                print(f"   {param:<27} {val_str:>15} {val_str:>15} {'相同':>15}")

        if not has_diff:
            print("\n✅ 閾值部分無差異")

        # 比較其他關鍵配置
        print(f"\n📊 其他配置:\n")

        # isolation_forest
        backup_if = backup_config.get('isolation_forest', {})
        current_if = current_config.get('isolation_forest', {})

        if backup_if != current_if:
            print("🔴 isolation_forest 配置有差異")
            print(f"   備份: {backup_if}")
            print(f"   當前: {current_if}")
        else:
            print("✅ isolation_forest 配置相同")

        print()

    except Exception as e:
        print(f"❌ 比較失敗: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='配置文件備份恢復工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 列出所有備份
  python3 restore_config_backup.py --list

  # 恢復最新的備份
  python3 restore_config_backup.py --restore latest

  # 恢復特定的備份（按序號）
  python3 restore_config_backup.py --restore 2

  # 恢復特定的備份（按文件名）
  python3 restore_config_backup.py --restore nad/config.yaml.backup.20251113_140000

  # 比較備份與當前配置
  python3 restore_config_backup.py --compare 1

  # 清理舊備份（保留最近 5 個）
  python3 restore_config_backup.py --clean --keep 5
        """
    )

    parser.add_argument('--config', type=str, default='nad/config.yaml',
                       help='配置文件路徑 (默認: nad/config.yaml)')
    parser.add_argument('--list', action='store_true',
                       help='列出所有備份')
    parser.add_argument('--restore', type=str,
                       help='恢復備份 (使用 "latest" 或序號或文件路徑)')
    parser.add_argument('--compare', type=str,
                       help='比較備份與當前配置 (使用序號或文件路徑)')
    parser.add_argument('--clean', action='store_true',
                       help='清理舊備份')
    parser.add_argument('--keep', type=int, default=5,
                       help='清理時保留的備份數量 (默認: 5)')
    parser.add_argument('--no-backup', action='store_true',
                       help='恢復時不備份當前配置')

    args = parser.parse_args()

    # 列出備份
    backups = list_backups(args.config)

    if args.list or (not args.restore and not args.compare and not args.clean):
        display_backups(backups)
        if backups:
            print("💡 使用 --restore <序號|latest> 來恢復備份")
            print("💡 使用 --compare <序號> 來查看差異")
            print("💡 使用 --clean --keep N 來清理舊備份")
        return

    # 恢復備份
    if args.restore:
        if not backups:
            print("❌ 沒有可恢復的備份")
            sys.exit(1)

        # 確定要恢復的備份
        if args.restore == 'latest':
            backup_to_restore = backups[0]
        elif args.restore.isdigit():
            index = int(args.restore) - 1
            if 0 <= index < len(backups):
                backup_to_restore = backups[index]
            else:
                print(f"❌ 無效的序號: {args.restore}")
                print(f"   可用範圍: 1-{len(backups)}")
                sys.exit(1)
        elif os.path.exists(args.restore):
            backup_to_restore = {'path': args.restore}
        else:
            print(f"❌ 找不到備份: {args.restore}")
            sys.exit(1)

        # 確認恢復
        print(f"⚠️  即將恢復備份: {backup_to_restore['path']}")
        if os.path.exists(args.config):
            print(f"   當前配置將被覆蓋: {args.config}")

        response = input("\n是否繼續? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("❌ 已取消")
            sys.exit(0)

        success = restore_backup(
            backup_to_restore['path'],
            args.config,
            create_backup=not args.no_backup
        )

        sys.exit(0 if success else 1)

    # 比較配置
    if args.compare:
        if not backups:
            print("❌ 沒有可比較的備份")
            sys.exit(1)

        # 確定要比較的備份
        if args.compare.isdigit():
            index = int(args.compare) - 1
            if 0 <= index < len(backups):
                backup_to_compare = backups[index]
            else:
                print(f"❌ 無效的序號: {args.compare}")
                sys.exit(1)
        elif os.path.exists(args.compare):
            backup_to_compare = {'path': args.compare}
        else:
            print(f"❌ 找不到備份: {args.compare}")
            sys.exit(1)

        compare_configs(backup_to_compare['path'], args.config)

    # 清理舊備份
    if args.clean:
        if len(backups) <= args.keep:
            print(f"✅ 備份數量 ({len(backups)}) 未超過保留數量 ({args.keep})，無需清理")
        else:
            to_delete = backups[args.keep:]
            print(f"\n⚠️  即將刪除 {len(to_delete)} 個舊備份 (保留最近 {args.keep} 個):\n")

            for backup in to_delete:
                print(f"   - {backup['filename']}")

            response = input("\n是否繼續? (yes/no): ")
            if response.lower() not in ['yes', 'y']:
                print("❌ 已取消")
                sys.exit(0)

            for backup in to_delete:
                try:
                    os.remove(backup['path'])
                    print(f"✓ 已刪除: {backup['filename']}")
                except Exception as e:
                    print(f"❌ 刪除失敗 {backup['filename']}: {e}")

            print(f"\n✅ 清理完成！保留了最近 {args.keep} 個備份")


if __name__ == '__main__':
    main()
