# 配置備份與恢復指南

## 📖 概述

配置文件 `nad/config.yaml` 包含了異常檢測系統的所有關鍵設置。本指南介紹如何自動備份、恢復和管理配置版本。

---

## 🔄 自動備份機制

### 何時會自動創建備份？

當您使用 `--apply` 參數時，系統會**自動備份**原配置：

```bash
python3 calculate_adaptive_thresholds.py --days 7 --apply
```

**自動備份特性：**
- ✅ 在修改前備份原配置（保留原始內容）
- ✅ 備份文件名包含時間戳：`config.yaml.backup.YYYYMMDD_HHMMSS`
- ✅ 顯示詳細的變更信息
- ✅ 提供回滾命令

**輸出示例：**
```
======================================================================
💾 應用閾值到配置文件
======================================================================

✓ 已備份原配置: nad/config.yaml.backup.20251113_143025

📝 更新閾值:
   high_connection                   1,000 →           1,245  (+24.5%)
   scanning_dsts                        30 →              45  (+50.0%)
   scanning_avg_bytes               10,000 →           1,234  (-87.7%)
   small_packet                      1,000 →           1,234  (+23.4%)
   large_flow                  104,857,600 →     123,456,000  (+17.7%)

✓ 已更新配置文件: nad/config.yaml

💡 如需回滾，執行:
   cp nad/config.yaml.backup.20251113_143025 nad/config.yaml
```

---

## 📋 管理備份

### 列出所有備份

```bash
python3 restore_config_backup.py --list
```

**輸出示例：**
```
======================================================================
📦 可用的配置備份
======================================================================

序號   時間                  檔案大小      備份文件名
----------------------------------------------------------------------------------------------------
🆕 1    2025-11-13 14:30:25     2.7 KB   config.yaml.backup.20251113_143025
   2    2025-11-13 10:15:00     2.6 KB   config.yaml.backup.20251113_101500
   3    2025-11-12 08:00:00     2.5 KB   config.yaml.backup.20251112_080000
   4    2025-11-10 02:00:00     2.5 KB   config.yaml.backup.20251110_020000

💡 使用 --restore <序號|latest> 來恢復備份
💡 使用 --compare <序號> 來查看差異
💡 使用 --clean --keep N 來清理舊備份
```

### 比較備份與當前配置

查看備份與當前配置的差異：

```bash
# 比較最新備份（序號 1）
python3 restore_config_backup.py --compare 1

# 比較特定備份
python3 restore_config_backup.py --compare nad/config.yaml.backup.20251113_143025
```

**輸出示例：**
```
======================================================================
🔍 配置差異對比
======================================================================

📊 閾值差異:

參數                              備份值         當前值           差異
----------------------------------------------------------------------------------------------------
🔴 high_connection                   1,000          1,245      +24.5%
🔴 scanning_dsts                        30             45      +50.0%
🔴 scanning_avg_bytes               10,000          1,234      -87.7%
   small_packet                      1,000          1,000         相同
   large_flow                  104,857,600    104,857,600         相同

📊 其他配置:

✅ isolation_forest 配置相同
```

---

## 🔙 恢復備份

### 方法 1: 恢復最新備份

```bash
python3 restore_config_backup.py --restore latest
```

### 方法 2: 恢復特定備份（按序號）

```bash
# 恢復序號 2 的備份
python3 restore_config_backup.py --restore 2
```

### 方法 3: 恢復特定備份（按文件名）

```bash
python3 restore_config_backup.py --restore nad/config.yaml.backup.20251113_143025
```

### 方法 4: 快速手動恢復

```bash
# 直接複製備份文件
cp nad/config.yaml.backup.20251113_143025 nad/config.yaml
```

**恢復過程：**
```
⚠️  即將恢復備份: nad/config.yaml.backup.20251113_143025
   當前配置將被覆蓋: nad/config.yaml

是否繼續? (yes/no): yes

======================================================================
🔄 恢復配置備份
======================================================================

✓ 已備份當前配置: nad/config.yaml.backup.20251113_144000
✓ 已恢復配置文件: nad/config.yaml
   來源: nad/config.yaml.backup.20251113_143025

======================================================================
✅ 配置已成功恢復！
======================================================================

⚠️  重要提醒:
   1. 如果閾值已改變，請重新訓練模型:
      python3 train_isolation_forest.py --days 7

   2. 驗證配置是否正確:
      python3 realtime_detection.py --minutes 10
```

**安全特性：**
- ✅ 恢復前會自動備份當前配置
- ✅ 需要手動確認
- ✅ 提供清晰的操作提示

---

## 🧹 清理舊備份

隨著時間推移，備份文件會累積。定期清理可節省空間。

### 保留最近 N 個備份

```bash
# 保留最近 5 個備份（默認）
python3 restore_config_backup.py --clean --keep 5

# 保留最近 10 個備份
python3 restore_config_backup.py --clean --keep 10

# 只保留最近 3 個備份
python3 restore_config_backup.py --clean --keep 3
```

**清理過程：**
```
⚠️  即將刪除 3 個舊備份 (保留最近 5 個):

   - config.yaml.backup.20251101_020000
   - config.yaml.backup.20251025_020000
   - config.yaml.backup.20251018_020000

是否繼續? (yes/no): yes

✓ 已刪除: config.yaml.backup.20251101_020000
✓ 已刪除: config.yaml.backup.20251025_020000
✓ 已刪除: config.yaml.backup.20251018_020000

✅ 清理完成！保留了最近 5 個備份
```

### 自動化清理（cron 任務）

```bash
# 每月自動清理，保留最近 10 個備份
# crontab -e
0 3 1 * * cd /home/kaisermac/snm_flow && python3 restore_config_backup.py --clean --keep 10 --yes
```

---

## 🎯 常見使用場景

### 場景 1: 測試新閾值

```bash
# Step 1: 計算並應用新閾值（自動備份）
python3 calculate_adaptive_thresholds.py --days 7 --apply

# Step 2: 重新訓練模型
python3 train_isolation_forest.py --days 7

# Step 3: 測試效果
python3 realtime_detection.py --minutes 30

# Step 4a: 如果效果不好，恢復備份
python3 restore_config_backup.py --restore latest

# Step 4b: 如果效果好，保留新配置
# 無需操作，已經自動保存
```

### 場景 2: 回滾到特定版本

```bash
# Step 1: 查看所有備份
python3 restore_config_backup.py --list

# Step 2: 比較差異
python3 restore_config_backup.py --compare 3

# Step 3: 確認後恢復
python3 restore_config_backup.py --restore 3

# Step 4: 重新訓練模型
python3 train_isolation_forest.py --days 7
```

### 場景 3: 定期維護

```bash
# Step 1: 每週自動更新閾值
python3 calculate_adaptive_thresholds.py --days 7 --apply

# Step 2: 每月清理舊備份
python3 restore_config_backup.py --clean --keep 10
```

### 場景 4: 配置遷移

```bash
# 從一台服務器遷移配置到另一台

# 源服務器：
scp nad/config.yaml target-server:/home/kaisermac/snm_flow/nad/

# 目標服務器：
# 自動創建備份並使用新配置
python3 train_isolation_forest.py --days 7
```

---

## ⚠️ 最佳實踐

### 1. 修改前先備份

**自動備份（推薦）：**
```bash
# 使用 --apply 自動備份
python3 calculate_adaptive_thresholds.py --days 7 --apply
```

**手動備份：**
```bash
# 手動創建備份
cp nad/config.yaml nad/config.yaml.backup.$(date +%Y%m%d_%H%M%S)
```

### 2. 修改後必須重新訓練

閾值變更會影響特徵工程，**必須重新訓練模型**：

```bash
python3 train_isolation_forest.py --days 7
```

否則模型使用的是舊閾值計算的特徵！

### 3. 定期清理備份

建議保留策略：
- **短期（1個月內）**：保留所有備份（用於快速回滾）
- **中期（1-6個月）**：每週保留1個
- **長期（6個月以上）**：每月保留1個

```bash
# 每月執行
python3 restore_config_backup.py --clean --keep 10
```

### 4. 版本控制（可選）

如果您使用 Git：

```bash
# 將配置文件納入版本控制
git add nad/config.yaml
git commit -m "Update thresholds based on 7-day analysis"
git push

# 回滾到之前的版本
git log nad/config.yaml  # 查看歷史
git checkout <commit-hash> nad/config.yaml
```

**優點：**
- 完整的變更歷史
- 可添加變更說明
- 支持分支測試

### 5. 文檔化重大變更

創建變更日誌：

```bash
# 創建 CHANGELOG.md
echo "## 2025-11-13 閾值調整" >> CHANGELOG.md
echo "- high_connection: 1000 → 1245 (+24.5%)" >> CHANGELOG.md
echo "- 原因: 基於7天歷史數據分析" >> CHANGELOG.md
echo "- 備份: nad/config.yaml.backup.20251113_143025" >> CHANGELOG.md
echo "" >> CHANGELOG.md
```

---

## 🔍 故障排除

### 問題 1: 找不到備份文件

**檢查：**
```bash
# 列出所有備份
ls -lh nad/*.backup.*

# 檢查是否在錯誤的目錄
pwd
```

**解決：**
```bash
# 確保在項目根目錄
cd /home/kaisermac/snm_flow

# 然後再次執行
python3 restore_config_backup.py --list
```

### 問題 2: 恢復後檢測結果異常

**原因：** 模型與配置不匹配

**解決：**
```bash
# 重新訓練模型
python3 train_isolation_forest.py --days 7

# 刪除舊模型文件
rm nad/models/isolation_forest.pkl
python3 train_isolation_forest.py --days 7
```

### 問題 3: 備份文件損壞

**檢查：**
```bash
# 驗證 YAML 語法
python3 -c "import yaml; yaml.safe_load(open('nad/config.yaml.backup.20251113_143025'))"
```

**解決：**
```bash
# 如果損壞，使用更早的備份
python3 restore_config_backup.py --list
python3 restore_config_backup.py --restore 2  # 使用序號 2
```

### 問題 4: 權限問題

**錯誤：**
```
PermissionError: [Errno 13] Permission denied: 'nad/config.yaml'
```

**解決：**
```bash
# 檢查權限
ls -l nad/config.yaml

# 修改權限
chmod 644 nad/config.yaml

# 或使用 sudo（不推薦）
sudo python3 restore_config_backup.py --restore latest
```

---

## 📊 進階技巧

### 批量比較多個備份

```bash
#!/bin/bash
# compare_all_backups.sh

echo "比較所有備份的閾值變化"
echo "========================================"

for i in {1..5}; do
    echo ""
    echo "備份 #$i:"
    python3 restore_config_backup.py --compare $i 2>/dev/null | grep -A 20 "閾值差異"
done
```

### 自動化週期性備份

```bash
#!/bin/bash
# weekly_backup_maintenance.sh

cd /home/kaisermac/snm_flow

# 1. 計算新閾值並應用（自動備份）
python3 calculate_adaptive_thresholds.py --days 7 --apply

# 2. 重新訓練模型
python3 train_isolation_forest.py --days 7 --evaluate

# 3. 運行測試檢測
python3 realtime_detection.py --minutes 30 > /tmp/detection_test.log

# 4. 檢查是否有異常結果
if grep -q "發現 0 個異常" /tmp/detection_test.log; then
    echo "警告: 未檢測到任何異常，閾值可能過於寬鬆"
    # 可選: 自動回滾
    # python3 restore_config_backup.py --restore 2 --no-backup
fi

# 5. 清理舊備份
python3 restore_config_backup.py --clean --keep 10 <<< "yes"

# 6. 發送報告
echo "週期性維護完成" | mail -s "NAD 維護報告" admin@example.com
```

### 備份到遠程存儲

```bash
#!/bin/bash
# backup_to_remote.sh

REMOTE_HOST="backup-server"
REMOTE_PATH="/backups/nad/config"
DATE=$(date +%Y%m%d)

# 同步所有備份到遠程服務器
rsync -avz nad/config.yaml.backup.* \
    $REMOTE_HOST:$REMOTE_PATH/

# 或使用 scp
scp nad/config.yaml.backup.* \
    $REMOTE_HOST:$REMOTE_PATH/
```

---

## 📚 命令參考

### calculate_adaptive_thresholds.py

```bash
# 基本用法
python3 calculate_adaptive_thresholds.py --days 7              # 分析但不應用
python3 calculate_adaptive_thresholds.py --days 7 --apply      # 分析並應用（自動備份）

# 自定義參數
python3 calculate_adaptive_thresholds.py --days 14 --apply     # 使用14天數據
python3 calculate_adaptive_thresholds.py --days 7 \
  --percentile high_connection=98 --apply                      # 自定義百分位數
```

### restore_config_backup.py

```bash
# 查看
python3 restore_config_backup.py --list                        # 列出所有備份
python3 restore_config_backup.py --compare 1                   # 比較差異

# 恢復
python3 restore_config_backup.py --restore latest              # 恢復最新備份
python3 restore_config_backup.py --restore 2                   # 恢復序號2
python3 restore_config_backup.py --restore nad/config.yaml.backup.XXX  # 恢復特定文件

# 清理
python3 restore_config_backup.py --clean --keep 5              # 保留5個
python3 restore_config_backup.py --clean --keep 10             # 保留10個
```

---

## 🔐 安全建議

1. **定期異地備份**
   - 每週將備份複製到其他服務器
   - 使用自動化腳本 (rsync/scp)

2. **權限控制**
   - 配置文件: `644` (rw-r--r--)
   - 備份文件: `644` (rw-r--r--)
   - 腳本文件: `755` (rwxr-xr-x)

3. **審計追蹤**
   - 記錄誰在何時修改了配置
   - 使用 Git 或日誌系統

4. **測試環境**
   - 在測試環境先驗證新配置
   - 再應用到生產環境

---

## 📝 總結

### 核心要點

1. **自動備份** - 使用 `--apply` 自動創建時間戳備份
2. **輕鬆恢復** - 一條命令即可回滾到任何版本
3. **差異對比** - 清楚了解配置變更
4. **定期清理** - 避免備份文件過多
5. **安全保護** - 恢復前自動備份當前配置

### 推薦工作流程

```
調整閾值 → 自動備份 → 重新訓練 → 測試效果 →
→ 滿意: 保留新配置 + 定期清理
→ 不滿意: 恢復備份 + 重新調整
```

---

**版本：** 1.0
**更新日期：** 2025-11-13
**相關文檔：** `ADAPTIVE_THRESHOLDS_GUIDE.md`, `ISOLATION_FOREST_GUIDE.md`
