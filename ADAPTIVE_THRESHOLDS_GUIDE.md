# 自適應閾值調整指南

## 📖 概述

本指南介紹如何基於歷史數據自動調整特徵閾值，使異常檢測系統能夠適應您的網路環境的實際流量模式。

### 為什麼需要自適應閾值？

**問題：** 默認閾值可能不適合您的網路環境
- 小型網路：默認閾值太高，無法檢測到異常
- 大型網路：默認閾值太低，產生過多誤報
- 不同業務：流量模式差異巨大（Web服務器 vs 辦公網路）

**解決方案：** 基於歷史數據統計計算閾值
- 使用百分位數方法
- 自動適應實際流量分布
- 減少誤報，提高檢測準確性

---

## 🎯 兩種調整方法

### 方法 1: 基於統計的自適應閾值（推薦）

**適用場景：** 初次部署或定期校準

**工具：** `calculate_adaptive_thresholds.py`

**原理：**
- 分析過去 N 天的歷史數據
- 計算特徵值的統計分布
- 使用百分位數設置閾值

**優點：**
- ✅ 客觀，基於實際數據
- ✅ 適應網路環境
- ✅ 可重複執行

### 方法 2: 基於誤報分析的調優

**適用場景：** 發現大量誤報時

**工具：** `tune_thresholds.py`

**原理：**
- 人工標記異常檢測結果（真實異常 vs 誤報）
- 分析誤報的共同特徵
- 提出閾值調整建議

**優點：**
- ✅ 針對性強
- ✅ 結合人工經驗
- ✅ 快速降低誤報

---

## 🚀 方法 1: 基於統計的自適應閾值

### Step 1: 分析歷史數據分布

```bash
# 分析過去 7 天的數據
python3 calculate_adaptive_thresholds.py --days 7
```

**輸出示例：**
```
======================================================================
📊 基於歷史數據計算自適應閾值
======================================================================

分析期間: 過去 7 天
數據源: netflow_stats_5m

📚 Step 1: 收集歷史聚合數據...
✓ 收集到 1,234,567 筆聚合記錄

🔍 Step 2: 提取特徵值分布...
✓ 提取特徵: flow_count, unique_dsts, avg_bytes, max_bytes, ...

📈 Step 3: 計算統計量和百分位數...

特徵名稱                      最小值       中位數       平均值      95%位      99%位       最大值
----------------------------------------------------------------------------------------------------
flow_count                        1.0        45.0       234.5     1,245.0     3,456.0    125,678.0
unique_dsts                       1.0         8.0        12.3        45.0        89.0        567.0
avg_bytes                       128.0     1,234.0     5,678.0    23,456.0    56,789.0  1,234,567.0
max_bytes                       256.0     5,678.0    23,456.0   123,456.0   345,678.0  9,876,543.0

🎯 Step 4: 計算自適應閾值...

======================================================================
🎯 自適應閾值計算結果
======================================================================

參數                              當前值         建議值      百分位          變化
----------------------------------------------------------------------------------------------------
high_connection                    1,000          1,245        P95      🟢 +24.5%
scanning_dsts                         30             45        P90      🟡 +50.0%
scanning_avg_bytes                10,000          1,234        P50      🔴 -87.7%
small_packet                       1,000          1,234        P25      🟢 +23.4%
large_flow                   104,857,600    123,456,000        P99      🟢 +17.7%
```

### Step 2: 理解結果

**變化標記說明：**
- 🟢 變化 < 20%：輕微調整
- 🟡 變化 20-50%：中等調整
- 🔴 變化 > 50%：顯著調整（需要特別關注）

**常見情況分析：**

| 參數 | 建議值比當前值高 | 建議值比當前值低 |
|------|----------------|----------------|
| `high_connection` | 您的網路流量較高，當前閾值太嚴格 | 您的網路流量較低，當前閾值太寬鬆 |
| `scanning_dsts` | 正常主機連接較多目的地，當前閾值太嚴格 | 掃描行為不常見，當前閾值太寬鬆 |
| `scanning_avg_bytes` | 正常流量較大，當前閾值太嚴格 | 您的網路有很多小流量，適合檢測掃描 |

### Step 3: 應用閾值

#### 3.1 自動應用（推薦）

```bash
# 自動更新配置文件並備份
python3 calculate_adaptive_thresholds.py --days 7 --apply
```

**效果：**
- ✅ 自動備份原配置到 `nad/config.yaml.backup.YYYYMMDD_HHMMSS`
- ✅ 更新 `nad/config.yaml` 的 `thresholds` 部分
- ✅ 顯示每個參數的變化

#### 3.2 手動應用

如果您想先審查再應用：

1. 執行分析（不加 `--apply`）
2. 複製建議的閾值
3. 手動編輯 `nad/config.yaml`：

```yaml
thresholds:
  high_connection: 1245        # 從 1000 調整
  scanning_dsts: 45            # 從 30 調整
  scanning_avg_bytes: 1234     # 從 10000 調整
  small_packet: 1234           # 從 1000 調整
  large_flow: 123456000        # 從 104857600 調整
```

### Step 4: 重新訓練模型

**重要：** 閾值影響二值特徵，必須重新訓練模型！

```bash
python3 train_isolation_forest.py --days 7 --evaluate
```

### Step 5: 驗證效果

```bash
# 運行實時檢測
python3 realtime_detection.py --minutes 30

# 對比調整前後的檢測結果
# 預期：誤報減少，真實異常依然能檢出
```

---

## 🔧 進階用法

### 自定義百分位數

根據您的需求調整敏感度：

```bash
# 更嚴格的閾值（檢出更少異常）
python3 calculate_adaptive_thresholds.py --days 7 \
  --percentile high_connection=98 \
  --percentile scanning_dsts=95

# 更寬鬆的閾值（檢出更多異常）
python3 calculate_adaptive_thresholds.py --days 7 \
  --percentile high_connection=90 \
  --percentile scanning_dsts=85
```

**百分位數選擇指南：**

| 百分位 | 含義 | 適用場景 |
|-------|------|---------|
| P75 (75%) | 寬鬆 | 開發/測試環境，希望檢出更多可疑行為 |
| P90 (90%) | 適中 | 一般生產環境 |
| P95 (95%) | 標準 | 推薦設置，平衡準確性和誤報率 |
| P99 (99%) | 嚴格 | 高流量環境，只關注極端異常 |

### 只調整特定參數

```bash
# 只調整高連線數和掃描相關閾值
python3 calculate_adaptive_thresholds.py --days 7 \
  --params high_connection,scanning_dsts \
  --apply
```

### 使用不同時間範圍

```bash
# 使用 14 天數據（更穩定，但反應較慢）
python3 calculate_adaptive_thresholds.py --days 14

# 使用 3 天數據（更靈敏，但可能不穩定）
python3 calculate_adaptive_thresholds.py --days 3
```

**時間範圍選擇：**
- **7 天（推薦）**：平衡穩定性和時效性
- **14-30 天**：適合流量模式穩定的環境
- **3-5 天**：適合快速變化的環境或初次部署

---

## 🎯 方法 2: 基於誤報分析的調優

### 使用場景

當您發現實時檢測產生很多誤報時，使用此方法：

```bash
# 檢測最近 30 分鐘的數據
python3 realtime_detection.py --minutes 30 > detection_result.txt

# 從結果中提取異常 IP
# 假設檢測到: 192.168.1.100, 192.168.1.101, 192.168.1.102

# 分析這些 IP 是否為真實異常
python3 tune_thresholds.py --ips '192.168.1.100,192.168.1.101,192.168.1.102' --minutes 30
```

### 輸出解讀

```
======================================================================
📊 分析匯總報告
======================================================================

📈 檢測結果統計:
   • 總共分析: 10 個 IP
   • 🚨 真實異常: 2 (20.0%)
   • ⚠️  可疑行為: 3 (30.0%)
   • ✅ 誤報: 5 (50.0%)        ← 誤報率過高！
   • ❓ 無法確定: 0 (0.0%)

======================================================================
🔧 閾值調優建議
======================================================================

📌 參數: thresholds.high_connection
   當前值: 1000
   建議值: 2500                     ← 提高閾值
   原因: 5 個誤報的連線數超過當前閾值
   影響: 5 個 IP

📌 參數: isolation_forest.contamination
   當前值: 0.05
   建議值: 0.030                    ← 降低異常比例
   原因: 誤報率過高 (50.0%)，建議降低異常比例
   影響: 5 個 IP
```

### 應用調優建議

根據分析結果手動調整 `nad/config.yaml`：

```yaml
# 調整閾值
thresholds:
  high_connection: 2500      # 從 1000 提高

# 調整模型參數
isolation_forest:
  contamination: 0.030       # 從 0.05 降低
```

然後重新訓練模型。

---

## 📊 最佳實踐

### 1. 初次部署工作流程

```bash
# Step 1: 使用默認配置訓練基線模型
python3 train_isolation_forest.py --days 7

# Step 2: 運行初次檢測
python3 realtime_detection.py --minutes 60

# Step 3: 基於歷史數據計算自適應閾值
python3 calculate_adaptive_thresholds.py --days 7 --apply

# Step 4: 重新訓練模型
python3 train_isolation_forest.py --days 7

# Step 5: 驗證效果
python3 realtime_detection.py --minutes 60
```

### 2. 定期維護工作流程

**每週一次（自動化）：**

```bash
#!/bin/bash
# weekly_calibration.sh

# 重新計算閾值
python3 calculate_adaptive_thresholds.py --days 7 --apply

# 重新訓練模型
python3 train_isolation_forest.py --days 7

# 發送通知
echo "閾值已更新並重新訓練模型" | mail -s "NAD 維護完成" admin@example.com
```

添加到 crontab：
```bash
# 每週日凌晨 2 點執行
0 2 * * 0 cd /home/kaisermac/snm_flow && bash weekly_calibration.sh
```

### 3. 當誤報率過高時

```bash
# Step 1: 收集最近的異常檢測結果
python3 realtime_detection.py --minutes 60 | tee detection_result.txt

# Step 2: 提取異常 IP（前 20 個）
ANOMALY_IPS=$(grep -oP '\d+\.\d+\.\d+\.\d+' detection_result.txt | head -20 | tr '\n' ',')

# Step 3: 分析誤報模式
python3 tune_thresholds.py --ips "$ANOMALY_IPS" --minutes 60

# Step 4: 根據建議調整配置
# 手動編輯 nad/config.yaml

# Step 5: 重新訓練
python3 train_isolation_forest.py --days 7
```

### 4. 針對不同環境的推薦設置

#### 高流量 Web 服務器環境

```bash
python3 calculate_adaptive_thresholds.py --days 7 \
  --percentile high_connection=98 \
  --percentile large_flow=99 \
  --apply
```

#### 辦公網路環境

```bash
python3 calculate_adaptive_thresholds.py --days 7 \
  --percentile high_connection=90 \
  --percentile scanning_dsts=85 \
  --apply
```

#### 數據中心環境

```bash
python3 calculate_adaptive_thresholds.py --days 14 \
  --percentile high_connection=99 \
  --percentile large_flow=99.5 \
  --apply
```

---

## ⚠️ 注意事項

### 1. 訓練數據質量

**確保歷史數據的代表性：**
- ✅ 包含正常業務流量
- ✅ 包含不同時段（工作時間 vs 非工作時間）
- ✅ 包含工作日和週末
- ❌ 避免只使用異常時期的數據（如攻擊期間）

**檢查數據質量：**
```bash
# 檢查數據覆蓋率
python3 verify_coverage.py --days 7

# 預期覆蓋率 > 95%
```

### 2. 避免過度調整

**問題：** 頻繁調整閾值導致模型不穩定

**建議：**
- 初次部署後觀察 1-2 週再調整
- 定期調整間隔：至少 1 週
- 每次調整後評估效果再繼續

### 3. 閾值變化過大的處理

如果建議值變化超過 100%：

```bash
# 分階段調整（保守策略）
# 第一次：調整 50%
# 例如：當前 1000 → 建議 3000
# 先調整到：1000 + (3000-1000)*0.5 = 2000

# 觀察 3-5 天

# 第二次：繼續調整
# 2000 → 3000
```

### 4. 備份和回滾

**自動備份：**
- `--apply` 自動創建備份（在修改前）
- 位置：`nad/config.yaml.backup.YYYYMMDD_HHMMSS`
- 保留原始配置的完整副本

**管理備份：**
```bash
# 列出所有備份
python3 restore_config_backup.py --list

# 比較備份與當前配置
python3 restore_config_backup.py --compare 1

# 恢復最新備份
python3 restore_config_backup.py --restore latest

# 清理舊備份（保留最近5個）
python3 restore_config_backup.py --clean --keep 5
```

**快速回滾：**
```bash
# 方法 1: 使用恢復工具（推薦）
python3 restore_config_backup.py --restore latest

# 方法 2: 手動複製
cp nad/config.yaml.backup.20251113_140000 nad/config.yaml

# 重新訓練模型
python3 train_isolation_forest.py --days 7
```

**詳細說明：** 參考 `CONFIG_BACKUP_GUIDE.md`

---

## 🔍 故障排除

### 問題 1: 沒有歷史數據

**錯誤：**
```
❌ 沒有找到歷史數據！
```

**解決：**
```bash
# 檢查聚合索引
curl "http://localhost:9200/netflow_stats_5m/_count"

# 檢查 Transform 狀態
curl "http://localhost:9200/_transform/netflow_production/_stats"

# 如果 Transform 未啟動
curl -X POST "http://localhost:9200/_transform/netflow_production/_start"
```

### 問題 2: 計算的閾值異常

**症狀：** 建議的閾值明顯不合理（如 scanning_avg_bytes = 1）

**原因：** 歷史數據包含異常時期

**解決：**
```bash
# 使用更長的時間範圍
python3 calculate_adaptive_thresholds.py --days 14

# 或排除特定時間段
# 手動編輯腳本中的查詢條件
```

### 問題 3: 應用後檢測不到任何異常

**原因：** 閾值設置過於寬鬆

**解決：**
```bash
# 使用更低的百分位數
python3 calculate_adaptive_thresholds.py --days 7 \
  --percentile high_connection=85 \
  --percentile scanning_dsts=80 \
  --apply

# 或調整 contamination
# 編輯 nad/config.yaml
isolation_forest:
  contamination: 0.08  # 從 0.05 提高到 0.08
```

---

## 📈 效果評估

### 評估指標

**1. 誤報率（False Positive Rate）**
```
誤報率 = 誤報數 / 總檢測異常數
目標：< 30%
```

**2. 檢出率（Detection Rate）**
```
檢出率 = 成功檢出的真實異常 / 總真實異常
目標：> 80%
```

**3. 異常數量變化**
```
調整前：每小時 50 個異常（其中 30 個誤報）
調整後：每小時 25 個異常（其中 5 個誤報）

改善：
- 異常數量：-50%
- 誤報率：60% → 20%（-67%）
```

### 持續監控

```bash
# 每天檢測並記錄
python3 realtime_detection.py --minutes 60 >> logs/daily_detection.log

# 每週分析趨勢
grep "發現.*個異常" logs/daily_detection.log | tail -7
```

---

## 📚 相關文檔

- **使用指南：** `ISOLATION_FOREST_GUIDE.md`
- **原理說明：** `AI_ANOMALY_DETECTION_OPTIMIZED.md`
- **誤報分析工具：** `tune_thresholds.py`

---

## 🤝 總結

### 關鍵要點

1. **自適應閾值是必要的** - 默認閾值無法適應所有環境
2. **定期校準** - 網路流量模式會隨時間變化
3. **數據驅動** - 基於統計方法比人工猜測更可靠
4. **逐步調整** - 避免一次性大幅修改
5. **持續評估** - 監控效果並迭代改進

### 推薦工作流程

```
初次部署 → 運行 7 天 → 計算自適應閾值 → 重新訓練 →
→ 驗證效果 → 定期維護（每週/每月）→ 根據需要微調
```

---

**版本：** 1.0
**更新日期：** 2025-11-13
**適用系統：** Isolation Forest 異常檢測系統
