# 資料不足時的訓練策略

## 📊 當前數據狀況

**實測數據：**
- 總文檔數：63,561 筆
- 時間跨度：6.6 小時（0.3 天）
- 最早：2025-11-11 14:15
- 最新：2025-11-11 20:50

**結論：** 數據量較少，但**可以訓練**！

---

## ✅ 解決方案

### 方案 1：使用現有數據訓練（推薦）

即使只有 6-12 小時的數據，Isolation Forest 仍然可以訓練：

```bash
# 使用所有可用數據
python3 train_isolation_forest.py --days 1 --evaluate
```

**優勢：**
- 立即可用
- 6.6 小時 ≈ 63,561 筆，足夠 Isolation Forest
- 可檢測明顯異常模式

**限制：**
- 基準線可能不夠完整
- 對正常行為的理解有限
- 建議後續重訓練

### 方案 2：降低最小樣本要求

修改配置以適應小數據集：

```yaml
# nad/config.yaml

isolation_forest:
  contamination: 0.10          # 提高到 10%（對小數據集更寬容）
  n_estimators: 100            # 減少樹的數量（從 150 降到 100）
  max_samples: 256             # 減少樣本數（從 512 降到 256）

training:
  min_samples: 100             # 降低最小樣本要求（從 1000 降到 100）
```

然後訓練：
```bash
python3 train_isolation_forest.py --days 1
```

### 方案 3：等待更多數據（最佳）

**建議等待時間：**
- **最少：** 24 小時（1天）
- **推薦：** 72 小時（3天）
- **理想：** 168 小時（7天）

**為什麼需要更多數據？**
1. 捕獲正常的日夜周期模式
2. 包含工作日和非工作日
3. 建立完整的基準線
4. 減少誤報率

**等待期間的替代方案：**
```bash
# 使用 analyze_from_aggregated.py（基於規則的檢測）
python3 analyze_from_aggregated.py
```

---

## 🚀 立即訓練指南

### Step 1: 修改配置（可選）

創建一個小數據集配置：

```bash
cp nad/config.yaml nad/config_small.yaml
```

編輯 `nad/config_small.yaml`：

```yaml
isolation_forest:
  contamination: 0.10        # 提高異常比例預期
  n_estimators: 100          # 減少樹的數量
  max_samples: 256           # 減少採樣數
  random_state: 42
  n_jobs: -1

training:
  baseline_days: 1           # 只用1天
  min_samples: 100           # 降低最小樣本
```

### Step 2: 使用小數據集訓練

```bash
# 選項 A: 使用默認配置
python3 train_isolation_forest.py --days 1 --evaluate

# 選項 B: 使用小數據集配置
python3 train_isolation_forest.py --days 1 --config nad/config_small.yaml --evaluate
```

**預期輸出：**
```
======================================================================
Isolation Forest 訓練 - 使用過去 1 天的聚合數據
======================================================================

📚 Step 1: 收集過去 1 天的聚合數據...
✓ 收集到 63,561 筆聚合記錄

🔧 Step 2: 提取特徵...
✓ 提取特徵矩陣: (63561, 17)

📊 Step 3: 標準化特徵...
✓ 特徵已標準化

🏋️  Step 4: 訓練 Isolation Forest...
✓ 訓練完成

📈 Step 5: 評估訓練結果...
  訓練集異常比例: 10.XX%
  異常樣本數: 6,356 / 63,561

💾 Step 6: 保存模型...
✓ 模型已保存
```

### Step 3: 測試檢測

```bash
# 檢測最近10分鐘
python3 realtime_detection.py --minutes 10
```

---

## 📊 數據量需求分析

### Isolation Forest 的最小需求

| 數據量 | 樣本數 | 訓練可行性 | 效果 |
|-------|-------|----------|------|
| 1 小時 | ~10,000 | ⚠️ 勉強可用 | 僅能檢測極端異常 |
| 6 小時 | ~63,000 | ✅ 可用 | 可檢測明顯異常 |
| 24 小時 | ~250,000 | ✅ 良好 | 包含日夜周期 |
| 3 天 | ~750,000 | ✅ 推薦 | 模式較完整 |
| 7 天 | ~1,750,000 | ✅ 理想 | 包含週末模式 |

**當前狀態：** 63,561 筆 → ✅ 可用

### 為什麼 63K 樣本就足夠？

Isolation Forest 的優勢：
1. **無監督學習** - 不需要標記數據
2. **隨機採樣** - 每棵樹只用 256-512 樣本
3. **異常檢測** - 關注離群點，而非整體分布

**實際需求：**
- 最少：~10,000 樣本
- 推薦：~50,000+ 樣本
- 當前：63,561 樣本 ✅

---

## ⚠️ 小數據集訓練的注意事項

### 1. 可能的問題

**基準線不完整：**
- 只有半天的數據，缺乏夜間模式
- 可能誤報夜間正常活動為異常

**解決：**
```bash
# 定期重訓練（當數據累積後）
# 例如：每天凌晨重訓練
0 2 * * * cd /path && python3 train_isolation_forest.py --days 7
```

**異常比例偏高：**
- 小數據集中異常可能被稀釋

**解決：**
```yaml
# 調整 contamination
contamination: 0.10  # 從 0.05 提高到 0.10
```

### 2. 驗證模型效果

訓練後立即測試：

```bash
# 檢測最近數據
python3 realtime_detection.py --minutes 30

# 檢查是否能檢測到已知異常
# 例如：之前發現的 192.168.10.135（AD Server 掃描）
```

如果檢測結果合理（能找到明顯異常），則模型可用。

### 3. 漸進式改進策略

**Week 1（當前）：**
- 使用 6-12 小時數據訓練
- 檢測極端異常
- 收集更多數據

**Week 2：**
- 使用 3-7 天數據重訓練
- 更新基準線
- 降低誤報率

**Month 1+：**
- 使用 30 天數據
- 建立完整基準
- 生產環境部署

---

## 🎯 實戰演練

### 立即訓練並測試

```bash
# 1. 使用現有數據訓練
python3 train_isolation_forest.py --days 1 --evaluate

# 2. 測試檢測效果
python3 realtime_detection.py --minutes 30

# 3. 查看結果是否合理
# 應該能檢測到：
#   - 高連線數的 IP
#   - 掃描行為
#   - 異常流量模式
```

### 預期結果

如果能檢測到以下異常之一，說明模型可用：
- ✅ 連線數 > 10,000 的 IP
- ✅ 目的地 > 50 的 IP（掃描）
- ✅ 流量 > 1GB 的 IP

### 如果效果不佳

**方案 A：調整參數**
```yaml
contamination: 0.15  # 進一步提高
```

**方案 B：使用規則檢測**
```bash
# 暫時使用規則引擎
python3 analyze_from_aggregated.py
```

**方案 C：等待更多數據**
```bash
# 24小時後重試
sleep 18h && python3 train_isolation_forest.py --days 1
```

---

## 📅 數據累積計劃

### 當前狀態（6.6 小時）

Transform 持續運行，數據持續累積：

```bash
# 檢查當前數據量
curl -s "http://localhost:9200/netflow_stats_5m/_count"

# 檢查時間範圍
curl -s "http://localhost:9200/netflow_stats_5m/_search?size=0" \
  -H 'Content-Type: application/json' -d'{
    "aggs": {
      "time_range": {"stats": {"field": "time_bucket"}}
    }
  }'
```

### 累積預測

| 時間 | 預期文檔數 | 建議操作 |
|------|-----------|---------|
| 當前（6.6h） | 63,561 | 可訓練（小數據集配置） |
| +6 小時 | ~126,000 | 重訓練（12小時數據） |
| +18 小時 | ~250,000 | 重訓練（24小時數據）✅ |
| +3 天 | ~750,000 | 重訓練（完整配置） |
| +7 天 | ~1,750,000 | 理想狀態 |

### 自動化重訓練

創建定時任務：

```bash
# 每天凌晨2點重訓練
crontab -e

# 添加：
0 2 * * * cd /home/kaisermac/snm_flow && python3 train_isolation_forest.py --days 3 > logs/train_$(date +\%Y\%m\%d).log 2>&1
```

---

## 💡 最佳建議

### 當前（數據 < 1天）

✅ **立即可做：**
```bash
# 1. 使用現有數據訓練（體驗系統）
python3 train_isolation_forest.py --days 1 --evaluate

# 2. 測試檢測功能
python3 realtime_detection.py --minutes 30

# 3. 繼續使用規則檢測（主力）
python3 analyze_from_aggregated.py
```

⏰ **建議等待：**
- 等待 24 小時後再重訓練
- 將有 ~250K 樣本，效果更好

### 明天（數據 = 1天）

✅ **推薦操作：**
```bash
# 使用完整24小時數據重訓練
python3 train_isolation_forest.py --days 1 --evaluate

# 啟動持續監控
python3 realtime_detection.py --continuous --interval 5
```

### 下週（數據 = 7天）

✅ **理想狀態：**
```bash
# 使用7天數據訓練（標準配置）
python3 train_isolation_forest.py --days 7 --evaluate

# 生產環境部署
```

---

## 🎓 總結

### 問題：資料不足能否訓練？

**答案：✅ 可以！**

- 當前 63,561 筆已足夠 Isolation Forest
- 建議使用 `--days 1` 訓練
- 效果會比理想狀態差，但可檢測明顯異常
- 隨著數據累積定期重訓練即可

### 立即行動

```bash
# 3 分鐘快速開始
python3 train_isolation_forest.py --days 1 --evaluate
python3 realtime_detection.py --minutes 10

# 如果效果可接受，繼續使用
# 如果效果不佳，等待更多數據
```

---

**更新：** 2025-11-11 21:00
**數據狀況：** 6.6 小時（可訓練）
**建議：** 立即嘗試 + 24小時後重訓練
