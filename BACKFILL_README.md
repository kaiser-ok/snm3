# NetFlow 歷史資料回填指南

## 🎯 目的

將過去 N 天的 NetFlow 原始資料聚合並寫入 `netflow_stats_5m` 索引，加速後續模型訓練。

---

## 🚀 快速開始

### 1️⃣ 測試模式（先確認會產生多少資料）

```bash
python3 backfill_historical_data.py --days 3
```

### 2️⃣ 正式執行（背景執行，可登出）

```bash
# 回填過去 3 天
./run_backfill.sh --execute --days 3

# 回填過去 7 天，每批處理 2 小時
./run_backfill.sh --execute --days 7 --batch-hours 2
```

### 3️⃣ 檢查執行狀態

```bash
# 查看狀態摘要
./check_backfill_status.sh

# 即時監控進度（找到最新日誌檔）
tail -f backfill_*.log
```

---

## 📋 詳細使用方式

### 選項 1: 直接執行（需保持終端連線）

```bash
# 測試模式
python3 backfill_historical_data.py --days 3

# 正式執行
python3 backfill_historical_data.py --execute --days 3
```

### 選項 2: 背景執行（推薦，可登出）

```bash
# 使用預設參數（3天，每批2小時）
./run_backfill.sh --execute --days 3

# 自訂參數
./run_backfill.sh --execute --days 7 --batch-hours 1
```

---

## 📊 監控執行狀態

### 方法 1: 使用狀態檢查腳本

```bash
./check_backfill_status.sh
```

### 方法 2: 手動查看日誌

```bash
# 列出所有日誌檔
ls -lth backfill_*.log

# 即時監控最新日誌
tail -f backfill_20251112_*.log

# 查看最後 50 行
tail -50 backfill_20251112_*.log

# 搜尋執行摘要
grep -A 10 "執行總結" backfill_20251112_*.log
```

### 方法 3: 檢查程序是否還在執行

```bash
# 查看 PID
cat backfill.pid

# 檢查程序狀態
ps -p $(cat backfill.pid)

# 詳細資訊
ps aux | grep backfill_historical_data
```

---

## ⏹️ 停止執行

```bash
# 優雅停止
kill $(cat backfill.pid)

# 強制停止（如必要）
kill -9 $(cat backfill.pid)

# 清理 PID 檔案
rm -f backfill.pid
```

---

## 📈 預期結果

### 資料量預估

| 天數 | 時間桶數 | 預估文檔數 | 執行時間 |
|------|---------|-----------|---------|
| 1 天 | ~288    | ~192,000  | 3-5 分鐘 |
| 3 天 | ~864    | ~576,000  | 10-15 分鐘 |
| 7 天 | ~2,016  | ~1,344,000| 20-30 分鐘 |

*實際數字取決於網路流量*

### 執行完成後

```bash
# 驗證覆蓋率
python3 verify_coverage.py

# 檢查索引中的資料範圍
python3 backfill_historical_data.py --check 7

# 查看總文檔數
curl -s "http://localhost:9200/netflow_stats_5m/_count" | python3 -m json.tool
```

---

## 🔧 進階選項

### 檢查現有資料

```bash
# 檢查過去 7 天的資料
python3 backfill_historical_data.py --check 7
```

### 自訂批次大小

```bash
# 每批處理 1 小時（適合資料量大的情況）
python3 backfill_historical_data.py --execute --days 3 --batch-hours 1

# 每批處理 6 小時（適合資料量小的情況）
python3 backfill_historical_data.py --execute --days 3 --batch-hours 6
```

### 只回填特定時間範圍

如需更精確的時間控制，需修改腳本中的時間計算邏輯。

---

## ⚠️ 注意事項

### 執行前

1. **確認 ES 有足夠空間**
   ```bash
   curl -s "http://localhost:9200/_cat/allocation?v"
   ```

2. **先執行測試模式**（不加 `--execute`）
   ```bash
   python3 backfill_historical_data.py --days 3
   ```

3. **確認時間範圍正確**
   - 腳本會處理「過去 N 天」的資料
   - 不會處理未來時間

### 執行中

1. **不會重複寫入**
   - 使用 `time_bucket + src_ip` 作為文檔 ID
   - 重新執行會自動跳過已存在的文檔

2. **可安全中斷**
   - 已寫入的資料不會遺失
   - 可從中斷處重新執行

3. **ES 負載**
   - 批次處理避免過載
   - 每 5 批暫停 5 秒

### 執行後

1. **驗證資料**
   ```bash
   python3 verify_coverage.py
   ```

2. **檢查錯誤**
   ```bash
   grep "錯誤" backfill_*.log
   grep "失敗" backfill_*.log
   ```

---

## 🐛 疑難排解

### 問題 1: 無法連接 ES

```bash
# 檢查 ES 是否運行
curl -s "http://localhost:9200"

# 檢查網路連線
ping localhost
```

### 問題 2: 查詢超時

```bash
# 減小批次大小
./run_backfill.sh --execute --days 3 --batch-hours 1
```

### 問題 3: 記憶體不足

```bash
# 檢查 ES 記憶體使用
curl -s "http://localhost:9200/_cat/nodes?v&h=heap.percent,ram.percent"

# 減小批次大小
./run_backfill.sh --execute --days 3 --batch-hours 1
```

### 問題 4: 找不到原始資料

```bash
# 確認原始索引存在
curl -s "http://localhost:9200/_cat/indices/radar_flow_collector-*?v"

# 確認資料時間範圍
curl -s "http://localhost:9200/radar_flow_collector-*/_search?size=0" -H 'Content-Type: application/json' -d '{
  "aggs": {
    "time_range": {
      "stats": {"field": "FLOW_START_MILLISECONDS"}
    }
  }
}' | python3 -m json.tool
```

---

## 📚 相關腳本

| 腳本 | 功能 | 用法 |
|------|------|------|
| `backfill_historical_data.py` | 主要回填腳本 | `python3 backfill_historical_data.py --execute --days 3` |
| `run_backfill.sh` | 背景執行包裝器 | `./run_backfill.sh --execute --days 3` |
| `check_backfill_status.sh` | 狀態檢查工具 | `./check_backfill_status.sh` |
| `verify_coverage.py` | 資料覆蓋率驗證 | `python3 verify_coverage.py` |

---

## ✅ 完整執行範例

```bash
# Step 1: 先測試
python3 backfill_historical_data.py --days 3

# Step 2: 確認無誤後，背景執行
./run_backfill.sh --execute --days 3

# Step 3: 離開終端（程序會繼續執行）
exit

# --- 稍後重新登入 ---

# Step 4: 檢查狀態
./check_backfill_status.sh

# Step 5: 驗證結果
python3 verify_coverage.py
python3 backfill_historical_data.py --check 7

# Step 6: 開始訓練模型
python3 train_isolation_forest.py
```

---

## 📞 需要幫助？

1. 查看日誌檔：`tail -100 backfill_*.log`
2. 檢查錯誤：`grep -i error backfill_*.log`
3. 查看腳本說明：`python3 backfill_historical_data.py --help`
