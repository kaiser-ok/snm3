# 7 天資料回填狀態報告

## 📋 執行資訊

**開始時間：** 2025-11-13 04:07:00
**命令：** `python3 backfill_historical_data.py --execute --auto-confirm --days 7 --batch-hours 1`
**模式：** 背景執行（nohup）

---

## 📊 回填配置

- **回填天數：** 7 天
- **批次大小：** 1 小時/批
- **總批次數：** 168 批（7天 × 24小時）
- **包含欄位：** `unique_src_ports`, `unique_dst_ports`（新增）

---

## ⏰ 時間範圍

- **最早：** 2025-11-06 04:05:00
- **最新：** 2025-11-13 04:05:00
- **時間跨度：** 168.0 小時（7.0 天）✅

---

## 📈 即時進度監控

### 監控命令

```bash
# 查看即時進度
./monitor_backfill.sh

# 或手動檢查
watch -n 60 './monitor_backfill.sh'

# 檢查進程
ps aux | grep "backfill.*days 7" | grep -v grep

# 檢查資料量
curl -s "http://localhost:9200/netflow_stats_5m/_count?q=unique_src_ports:*" | \
  python3 -c "import sys,json;print(f\"有新欄位: {json.load(sys.stdin)['count']:,} 筆\")"
```

### 當前進度（最後更新：04:14）

| 指標 | 數值 |
|------|------|
| **已回填記錄** | 625,706 筆 |
| **覆蓋率** | 39.50% |
| **預估進度** | 46.3% |
| **執行時間** | 20 分鐘 |
| **速度** | ~67,620 筆/分鐘 |
| **預估剩餘時間** | 10-15 分鐘 |

---

## 🎯 完成標準

回填完成的判斷標準：

1. ✅ **時間範圍完整：** 已達成（7.0 天）
2. ⏳ **資料量充足：** 進行中（目標 ~1,350,000 筆）
3. ⏳ **進程結束：** 等待中

**預計完成時間：** 04:20 - 04:25

---

## ✅ 完成後的下一步

### 1. 驗證回填結果

```bash
# 檢查最終資料量
curl -s "http://localhost:9200/netflow_stats_5m/_count?q=unique_src_ports:*"

# 檢查時間範圍
curl -s "http://localhost:9200/netflow_stats_5m/_search" -H 'Content-Type: application/json' -d '{
  "size":0,
  "query":{"exists":{"field":"unique_src_ports"}},
  "aggs":{
    "min_time":{"min":{"field":"time_bucket"}},
    "max_time":{"max":{"field":"time_bucket"}}
  }
}' | python3 -m json.tool

# 檢查進程是否已結束
ps aux | grep backfill | grep -v grep
```

### 2. 重新訓練模型（使用 7 天資料）

```bash
# 使用 7 天資料訓練（推薦）
python3 train_isolation_forest.py --days 7 --evaluate --exclude-servers

# 訓練後模型將更穩定、更準確
```

### 3. 驗證改進效果

```bash
# 測試檢測
python3 realtime_detection.py --minutes 30 --exclude-servers

# 驗證 AD 伺服器不再誤報
python3 verify_anomaly.py --ip 192.168.10.135 --minutes 30

# 確認 8.8.8.8 也不會誤報
python3 verify_anomaly.py --ip 8.8.8.8 --minutes 30
```

---

## 📝 日誌位置

- **回填日誌：** `backfill_7days.log`
- **訓練日誌：** `train_with_new_features.log`
- **監控腳本：** `monitor_backfill.sh`

---

## ⚠️ 注意事項

1. **不要停止進程**：回填過程中請勿停止 Python 進程
2. **ES 負載**：回填期間 Elasticsearch 負載會略微增加（正常）
3. **磁碟空間**：確保有足夠空間存儲新資料
4. **重複寫入**：回填使用 `time_bucket + src_ip` 作為文檔 ID，會覆蓋舊資料（正常行為）

---

## 🔧 故障排除

### 如果進程意外停止

```bash
# 檢查日誌
tail -100 backfill_7days.log

# 確認已回填的資料
./monitor_backfill.sh

# 重新執行（自動跳過已存在的資料）
nohup python3 backfill_historical_data.py --execute --auto-confirm --days 7 --batch-hours 1 > backfill_7days_retry.log 2>&1 &
```

### 如果資料量異常

```bash
# 檢查 ES 健康狀態
curl http://localhost:9200/_cluster/health?pretty

# 檢查索引狀態
curl "http://localhost:9200/netflow_stats_5m/_stats?pretty"

# 檢查 Transform 狀態
curl "http://localhost:9200/_transform/netflow_production/_stats?pretty"
```

---

## 📚 相關文檔

- **Transform 改進報告：** `TRANSFORM_PORT_IMPROVEMENT.md`
- **使用指南：** `ISOLATION_FOREST_GUIDE.md`
- **異常驗證指南：** `ANOMALY_VERIFICATION_GUIDE.md`
- **術語對照表：** `TERMINOLOGY.md`

---

**建立時間：** 2025-11-13 04:15:00
**狀態：** ⏳ 進行中（46.3%）
