# 快速參考卡片

## 🚀 常用命令速查

### 自適應閾值調整

```bash
# 1. 分析並應用新閾值（自動備份）
python3 calculate_adaptive_thresholds.py --days 7 --apply

# 2. 只分析不應用
python3 calculate_adaptive_thresholds.py --days 7

# 3. 自定義百分位數（更嚴格）
python3 calculate_adaptive_thresholds.py --days 7 \
  --percentile high_connection=98 \
  --percentile scanning_dsts=95 \
  --apply
```

### 備份管理

```bash
# 列出所有備份
python3 restore_config_backup.py --list

# 比較備份與當前配置
python3 restore_config_backup.py --compare 1

# 恢復最新備份
python3 restore_config_backup.py --restore latest

# 恢復特定備份
python3 restore_config_backup.py --restore 2

# 清理舊備份（保留最近5個）
python3 restore_config_backup.py --clean --keep 5
```

### 模型訓練

```bash
# 訓練模型（7天數據）
python3 train_isolation_forest.py --days 7

# 訓練並評估
python3 train_isolation_forest.py --days 7 --evaluate
```

### 實時檢測

```bash
# 單次檢測（最近10分鐘）
python3 realtime_detection.py --minutes 10

# 持續監控（每5分鐘檢測一次）
python3 realtime_detection.py --continuous --interval 5 --minutes 10
```

### 誤報分析

```bash
# 分析特定IP
python3 tune_thresholds.py --ips '192.168.1.100,192.168.1.101' --minutes 30

# 從文件讀取IP列表
python3 tune_thresholds.py --file anomaly_ips.txt --minutes 30
```

---

## 📋 完整工作流程

### 初次部署

```bash
# 1. 使用默認配置訓練
python3 train_isolation_forest.py --days 7

# 2. 計算自適應閾值並應用
python3 calculate_adaptive_thresholds.py --days 7 --apply

# 3. 重新訓練
python3 train_isolation_forest.py --days 7

# 4. 驗證效果
python3 realtime_detection.py --minutes 60
```

### 週期性維護

```bash
# 1. 更新閾值（自動備份）
python3 calculate_adaptive_thresholds.py --days 7 --apply

# 2. 重新訓練
python3 train_isolation_forest.py --days 7

# 3. 清理舊備份
python3 restore_config_backup.py --clean --keep 5
```

### 測試新閾值

```bash
# 1. 應用新閾值（自動備份）
python3 calculate_adaptive_thresholds.py --days 7 --apply

# 2. 重新訓練
python3 train_isolation_forest.py --days 7

# 3. 測試
python3 realtime_detection.py --minutes 30

# 4a. 如果不滿意，回滾
python3 restore_config_backup.py --restore latest
python3 train_isolation_forest.py --days 7

# 4b. 如果滿意，保留配置
# 無需操作
```

### 處理誤報

```bash
# 1. 檢測並記錄結果
python3 realtime_detection.py --minutes 60 > detection_result.txt

# 2. 提取異常IP
ANOMALY_IPS=$(grep -oP '\d+\.\d+\.\d+\.\d+' detection_result.txt | head -20 | tr '\n' ',')

# 3. 分析誤報
python3 tune_thresholds.py --ips "$ANOMALY_IPS" --minutes 60

# 4. 根據建議調整配置（手動編輯 nad/config.yaml）

# 5. 重新訓練
python3 train_isolation_forest.py --days 7
```

---

## ⚙️ 配置文件位置

- **主配置**: `nad/config.yaml`
- **備份**: `nad/config.yaml.backup.YYYYMMDD_HHMMSS`
- **模型**: `nad/models/isolation_forest.pkl`
- **日誌**: `logs/nad.log`

---

## 🔍 檢查系統狀態

```bash
# 檢查 Elasticsearch
curl http://localhost:9200

# 檢查聚合索引數據量
curl "http://localhost:9200/netflow_stats_5m/_count"

# 檢查 Transform 狀態
curl "http://localhost:9200/_transform/netflow_production/_stats"

# 檢查模型是否存在
ls -lh nad/models/isolation_forest.pkl

# 查看最近日誌
tail -f logs/nad.log
```

---

## 📊 重要閾值參數

| 參數 | 含義 | 默認值 | 調整方向 |
|-----|------|--------|---------|
| `high_connection` | 高連線數閾值 | 1000 | 根據 P95 調整 |
| `scanning_dsts` | 掃描目的地數 | 30 | 根據 P90 調整 |
| `scanning_avg_bytes` | 掃描平均流量 | 10000 | 根據 P50 調整 |
| `small_packet` | 小封包閾值 | 1000 | 根據 P25 調整 |
| `large_flow` | 大流量閾值 | 104857600 | 根據 P99 調整 |

---

## 🎯 百分位數選擇指南

| 環境類型 | high_connection | scanning_dsts | 備註 |
|---------|----------------|---------------|------|
| 辦公網路 | P90 | P85 | 流量較低，寬鬆設置 |
| 標準環境 | P95 | P90 | 推薦設置 |
| Web服務器 | P98 | P95 | 高流量，嚴格設置 |
| 數據中心 | P99 | P97 | 超高流量 |

---

## 🆘 緊急故障處理

### Elasticsearch 連接失敗
```bash
# 檢查服務
sudo systemctl status elasticsearch

# 重啟服務
sudo systemctl restart elasticsearch
```

### 模型文件不存在
```bash
# 重新訓練
python3 train_isolation_forest.py --days 7
```

### 配置文件損壞
```bash
# 恢復最新備份
python3 restore_config_backup.py --restore latest
```

### 檢測不到任何異常
```bash
# 1. 檢查閾值是否過於寬鬆
cat nad/config.yaml | grep -A 10 thresholds

# 2. 降低百分位數重新計算
python3 calculate_adaptive_thresholds.py --days 7 \
  --percentile high_connection=85 \
  --percentile scanning_dsts=80 \
  --apply

# 3. 或提高 contamination
# 編輯 nad/config.yaml
# isolation_forest:
#   contamination: 0.08  # 從 0.05 提高
```

---

## 📚 文檔索引

- **主指南**: `ISOLATION_FOREST_GUIDE.md`
- **自適應閾值**: `ADAPTIVE_THRESHOLDS_GUIDE.md`
- **備份管理**: `CONFIG_BACKUP_GUIDE.md`
- **快速參考**: `QUICK_REFERENCE.md` (本文件)

---

## 💡 小貼士

1. **修改配置後必須重新訓練模型**
2. **使用 `--apply` 自動創建備份**
3. **定期清理舊備份節省空間**
4. **測試新配置前先比較差異**
5. **每週運行一次自適應閾值計算**

---

**快速搜索關鍵字:**
- 訓練: `train_isolation_forest.py`
- 檢測: `realtime_detection.py`
- 閾值: `calculate_adaptive_thresholds.py`
- 備份: `restore_config_backup.py`
- 誤報: `tune_thresholds.py`
