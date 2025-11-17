# Isolation Forest 異常檢測系統 - 使用指南

## 📦 系統概述

基於 netflow_stats_5m 聚合數據的無監督異常檢測系統。

**核心優勢：**
- ✅ 99.57% 數據覆蓋率
- ✅ 訓練速度快（5-10分鐘）
- ✅ 推論延遲低（< 5秒）
- ✅ 自動化特徵工程
- ✅ 無需標記數據

---

## 🏗️ 項目結構

```
snm_flow/
├── nad/                          # 主模組
│   ├── config.yaml              # 配置文件
│   ├── ml/                      # ML 模組
│   │   ├── feature_engineer.py          # 特徵工程
│   │   └── isolation_forest_detector.py # Isolation Forest
│   ├── utils/                   # 工具模組
│   │   └── config_loader.py     # 配置加載
│   └── models/                  # 訓練好的模型（自動創建）
│
├── train_isolation_forest.py   # 訓練腳本
├── realtime_detection.py        # 實時檢測腳本
└── test_isolation_forest.py     # 測試腳本
```

---

## 📋 前置需求

### 1. Python 依賴

```bash
# 安裝依賴包
pip3 install scikit-learn elasticsearch pyyaml numpy

# 或使用 apt（Ubuntu/Debian）
sudo apt install python3-sklearn python3-elasticsearch python3-yaml python3-numpy
```

### 2. Elasticsearch 數據

確保以下條件：
- Elasticsearch 運行在 localhost:9200
- `netflow_stats_5m` 索引有數據
- Transform 覆蓋率 > 95%（已驗證為 99.57%）

**驗證數據：**
```bash
# 檢查聚合索引
curl -s "http://localhost:9200/netflow_stats_5m/_count" | python3 -m json.tool

# 查看最近數據
curl -s "http://localhost:9200/netflow_stats_5m/_search?size=1&sort=time_bucket:desc" | python3 -m json.tool
```

---

## 🚀 快速開始

### Step 1: 配置檢查

檢查 `nad/config.yaml` 配置：

```yaml
elasticsearch:
  host: "http://localhost:9200"  # ES 地址
  indices:
    aggregated: "netflow_stats_5m"  # 聚合索引

isolation_forest:
  contamination: 0.05              # 預期異常比例 5%
  n_estimators: 150                # 樹的數量
```

### Step 2: 訓練模型

使用過去 7 天的數據訓練模型：

```bash
python3 train_isolation_forest.py --days 7 --evaluate
```

**預期輸出：**
```
======================================================================
Isolation Forest 訓練 - 使用過去 7 天的聚合數據
======================================================================

📚 Step 1: 收集過去 7 天的聚合數據...
✓ 收集到 XXX,XXX 筆聚合記錄

🔧 Step 2: 提取特徵...
✓ 提取特徵矩陣: (XXX, 17)

📊 Step 3: 標準化特徵...
✓ 特徵已標準化

🏋️  Step 4: 訓練 Isolation Forest...
✓ 訓練完成

📈 Step 5: 評估訓練結果...
  訓練集異常比例: 5.XX%

💾 Step 6: 保存模型...
✓ 模型已保存到: nad/models/isolation_forest.pkl

======================================================================
✅ 訓練完成！
======================================================================
```

**訓練時間：** 5-10 分鐘（取決於數據量）

### Step 3: 實時檢測

#### 3.1 單次檢測

分析最近 10 分鐘的數據：

```bash
python3 realtime_detection.py --minutes 10
```

**預期輸出：**
```
======================================================================
實時異常檢測 - 分析最近 10 分鐘
======================================================================

⏱️  檢測耗時: 3.45 秒

⚠️  發現 14 個異常

===================================================================================================
排名   IP地址           異常分數     置信度      連線數      目的地    平均流量
===================================================================================================
1      192.168.10.135   0.6234      0.89       510,823    107       4,567
2      192.168.20.56    0.5891      0.82       394,143    8         342
...
```

#### 3.2 持續監控

每 5 分鐘自動檢測一次：

```bash
python3 realtime_detection.py --continuous --interval 5 --minutes 10
```

**輸出示例：**
```
======================================================================
持續監控模式
======================================================================
檢測間隔: 每 5 分鐘
分析窗口: 最近 10 分鐘
按 Ctrl+C 停止

======================================================================

🔍 檢測 #1 - 2025-11-11 20:45:00
----------------------------------------------------------------------------------------------------

⚠️  發現 3 個高置信度異常:

   1. 192.168.10.135 | 分數: 0.6234 | 置信度: 0.89 | 510,823 連線 | 107 目的地
   2. 192.168.20.56  | 分數: 0.5891 | 置信度: 0.82 | 394,143 連線 |   8 目的地
   3. 192.168.15.42  | 分數: 0.5123 | 置信度: 0.76 |  12,456 連線 |  65 目的地

⏰ 下次檢測: 5 分鐘後...
```

---

## 🔧 進階配置

### 調整異常檢測靈敏度

編輯 `nad/config.yaml`：

```yaml
isolation_forest:
  contamination: 0.05   # 預期異常比例
  # 0.01 = 1%（更嚴格，誤報少）
  # 0.10 = 10%（更寬鬆，檢出更多）
```

### 調整特徵閾值

```yaml
thresholds:
  high_connection: 1000      # 高連線數閾值
  scanning_dsts: 30          # 掃描目的地數
  scanning_avg_bytes: 10000  # 掃描平均流量
```

### 調整訓練參數

```yaml
isolation_forest:
  n_estimators: 150   # 樹的數量（越多越準確但越慢）
  max_samples: 512    # 每棵樹的樣本數
```

---

## 📊 特徵說明

系統自動提取 17 個特徵：

### 基礎特徵（7個）
直接從聚合數據獲取：

- `flow_count` - 連線數
- `total_bytes` - 總流量
- `total_packets` - 總封包數
- `unique_dsts` - 唯一目的地數
- `unique_ports` - 不同通訊埠數
- `avg_bytes` - 平均流量
- `max_bytes` - 最大單一連線流量

### 衍生特徵（4個）
計算得出：

- `dst_diversity` - 目的地多樣性（unique_dsts / flow_count）
- `port_diversity` - 通訊埠分散度（unique_ports / flow_count）
- `traffic_concentration` - 流量集中度（max_bytes / total_bytes）
- `bytes_per_packet` - 每封包流量（total_bytes / total_packets）

### 二值特徵（4個）
行為標記：

- `is_high_connection` - 是否高連線數
- `is_scanning_pattern` - 是否掃描模式
- `is_small_packet` - 是否小封包
- `is_large_flow` - 是否大流量

### 對數特徵（2個）
處理偏態分布：

- `log_flow_count` - log(flow_count + 1)
- `log_total_bytes` - log(total_bytes + 1)

---

## 📈 性能基準

基於實測數據（聚合索引 99.57% 覆蓋率）：

| 操作 | 數據量 | 耗時 |
|------|-------|------|
| **訓練（7天數據）** | ~100萬筆聚合記錄 | 5-10 分鐘 |
| **特徵提取** | 1萬筆 | < 0.1 秒 |
| **模型推論** | 1千筆 | < 1 秒 |
| **實時檢測（10分鐘）** | ~100-500筆 | < 5 秒 |

**對比原始數據：**
- 查詢速度：100x 提升
- 特徵提取：200-400x 提升
- 總體性能：50-100x 提升

---

## 🔍 異常解讀

### 異常分數（Anomaly Score）

- **範圍：** 0.0 - 1.0
- **含義：** 越高越異常
- **閾值建議：**
  - > 0.7：高度異常，需立即調查
  - 0.5-0.7：可疑，建議關注
  - < 0.5：輕微異常

### 置信度（Confidence）

- **範圍：** 0.0 - 1.0
- **含義：** 模型對預測的信心
- **建議：**
  - > 0.8：高信心，誤報機率低
  - 0.6-0.8：中等信心
  - < 0.6：低信心，可能誤報

### 常見異常模式

**1. 通訊埠/網路掃描**
```
特徵：
- unique_dsts: > 100
- avg_bytes: < 10,000
- flow_count: > 1,000
- is_scanning_pattern: 1
```

**2. DNS 濫用**
```
特徵：
- flow_count: > 10,000
- avg_bytes: < 500
- unique_dsts: < 10
```

**3. 數據外洩**
```
特徵：
- total_bytes: > 1GB
- unique_dsts: < 5
- avg_bytes: > 1MB
- is_large_flow: 1
```

---

## 🛠️ 故障排除

### 問題 1: 模型文件不存在

**錯誤：**
```
❌ 模型文件不存在: nad/models/isolation_forest.pkl
```

**解決：**
```bash
# 先訓練模型
python3 train_isolation_forest.py --days 7
```

### 問題 2: Elasticsearch 連接失敗

**錯誤：**
```
ConnectionError: [Errno 111] Connection refused
```

**檢查：**
```bash
# 1. 確認 ES 運行
curl http://localhost:9200

# 2. 檢查配置
cat nad/config.yaml | grep host
```

### 問題 3: 沒有訓練數據

**錯誤：**
```
沒有找到訓練數據！請檢查 Elasticsearch 索引。
```

**檢查：**
```bash
# 1. 確認索引存在
curl "http://localhost:9200/_cat/indices/netflow_stats_5m?v"

# 2. 檢查數據量
curl "http://localhost:9200/netflow_stats_5m/_count"

# 3. 確認 Transform 運行
curl "http://localhost:9200/_transform/netflow_production/_stats"
```

### 問題 4: 檢測到的異常太多/太少

**調整 contamination 參數：**

```yaml
# nad/config.yaml

isolation_forest:
  contamination: 0.05  # 調整此值
  # 異常太多 → 降低（如 0.02）
  # 異常太少 → 提高（如 0.10）
```

**重新訓練：**
```bash
python3 train_isolation_forest.py --days 7
```

---

## 📝 定期維護

### 每週重訓練

建議每週使用最新數據重訓練模型：

```bash
# 使用 cron 定期執行
0 2 * * 0 cd /home/kaisermac/snm_flow && python3 train_isolation_forest.py --days 7
```

### 性能監控

定期檢查模型性能：

```bash
# 評估模型
python3 train_isolation_forest.py --days 1 --evaluate
```

### 日誌管理

日誌位置：`logs/nad.log`

```bash
# 查看最近日誌
tail -f logs/nad.log

# 清理舊日誌
find logs/ -name "*.log" -mtime +30 -delete
```

---

## 🎯 下一步

### 1. 整合告警系統（可選）

修改 `realtime_detection.py` 添加告警：

```python
def send_alert(anomalies):
    """發送告警"""
    for anomaly in anomalies:
        if anomaly['confidence'] > 0.8:
            # 發送郵件/Slack/Webhook
            pass
```

### 2. 建立 Dashboard（可選）

使用 Kibana 視覺化檢測結果：
- 連接到 Elasticsearch
- 創建異常趨勢圖
- 設置告警規則

### 3. 進階 ML（Phase 2）

- 行為分類器（Behavior Classifier）
- 時間序列分析
- LLM 根因分析

參考：`AI_ANOMALY_DETECTION_OPTIMIZED.md`

---

## 📚 相關文檔

- **原理說明：** `AI_ANOMALY_DETECTION_OPTIMIZED.md`
- **優化總結：** `ML_OPTIMIZATION_SUMMARY.md`
- **覆蓋率驗證：** `COVERAGE_VERIFICATION_RESULT.md`
- **使用方法：** `HOW_TO_USE_AGGREGATED_DATA.md`

---

## 🤝 支援

遇到問題？

1. 檢查故障排除章節
2. 查看 `logs/nad.log` 日誌
3. 驗證數據源（`verify_coverage.py`）
4. 檢查配置文件（`nad/config.yaml`）

---

**版本：** 1.0
**更新日期：** 2025-11-11
**基於：** Transform 覆蓋率驗證（99.57%）
