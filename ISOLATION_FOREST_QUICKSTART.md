# Isolation Forest - 快速開始

## ⚡ 5 分鐘快速開始

### 1. 安裝依賴（一次性）

```bash
pip3 install scikit-learn elasticsearch pyyaml numpy
```

### 2. 訓練模型（一次性，5-10分鐘）

```bash
python3 train_isolation_forest.py --days 7 --evaluate
```

### 3. 實時檢測

```bash
# 單次檢測（最近10分鐘）
python3 realtime_detection.py --minutes 10

# 持續監控（每5分鐘檢測一次）
python3 realtime_detection.py --continuous --interval 5
```

---

## 📋 命令速查

### 訓練相關

```bash
# 基礎訓練（7天數據）
python3 train_isolation_forest.py --days 7

# 訓練並評估
python3 train_isolation_forest.py --days 7 --evaluate

# 使用更多數據訓練（30天）
python3 train_isolation_forest.py --days 30
```

### 檢測相關

```bash
# 檢測最近10分鐘
python3 realtime_detection.py --minutes 10

# 檢測最近1小時
python3 realtime_detection.py --minutes 60

# 持續監控（每5分鐘檢測一次，分析最近10分鐘）
python3 realtime_detection.py --continuous --interval 5 --minutes 10

# 持續監控（每10分鐘檢測一次，分析最近30分鐘）
python3 realtime_detection.py --continuous --interval 10 --minutes 30
```

---

## 🎯 預期結果

### 訓練完成後

```
✅ 訓練完成！
模型已保存到: nad/models/isolation_forest.pkl
```

檢查模型文件：
```bash
ls -lh nad/models/
# 應該看到:
# isolation_forest.pkl
# scaler.pkl
```

### 檢測輸出示例

```
⚠️  發現 14 個異常

排名   IP地址           異常分數     置信度      連線數      目的地    平均流量
========================================================================================
1      192.168.10.135   0.6234      0.89       510,823    107       4,567
2      192.168.20.56    0.5891      0.82       394,143    8         342
3      192.168.15.42    0.5123      0.76        12,456    65       8,912
```

---

## 🔧 常見調整

### 調整異常檢測靈敏度

編輯 `nad/config.yaml`：

```yaml
isolation_forest:
  contamination: 0.05   # 預期異常比例
```

- **異常太多** → 降低值（如 0.02 = 2%）
- **異常太少** → 提高值（如 0.10 = 10%）

修改後需重新訓練：
```bash
python3 train_isolation_forest.py --days 7
```

### 調整特徵閾值

```yaml
thresholds:
  high_connection: 1000      # 高連線數閾值（調高=更嚴格）
  scanning_dsts: 30          # 掃描目的地數（調高=更嚴格）
```

---

## 📊 項目結構

```
snm_flow/
├── nad/
│   ├── config.yaml              # ← 配置文件（可修改）
│   ├── ml/                      # ML 代碼
│   ├── utils/                   # 工具代碼
│   └── models/                  # 訓練好的模型
│       ├── isolation_forest.pkl # ← 模型文件
│       └── scaler.pkl           # ← 標準化器
│
├── train_isolation_forest.py   # ← 訓練腳本
├── realtime_detection.py        # ← 檢測腳本
└── logs/                        # 日誌目錄
    └── nad.log
```

---

## ❓ 故障排除

### 問題：模型文件不存在

```bash
# 先訓練模型
python3 train_isolation_forest.py --days 7
```

### 問題：ES 連接失敗

```bash
# 檢查 ES 是否運行
curl http://localhost:9200

# 檢查聚合索引
curl "http://localhost:9200/netflow_stats_5m/_count"
```

### 問題：沒有檢測到異常

```bash
# 1. 降低閾值（編輯 config.yaml）
contamination: 0.10  # 從 0.05 提高到 0.10

# 2. 重新訓練
python3 train_isolation_forest.py --days 7

# 3. 檢查數據範圍
python3 realtime_detection.py --minutes 60  # 擴大到1小時
```

---

## 📈 性能數據

基於實測（99.57% 覆蓋率）：

| 操作 | 耗時 |
|------|------|
| 訓練（7天） | 5-10 分鐘 |
| 實時檢測（10分鐘） | < 5 秒 |
| 持續監控（每5分鐘） | < 5 秒/次 |

---

## 🎓 完整文檔

- **詳細使用指南：** `ISOLATION_FOREST_GUIDE.md`
- **原理說明：** `AI_ANOMALY_DETECTION_OPTIMIZED.md`
- **性能優化：** `ML_OPTIMIZATION_SUMMARY.md`

---

**版本：** 1.0
**更新：** 2025-11-11
