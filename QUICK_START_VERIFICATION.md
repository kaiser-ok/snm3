# 異常驗證快速開始

## 🚀 三種使用方式

### 方式 1: 一鍵批量驗證（推薦新手）

自動檢測 → 自動驗證前 N 個異常：

```bash
# 默認：檢測最近30分鐘，驗證前5個異常
./batch_verify.sh

# 自定義：檢測最近60分鐘，驗證前10個異常
./batch_verify.sh --minutes 60 --top 10
```

### 方式 2: 手動驗證單個 IP

先檢測，再手動選擇要驗證的 IP：

```bash
# Step 1: 檢測異常
python3 realtime_detection.py --minutes 30

# 輸出示例：
# 1  192.168.10.135  0.6859  1.00  4,290  67  1,208
# 2  192.168.10.160  0.6494  1.00  2,922  49  1,618

# Step 2: 驗證感興趣的 IP
python3 verify_anomaly.py --ip 192.168.10.135 --minutes 30
```

### 方式 3: 批量分析並獲取調優建議

收集多個異常 IP，一次性分析並獲取閾值調整建議：

```bash
# 方法 A: 直接指定 IP
python3 tune_thresholds.py --ips '192.168.10.135,192.168.10.160,192.168.20.50' --minutes 30

# 方法 B: 從文件讀取
echo "192.168.10.135
192.168.10.160
192.168.20.50" > anomalies.txt

python3 tune_thresholds.py --file anomalies.txt --minutes 30
```

---

## 📊 實際案例演示

### 案例 1: 檢測到 DNS 異常

**檢測結果：**
```
14  8.8.8.8  0.6170  1.00  2,705  1  1,173
```

**驗證命令：**
```bash
python3 verify_anomaly.py --ip 192.168.10.135 --minutes 30
```

**驗證報告顯示：**
```
🔍 行為分析:
   🔴 [HIGH] PORT_SCANNING
      檢測到通訊埠掃描：4546 個不同通訊埠
   🟡 [MEDIUM] DNS_ABUSE
      疑似 DNS 濫用：4980 個 DNS 查詢

🚨 最終判斷: 真實異常 (置信度: HIGH)
💡 建議: 建議立即調查
```

**結論：** 這是真實異常，該主機可能在進行通訊埠掃描並濫用 DNS。

---

### 案例 2: 檢測到正常服務器流量

**檢測結果：**
```
5  192.168.1.100  0.5234  0.85  3,456  12  15,678
```

**驗證報告顯示：**
```
🔌 通訊埠分析:
   前 5 個通訊埠:
      80 (HTTP   ) → 1,234 次 (35.7%)
      443 (HTTPS ) → 987 次 (28.6%)
      22 (SSH    ) → 567 次 (16.4%)

🔍 行為分析:
   🟢 [LOW] NORMAL_SERVICE
      看起來像正常服務流量

✅ 最終判斷: 誤報（正常流量） (置信度: HIGH)
💡 建議: 建議調整特徵閾值，降低此類誤報
```

**結論：** 這是誤報，該主機是正常的 Web 服務器。建議調整閾值。

---

## 🔧 根據驗證結果調整閾值

### 情況 A: 誤報太多

如果發現多個正常服務被標記為異常：

```bash
# Step 1: 收集所有誤報的 IP
echo "192.168.1.100
192.168.1.101
192.168.1.102" > false_positives.txt

# Step 2: 批量分析獲取建議
python3 tune_thresholds.py --file false_positives.txt --minutes 30

# Step 3: 查看調優建議
# 輸出會顯示：
#   📌 參數: thresholds.high_connection
#      當前值: 1000
#      建議值: 2500
#      原因: 2 個誤報的連線數超過當前閾值

# Step 4: 應用調整
nano nad/config.yaml
# 修改相應參數

# Step 5: 重新訓練
python3 train_isolation_forest.py --days 7

# Step 6: 驗證效果
python3 realtime_detection.py --minutes 30
```

### 情況 B: 真實異常需要處理

如果驗證確認為真實異常：

1. **記錄異常詳情** - 保存報告用於調查
2. **採取安全措施** - 隔離/封鎖該 IP
3. **持續監控** - 觀察該 IP 後續行為

---

## 📝 驗證報告解讀

### 判斷類型

| 判斷 | 圖標 | 含義 | 下一步 |
|------|------|------|--------|
| **TRUE_ANOMALY** | 🚨 | 確認異常 | 立即調查 |
| **SUSPICIOUS** | ⚠️ | 可疑 | 持續觀察 |
| **FALSE_POSITIVE** | ✅ | 誤報 | 調整閾值 |
| **UNCLEAR** | ❓ | 不確定 | 需更多數據 |

### 異常類型

| 類型 | 嚴重度 | 特徵 |
|------|--------|------|
| **PORT_SCANNING** | 🔴 HIGH | 大量不同通訊埠 |
| **NETWORK_SCANNING** | 🔴 HIGH | 大量目的地 IP |
| **DNS_ABUSE** | 🟡 MEDIUM | 大量 DNS 查詢 |
| **DATA_EXFILTRATION** | 🔴 HIGH | 大流量到少數目的地 |
| **ICMP_ABUSE** | 🟡 MEDIUM | 大量 ICMP 流量 |
| **NORMAL_SERVICE** | 🟢 LOW | 正常服務流量 |

---

## 🎯 最佳實踐

### 每日工作流程

```bash
# 早上：檢查過夜的異常
python3 realtime_detection.py --minutes 720  # 12小時
./batch_verify.sh --minutes 720 --top 10

# 每4小時：快速檢查
python3 realtime_detection.py --minutes 240  # 4小時
# 只驗證高分異常（手動選擇 > 0.7 的）

# 下班前：驗證當天異常
./batch_verify.sh --minutes 480 --top 5     # 8小時
```

### 每週調優流程

```bash
# 週五：收集一週的誤報
cat daily_false_positives.txt > weekly_fps.txt

# 批量分析
python3 tune_thresholds.py --file weekly_fps.txt --minutes 10080  # 7天

# 週末：應用調整並重訓練
nano nad/config.yaml  # 根據建議調整
python3 train_isolation_forest.py --days 7

# 週一：驗證效果
python3 realtime_detection.py --minutes 30
```

---

## ❓ 常見問題

### Q1: 為什麼找不到某些 IP 的數據？

**A:** 可能原因：
1. 該 IP 不是源 IP（是目的 IP）
2. 時間範圍太短，增加 `--minutes` 參數
3. 原始 netflow 數據已過期被刪除

### Q2: 報告中目的地顯示 0.0.0.0？

**A:** 這是原始數據的問題，某些 netflow 記錄的目的地未正確記錄。這不影響其他分析維度（通訊埠、協定、流量等）。

### Q3: 驗證很慢怎麼辦？

**A:** 原始 netflow 索引很大，查詢需要時間。建議：
1. 減少時間範圍（--minutes 15）
2. 只驗證高分異常（> 0.7）
3. 使用批量腳本自動化

### Q4: 如何保存驗證報告？

**A:**
```bash
python3 verify_anomaly.py --ip 192.168.10.135 --minutes 30 > report_192.168.10.135.txt
```

---

## 📚 相關文檔

- **詳細指南：** `ANOMALY_VERIFICATION_GUIDE.md`
- **使用指南：** `ISOLATION_FOREST_GUIDE.md`
- **配置參考：** `nad/config.yaml`

---

**版本：** 1.0
**更新：** 2025-11-12
