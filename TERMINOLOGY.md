# 術語對照表

本文檔說明系統中使用的中英文術語對照。

## 🌏 本地化版本

本系統採用**台灣繁體中文**用語。

---

## 📋 網路相關術語

| 英文 | 本系統用語 | 大陸用語 | 說明 |
|------|-----------|---------|------|
| **Port** | 通訊埠 | 端口 | 網路通訊的邏輯端點 |
| **Packet** | 封包 | 数据包 | 網路傳輸的數據單位 |
| **Flow** | 流量 | 流量 | 通用 |
| **Connection** | 連線 | 连接 | 通用 |
| **Destination** | 目的地 | 目标 | IP 目的地 |
| **Source** | 來源 | 源 | IP 來源 |

---

## 📊 統計分析術語

| 英文 | 本系統用語 | 說明 |
|------|-----------|------|
| **Unique destinations** | 不同目的地數量 | 不重複的目的地 IP 數量 |
| **Unique ports** | 不同通訊埠數量 | 不重複的通訊埠數量 |
| **Diversity ratio** | 分散度 | 統計學上的離散程度 |
| **Concentration** | 集中度 | 與分散度相反 |
| **Distribution** | 分布 | 數據分布狀況 |

---

## 🔒 資安術語

| 英文 | 本系統用語 | 說明 |
|------|-----------|------|
| **Port scanning** | 通訊埠掃描 | 探測目標主機開放的通訊埠 |
| **Network scanning** | 網路掃描 | 探測網路中的主機 |
| **Anomaly** | 異常 | 偏離正常行為的事件 |
| **False positive** | 誤報 | 正常行為被誤判為異常 |
| **True positive** | 真陽性 | 正確識別的異常 |
| **Data exfiltration** | 資料外洩 | 未授權的資料傳出 |
| **DDoS** | 分散式阻斷服務攻擊 | Distributed Denial of Service |
| **DNS abuse** | DNS 濫用 | 異常的 DNS 使用行為 |

---

## 🤖 機器學習術語

| 英文 | 本系統用語 | 說明 |
|------|-----------|------|
| **Feature** | 特徵 | 用於訓練的數據特性 |
| **Model** | 模型 | 訓練好的機器學習模型 |
| **Training** | 訓練 | 建立模型的過程 |
| **Prediction** | 預測 | 使用模型進行判斷 |
| **Score** | 分數 | 模型給出的評分 |
| **Confidence** | 置信度 | 預測的可信程度 |
| **Contamination** | 污染率/異常比例 | 預期異常資料的比例 |
| **Threshold** | 閾值 | 判斷的臨界值 |

---

## 📈 特徵名稱對照

### 基礎特徵 (Basic Features)

| 程式碼 | 顯示名稱 | 說明 |
|--------|---------|------|
| `flow_count` | 連線數 | 流量記錄的數量 |
| `total_bytes` | 總流量 | 傳輸的總位元組數 |
| `total_packets` | 總封包數 | 傳輸的總封包數 |
| `unique_dsts` | 不同目的地數量 | 不重複的目的地 IP |
| `unique_ports` | 不同通訊埠數量 | 不重複的通訊埠 |
| `avg_bytes` | 平均流量 | 每次連線的平均位元組數 |
| `max_bytes` | 最大單一連線流量 | 單次連線的最大位元組數 |

### 衍生特徵 (Derived Features)

| 程式碼 | 顯示名稱 | 說明 |
|--------|---------|------|
| `dst_diversity` | 目的地分散度 | unique_dsts / flow_count |
| `port_diversity` | 通訊埠分散度 | unique_ports / flow_count |
| `traffic_concentration` | 流量集中度 | max_bytes / total_bytes |
| `bytes_per_packet` | 每封包流量 | total_bytes / total_packets |

### 二值特徵 (Binary Features)

| 程式碼 | 顯示名稱 | 觸發條件 |
|--------|---------|---------|
| `is_high_connection` | 高連線數 | flow_count > 1000 |
| `is_scanning_pattern` | 掃描模式 | unique_dsts > 30 且 avg_bytes < 10000 |
| `is_small_packet` | 小封包 | avg_bytes < 1000 |
| `is_large_flow` | 大流量 | max_bytes > 100MB |
| `is_likely_server_response` | 疑似伺服器回應 | port_diversity > 0.5 且其他條件 |

---

## 🎯 異常類型

| 程式碼 | 顯示名稱 | 嚴重性 |
|--------|---------|--------|
| `PORT_SCANNING` | 通訊埠掃描 | 🔴 HIGH |
| `NETWORK_SCANNING` | 網路掃描 | 🔴 HIGH |
| `DNS_ABUSE` | DNS 濫用 | 🟡 MEDIUM |
| `DATA_EXFILTRATION` | 資料外洩 | 🔴 HIGH |
| `ICMP_ABUSE` | ICMP 濫用 | 🟡 MEDIUM |
| `DNS_SERVER_RESPONSE` | DNS 伺服器回應 | 🟢 LOW |
| `WEB_SERVER_RESPONSE` | Web 伺服器回應 | 🟢 LOW |
| `NORMAL_SERVICE` | 正常服務 | 🟢 LOW |

---

## 📝 判斷結果

| 程式碼 | 顯示名稱 | 圖示 | 說明 |
|--------|---------|------|------|
| `TRUE_ANOMALY` | 真實異常 | 🚨 | 確認為異常行為 |
| `SUSPICIOUS` | 可疑行為 | ⚠️ | 需要進一步觀察 |
| `FALSE_POSITIVE` | 誤報（正常流量） | ✅ | 正常行為被誤判 |
| `UNCLEAR` | 無法確定 | ❓ | 需要更多資料判斷 |

---

## 🔧 配置參數

| 參數 | 顯示名稱 | 說明 |
|------|---------|------|
| `contamination` | 污染率/預期異常比例 | 訓練時預期的異常比例（如 0.05 = 5%）|
| `n_estimators` | 樹的數量 | Isolation Forest 的決策樹數量 |
| `threshold` | 閾值 | 判斷異常的臨界值 |
| `confidence` | 置信度 | 預測結果的可信度 |

---

## 📌 常見縮寫

| 縮寫 | 完整名稱 | 中文 |
|------|---------|------|
| **IP** | Internet Protocol | 網際網路協定 |
| **TCP** | Transmission Control Protocol | 傳輸控制協定 |
| **UDP** | User Datagram Protocol | 使用者資料包協定 |
| **ICMP** | Internet Control Message Protocol | 網際網路控制訊息協定 |
| **DNS** | Domain Name System | 網域名稱系統 |
| **HTTP** | Hypertext Transfer Protocol | 超文本傳輸協定 |
| **HTTPS** | HTTP Secure | 安全超文本傳輸協定 |
| **SSH** | Secure Shell | 安全外殼協定 |
| **ML** | Machine Learning | 機器學習 |
| **ES** | Elasticsearch | Elasticsearch（保持原文）|

---

## 💡 使用建議

### 一致性原則
- 在同一份文件或系統中，保持術語的一致性
- 技術文件優先使用本地化術語，括號內附英文原文
- 程式碼中保持英文變數名稱

### 範例
```markdown
✅ 好的寫法：
- 系統檢測到通訊埠掃描（Port Scanning）行為
- unique_ports（不同通訊埠數量）> 20

❌ 避免的寫法：
- 系統檢測到 port scanning 行為（混用中英文）
- 唯一端口數量（用詞不統一）
```

---

**版本：** 1.0
**更新日期：** 2025-11-12
**適用地區：** 台灣
