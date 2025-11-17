# 異常分類系統使用指南

## 📖 概述

異常分類器是在 **Isolation Forest 異常檢測**之後的第二階段，用於判斷異常的具體類型和威脅等級。

```
Isolation Forest → 檢測異常（這個IP異常）
        ↓
Anomaly Classifier → 分類異常（這是端口掃描攻擊）
```

---

## 🎯 支持的威脅類別

| 類別 | 中文名稱 | 嚴重性 | 優先級 | 描述 |
|------|---------|--------|--------|------|
| PORT_SCAN | 端口掃描 | HIGH | P0 | 探測大量端口，尋找漏洞 |
| NETWORK_SCAN | 網路掃描 | HIGH | P0 | 掃描多個主機，橫向移動 |
| DATA_EXFILTRATION | 數據外洩 | CRITICAL | P0 | 大量數據傳輸到外部 |
| DNS_TUNNELING | DNS 隧道 | HIGH | P0 | 通過 DNS 查詢傳輸數據 |
| DDOS | DDoS 攻擊 | CRITICAL | P0 | 分散式拒絕服務攻擊 |
| C2_COMMUNICATION | C&C 通訊 | CRITICAL | P0 | 與控制服務器通訊（殭屍網路）|
| NORMAL_HIGH_TRAFFIC | 正常高流量 | LOW | P3 | 合法的高流量服務 |
| UNKNOWN | 未知異常 | MEDIUM | P2 | 無法分類的異常行為 |

---

## 🚀 使用方法

### 自動集成（已實現）

分類器已自動集成到 `realtime_detection.py` 中：

```bash
# 運行實時檢測（自動包含分類）
python3 realtime_detection.py --minutes 60
```

**輸出示例：**
```
3. 192.168.10.135
   時間: 2025-11-13T04:10:00.000Z
   異常分數: 0.6660 (置信度: 1.00)
   連線數: 3,497
   行為特徵: 高連線數, 掃描模式

   🟠 威脅分類: 端口掃描 (Port Scanning)
      置信度: 98%
      嚴重性: HIGH | 優先級: P0
      描述: 探測大量端口，尋找漏洞
      關鍵指標:
         • 掃描 2,125 個不同端口
         • 平均封包 1,402 bytes（小封包）
         • 端口分散度 0.61（高度分散）
      建議行動: 立即隔離主機
```

---

## 🔬 分類邏輯詳解

### 1. 端口掃描 (PORT_SCAN)

**判斷條件：**
```python
unique_dst_ports > 100          # 掃描大量端口
avg_bytes < 5000                # 小封包
dst_port_diversity > 0.5        # 端口高度分散
```

**特徵：**
- ✅ 掃描 100+ 個不同端口
- ✅ 小封包（平均 < 5KB）
- ✅ 端口分散度高（> 0.5）

**響應建議：**
1. 立即隔離主機
2. 檢查主機是否被入侵
3. 掃描惡意軟件
4. 追蹤掃描目標，檢查是否已被攻破

**實際案例：**
```
192.168.10.135
- 掃描 2,125 個端口
- 平均封包 1,402 bytes
- 端口分散度 0.61
→ 分類: 端口掃描 (98% 置信度)
```

---

### 2. 網路掃描 (NETWORK_SCAN)

**判斷條件：**
```python
unique_dsts > 50                # 掃描大量主機
dst_diversity > 0.3             # 目的地高度分散
flow_count > 1000               # 高連線數
avg_bytes < 50000               # 小到中等流量
```

**特徵：**
- ✅ 掃描 50+ 個不同主機
- ✅ 目的地分散度高（> 0.3）
- ✅ 高連線數（> 1000）

**響應建議：**
1. 立即隔離主機
2. 追蹤掃描的目標主機
3. 檢查被掃描主機的安全狀態
4. 調查掃描來源

---

### 3. 數據外洩 (DATA_EXFILTRATION)

**判斷條件：**
```python
total_bytes > 1GB               # 大流量
unique_dsts <= 5                # 目的地極少
dst_diversity < 0.1             # 目的地集中
has_external_ip                 # 有外部 IP
```

**特徵：**
- ✅ 大流量傳輸（> 1GB）
- ✅ 目的地極少（< 5 個）
- ✅ 連接外部 IP
- ✅ 持續時間長

**響應建議：**
1. 立即封鎖目標 IP
2. 終止所有活動連線
3. 調查數據來源和內容
4. 檢查內網是否被入侵
5. 報告安全事件

**實際案例：**
```
144.195.35.179
- 傳輸 21 GB 數據
- 僅 2 個目的地
- 目標: 118.163.8.90 (外部)
→ 分類: 數據外洩 (92% 置信度)
```

---

### 4. DNS 隧道 (DNS_TUNNELING)

**判斷條件：**
```python
flow_count > 1000               # 大量連線
unique_dst_ports <= 2           # 只用 DNS 端口
avg_bytes < 1000                # 小封包
unique_dsts <= 5                # 目的地極少
```

**特徵：**
- ✅ 大量 DNS 查詢（> 1000）
- ✅ 僅使用 DNS 端口（53）
- ✅ 查詢異常長的域名
- ✅ 目的地 DNS 服務器極少

**響應建議：**
1. 封鎖目標 DNS 服務器
2. 分析 DNS 查詢內容
3. 檢查主機是否被植入後門
4. 監控 DNS 流量模式

---

### 5. DDoS 攻擊 (DDOS)

**判斷條件：**
```python
flow_count > 10000              # 極高連線數
avg_bytes < 500                 # 極小封包
unique_dsts < 20                # 目的地少
```

**特徵：**
- ✅ 極高連線數（> 10000）
- ✅ 小封包（< 500 bytes）- SYN Flood
- ✅ 目的地集中

**響應建議：**
1. 啟動 DDoS 防護
2. 限速/黑洞路由
3. 聯繫 ISP 協助
4. 分析攻擊源

---

### 6. C&C 通訊 (C2_COMMUNICATION)

**判斷條件：**
```python
unique_dsts == 1                # 單一目的地
100 < flow_count < 1000         # 中等連線數
1KB < avg_bytes < 100KB         # 中等流量
# + 週期性（需時間序列分析）
```

**特徵：**
- ✅ 單一目的地
- ✅ 中等連線數（100-1000）
- ✅ 中等流量（1KB-100KB）
- ✅ 週期性連線

**響應建議：**
1. 立即隔離主機
2. 全面掃描惡意軟件
3. 分析通訊內容
4. 追蹤感染源
5. 檢查其他主機是否也被感染

---

### 7. 正常高流量 (NORMAL_HIGH_TRAFFIC)

**判斷條件：**
```python
total_bytes > 1GB               # 大流量
all_internal_ips                # 都是內網 OR
is_likely_server_response       # 服務器回應 OR
is_backup_time                  # 備份時間
10 < unique_dsts < 100          # 目的地數量合理
```

**特徵：**
- ✅ 大流量但目標是內網
- ✅ 或者是服務器回應流量
- ✅ 或者在備份時間（凌晨 1-5 點）
- ✅ 目的地數量合理

**響應建議：**
1. 加入白名單
2. 持續監控流量模式
3. 驗證服務合法性
4. 無需立即行動

---

## 📊 輸出格式說明

### 嚴重性標記

| Emoji | 嚴重性 | 含義 |
|-------|--------|------|
| 🔴 | CRITICAL | 嚴重威脅，立即處理 |
| 🟠 | HIGH | 高風險，優先處理 |
| 🟡 | MEDIUM | 中等風險，需關注 |
| 🟢 | LOW | 低風險，持續監控 |

### 優先級

- **P0**: 緊急，立即處理（< 15分鐘）
- **P1**: 高優先級（< 1小時）
- **P2**: 中等優先級（< 24小時）
- **P3**: 低優先級（持續監控）

---

## 🔧 自定義配置

### 調整分類閾值

編輯 `nad/ml/anomaly_classifier.py`：

```python
# 例如：調整端口掃描的閾值
def _is_port_scan(self, features: Dict) -> bool:
    unique_dst_ports = features.get('unique_dst_ports', 0)
    avg_bytes = features.get('avg_bytes', 0)
    dst_port_diversity = features.get('dst_port_diversity', 0)

    return (
        unique_dst_ports > 100 and      # 調整這裡：從 100 改為 200
        avg_bytes < 5000 and
        dst_port_diversity > 0.5
    )
```

### 添加已知服務器白名單

編輯 `nad/config.yaml`：

```yaml
# 添加已知的合法服務器
known_servers:
  - "192.168.100.10"  # 備份服務器
  - "192.168.100.20"  # 文件服務器
  - "192.168.100.30"  # 更新服務器
```

---

## 💡 最佳實踐

### 1. 定期檢測

```bash
# 每小時檢測一次
python3 realtime_detection.py --minutes 60
```

### 2. 持續監控

```bash
# 持續監控模式（每 5 分鐘檢測一次）
python3 realtime_detection.py --continuous --interval 5 --minutes 10
```

### 3. 針對性調查

當分類器識別出特定威脅時：

```bash
# 深入調查端口掃描
python3 verify_anomaly.py --ip 192.168.10.135 --minutes 120

# 追蹤數據外洩
python3 verify_anomaly.py --ip 144.195.35.179 --minutes 200
```

### 4. 響應流程

```
檢測 → 分類 → 驗證 → 響應

1. realtime_detection.py   # 檢測並分類
2. verify_anomaly.py        # 深入驗證
3. 根據優先級響應:
   - P0: 立即隔離/封鎖
   - P1: 1小時內調查
   - P2: 24小時內審查
   - P3: 持續監控
```

---

## 🎓 理解分類器 vs 行為特徵

### 行為特徵（Feature Labels）

```
行為特徵: 高連線數, 掃描模式
```

- **性質**: 特徵標籤列表
- **目的**: 描述"有什麼特徵"
- **問題**: 不明確類型和威脅

### 威脅分類（Threat Classification）

```
🟠 威脅分類: 端口掃描 (Port Scanning)
   置信度: 98%
   嚴重性: HIGH | 優先級: P0
   建議行動: 立即隔離主機
```

- **性質**: 威脅診斷
- **目的**: 明確"是什麼威脅"
- **優點**: 可操作、有優先級

**關鍵區別：**
- 行為特徵是**描述性的**（describe）
- 威脅分類是**診斷性的**（diagnose）

---

## 📈 準確度提升

### 當前方法（規則型）

**優點：**
- ✅ 無需訓練數據
- ✅ 立即可用
- ✅ 可解釋性強
- ✅ 易於調整

**局限：**
- ⚠️ 無法學習新模式
- ⚠️ 需要手工制定規則
- ⚠️ 可能遺漏複雜攻擊

### 未來增強（機器學習型）

**Phase 2 計劃：**
1. 收集人工標記數據（500-1000 個樣本）
2. 訓練 ML 分類器（Random Forest / XGBoost）
3. 混合方法：規則 + ML

**預期改進：**
- 準確度：85% → 95%+
- 支持更多威脅類型
- 自動學習新攻擊模式

---

## 🔍 故障排除

### 問題 1: 所有異常都被分類為 UNKNOWN

**可能原因：**
- 閾值設置過嚴
- 特徵不符合任何已知模式

**解決：**
```bash
# 1. 查看詳細特徵
python3 realtime_detection.py --minutes 60

# 2. 檢查特徵值是否在預期範圍
# 例如：端口掃描需要 unique_dst_ports > 100
```

### 問題 2: 誤分類（正常流量被標記為攻擊）

**解決：**
```python
# 調整 nad/ml/anomaly_classifier.py 中的閾值
# 或添加到白名單
```

### 問題 3: 分類器崩潰

**檢查：**
```bash
# 確認特徵完整
# 分類器需要所有必需的特徵字段
```

---

## 📚 相關文檔

- **異常檢測**: `ISOLATION_FOREST_GUIDE.md`
- **自適應閾值**: `ADAPTIVE_THRESHOLDS_GUIDE.md`
- **特徵說明**: `ANOMALY_FEATURES_EXPLAINED.md`
- **快速參考**: `Quick_reference_for_forest_feature.md`

---

## 🤝 支持

遇到問題？

1. 檢查日誌: `logs/nad.log`
2. 驗證特徵值是否正常
3. 調整分類閾值
4. 查看相關文檔

---

**版本**: 1.0
**更新日期**: 2025-11-13
**狀態**: Production Ready ✅
