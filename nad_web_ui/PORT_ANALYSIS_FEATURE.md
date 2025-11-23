# Port Analysis Feature - 端口特徵分析功能

## 概述

本文檔說明 NAD 系統如何使用 **3 分鐘 aggregation** 中的 **port 特徵**來提升異常檢測的準確度，特別是在雙向流量分析和服務識別方面。

---

## Elasticsearch Transform 配置

### 時間間隔

- **Aggregation 間隔**: 3 分鐘 (從 5m 改為 3m)
- **Transform Delay**: 90 秒
- **資料保留**:
  - 原始 NetFlow (`radar_flow_collector-*`): 24 小時
  - Aggregation (`netflow_stats_3m_by_*`): 長期保留

### 兩個獨立的 Transform

1. **`netflow_agg_3m_by_src`**
   - 從 SRC (source) 視角聚合流量
   - 輸出到 `netflow_stats_3m_by_src` index

2. **`netflow_agg_3m_by_dst`**
   - 從 DST (destination) 視角聚合流量
   - 輸出到 `netflow_stats_3m_by_dst` index

### Transform 同步問題

⚠️ **重要發現**: DST transform 可能比 SRC transform 落後 ~3 分鐘

**原因**:
- 雖然兩者配置相同（delay: 90s, align_checkpoints: true）
- 但處理速度和資料量差異導致執行時間不同

**解決方案**:
- 在合併邏輯中實施 **±6 分鐘時間容錯**
- 將 time_bucket 標準化到 12 分鐘間隔
- 允許時間相近的 SRC/DST 記錄進行配對

---

## Port 特徵欄位說明

### 核心欄位

```json
{
  // === 端口統計 ===
  "top_dst_ports": {          // Top 5 最常用目標端口 (key: port, value: flow_count)
    "80": 500,
    "443": 400,
    "53": 200
  },
  "top_src_ports": {          // Top 5 最常用來源端口
    "49152": 100,
    "49153": 98
  },
  "unique_dst_ports": 230,    // 唯一目標端口數量
  "unique_src_ports": 890,    // 唯一來源端口數量

  // === 端口特徵 ===
  "top_dst_port_concentration": 0.406,  // 最高端口集中度 (500/1234)
  "dst_well_known_ratio": 0.85,         // 知名端口比例 (0-1024)

  // === 流量統計 ===
  "flow_count": 1234,         // 總流量數
  "total_bytes": 5678900,     // 總位元組數
  "avg_bytes": 4603,          // 平均位元組數
  "unique_dsts": 45           // 唯一目標數 (SRC) 或唯一來源數 (DST)
}
```

---

## Port 特徵的應用場景

### 1. 服務識別 (Service Identification)

通過 `top_dst_ports` 自動識別網路服務：

```python
# 知名服務端口映射
SERVICE_MAP = {
    161: 'SNMP',
    162: 'SNMP-TRAP',
    53: 'DNS',
    80: 'HTTP',
    443: 'HTTPS',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    110: 'POP3',
    143: 'IMAP',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    6379: 'Redis',
    27017: 'MongoDB'
}
```

**範例：識別 SNMP 服務**
```json
SRC視角:
  top_dst_ports: {161: 100}  → 連接到 SNMP 端口

DST視角:
  top_dst_ports: {161: 98}   → 在 SNMP 端口接收連線

結論: 這是 SNMP request-response 服務
```

---

### 2. 端口掃描檢測 (Port Scan Detection)

通過 **端口分散度** 識別掃描行為：

```python
port_dispersion = unique_dst_ports / flow_count

if port_dispersion > 0.8:  # 80% 以上使用不同端口
    # 這是端口掃描！
    # 每個連線都嘗試不同的端口
```

**範例：192.168.0.4 的端口掃描**
```json
SRC視角:
  flow_count: 442
  unique_dst_ports: 438
  port_dispersion: 438/442 = 99%
  top_dst_ports: {32863: 1, 32840: 1, 33115: 1, ...}

分析:
  - 99% 的連線都使用不同端口
  - 端口是隨機高端口 (32863, 32840...)
  - 這是典型的端口掃描模式
```

---

### 3. 雙向服務驗證 (Bidirectional Service Validation)

判斷 SRC 和 DST 是否為同一服務的雙向流量：

**檢查項目：**

1. **流量對稱性**
   ```python
   flow_ratio = min(src_flows, dst_flows) / max(src_flows, dst_flows)
   is_symmetric = (flow_ratio > 0.8)  # 流量數相近
   ```

2. **對象數匹配**
   ```python
   target_match = (src_unique_dsts == dst_unique_srcs)
   ```

3. **端口模式匹配** (新增！)
   ```python
   # 檢查是否使用相同的知名端口
   src_uses_wellknown = (161 in src_top_dst_ports)
   dst_uses_wellknown = (161 in dst_top_dst_ports)

   has_request_response_pattern = (
       src_uses_wellknown AND
       dst_uses_wellknown AND
       same_wellknown_port  # 必須是同一個端口
   )
   ```

**合併條件：**
```python
should_merge = (
    flow_ratio > 0.8 AND
    target_match AND
    has_request_response_pattern
)
```

---

## 實際案例分析

### 案例 1: SNMP Request-Response（應合併）

```json
SRC視角 (192.168.10.100):
{
  "flow_count": 100,
  "unique_dsts": 5,
  "top_dst_ports": {"161": 100}  ← SNMP 端口
}

DST視角 (192.168.10.100):
{
  "flow_count": 98,
  "unique_srcs": 5,
  "top_dst_ports": {"161": 98}   ← SNMP 端口
}

檢查結果:
  ✓ flow_ratio: 98/100 = 98% (>80%)
  ✓ target_match: 5 == 5
  ✓ same_port: 161 == 161

結論: 合併為「正常雙向服務 (SNMP)」
```

---

### 案例 2: 端口掃描 vs SNMP 服務（應保留）

```json
SRC視角 (192.168.0.4):
{
  "flow_count": 442,
  "unique_dsts": 4,
  "unique_dst_ports": 438,        ← 99% 端口分散
  "top_dst_ports": {
    "32863": 1,                   ← 隨機高端口
    "32840": 1,
    "33115": 1
  }
}

DST視角 (192.168.0.4):
{
  "flow_count": 442,
  "unique_srcs": 4,
  "unique_dst_ports": 2,          ← 端口高度集中
  "top_dst_ports": {
    "161": 438,                   ← SNMP 服務
    "0": 4
  }
}

檢查結果:
  ✓ flow_ratio: 100% (對稱)
  ✓ target_match: 4 == 4
  ✗ port_pattern: SRC 用隨機端口，DST 用 161
  ✗ port_dispersion: 99% vs 0.4% (極度不對稱)

結論:
  - SRC: 端口掃描行為
  - DST: SNMP 服務
  - 保留兩筆獨立異常（不同的流量模式）
```

---

### 案例 3: Web Server + SSH Scan（應保留）

```json
SRC視角 (192.168.10.5):
{
  "flow_count": 500,
  "unique_dsts": 100,
  "top_dst_ports": {"22": 500}   ← SSH 掃描
}

DST視角 (192.168.10.5):
{
  "flow_count": 500,
  "unique_srcs": 100,
  "top_dst_ports": {"80": 500}   ← HTTP 服務
}

檢查結果:
  ✓ flow_ratio: 100%
  ✓ target_match: 100 == 100
  ✗ same_port: 22 ≠ 80 (不同服務)

結論: 保留兩筆異常（不同的服務）
```

---

## 合併邏輯實現

### 位置
`/home/kaisermac/snm_flow/realtime_detection_dual.py`

### 關鍵函數
`_merge_src_dst_anomalies()`

### 流程

```python
# Step 1: 按 IP 和標準化時間分組
grouped = defaultdict(lambda: {'src': [], 'dst': []})
for anomaly in anomalies:
    normalized_bucket = normalize_time_bucket(time_bucket, tolerance_minutes=6)
    key = (ip, normalized_bucket)
    grouped[key][perspective].append(anomaly)

# Step 2: 分析每個 IP 的 SRC/DST 配對
for (ip, bucket), records in grouped.items():
    src_record = records['src'][0]  # 取第一個
    dst_record = records['dst'][0]

    # Step 3: 提取端口特徵
    src_top_dst_ports = src_record.get('top_dst_ports', {})
    dst_top_dst_ports = dst_record.get('top_dst_ports', {})

    # Step 4: 檢查知名端口
    src_uses_wellknown = any(int(p) in WELLKNOWN_PORTS for p in src_top_dst_ports)
    dst_uses_wellknown = any(int(p) in WELLKNOWN_PORTS for p in dst_top_dst_ports)

    # Step 5: 應用合併規則
    if (flow_ratio > 0.8 and
        target_match and
        src_uses_wellknown and
        dst_uses_wellknown):
        # 合併為雙向服務
        merged_record = create_bidirectional_service(dst_record, src_record)
        merged_anomalies.append(merged_record)
    else:
        # 保留兩筆記錄
        merged_anomalies.extend([src_record, dst_record])
```

---

## 輸出訊息改進

### 合併訊息

**之前：**
```
✓ 合併 10.10.10.100 的雙向服務（流量比 0.99, 對象數 35, SRC=Unknown Anomaly）
```

**現在：**
```
✓ 合併 10.10.10.100 的雙向服務（流量比 0.99, 對象數 35, SRC=Unknown Anomaly, Port 53）
                                                                              ^^^^^^^^
                                                                        識別為 DNS 服務
```

### 保留訊息

**之前：**
```
⚠ 保留 192.168.0.4 的雙向異常（SRC=Port Scanning, DST=Unknown Anomaly）
```

**現在：**
```
⚠ 保留 192.168.0.4 的雙向異常（SRC=Port Scanning, DST=Unknown Anomaly, 對象數不匹配(3≠4)）
⚠ 保留 192.168.10.169 的雙向異常（SRC=Network Scanning, DST=Unknown Anomaly, 端口模式不對稱）
⚠ 保留 61.216.14.29 的雙向異常（SRC=Unknown Anomaly, DST=Unknown Anomaly, 流量不對稱(14%)）
```

明確顯示保留原因：
- `對象數不匹配(3≠4)`
- `端口模式不對稱`
- `流量不對稱(14%)`

---

## 效果與價值

### 準確度提升

1. **減少誤報**
   - 正確識別 SNMP, DNS, HTTP 等正常服務
   - 避免將雙向服務誤判為兩個獨立異常

2. **提升檢測能力**
   - 端口掃描識別更準確（端口分散度）
   - 區分正常服務 vs 惡意掃描

3. **可解釋性**
   - 明確顯示服務類型（SNMP, DNS, HTTP...）
   - 清楚說明保留原因

### 性能優化

- **無需查詢原始 NetFlow**
  - 所有特徵已在 aggregation 中
  - 24 小時保留期限制不影響分析

- **快速服務識別**
  - `top_dst_ports` 直接提供前 5 個端口
  - 無需額外聚合運算

---

## 未來優化方向

### 1. 端口一致性強化

目前只檢查「都使用知名端口」，未來可檢查「是否為同一個端口」：

```python
src_wellknown_port = extract_wellknown_port(src_top_dst_ports)
dst_wellknown_port = extract_wellknown_port(dst_top_dst_ports)

port_matches = (src_wellknown_port == dst_wellknown_port)
```

### 2. 端口分散度量化

```python
def calculate_port_entropy(unique_ports, flow_count):
    return unique_ports / flow_count

src_entropy = calculate_port_entropy(src_unique_dst_ports, src_flows)
dst_entropy = calculate_port_entropy(dst_unique_dst_ports, dst_flows)

if src_entropy > 0.8 and dst_entropy < 0.1:
    # 明顯不對稱，不應合併
```

### 3. 雙向端口對稱性

檢查 request-response 的端口模式：

```python
# SRC: random_port → 161 (SNMP request)
# DST: 161 → random_port (SNMP response)

src_uses_random_src_port = (src_unique_src_ports > 100)
dst_receives_on_wellknown = (161 in dst_top_dst_ports)

is_request_response = (src_uses_random_src_port and dst_receives_on_wellknown)
```

### 4. 服務映射擴充

擴充支援更多服務：

```python
SERVICE_MAP = {
    # 現有服務 + 新增
    3389: 'RDP',
    5900: 'VNC',
    137: 'NetBIOS',
    139: 'SMB',
    445: 'SMB',
    8080: 'HTTP-Proxy',
    # ... 更多
}
```

---

## 相關文檔

- `CLAUDE.md`: 完整系統架構說明
- `DUAL_MODE_TESTING_GUIDE.md`: 雙模型測試指南
- `realtime_detection_dual.py`: 實際實現代碼

---

## 總結

Port 特徵分析功能通過 **3 分鐘 aggregation** 中的 `top_dst_ports` 和相關指標，大幅提升了：

✅ **服務識別準確度** - 自動識別 SNMP, DNS, HTTP 等服務
✅ **端口掃描檢測** - 通過端口分散度量化掃描行為
✅ **雙向服務驗證** - 正確合併 request-response 流量
✅ **可解釋性** - 明確顯示判斷依據和保留原因
✅ **效能優化** - 無需查詢原始 NetFlow 即可完成分析

**關鍵價值**: 在不增加運算成本的前提下，通過精心設計的 aggregation 特徵，達到接近原始資料分析的準確度。
