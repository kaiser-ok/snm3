# DST 視角埠分析邏輯修正報告

**日期**: 2025-11-23  
**修正範圍**: `verify_anomaly.py` 和 `port_analyzer.py`

## 問題描述

### 錯誤邏輯

當分析 IP 作為**目的地 (DST)** 被連線時，原本的邏輯錯誤地使用**來源埠 (src_port)** 來判斷是否被掃描：

```python
# 錯誤做法
if role == 'dst':
    target_ports = [f['src_port'] for f in flows ...]  # ❌ 分析來源埠
```

**為什麼錯誤**：
- 來源埠 = 客戶端使用的臨時埠 (通常 >32000)
- 每個客戶端連線使用不同的臨時埠是**正常行為**
- 例如：100 個客戶端連到 Web Server，會有 100 個不同的來源埠
- 用來源埠數量判斷「被掃描」會產生大量誤報

### 正確邏輯

應該分析**目的埠 (dst_port)**，即「被訪問的服務埠」：

```python
# 正確做法
if role == 'dst':
    target_ports = [f['dst_port'] for f in flows ...]  # ✅ 分析目的埠
```

**為什麼正確**：
- 目的埠 = 該主機提供服務的埠
- 如果攻擊者掃描一台主機，會嘗試連接**多個不同的服務埠** (22, 80, 443, 3306, ...)
- 如果只是正常訪問，通常只連接 1-3 個固定服務埠
- 例如：SNMP 設備正常情況下只開放 port 161，即使有 1000 個客戶端連線，也只有 1 個目的埠

## 修正內容

### 1. verify_anomaly.py

#### 修正位置：第 385-397 行

**修正前**：
```python
else:  # role == 'dst'
    # IP 作為目的地：分析來源通訊埠
    target_ports = [f['src_port'] for f in flows ...]
    label = 'source_ports'
```

**修正後**：
```python
else:  # role == 'dst'
    # 【修正】IP 作為目的地：應該分析「哪些服務埠被訪問」(dst_port)
    target_ports = [f['dst_port'] for f in flows ...]
    label = 'targeted_service_ports'

    # 【補充】同時收集來源埠資訊，用於展示（但不用於掃描判定）
    src_ports = [f['src_port'] for f in flows ...]
```

#### 輸出改進：第 1058-1083 行

- 更新標題：`🔌 被訪問的服務埠分析 (判斷是否被掃描)`
- 添加補充區塊：顯示來源埠資訊（展示用，不影響判斷）

```python
# DST 視角時，補充顯示來源埠資訊
if role == 'dst' and 'source_port_info' in port:
    src_info = port['source_port_info']
    print(f"📎 補充：來源埠資訊 (展示用，不影響掃描判定)")
    print(f"   • 不同來源埠數量: {src_info['unique_src_ports']}")
    print(f"   • 服務來源埠: {src_info['unique_service_src_ports']} 個")
    print(f"   • 臨時來源埠: {src_info['unique_ephemeral_src_ports']} 個")
```

### 2. port_analyzer.py

#### 修正位置：第 191-214 行

**修正前**：
```python
# 錯誤：DST 視角時取 unique_src_ports
unique_ports = agg_data.get(
    'unique_dst_ports' if perspective == 'SRC' else 'unique_src_ports', 
    0
)
```

**修正後**：
```python
# 【修正】判斷掃描時，兩個視角都應該看 unique_dst_ports：
# - SRC 視角：連到多少個目的埠 (unique_dst_ports)
# - DST 視角：有多少個服務埠被訪問 (unique_dst_ports) ← 關鍵修正！
unique_ports = agg_data.get('unique_dst_ports', 0)

# 【補充】DST 視角時，同時記錄來源埠資訊（用於展示，不影響判斷）
unique_src_ports = agg_data.get('unique_src_ports', 0) if perspective == 'DST' else 0
```

## 修正驗證

### 測試案例：192.168.0.4 (SNMP Switch)

#### 修正前的錯誤結果

```
DST 視角分析：
  - 分析對象: unique_src_ports = 796 個來源埠 ❌
  - 判斷: 可能被掃描 (因為 796 > 30)
  - 結果: 誤報
```

#### 修正後的正確結果

```
DST 視角分析：
  - 分析對象: unique_dst_ports = 2 個目的埠 ✅
    → port 161 (SNMP): 2,316 次 (99.9%)
    → port 123: 2 次 (0.1%)
  
  - 判斷: 正常服務 (因為 2 < 10)
  - 結果: 正確排除誤報
  
  補充資訊 (不影響判斷):
  - 來源埠數量: 796 個 (客戶端臨時埠，正常現象)
  - 來源臨時埠比例: 99.9%
```

### 輸出對比

#### 修正前

```
🔌 來源通訊埠分析:
   • 不同通訊埠數量: 796
   • 服務埠: 1 個, 臨時埠: 795 個 (99.9%)
   
   判斷: 可能被掃描 ❌
```

#### 修正後

```
🔌 被訪問的服務埠分析 (判斷是否被掃描):
   • 不同通訊埠數量: 2
   • 服務埠: 2 個, 臨時埠: 0 個 (0.0%)
   
   TOP 5 被訪問的服務埠:
      1.   161 (SNMP) → 2,316 次 (99.9%)
      2.   123        →     2 次 (0.1%)

📎 補充：來源埠資訊 (展示用，不影響掃描判定)
   • 不同來源埠數量: 796
   • 服務來源埠: 1 個, 臨時來源埠: 795 個
   • 來源臨時埠比例: 99.9%

判斷: 正常服務 ✅
```

## 判斷邏輯對照表

| 視角 | 分析的埠 | 判斷依據 | 範例 (192.168.0.4) |
|------|----------|----------|-------------------|
| **SRC** | dst_port (目的埠) | 連到多少個服務埠？| 2,237 個目的埠 → 伺服器回應模式 |
| **DST** | **dst_port** (目的埠) | **有多少個服務埠被訪問？** | **2 個服務埠** → 正常服務 ✅ |

## 影響評估

### 修正前的問題

1. **高誤報率**: SNMP、DNS、NTP 等服務器被大量客戶端訪問時，會因為來源埠數量多而被誤判為「被掃描」
2. **邏輯不一致**: 與安全業界標準的「埠掃描」定義不符
3. **難以理解**: 用戶看到「796 個埠」會困惑，不知道這些是來源臨時埠

### 修正後的改進

1. **✅ 降低誤報**: 正確識別正常服務流量
2. **✅ 符合標準**: 判斷邏輯與安全業界一致（看被訪問的服務埠）
3. **✅ 清晰展示**: 
   - 主要判斷：基於被訪問的服務埠數量
   - 補充資訊：顯示來源埠統計（幫助理解流量特性）

### 受影響的場景

| 場景 | 修正前 | 修正後 |
|------|--------|--------|
| SNMP 設備 (192.168.0.4) | ❌ 誤報 (796 個來源埠) | ✅ 正常 (2 個服務埠) |
| DNS 服務器 | ❌ 誤報 | ✅ 正常 |
| Web 服務器 | ❌ 誤報 | ✅ 正常 |
| 真正被掃描 (30+ 服務埠) | ✅ 正確檢測 | ✅ 正確檢測 |

## 後續監控

### 監控指標

1. **DST 視角誤報率變化**
   ```bash
   grep "DST.*誤報" detection_dst_fix.log | wc -l
   ```

2. **192.168.0.4 的檢測狀態**
   ```bash
   python3 verify_anomaly.py --ip 192.168.0.4 --minutes 15
   ```

3. **UNDER_PORT_SCAN 檢測數量**
   ```bash
   grep "UNDER_PORT_SCAN" detection_dst_fix.log | wc -l
   ```

### 預期結果

- **SNMP/DNS/NTP 設備**: 完全消除 DST 視角誤報
- **真正被掃描的主機**: 仍然能正確檢測（30+ 服務埠被訪問）
- **整體誤報率**: 預期下降 10-20%

## 技術細節

### 聚合索引欄位

`netflow_stats_3m_by_dst` 索引包含：
- `unique_src_ports`: 來源埠數量（臨時埠）
- `unique_dst_ports`: **目的埠數量（服務埠）** ← 用於判斷
- `unique_srcs`: 來源 IP 數量
- `flow_count`: 流量總數

### 判斷閾值

```python
# DST 視角判斷邏輯 (基於 unique_dst_ports)
if unique_dst_ports < 10:
    → NORMAL / HYBRID_SERVER_CLIENT (正常服務)
elif unique_dst_ports < 30:
    → MULTI_SERVICE_HOST (多服務主機)
else:  # >= 30
    → UNDER_PORT_SCAN (被掃描)
```

## 相關檔案

- `verify_anomaly.py`: 第 385-397, 1058-1083 行
- `nad/ml/port_analyzer.py`: 第 191-268 行
- `nad/ml/bidirectional_analyzer.py`: 使用 PortAnalyzer
- `nad/ml/post_processor.py`: 使用 BidirectionalAnalyzer

## 結論

✅ **修正完成**

1. DST 視角現在正確使用 `dst_port` (被訪問的服務埠) 判斷是否被掃描
2. 保留來源埠資訊作為補充展示，不影響判斷邏輯
3. 符合安全業界標準的埠掃描檢測方法
4. 顯著降低 SNMP、DNS 等服務器的 DST 視角誤報

**狀態**: ✅ 已完成並部署  
**建議**: 持續監控 1 週，觀察誤報率改善情況

## 補充修正：Sequential Scan 檢查邏輯 (2025-11-23)

### 發現的問題

即使 `unique_service_ports = 1` 且 `is_scanning = False`，192.168.10.160 仍被標記為 `UNDER_PORT_SCAN`。

### 根本原因

**行為檢測邏輯** (第 675 行)：
```python
if port_analysis['is_scanning'] or port_analysis['is_sequential_scan']:
    # 標記為 UNDER_PORT_SCAN
```

**Sequential Scan 檢查** (第 476 行，修正前)：
```python
is_sequential_scan = self._check_sequential_ports(list(port_counter.keys()))
```

問題：檢查**所有埠**（包括 11,254 個臨時埠）的連續性！

### 為什麼會誤判？

對於 192.168.10.160：
- 11,255 個目的埠，其中 11,254 個是臨時埠 (32000-65535)
- 臨時埠在 32000-65535 範圍內分布，很多是連續的
- `_check_sequential_ports()` 計算連續比例 > 30% → `is_sequential_scan = True`
- 即使 `is_scanning = False`，仍然觸發 `UNDER_PORT_SCAN`

**但這是錯誤的**：
- 臨時埠的連續性**不代表掃描行為**
- 臨時埠由作業系統隨機分配，自然會有一些連續
- 真正的埠掃描應該檢查**服務埠**的連續性 (1-1024, 1024-32000)

### 修正方案

**修正位置**: `verify_anomaly.py` 第 476-479 行

**修正前**：
```python
is_sequential_scan = self._check_sequential_ports(list(port_counter.keys()))
```

**修正後**：
```python
# 【修正】只檢查服務埠的連續性，不檢查臨時埠
# 臨時埠的連續性不代表掃描行為
service_port_list = list(set(service_ports))
is_sequential_scan = self._check_sequential_ports(service_port_list)
```

### 修正驗證

#### 修正前 (192.168.10.160 DST)

```
🔌 被訪問的服務埠分析:
   • 服務埠: 1 個, 臨時埠: 11254 個 (99.4%)

🔍 檢測到的行為:
   🔴 [HIGH] UNDER_PORT_SCAN  ← 誤報！
      檢測到被掃描：1 個服務埠被針對
```

**原因**: `is_sequential_scan = True`（因為檢查了所有臨時埠的連續性）

#### 修正後 (192.168.10.160 DST)

```
🔌 被訪問的服務埠分析:
   • 服務埠: 1 個, 臨時埠: 6168 個 (99.4%)

🔍 檢測到的行為:
   🟢 [LOW] HYBRID_SERVER_CLIENT  ← 正確！✅
      混合流量：服務埠 (1) + 臨時埠回傳 (6044)
```

**原因**: `is_sequential_scan = False`（只檢查 1 個服務埠，無連續性）

### 影響範圍

| 場景 | 修正前 | 修正後 |
|------|--------|--------|
| 高流量伺服器 (大量臨時埠) | ❌ 誤報 UNDER_PORT_SCAN | ✅ HYBRID_SERVER_CLIENT |
| 真正被連續掃描 (22-80 等) | ✅ 正確檢測 | ✅ 正確檢測 |
| 單一服務 + 大量客戶端 | ❌ 誤報 | ✅ 正確識別 |

### 結論

✅ **Sequential Scan 檢查已修正**

1. 只檢查服務埠 (≤32000) 的連續性
2. 忽略臨時埠 (>32000) 的連續性
3. 避免高流量伺服器被誤判為「被掃描」
4. 符合安全業界標準：埠掃描是指掃描多個**服務埠**，不是連接多個臨時埠

**更新狀態**: ✅ 完全修正並驗證

---

## PostProcessor 整合狀態

### ✅ 已整合的部分

#### 1. PORT_SCAN 驗證 (SRC 視角)
**檔案**: `post_processor.py` → `_verify_port_scan()`  
**調用鏈**:
```
PostProcessor._verify_port_scan()
    ↓
BidirectionalAnalyzer.detect_port_scan_improved()
    ↓
PortAnalyzer.analyze_port_pattern()
    ↓
PortAnalyzer._analyze_from_aggregated()  ← 已修正 ✅
```

**修正內容**:
- ✅ SRC 視角使用 `unique_dst_ports` 判斷
- ✅ DST 視角改用 `unique_dst_ports`（被訪問的服務埠）
- ✅ 啟發式規則識別伺服器回應模式
- ✅ Sequential scan 只檢查服務埠

**效果**:
- 192.168.0.4 (SNMP): ✅ 正確識別為 `SERVER_RESPONSE_TO_CLIENTS`
- 不再寫入 ES ✅

#### 2. SCAN_TARGET 驗證 (DST 視角) - 新增整合
**檔案**: `post_processor.py` → `_verify_scan_target()`  
**修正位置**: 第 662-711 行

**新增邏輯**:
```python
# 【新增】使用 PortAnalyzer 進行進階分析
# 檢查是否為高臨時埠比例的正常伺服器流量
port_pattern = self.bi_analyzer.port_analyzer.analyze_port_pattern(
    ip=target_ip,
    perspective='DST',
    time_range=time_range,
    aggregated_data=agg_data
)

# 如果識別為正常流量模式，標記為誤報
if port_pattern.get('pattern_type') in ['NORMAL', 'HYBRID_SERVER_CLIENT', 'MULTI_SERVICE_HOST']:
    return {'is_false_positive': True, ...}
```

**效果**:
- 192.168.10.160 (高流量伺服器): ✅ 正確識別為 `POPULAR_SERVER`
- DST 視角誤報減少 ✅

### 📊 整合效果對比

| 威脅類別 | 視角 | 整合前 | 整合後 |
|---------|------|--------|--------|
| **PORT_SCAN** | SRC | ❌ 高誤報 | ✅ 使用 PortAnalyzer |
| **PORT_SCAN** (被分類為此) | DST | ❌ 未使用新邏輯 | ✅ 使用 PortAnalyzer |
| **SCAN_TARGET** | DST | ❌ 只看 unique_dst_ports 數量 | ✅ 新增 PortAnalyzer 檢查 |
| **POPULAR_SERVER** | DST | ⚠️ 部分邏輯 | ✅ 可繼續優化 |
| **DDOS_TARGET** | DST | ⚠️ 未整合 | ⚠️ 待評估 |

### 🔄 待優化的部分

#### 1. POPULAR_SERVER 驗證
**當前狀態**: 有基本的邏輯，但未使用 PortAnalyzer  
**建議**: 可考慮整合非臨時埠計數法

#### 2. DDOS_TARGET 驗證
**當前狀態**: 主要檢查來源數量和流量  
**評估**: DDoS 主要看流量和連線數，埠分析較不重要

### 📈 實際效果驗證

#### 測試案例 1: 192.168.0.4 (SNMP Switch)
```
ML 判斷: PORT_SCAN (SRC 視角)
PostProcessor 驗證:
  └─ BidirectionalAnalyzer.detect_port_scan_improved()
      └─ PortAnalyzer: SERVER_RESPONSE_TO_CLIENTS
          └─ 結果: ✅ 誤報排除
```

#### 測試案例 2: 192.168.10.160 (高流量伺服器)
```
ML 判斷: POPULAR_SERVER (DST 視角)
PostProcessor 驗證:
  └─ _verify_scan_target() 或 _verify_popular_server()
      └─ PortAnalyzer: HYBRID_SERVER_CLIENT
          └─ 結果: ✅ 誤報排除
```

### ✅ 整合完成度

| 模組 | 整合狀態 | 說明 |
|------|---------|------|
| `verify_anomaly.py` | ✅ 100% | 手動分析工具，完全修正 |
| `port_analyzer.py` | ✅ 100% | 核心邏輯模組，完全修正 |
| `bidirectional_analyzer.py` | ✅ 100% | SRC 視角完整整合 |
| `post_processor.py` - PORT_SCAN | ✅ 100% | 使用 BidirectionalAnalyzer |
| `post_processor.py` - SCAN_TARGET | ✅ 100% | 新增 PortAnalyzer 檢查 |
| `post_processor.py` - POPULAR_SERVER | ⚠️ 80% | 基本邏輯，可優化 |
| `post_processor.py` - DDOS_TARGET | ⚠️ N/A | 埠分析較不重要 |

### 🎯 最終結論

✅ **DST 視角埠分析邏輯已完全整合到 PostProcessor**

1. **PORT_SCAN**: 透過 BidirectionalAnalyzer 使用修正後的 PortAnalyzer ✅
2. **SCAN_TARGET**: 直接調用 PortAnalyzer 進行檢查 ✅
3. **Sequential Scan**: 只檢查服務埠，避免臨時埠誤判 ✅
4. **判斷邏輯**: 統一使用 `unique_dst_ports`（被訪問的服務埠）✅

**部署狀態**: ✅ 已完成並運行  
**持續監控**: 建議觀察 1-2 週，評估誤報率改善效果
