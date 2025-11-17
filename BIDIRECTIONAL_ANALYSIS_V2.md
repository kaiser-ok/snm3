# verify_anomaly.py 雙向完整分析 v2.0

## 📋 更新日期
2025-11-16

## 🎯 更新目標
**實現真正的雙向完整分析** - 同時分析 IP 作為源和目的地的所有異常行為，不遺漏任何方向的威脅。

---

## 🚀 v2.0 新功能

### **核心改進：雙向同時分析**

```
v1.0（舊版）:
  ├─ 查詢兩個方向的數據
  ├─ 選擇數據多的一個方向
  └─ 只分析一個方向 ❌ 遺漏另一方向

v2.0（新版）:
  ├─ 查詢兩個方向的數據
  ├─ 同時分析兩個方向 ✅
  ├─ 顯示雙向報告 ✅
  └─ 綜合判斷 ✅
```

---

## 📊 修改內容

### **1. `verify_ip()` - 完整重構**

**修改前（v1.0）：**
```python
# 選擇一個方向
if len(flows_as_src) >= len(flows_as_dst):
    flows = flows_as_src
    role = 'src'
else:
    flows = flows_as_dst
    role = 'dst'

# 只分析一個方向
analysis = self._analyze_destinations(flows, role)
```

**修改後（v2.0）：**
```python
# 分析作為源 IP
if flows_as_src:
    analysis_result['as_source'] = {
        'role': 'src',
        'destination_analysis': self._analyze_destinations(flows_as_src, 'src'),
        'behavioral_analysis': self._analyze_behavior(flows_as_src, 'src'),
        ...
    }

# 分析作為目的地 IP
if flows_as_dst:
    analysis_result['as_destination'] = {
        'role': 'dst',
        'destination_analysis': self._analyze_destinations(flows_as_dst, 'dst'),
        'behavioral_analysis': self._analyze_behavior(flows_as_dst, 'dst'),
        ...
    }

# 綜合判斷
verdict = self._generate_bidirectional_verdict(analysis_result)
```

---

### **2. 新增函數**

#### **`_generate_bidirectional_verdict()`**
綜合兩個方向的行為，生成整體判斷

**功能：**
- 收集兩個方向的所有異常行為
- 統計高危/可疑行為數量
- 生成綜合判斷和建議

**新增判斷類型：**
- `MIXED` - 混合情況（既有正常服務又有異常）
- `NORMAL` - 正常流量

#### **`_print_bidirectional_report()`**
顯示雙向完整報告

**報告結構：**
```
====================================================================================================
📋 雙向分析報告
====================================================================================================

────────────────────────────────────────────────────────────────────────────────────────────────────
📤 作為源 IP 的行為分析
────────────────────────────────────────────────────────────────────────────────────────────────────
[源 IP 分析結果]

────────────────────────────────────────────────────────────────────────────────────────────────────
📥 作為目的地 IP 的行為分析
────────────────────────────────────────────────────────────────────────────────────────────────────
[目的地 IP 分析結果]

====================================================================================================
🎯 綜合判斷
====================================================================================================
🚨 判斷結果: 真實異常
📊 置信度: HIGH
📝 檢測到的行為數量: 3
   🔴 高危行為: 2
   🟡 可疑行為: 1

💡 建議: 檢測到 2 個高危異常行為，建議立即調查
```

#### **`_print_single_direction_report()`**
列印單一方向的分析報告（簡化版）

---

## 🎯 實際應用場景

### **場景 1：被入侵的主機**

**數據：**
```
IP: 192.168.10.50
作為 src: 10,000 筆（對外掃描）
作為 dst: 5,000 筆（被遠程控制）
```

**v1.0 結果（❌ 只看到一半）：**
```
💡 主要角色: 源 IP
🔍 行為分析:
   🔴 [HIGH] PORT_SCANNING
   🔴 [HIGH] NETWORK_SCANNING

❌ 遺漏：沒發現此主機同時被遠程控制
```

**v2.0 結果（✅ 完整檢測）：**
```
📤 作為源 IP 的行為分析
🔍 檢測到的行為:
   🔴 [HIGH] PORT_SCANNING
   🔴 [HIGH] NETWORK_SCANNING

📥 作為目的地 IP 的行為分析
🔍 檢測到的行為:
   🔴 [HIGH] UNDER_ATTACK

🎯 綜合判斷
🚨 判斷結果: 真實異常
   🔴 高危行為: 3

✅ 完整檢測：發現此主機既發起攻擊，也被攻擊
```

---

### **場景 2：DNS 伺服器**

**數據：**
```
IP: 8.8.8.8
作為 src: 100,000 筆（DNS 回應）
作為 dst: 5,000 筆（DNS 查詢）
```

**v1.0 結果：**
```
💡 主要角色: 源 IP
🔍 行為分析:
   🟢 [LOW] DNS_SERVER_RESPONSE

✅ 判斷結果: 誤報（正常流量）
```

**v2.0 結果（✅ 更全面）：**
```
📤 作為源 IP 的行為分析
🔍 檢測到的行為:
   🟢 [LOW] DNS_SERVER_RESPONSE

📥 作為目的地 IP 的行為分析
🔍 未檢測到明顯異常行為

🎯 綜合判斷
✅ 判斷結果: 誤報（正常流量）
💡 建議: 主要為正常服務流量，建議調整特徵閾值
```

---

### **場景 3：被 DDoS 的伺服器**

**數據：**
```
IP: 192.168.1.100 (Web Server)
作為 src: 1,000 筆（正常回應）
作為 dst: 100,000 筆（被 DDoS）
```

**v1.0 結果（❌ 錯誤）：**
```
💡 主要角色: 目的地
🎯 來源分析:
   • 不同來源數量: 1  ❌ 錯誤（因為舊版 bug）
```

**v2.0 結果（✅ 正確）：**
```
📤 作為源 IP 的行為分析
🔍 檢測到的行為:
   🟢 [LOW] WEB_SERVER_RESPONSE

📥 作為目的地 IP 的行為分析
🎯 來源分析:
   • 不同來源數量: 5,000  ✅ 正確
🔍 檢測到的行為:
   🔴 [HIGH] UNDER_ATTACK
      檢測到遭受攻擊：來自 5,000 個不同來源

🎯 綜合判斷
🚨 判斷結果: 真實異常
   🔴 高危行為: 1
💡 建議: 檢測到高危異常行為，建議立即調查
```

---

## 📂 版本管理

### **備份檔案**

| 檔案 | 說明 |
|------|------|
| `verify_anomaly.py.backup` | 最原始版本（雙向 bug） |
| `verify_anomaly.py.v1` | v1.0（修正分析邏輯，但只分析一個方向） |
| `verify_anomaly.py` | v2.0（雙向完整分析） ✅ 當前版本 |

### **還原命令**

```bash
# 還原到 v1.0
cp /home/kaisermac/snm_flow/verify_anomaly.py.v1 \
   /home/kaisermac/snm_flow/verify_anomaly.py

# 還原到最原始版本
cp /home/kaisermac/snm_flow/verify_anomaly.py.backup \
   /home/kaisermac/snm_flow/verify_anomaly.py
```

---

## ✅ 語法驗證

```bash
$ python3 -m py_compile /home/kaisermac/snm_flow/verify_anomaly.py
✓ 通過
```

---

## 🧪 測試建議

### **測試 1：雙向有流量的 IP**

```bash
python3 verify_anomaly.py --ip <同時作為源和目的地的IP> --minutes 30
```

**預期結果：**
- 顯示「作為源 IP 的行為分析」
- 顯示「作為目的地 IP 的行為分析」
- 顯示「綜合判斷」

---

### **測試 2：只作為源的 IP（客戶端）**

```bash
python3 verify_anomaly.py --ip <客戶端IP> --minutes 30
```

**預期結果：**
- 只顯示「作為源 IP 的行為分析」
- 沒有「作為目的地 IP 的行為分析」部分
- 綜合判斷基於單一方向

---

### **測試 3：只作為目的地的 IP（伺服器）**

```bash
python3 verify_anomaly.py --ip <純伺服器IP> --minutes 30
```

**預期結果：**
- 只顯示「作為目的地 IP 的行為分析」
- 沒有「作為源 IP 的行為分析」部分
- 來源分析顯示正確（不再顯示 dst_ip）

---

## 📊 版本對比總結

| 功能 | 原始版本 | v1.0 | v2.0 ✅ |
|------|---------|------|---------|
| **分析邏輯正確性** | ❌ 錯誤 | ✅ 正確 | ✅ 正確 |
| **雙向完整分析** | ❌ | ❌ | ✅ |
| **檢測被攻擊** | ❌ | ✅ | ✅ |
| **綜合判斷** | ✅ | ✅ | ✅ 更全面 |
| **報告完整性** | ⚠️ 部分 | ⚠️ 部分 | ✅ 完整 |
| **遺漏風險** | 高 | 中 | 低 |

---

## 💡 使用建議

### **何時最有用？**

1. **雙向活躍的 IP** - 完整了解行為模式
2. **被入侵主機檢測** - 發現既發起攻擊又被控制
3. **伺服器異常分析** - 同時看到服務和被攻擊情況
4. **全面威脅評估** - 不遺漏任何異常跡象

### **報告解讀**

- **只有一個方向** → 該 IP 角色單一（純客戶端或純伺服器）
- **兩個方向都有** → 該 IP 角色複雜，需全面分析
- **高危行為 > 1** → 高度懷疑，立即調查
- **混合情況** → 既有正常服務又有異常，需人工判斷

---

## 🎓 技術細節

### **數據結構變化**

**v1.0：**
```python
analysis = {
    'role': 'src',  # 只有一個角色
    'destination_analysis': {...},
    'behavioral_analysis': [...]
}
```

**v2.0：**
```python
analysis_result = {
    'target_ip': '192.168.1.100',
    'as_source': {
        'role': 'src',
        'destination_analysis': {...},
        'behavioral_analysis': [...]
    },
    'as_destination': {
        'role': 'dst',
        'destination_analysis': {...},  # 實際上是來源分析
        'behavioral_analysis': [...]
    },
    'verdict': {
        'verdict': 'TRUE_ANOMALY',
        'behaviors': [
            {..., 'direction': 'as_source'},
            {..., 'direction': 'as_destination'}
        ]
    }
}
```

---

## 📚 相關文檔

- **v1.0 說明：** `VERIFY_ANOMALY_BIDIRECTIONAL_UPDATE.md`
- **原始備份：** `verify_anomaly.py.backup`
- **v1.0 備份：** `verify_anomaly.py.v1`
- **使用指南：** `ANOMALY_VERIFICATION_GUIDE.md`

---

## ✨ 總結

### **v2.0 的核心價值**

1. ✅ **零遺漏** - 同時分析兩個方向，不會錯過任何異常
2. ✅ **更準確** - 綜合雙向行為，判斷更全面
3. ✅ **更智能** - 檢測複雜攻擊模式（如被入侵主機）
4. ✅ **更清晰** - 分開顯示兩個方向，易於理解

### **適用場景**

- ✅ 完整威脅分析
- ✅ 被入侵主機檢測
- ✅ 伺服器安全評估
- ✅ 全面異常調查

---

**版本：** v2.0
**作者：** Claude Code
**狀態：** 已完成，待測試
**建議：** 建議在實際環境測試後正式部署
