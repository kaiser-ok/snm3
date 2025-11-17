# verify_anomaly.py 雙向分析更新

## 📋 更新日期
2025-11-16

## 🎯 更新目的
修正 `verify_anomaly.py` 沒有正確處理 IP 作為目的地（destination）情況的問題。

---

## 🔍 原始問題

### **問題描述**
原始程式只選擇數據量較多的角色（src 或 dst）進行分析，但分析邏輯固定查看 `dst_ip` 和 `dst_port`，導致：

1. **當 IP 作為 destination 時**，分析結果錯誤
2. **無法檢測被攻擊場景**（DDoS、被掃描等）
3. **遺漏雙向異常行為**

### **錯誤範例**

```python
# 原始邏輯
if len(flows_as_src) >= len(flows_as_dst):
    flows = flows_as_src  # 選擇數據多的
    role = 'src'
else:
    flows = flows_as_dst
    role = 'dst'

# 但分析時固定看 dst_ip
def _analyze_destinations(self, flows):
    dst_ips = [f['dst_ip'] for f in flows]  # ❌ 錯誤！
```

**實際案例：被 DDoS 攻擊的 IP**

```
IP: 192.168.1.10 (Web Server)
作為 dst: 100,000 筆流量
  - 來自 5,000 個不同攻擊者
  - 目的埠: 80

錯誤分析結果:
  - dst_ips 全部是 192.168.1.10
  - unique_destinations = 1  ❌ 錯誤！應該是 5,000 個來源
  - 誤判為「高度集中」而非「被大量來源攻擊」
```

---

## ✅ 修正內容

### **1. `_analyze_destinations()` - 支援雙向分析**

**修改前：**
```python
def _analyze_destinations(self, flows):
    dst_ips = [f['dst_ip'] for f in flows if 'dst_ip' in f]
    # 固定分析目的地
```

**修改後：**
```python
def _analyze_destinations(self, flows, role='src'):
    if role == 'src':
        # IP 作為源：分析它連到哪些目的地
        target_ips = [f['dst_ip'] for f in flows if 'dst_ip' in f]
        label = 'destinations'
    else:  # role == 'dst'
        # IP 作為目的地：分析誰連到它（來源分析）
        target_ips = [f['src_ip'] for f in flows if 'src_ip' in f]
        label = 'sources'
```

---

### **2. `_analyze_ports()` - 支援雙向分析**

**修改前：**
```python
def _analyze_ports(self, flows):
    dst_ports = [f['dst_port'] for f in flows ...]
    # 固定分析目的埠
```

**修改後：**
```python
def _analyze_ports(self, flows, role='src'):
    if role == 'src':
        # IP 作為源：分析目的通訊埠
        target_ports = [f['dst_port'] for f in flows ...]
        label = 'destination_ports'
    else:  # role == 'dst'
        # IP 作為目的地：分析來源通訊埠
        target_ports = [f['src_port'] for f in flows ...]
        label = 'source_ports'
```

---

### **3. `_analyze_behavior()` - 新增被攻擊行為檢測**

**新增的行為類型：**

| 行為類型 | 觸發角色 | 嚴重性 | 說明 |
|---------|---------|--------|------|
| `UNDER_PORT_SCAN` | dst | HIGH | 檢測到被通訊埠掃描 |
| `UNDER_ATTACK` | dst | HIGH | 檢測到遭受攻擊（來自大量來源）|
| `LARGE_DATA_RECEIVE` | dst | MEDIUM | 接收大量數據 |

**修改前：**
```python
def _analyze_behavior(self, flows):
    # 只檢測主動攻擊行為
    if port_analysis['is_scanning']:
        behaviors.append({'type': 'PORT_SCANNING', ...})
```

**修改後：**
```python
def _analyze_behavior(self, flows, role='src'):
    if port_analysis['is_scanning']:
        if role == 'src':
            behaviors.append({
                'type': 'PORT_SCANNING',
                'description': f"檢測到通訊埠掃描：{unique_ports} 個不同目的埠"
            })
        else:  # role == 'dst'
            behaviors.append({
                'type': 'UNDER_PORT_SCAN',
                'description': f"檢測到被掃描：來自 {unique_ports} 個不同來源埠"
            })
```

---

### **4. `verify_ip()` - 傳遞 role 參數**

**修改：**
```python
# 執行多維度分析（傳入 role 參數）
analysis = {
    'src_ip': src_ip,
    'role': role,  # 新增
    'destination_analysis': self._analyze_destinations(flows, role),
    'port_analysis': self._analyze_ports(flows, role),
    'behavioral_analysis': self._analyze_behavior(flows, role),
}
```

---

### **5. `_print_report()` - 動態標籤顯示**

**修改前：**
```python
print(f"🎯 目的地分析:")
print(f"   • 不同目的地數量: {dst['unique_destinations']}")
```

**修改後：**
```python
if role == 'src':
    title = "🎯 目的地分析:"
    count_label = "不同目的地數量"
else:  # role == 'dst'
    title = "🎯 來源分析:"
    count_label = "不同來源數量"

print(title)
print(f"   • {count_label}: {dst['unique_destinations']}")
```

---

## 📊 修正前後對比

### **場景：被 DDoS 攻擊的伺服器**

**數據：**
```
IP: 192.168.1.100
作為 dst: 100,000 筆流量
  - 來源: 5,000 個不同 IP
  - 目的埠: 80
```

#### **修正前（錯誤）**

```
🎯 目的地分析:
   • 不同目的地數量: 1
   • 目的地分散度: 0.00001
   ⚠️  連線高度集中（疑似定向攻擊）  ❌ 錯誤判斷

🔍 行為分析:
   🟢 [LOW] NORMAL_SERVICE  ❌ 完全誤判
```

#### **修正後（正確）**

```
🎯 來源分析:  ✅ 正確標籤
   • 不同來源數量: 5,000  ✅ 正確數據
   • 來源分散度: 0.05
   ⚠️  來源高度分散（疑似遭受攻擊）  ✅ 正確判斷

🔌 來源通訊埠分析:  ✅ 正確標籤
   • 不同來源通訊埠數量: 4,500

🔍 行為分析:
   🔴 [HIGH] UNDER_ATTACK  ✅ 正確檢測
      檢測到遭受攻擊：來自 5,000 個不同來源
```

---

## 🎯 新增的異常檢測能力

### **1. 被通訊埠掃描**
```python
behaviors.append({
    'type': 'UNDER_PORT_SCAN',
    'severity': 'HIGH',
    'description': "檢測到被掃描：來自 X 個不同來源埠"
})
```

### **2. 遭受攻擊（DDoS）**
```python
behaviors.append({
    'type': 'UNDER_ATTACK',
    'severity': 'HIGH',
    'description': "檢測到遭受攻擊：來自 X 個不同來源"
})
```

### **3. 接收大量數據**
```python
behaviors.append({
    'type': 'LARGE_DATA_RECEIVE',
    'severity': 'MEDIUM',
    'description': "接收大量數據：X GB 來自少數來源"
})
```

---

## 🔄 備份與還原

### **備份位置**
```bash
/home/kaisermac/snm_flow/verify_anomaly.py.backup
```

### **還原命令**
```bash
cp /home/kaisermac/snm_flow/verify_anomaly.py.backup \
   /home/kaisermac/snm_flow/verify_anomaly.py
```

---

## ✅ 測試驗證

### **語法檢查**
```bash
python3 -m py_compile /home/kaisermac/snm_flow/verify_anomaly.py
# ✓ 通過
```

### **建議測試場景**

#### **測試 1: 作為源 IP（正常）**
```bash
python3 verify_anomaly.py --ip <某個客戶端IP> --minutes 30
```

**預期結果：**
- 顯示「目的地分析」
- 顯示「目的通訊埠分析」

#### **測試 2: 作為目的地 IP（伺服器）**
```bash
python3 verify_anomaly.py --ip <某個伺服器IP> --minutes 30
```

**預期結果：**
- 顯示「來源分析」✅
- 顯示「來源通訊埠分析」✅
- 如果被攻擊，顯示 `UNDER_ATTACK` ✅

#### **測試 3: 被掃描的伺服器**
```bash
# 找一個被掃描過的 IP
python3 verify_anomaly.py --ip <被掃描IP> --minutes 30
```

**預期結果：**
- 檢測到 `UNDER_PORT_SCAN` ✅

---

## 📚 相關文檔

- **原始程式：** `verify_anomaly.py.backup`
- **修改後程式：** `verify_anomaly.py`
- **使用指南：** `ANOMALY_VERIFICATION_GUIDE.md`
- **Isolation Forest 指南：** `ISOLATION_FOREST_GUIDE.md`

---

## 🎓 總結

### **修正內容**
1. ✅ 新增 `role` 參數到所有分析函數
2. ✅ 根據角色動態選擇分析欄位（src_ip/dst_ip, src_port/dst_port）
3. ✅ 新增 3 種被動攻擊檢測類型
4. ✅ 更新報告顯示，使用正確的標籤

### **修正效果**
- ✅ 正確分析 IP 作為 destination 的情況
- ✅ 能夠檢測 DDoS 攻擊、被掃描等被動威脅
- ✅ 報告標籤清晰，不會誤導使用者
- ✅ 向下兼容，不影響原有功能

### **待完成（可選）**
- [ ] 實現完整雙向分析（同時顯示兩個方向）
- [ ] 新增雙向異常關聯分析
- [ ] 整合到 `tune_thresholds.py`

---

**更新人員：** Claude Code
**審核狀態：** 待測試
**版本：** v1.1
