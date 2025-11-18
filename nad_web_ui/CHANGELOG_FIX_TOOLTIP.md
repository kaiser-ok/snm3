# 修改記錄 - 修正 Top 10 異常 IP 的 Tooltip 說明

**日期**: 2025-11-17
**修改者**: Claude Code
**問題描述**: Top 10 異常 IP 表格中，「平均置信度」欄位的 tooltip 說明錯誤，內容應該是「平均異常分數」的說明

---

## 🐛 問題說明

### 修改前
- **平均異常分數**欄位：沒有 tooltip 說明
- **平均置信度**欄位：tooltip 顯示「系統關注閥值：≥60%」

### 問題
「系統關注閥值：≥60%」應該是指「平均異常分數 ≥ 0.6」，而不是「平均置信度 ≥ 60%」

---

## 🔧 修改內容

**檔案**: `/home/kaisermac/nad_web_ui/frontend/src/views/Dashboard.vue`

### 修改位置：Top 10 異常 IP 表格 (Line 57-105)

**修改前**:
```vue
<el-table-column label="平均異常分數" width="140" sortable>
  <template #default="{ row }">
    <el-tag :type="getScoreType(row.avg_anomaly_score)">
      {{ row.avg_anomaly_score.toFixed(4) }}
    </el-tag>
  </template>
</el-table-column>

<el-table-column width="140" sortable>
  <template #header>
    <span>平均置信度</span>
    <el-tooltip placement="top" raw-content>
      <template #content>
        <div style="max-width: 300px;">
          模型對異常判斷的確信程度，越高表示越確定為異常<br/>
          • 最大值：100%<br/>
          • 系統關注閥值：≥60%
        </div>
      </template>
      <el-icon style="margin-left: 4px; cursor: help;">
        <InfoFilled />
      </el-icon>
    </el-tooltip>
  </template>
  <template #default="{ row }">
    {{ (row.avg_confidence * 100).toFixed(0) }}%
  </template>
</el-table-column>
```

**修改後**:
```vue
<el-table-column width="140" sortable>
  <template #header>
    <span>平均異常分數</span>
    <el-tooltip placement="top" raw-content>
      <template #content>
        <div style="max-width: 300px;">
          Isolation Forest 計算的異常分數<br/>
          • 數值範圍：0.0 ~ 1.0<br/>
          • 系統關注閥值：≥0.6
        </div>
      </template>
      <el-icon style="margin-left: 4px; cursor: help;">
        <InfoFilled />
      </el-icon>
    </el-tooltip>
  </template>
  <template #default="{ row }">
    <el-tag :type="getScoreType(row.avg_anomaly_score)">
      {{ row.avg_anomaly_score.toFixed(4) }}
    </el-tag>
  </template>
</el-table-column>

<el-table-column width="140" sortable>
  <template #header>
    <span>平均置信度</span>
    <el-tooltip placement="top" raw-content>
      <template #content>
        <div style="max-width: 300px;">
          分類器對威脅類型判斷的確信程度<br/>
          • 數值範圍：0% ~ 100%<br/>
          • 越高表示分類越可靠
        </div>
      </template>
      <el-icon style="margin-left: 4px; cursor: help;">
        <InfoFilled />
      </el-icon>
    </el-tooltip>
  </template>
  <template #default="{ row }">
    {{ (row.avg_confidence * 100).toFixed(0) }}%
  </template>
</el-table-column>
```

---

## ✅ 修改說明

### 平均異常分數 Tooltip（新增）
```
Isolation Forest 計算的異常分數
• 數值範圍：0.0 ~ 1.0
• 系統關注閥值：≥0.6
```

**說明**:
- 這是 Isolation Forest 模型計算的原始異常分數
- 範圍是 0.0 到 1.0
- 系統將 ≥0.6 的分數標記為需要關注的異常

### 平均置信度 Tooltip（修正）
```
Classifier 對威脅類型分類的可靠度評分
• 數值範圍：0% ~ 100%
• 越高表示威脅類型判斷越可靠
```

**說明**:
- 這是 Anomaly Classifier 對威脅類型分類的可靠度評分
- 範圍是 0% 到 100%
- 置信度越高，表示分類器越確定該異常屬於某種威脅類型（如：埠掃描、DDoS、數據外洩等）
- 每種威脅類型都有自己的置信度計算函數（如：`_calculate_port_scan_confidence()`）

---

## 📊 兩者的區別

| 項目 | 平均異常分數 | 平均置信度 |
|------|-------------|-----------|
| **來源** | Isolation Forest 模型 | 異常分類器 |
| **用途** | 判斷是否為異常 | 判斷異常的類型 |
| **數值範圍** | 0.0 ~ 1.0 | 0% ~ 100% |
| **關注閥值** | ≥0.6 | 無固定閥值 |
| **意義** | 越高越異常 | 越高分類越可靠 |

---

## 🎯 實例說明

### 範例 1：高異常分數 + 高置信度
```
IP: 192.168.10.135
平均異常分數: 0.7845  ← 明顯異常
平均置信度: 89%      ← 很確定是「埠掃描」
威脅類型: 埠掃描
```
**解讀**: 系統非常確定這是一個埠掃描異常

### 範例 2：高異常分數 + 低置信度
```
IP: 192.168.10.160
平均異常分數: 0.8234  ← 明顯異常
平均置信度: 52%      ← 不太確定類型
威脅類型: 未知異常
```
**解讀**: 確定是異常，但無法明確分類威脅類型

### 範例 3：中等異常分數 + 高置信度
```
IP: 192.168.10.180
平均異常分數: 0.6512  ← 輕微異常
平均置信度: 91%      ← 很確定是「正常高流量」
威脅類型: 正常高流量
```
**解讀**: 分數略高但確定是正常的高流量，可能是合法服務

---

## 🧪 驗證方式

1. 前往 Dashboard 頁面
2. 查看 Top 10 異常 IP 表格
3. 將滑鼠移到「平均異常分數」旁的 ℹ️ 圖示
   - ✅ 應該顯示：「Isolation Forest 計算的異常分數」
   - ✅ 應該顯示：「系統關注閥值：≥0.6」
4. 將滑鼠移到「平均置信度」旁的 ℹ️ 圖示
   - ✅ 應該顯示：「分類器對威脅類型判斷的確信程度」
   - ✅ 應該顯示：「數值範圍：0% ~ 100%」

---

## 📝 相關檔案

- **Dashboard**: `/home/kaisermac/nad_web_ui/frontend/src/views/Dashboard.vue`

---

**修改完成時間**: 2025-11-17
**狀態**: ✅ 已完成
