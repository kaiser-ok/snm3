# AI 報告 PDF 功能增強

## 修改內容

### 1. PDF 內容擴充

**修改前：**
- PDF 只包含 AI 分析報告文字

**修改後：**
PDF 包含完整的分析報告，依序包含：
1. **報告標題與基本資訊**
   - 製作日期
   - 分析 IP
   - 設備類型

2. **🚨 威脅評估**（如果有）
   - 威脅類型
   - 嚴重性與優先級
   - 置信度
   - 檢測時間
   - 描述
   - 關鍵指標
   - 建議行動

3. **📊 流量統計摘要**
   - 分析時間範圍
   - 時間長度
   - 總流量數、封包數、位元組
   - 平均封包大小
   - 不重複目的地、來源埠、目的埠
   - 埠分散度

4. **🎯 Top N 通訊目的地**
   - 目的 IP
   - 流量數
   - 總位元組
   - 佔比

5. **🔌 Top N 目的埠號**
   - 埠號
   - 連線數
   - 佔比

6. **📡 協定分佈**
   - 協定編號與名稱
   - 流量數
   - 佔比

7. **🤖 AI 深度分析**
   - OpenAI 生成的安全分析報告（原有內容）

### 2. 網頁顯示

**不變：**
- 網頁上的所有內容保持原樣
- 威脅評估、流量統計、Top N 等資訊依然在主頁面顯示

**改進：**
- AI 報告對話框中的 PDF 預覽包含完整分析資訊
- 下載的 PDF 包含所有統計數據和 AI 分析

### 3. 樣式優化

新增 PDF 專用樣式：

```css
/* PDF 區塊 */
.pdf-section {
  margin: 24px 0;
  page-break-inside: avoid;  /* 避免跨頁斷開 */
}

/* PDF 表格 */
.pdf-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}

/* 偶數行背景色 */
.pdf-table tbody tr:nth-child(even) {
  background-color: #fafafa;
}
```

### 4. 數據結構

PDF 使用的資料來源：

```javascript
// 威脅評估
results.threat_classification {
  severity_emoji,
  class_name,
  class_name_en,
  severity,
  priority,
  confidence,
  detection_time,
  description,
  indicators: [],
  response: []
}

// 流量統計
results.summary {
  total_flows,
  total_packets,
  total_bytes,
  avg_bytes,
  unique_destinations,
  unique_src_ports,
  unique_dst_ports
}

// Top 目的地
results.details.top_destinations [
  { dst_ip, flow_count, total_bytes }
]

// 埠號分佈
results.details.port_distribution {
  "port": count
}

// 協定分佈
results.details.protocol_breakdown {
  "protocol_number": count
}
```

## 影響的檔案

### 前端
- `frontend/src/views/IPAnalysis.vue`
  - 修改 `#pdf-content` 區塊，增加威脅評估、統計摘要、Top N 表格
  - 新增 `.pdf-section`、`.pdf-table` 等樣式

## 使用方式

### 步驟 1: 執行 IP 分析
1. 在 Dashboard 或 IP Analysis 頁面執行 IP 分析
2. 查看分析結果

### 步驟 2: 生成 AI 報告
1. 點擊「AI 安全報告」按鈕
2. 等待 AI 分析完成（需要設定 `OPENAI_API_KEY`）

### 步驟 3: 下載 PDF
1. 在 AI 報告對話框中，點擊「下載 PDF 報告」按鈕
2. PDF 將包含：
   - 威脅評估（如果有）
   - 流量統計摘要
   - Top N 通訊目的地
   - Top N 目的埠號
   - 協定分佈
   - AI 深度分析

### PDF 檔案命名

```
AI安全分析報告_<IP>_<日期時間>.pdf

範例：
AI安全分析報告_192.168.10.135_2025-11-16_14-03-25.pdf
```

## 範例報告結構

```
╔══════════════════════════════════════════════════════╗
║          AI 安全分析報告                              ║
║                                                      ║
║  製作日期: 2025/11/16 14:03:25                       ║
║  分析 IP: 192.168.10.135                             ║
║  設備類型: 🏭 伺服器群組                              ║
╚══════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🚨 威脅評估
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

威脅類型：⚠️ 掃描行為 (Port Scanning)
嚴重性：MEDIUM | 優先級：2
置信度：85.5%
檢測時間：2025/11/16 14:00:00
描述：此 IP 顯示出典型的埠號掃描特徵...

🔍 關鍵指標：
• 高埠號分散度 (0.75)
• 目標多個不同目的地
• 短時間內大量連線

💡 建議行動：
• 監控此 IP 的後續活動
• 檢查是否為授權的安全掃描

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 流量統計摘要
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

分析時間範圍：2025/11/16 13:00:00 ~ 2025/11/16 14:00:00
時間長度：60.0 分鐘
總流量數：15,234 flows
總封包數：45,678 packets
總位元組：12.34 GB
...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎯 Top 10 通訊目的地
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

┌────┬─────────────────┬──────────┬──────────┬────────┐
│ #  │ 目的 IP         │ 流量數   │ 總位元組 │ 佔比   │
├────┼─────────────────┼──────────┼──────────┼────────┤
│ 1  │ 192.168.10.100  │ 5,234    │ 3.45 GB  │ 28.5%  │
│ 2  │ 192.168.10.101  │ 3,456    │ 2.13 GB  │ 17.3%  │
│ 3  │ 192.168.10.102  │ 2,345    │ 1.56 GB  │ 12.6%  │
...
└────┴─────────────────┴──────────┴──────────┴────────┘

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🤖 AI 深度分析
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[OpenAI 生成的分析內容...]

```

## 技術細節

### PDF 生成流程

1. **HTML 內容準備**
   - 所有數據渲染到 `#pdf-content` div
   - 使用 Vue 模板渲染表格和文字

2. **轉換為圖片**
   ```javascript
   const canvas = await html2canvas(element, {
     scale: 2,        // 2倍解析度，確保清晰
     useCORS: true,
     backgroundColor: '#ffffff'
   })
   ```

3. **生成 PDF**
   ```javascript
   const pdf = new jsPDF({
     orientation: 'portrait',
     unit: 'mm',
     format: 'a4'
   })
   ```

4. **處理多頁**
   - 自動計算內容高度
   - 超過一頁時自動分頁
   - 使用 `page-break-inside: avoid` 避免表格跨頁斷開

### 相容性

- ✅ Chrome / Edge
- ✅ Firefox
- ✅ Safari
- ⚠️ IE11 不支援（但整個 Vue 3 應用都不支援 IE11）

## 建置驗證

```bash
cd frontend
npm run build
# ✓ built in 36.80s
```

構建成功，無錯誤。

## 後續改進建議

1. **多語言支援**
   - 支援英文 PDF 報告

2. **PDF 樣式優化**
   - 添加頁碼
   - 添加水印
   - 更精美的圖表（使用 ECharts 生成圖表截圖）

3. **匯出格式**
   - 支援 Excel 格式匯出（原始數據）
   - 支援 JSON 格式匯出（機器可讀）

4. **批次報告**
   - 支援多個 IP 的批次分析報告
   - 生成匯總報告

## 相關文件

- `CHANGE_HOURS_TO_MINUTES.md` - 時間參數改為分鐘
- `frontend/src/views/IPAnalysis.vue` - IP 分析頁面
- `backend/api/analysis.py` - 分析 API
