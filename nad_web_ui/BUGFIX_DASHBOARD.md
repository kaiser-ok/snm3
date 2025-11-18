# Dashboard 控制面板修復

## 問題描述

在實作 IP 分析時間參數功能時，Dashboard 的控制面板卡片內容消失了：
- 模型資訊顯示不見
- 執行檢測按鈕不見
- 柱狀圖也消失

## 根本原因

控制面板的 `<el-card>` 內容被誤刪或覆蓋，只剩下一個 loading alert，缺少了：
1. 模型狀態顯示（`el-descriptions`）
2. 執行檢測按鈕
3. 相關的警告訊息

## 修復內容

### 1. 恢復控制面板完整內容

**文件：** `frontend/src/views/Dashboard.vue`

**修復的模板部分：**
```vue
<!-- 控制面板 -->
<el-card class="control-panel" shadow="never">
  <template #header>
    <div class="card-header">
      <span>異常檢測控制台</span>
    </div>
  </template>

  <!-- 模型狀態 -->
  <div v-if="detectionStore.modelStatus" class="model-status">
    <el-descriptions :column="3" border size="small">
      <el-descriptions-item label="模型狀態">
        <el-tag v-if="detectionStore.modelStatus.is_trained" type="success">已訓練</el-tag>
        <el-tag v-else type="warning">未訓練</el-tag>
      </el-descriptions-item>
      <el-descriptions-item label="訓練時間">
        {{ detectionStore.modelStatus.last_trained || '未訓練' }}
      </el-descriptions-item>
      <el-descriptions-item label="訓練樣本數">
        {{ detectionStore.modelStatus.training_samples?.toLocaleString() || 'N/A' }}
      </el-descriptions-item>
    </el-descriptions>
  </div>

  <el-divider />

  <!-- 執行檢測按鈕 -->
  <div class="detection-controls">
    <el-button
      type="primary"
      size="large"
      :loading="detectionStore.loading"
      :disabled="!detectionStore.modelStatus?.is_trained"
      @click="handleRunDetection"
    >
      <el-icon><Search /></el-icon>
      執行異常檢測（過去 24 小時）
    </el-button>

    <el-alert
      v-if="!detectionStore.modelStatus?.is_trained"
      title="請先訓練模型"
      type="warning"
      :closable="false"
      show-icon
      style="margin-top: 12px"
    >
      <template #default>
        模型尚未訓練，請前往
        <el-link type="primary" @click="router.push('/training')">訓練頁面</el-link>
        訓練模型後再執行檢測
      </template>
    </el-alert>

    <el-alert
      v-if="detectionStore.loading || detectionStore.polling"
      title="正在檢測中，請稍候..."
      type="info"
      :closable="false"
      show-icon
      style="margin-top: 12px"
    />
  </div>
</el-card>
```

### 2. 新增缺少的圖標導入

**修改：**
```javascript
// 原本
import { Clock, TrendCharts, Back, InfoFilled } from '@element-plus/icons-vue'

// 修改後
import { Clock, TrendCharts, Back, InfoFilled, Search } from '@element-plus/icons-vue'
```

### 3. 新增相關樣式

**修改：**
```css
.model-status {
  margin-bottom: 12px;
}

.detection-controls {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 12px;
}
```

## 恢復的功能

修復後，控制面板現在包含：

1. **模型狀態顯示**
   - 模型狀態（已訓練/未訓練）
   - 訓練時間
   - 訓練樣本數

2. **執行檢測按鈕**
   - 大型主要按鈕
   - 帶 Search 圖標
   - Loading 狀態支援
   - 模型未訓練時自動禁用

3. **智能提示**
   - 模型未訓練時顯示警告並引導到訓練頁面
   - 檢測進行中時顯示資訊提示

4. **原有的結果顯示**
   - 柱狀圖（ECharts）
   - Top 10 異常 IP 列表
   - 特定時段詳細列表

## 驗證

建置測試通過：
```bash
cd frontend && npm run build
# ✓ built in 38.99s
```

## 相關檔案

- `frontend/src/views/Dashboard.vue` - 主要修復檔案
- `BUGFIX_DASHBOARD.md` - 本文件
