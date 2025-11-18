# Bug 修復：模型狀態顯示「尚未訓練」

## 🐛 問題描述

**症狀：**
- Web UI 訓練頁面顯示 By Dst 模型狀態為「尚未訓練」
- 但模型文件實際上已存在於磁碟上（`isolation_forest_by_dst.pkl`，1.1MB，2025-11-18 11:41 生成）
- API 返回 `status: "not_trained"`，缺少 `trained_at` 等信息

**原因：**
- `nad/config.yaml` 中的路徑配置使用相對路徑（`models_dir: nad/models`）
- Web UI backend 從 `/home/kaisermac/nad_web_ui/backend` 目錄運行
- 當 `IsolationForestByDst` 檢查模型文件時，使用相對路徑找不到文件
- 導致 `os.path.exists(detector.model_path)` 返回 False

## ✅ 解決方案

### 修改文件
`/home/kaisermac/snm_flow/nad/config.yaml`

### 修改內容

**修改前（相對路徑）：**
```yaml
output:
  logs_dir: logs
  models_dir: nad/models
  reports_dir: reports
  save_predictions: true

logging:
  file: logs/nad.log
  format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
  level: INFO
```

**修改後（絕對路徑）：**
```yaml
output:
  logs_dir: /home/kaisermac/snm_flow/logs
  models_dir: /home/kaisermac/snm_flow/nad/models
  reports_dir: /home/kaisermac/snm_flow/reports
  save_predictions: true

logging:
  file: /home/kaisermac/snm_flow/logs/nad.log
  format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
  level: INFO
```

## 🔍 根本原因分析

### 問題流程

1. **Web UI Backend 啟動**
   - 工作目錄：`/home/kaisermac/nad_web_ui/backend`

2. **API 調用 `/api/training/config?mode=by_dst`**
   - 創建 `IsolationForestByDst(config)` 實例
   - 從 config 讀取 `models_dir = "nad/models"`（相對路徑）
   - 設置 `model_path = "nad/models/isolation_forest_by_dst.pkl"`

3. **檢查模型狀態**
   ```python
   model_info = detector.get_model_info()  # 返回 {'status': 'not_trained'}

   # 嘗試從磁碟加載
   if model_info.get('status') == 'not_trained' and os.path.exists(detector.model_path):
       # ❌ os.path.exists("nad/models/isolation_forest_by_dst.pkl")
       #    從 /home/kaisermac/nad_web_ui/backend 找不到此相對路徑
       # ❌ 條件不滿足，不執行加載
   ```

4. **結果**
   - API 返回 `status: "not_trained"`
   - 即使模型實際存在於 `/home/kaisermac/snm_flow/nad/models/isolation_forest_by_dst.pkl`

### 為什麼之前沒發現？

- **命令行工具**（如 `train_isolation_forest_by_dst.py`）從 `/home/kaisermac/snm_flow` 目錄運行，相對路徑正常工作
- **By Src 模型** 也受影響，但可能之前從正確目錄訓練過，所以沒注意到

## 🧪 驗證

### 修復前
```bash
curl http://localhost:5000/api/training/config?mode=by_dst | jq .model_info
# 輸出:
# {
#   "status": "not_trained",
#   "n_features": 29
# }
```

### 修復後
```bash
curl http://localhost:5000/api/training/config?mode=by_dst | jq .model_info
# 輸出:
# {
#   "status": "trained",
#   "n_features": 29,
#   "contamination": 0.05,
#   "n_estimators": 150,
#   "perspective": "DST",
#   "model_path": "/home/kaisermac/snm_flow/nad/models/isolation_forest_by_dst.pkl",
#   "trained_at": "2025-11-18T03:41:51.734715+00:00"
# }
```

### Web UI 驗證

1. 訪問 http://192.168.10.25:5173/training
2. 切換到「📥 目標 IP 視角 (By Dst)」Tab
3. 模型資訊卡片應顯示：
   - ✅ **模型狀態：已訓練**
   - ✅ **訓練日期：2025-11-18 11:41**
   - ✅ **特徵數量：29**
   - ✅ **決策樹數量：150**
   - ✅ **污染率：0.05**

## 📊 影響範圍

### 受影響組件
- ✅ Web UI 訓練頁面 - 已修復
- ✅ By Dst 模型狀態檢測 - 已修復
- ✅ By Src 模型狀態檢測 - 同時修復

### 不受影響
- ✅ 命令行訓練工具（從 snm_flow 目錄運行）
- ✅ 實時檢測功能
- ✅ 模型文件本身（未損壞）

## 🎯 最佳實踐建議

### 配置文件路徑原則
1. **絕對路徑 vs 相對路徑**
   - ✅ **推薦：絕對路徑** - 適用於跨目錄調用的服務
   - ⚠️ **相對路徑** - 僅適用於固定工作目錄的腳本

2. **路徑解析策略**
   ```python
   # ❌ 不推薦：直接使用配置中的相對路徑
   model_path = config.output_config['models_dir']

   # ✅ 推薦：在配置中使用絕對路徑
   model_path = "/home/kaisermac/snm_flow/nad/models"

   # ✅ 替代方案：運行時解析為絕對路徑
   import os
   base_dir = "/home/kaisermac/snm_flow"
   model_path = os.path.join(base_dir, config.output_config['models_dir'])
   ```

## 🚀 部署

修復已完成，無需重啟服務。下次訪問訓練頁面將自動顯示正確狀態。

### 測試步驟
1. ✅ 驗證配置文件已更新為絕對路徑
2. ✅ 測試 API 返回正確的模型狀態
3. ✅ 確認 Web UI 顯示「已訓練」
4. ⏳ 測試新的模型訓練（確保仍然正常工作）

---

**修復時間**: 2025-11-18
**修復者**: Claude
**狀態**: ✅ 已完成並驗證
