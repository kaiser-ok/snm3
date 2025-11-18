# 將 nad_web_ui 加入 Git Repository 指南

## 📋 背景

- **主專案目錄**: `/home/kaisermac/snm_flow` (已推送到 GitHub)
- **Web UI 目錄**: `/home/kaisermac/nad_web_ui` (尚未加入)
- **GitHub Repository**: https://github.com/kaiser-ok/snm3.git

## 🎯 目標

將 `nad_web_ui` 目錄整合到 `snm_flow` 專案中，並推送到 GitHub。

---

## 📝 操作步驟

### Step 1: 複製 nad_web_ui 到專案目錄

```bash
cd /home/kaisermac/snm_flow
cp -r /home/kaisermac/nad_web_ui ./
```

驗證複製成功：
```bash
ls -la nad_web_ui/
```

---

### Step 2: 更新 .gitignore

編輯 `/home/kaisermac/snm_flow/.gitignore`，添加 Web UI 相關的排除項目：

```bash
# 在 .gitignore 文件末尾添加以下內容：

# Web UI - Node.js
nad_web_ui/frontend/node_modules/
nad_web_ui/frontend/dist/
nad_web_ui/frontend/.vscode/
nad_web_ui/frontend/package-lock.json

# Web UI - Python Backend
nad_web_ui/backend/venv/
nad_web_ui/backend/__pycache__/
nad_web_ui/backend/*.pyc
nad_web_ui/backend/logs/
nad_web_ui/backend/reports/

# Web UI - Sensitive config
nad_web_ui/backend/config.py
nad_web_ui/backend/.env
```

---

### Step 3: 創建 Web UI 設定檔範本

如果 `nad_web_ui/backend/config.py` 包含密碼等敏感資訊，需要創建範本：

```bash
cd /home/kaisermac/snm_flow/nad_web_ui/backend
cp config.py config.py.example
```

然後編輯 `config.py.example`，將敏感資訊替換為範例值。

---

### Step 4: 添加到 Git

```bash
cd /home/kaisermac/snm_flow

# 查看將要添加的檔案
git status

# 添加 nad_web_ui 目錄
git add nad_web_ui/

# 檢查暫存的檔案（確認沒有敏感資訊）
git status
```

---

### Step 5: 提交變更

```bash
git commit -m "$(cat <<'EOF'
Add Web UI for Network Anomaly Detection System

- Frontend: Vue.js + Vite based dashboard
- Backend: Flask/FastAPI REST API
- Features:
  - Real-time anomaly monitoring
  - Historical data visualization
  - Device mapping management
  - Anomaly classification reports

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
EOF
)"
```

---

### Step 6: 推送到 GitHub

```bash
git push origin main
```

---

## ✅ 驗證

推送成功後，前往 GitHub 檢查：
- https://github.com/kaiser-ok/snm3

應該可以看到 `nad_web_ui/` 目錄及其所有檔案（除了 .gitignore 中排除的）。

---

## 🔍 檢查清單

在執行前，確認以下事項：

- [ ] 確認 `nad_web_ui/backend/config.py` 不包含密碼（或已加入 .gitignore）
- [ ] 確認 `nad_web_ui/frontend/node_modules/` 被排除
- [ ] 確認 `nad_web_ui/backend/venv/` 被排除
- [ ] 使用 `git status` 確認沒有不該提交的檔案
- [ ] 使用 `git diff --cached` 檢查即將提交的內容

---

## 🛠️ 常用 Git 指令

### 查看當前狀態
```bash
git status
```

### 查看即將提交的變更
```bash
git diff --cached
```

### 取消暫存某個檔案
```bash
git reset HEAD <file>
```

### 查看提交歷史
```bash
git log --oneline
```

### 推送前先拉取最新版本（如果有其他人協作）
```bash
git pull origin main
git push origin main
```

---

## 📦 建議的 .gitignore 完整內容

以下是完整的 `.gitignore` 建議內容（供參考）：

```gitignore
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
pip-wheel-metadata/
share/python-wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# Virtual Environment
venv/
ENV/
env/
.venv

# IDE
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store

# Logs
*.log
logs/
*.pid

# Machine Learning Models
nad/models/*.pkl
nad/models/*.joblib
nad/models/*.h5
nad/models/*.pt
nad/models/*.pth

# Reports
reports/*.html
reports/*.pdf

# Backup files
*.backup
*.bak
*.tmp
*~

# Database
*.db
*.sqlite
*.sqlite3

# Environment variables
.env
.env.local
.env.*.local
config.local.yaml
secrets.yaml

# Config files with sensitive data
nad/config.yaml

# Temporary files
*.tmp
temp/
tmp/

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Project specific
backfill_*.log
training_*.log
realtime_detection.log
*.pid

# Web UI - Node.js
nad_web_ui/frontend/node_modules/
nad_web_ui/frontend/dist/
nad_web_ui/frontend/.vscode/

# Web UI - Python Backend
nad_web_ui/backend/venv/
nad_web_ui/backend/__pycache__/
nad_web_ui/backend/*.pyc
nad_web_ui/backend/logs/
nad_web_ui/backend/reports/

# Web UI - Sensitive config
nad_web_ui/backend/config.py
nad_web_ui/backend/.env

# Keep model directory but ignore models
!nad/models/.gitkeep
```

---

## 💡 提示

1. **在複製前先備份**（可選）：
   ```bash
   tar -czf nad_web_ui_backup.tar.gz /home/kaisermac/nad_web_ui
   ```

2. **如果需要移除已經 commit 的敏感檔案**：
   ```bash
   git rm --cached <file>
   git commit -m "Remove sensitive file"
   git push origin main
   ```

3. **如果想預覽將要推送的內容**：
   ```bash
   git log origin/main..HEAD
   git diff origin/main..HEAD
   ```

---

## 📞 需要協助？

如果遇到問題，可以：
1. 查看 Git 狀態：`git status`
2. 查看最近的錯誤訊息
3. 回到這份指南重新檢查步驟

---

**建立日期**: 2025-11-17
**GitHub Repository**: https://github.com/kaiser-ok/snm3
