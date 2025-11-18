#!/usr/bin/env python3
"""
自動添加 By Dst Tab 內容到 Training.vue
"""

import re

# 讀取文件
with open('frontend/src/views/Training.vue', 'r', encoding='utf-8') as f:
    content = f.read()

# 找到 By Dst tab 的佔位符位置
placeholder_pattern = r'(<el-alert type="warning" show-icon>\s*By Dst 模式面板.*?</el-alert>)'

# By Src 的內容 (從第一個 el-row 到 </el-tab-pane>)
# 提取 By Src 的完整內容
by_src_pattern = r'(<el-row :gutter="20">.*?</el-card>\s*</el-tab-pane>)'
by_src_match = re.search(by_src_pattern, content, re.DOTALL)

if by_src_match:
    by_src_content = by_src_match.group(1)

    # 複製並替換綁定
    by_dst_content = by_src_content.replace('configBySrc', 'configByDst')
    by_dst_content = by_dst_content.replace('progressBySrc', 'progressByDst')
    by_dst_content = by_dst_content.replace('trainingBySrc', 'trainingByDst')
    by_dst_content = by_dst_content.replace('showFeaturesBySrc', 'showFeaturesByDst')
    by_dst_content = by_dst_content.replace('By Src', 'By Dst')
    by_dst_content = by_dst_content.replace("'by_src'", "'by_dst'")
    by_dst_content = by_dst_content.replace('(By Src)', '(By Dst)')

    # 替換佔位符
    content = re.sub(placeholder_pattern, by_dst_content.replace('</el-tab-pane>', ''), content, flags=re.DOTALL)

    # 寫回文件
    with open('frontend/src/views/Training.vue', 'w', encoding='utf-8') as f:
        f.write(content)

    print("✅ 成功添加 By Dst Tab 內容")
else:
    print("❌ 無法找到 By Src 內容模式")
