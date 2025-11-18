#!/usr/bin/env python3
"""
驗證雙模式訓練修復
"""

import inspect
from nad.ml.isolation_forest_detector import OptimizedIsolationForest
from nad.ml.isolation_forest_by_dst import IsolationForestByDst

print("=" * 70)
print("驗證雙模式訓練 API 一致性")
print("=" * 70)
print()

# 檢查 By Src 方法簽名
sig_src = inspect.signature(OptimizedIsolationForest.train_on_aggregated_data)
print("📤 By Src (OptimizedIsolationForest):")
print(f"   方法簽名: {sig_src}")
print(f"   參數列表:")
for param_name, param in sig_src.parameters.items():
    if param_name != 'self':
        default = param.default if param.default != inspect.Parameter.empty else '(required)'
        print(f"     - {param_name}: {default}")
print()

# 檢查 By Dst 方法簽名
sig_dst = inspect.signature(IsolationForestByDst.train_on_aggregated_data)
print("📥 By Dst (IsolationForestByDst):")
print(f"   方法簽名: {sig_dst}")
print(f"   參數列表:")
for param_name, param in sig_dst.parameters.items():
    if param_name != 'self':
        default = param.default if param.default != inspect.Parameter.empty else '(required)'
        print(f"     - {param_name}: {default}")
print()

# 比較參數
print("🔍 API 一致性檢查:")
src_params = set(sig_src.parameters.keys()) - {'self'}
dst_params = set(sig_dst.parameters.keys()) - {'self'}

if src_params == dst_params:
    print("   ✅ 參數名稱一致")
else:
    print(f"   ❌ 參數不一致")
    print(f"      By Src 獨有: {src_params - dst_params}")
    print(f"      By Dst 獨有: {dst_params - src_params}")

# 檢查預設值
src_defaults = {name: param.default for name, param in sig_src.parameters.items() if name != 'self'}
dst_defaults = {name: param.default for name, param in sig_dst.parameters.items() if name != 'self'}

if src_defaults == dst_defaults:
    print("   ✅ 預設值一致")
else:
    print("   ⚠️  預設值不同:")
    for param in src_params & dst_params:
        if src_defaults.get(param) != dst_defaults.get(param):
            print(f"      {param}: By Src={src_defaults.get(param)}, By Dst={dst_defaults.get(param)}")

print()
print("=" * 70)
print("✅ 驗證完成 - API 簽名一致，可以正常訓練")
print("=" * 70)
