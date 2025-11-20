# DDoS 检测与阈值优化 - 问答记录

**日期**: 2025-11-17
**主题**: DDoS 检测机制、Isolation Forest 必要性、阈值配置与优化逻辑

---

## 目录

1. [程序如何检测 DDoS？](#1-程序如何检测-ddos)
2. [为何需要 Isolation Forest？](#2-为何需要-isolation-forest)
3. [YAML 中的 Threshold 用途](#3-yaml-中的-threshold-用途)
4. [Classifier 是否有另一套 Threshold？](#4-classifier-是否有另一套-threshold)
5. [优化逻辑详解](#5-优化逻辑详解)

---

## 1. 程序如何检测 DDoS？

### 两阶段检测方法

系统使用**两阶段检测方法**：

```
                    第一阶段                    第二阶段
                 Isolation Forest          AnomalyClassifier
netflow_stats_5m ──────────▶ 异常检测 ──────────▶ 威胁分类
                    (机器学习)              (规则引擎)
```

### 第一阶段：Isolation Forest 异常检测

使用机器学习算法检测流量异常，分析 17 个特征：
- 连线数 (flow_count)
- 独特目的地数量 (unique_dsts)
- 独特端口数量 (unique_dst_ports, unique_src_ports)
- 流量大小 (total_bytes, avg_bytes)
- 目的地分散度 (dst_diversity)
- 二值特征 (is_high_connection, is_scanning_pattern 等)

### 第二阶段：DDoS 分类器判断

**代码位置**: `nad/ml/anomaly_classifier.py:387-401`

```python
def _is_ddos(self, features: Dict) -> bool:
    """判断是否为 DDoS 攻击"""
    flow_count = features.get('flow_count', 0)
    avg_bytes = features.get('avg_bytes', 0)
    unique_dsts = features.get('unique_dsts', 0)

    # DDoS 特征:
    # 1. 极高连线数 (> 10000)
    # 2. 极小封包 (< 500 bytes) - SYN Flood
    # 3. 目的地少 (< 20)
    return (
        flow_count > 10000 and
        avg_bytes < 500 and
        unique_dsts < 20
    )
```

### DDoS 检测条件

**必须同时满足三个条件**：

1. **极高连线数**: `> 10,000` 个连接
2. **极小封包**: `< 500 bytes` (典型的 SYN Flood 模式)
3. **目标集中**: `< 20` 个目的地

### 置信度计算

**代码位置**: `nad/ml/anomaly_classifier.py:531-546`

```python
def _calculate_ddos_confidence(self, features: Dict) -> float:
    confidence = 0.7  # 基础置信度 70%

    # 连线数越高,置信度越高
    if flow_count > 50000:
        confidence += 0.2  # 90%
    elif flow_count > 20000:
        confidence += 0.1  # 80%

    # 封包越小,置信度越高
    if avg_bytes < 300:
        confidence += 0.1  # 最高 99%

    return min(confidence, 0.99)
```

### DDoS 威胁等级

**代码位置**: `nad/ml/anomaly_classifier.py:104-123`

- **严重性**: `CRITICAL` (严重)
- **优先级**: `P0` (最高优先级)
- **关键指标**:
  - 极高连线数
  - SYN Flood 模式 (小封包)
  - 目标集中

- **响应建议**:
  1. 启动 DDoS 防护
  2. 限速/黑洞路由
  3. 联系 ISP 协助
  4. 分析攻击源

### 使用方式

```bash
# 单次检测
python3 realtime_detection.py --minutes 10

# 持续监控
python3 realtime_detection.py --continuous --interval 5
```

### 与其他威胁的区别

| 威胁类型 | 连线数 | 封包大小 | 目的地 |
|---------|--------|---------|--------|
| **DDoS** | > 10,000 | < 500 bytes | < 20 |
| Port Scan | 中等 | < 5KB | > 100 端口 |
| Network Scan | > 1,000 | < 50KB | > 50 主机 |
| Data Exfiltration | 低 | 大流量 | < 5 (外部) |

---

## 2. 为何需要 Isolation Forest？

### 核心问题：阈值难以确定

#### ❌ 直接规则判断的问题

假设使用规则判断 DDoS：
```python
if flow_count > 10000 and avg_bytes < 500 and unique_dsts < 20:
    return "DDoS"
```

**存在的问题**：

1. **阈值难以统一**
   - 大企业：正常服务器可能有 50,000 连线
   - 小公司：5,000 连线就可能是异常
   - **同一个阈值无法适应不同环境**

2. **不同时间的基线不同**
   - 上班时间：流量高是正常的
   - 凌晨：1,000 连线就可能是异常
   - 周末 vs 工作日：模式完全不同

3. **正常行为也可能触发规则**
   - 合法的视频会议服务器
   - 备份系统
   - CDN 节点
   - **误报率会很高**

### ✅ Isolation Forest 的优势

#### 1. 自动学习正常基线

Isolation Forest 会学习你的网络的**正常模式**：

```
训练阶段（7天数据）:
- 192.168.1.10: 通常有 2,000-5,000 连线 ✓ 正常
- 192.168.1.20: 通常有 500-800 连线   ✓ 正常
- 192.168.1.30: 通常有 10,000 连线    ✓ 正常（服务器）

检测阶段:
- 192.168.1.10: 突然有 50,000 连线   ⚠️ 异常！（偏离自己的基线）
- 192.168.1.30: 有 12,000 连线       ✓ 正常（符合服务器模式）
```

**关键点**：不是用固定阈值，而是**相对于历史行为判断**

#### 2. 多维度综合判断

规则判断通常是单维度或简单的 AND/OR：
```python
# 规则方法：简单组合
if A > 10000 AND B < 500 AND C < 20:
```

Isolation Forest 考虑 **17 个特征的复杂交互**：

**特征列表** (`nad/ml/feature_engineer.py:52-71`)：
```python
'flow_count', 'total_bytes', 'unique_dsts',
'unique_src_ports', 'unique_dst_ports',
'dst_diversity', 'src_port_diversity',
'is_high_connection', 'is_scanning_pattern',
...
```

这些特征的**组合模式**很难用简单规则表达。

#### 3. 发现未知威胁

| 方法 | 能检测的威胁 |
|------|------------|
| **规则判断** | 只能检测**已知模式**（你写了规则的） |
| **Isolation Forest** | 检测**所有偏离正常的行为**（包括未知威胁） |

**实例**：
```
新型攻击（未见过的）:
- flow_count = 3000（不算高）
- avg_bytes = 800（不算小）
- 但是 dst_port_diversity = 0.95（极度分散）
- 且 traffic_concentration = 0.01（极度均匀）

规则判断：✓ 通过（没触发 DDoS 规则）
Isolation Forest：⚠️ 异常！（这种组合很罕见）
```

#### 4. 分类器的作用是"解释"，不是"检测"

**架构设计**：

```
                    第一阶段                    第二阶段
                 Isolation Forest          AnomalyClassifier
netflow_stats_5m ──────────▶ 异常检测 ──────────▶ 威胁分类
                    (机器学习)              (规则引擎)

作用：找出异常                  作用：解释异常类型
输出：异常分数 0.0-1.0          输出：DDoS/扫描/正常高流量
```

**为什么这样设计？**

1. **Isolation Forest**: 回答 "**这个行为异常吗？**"
   - 使用机器学习
   - 自适应阈值
   - 高召回率（不漏掉异常）

2. **AnomalyClassifier**: 回答 "**这是什么类型的异常？**"
   - 使用规则引擎
   - 可解释性强
   - 给出响应建议

#### 5. 实际数据说话

根据 `ISOLATION_FOREST_SUMMARY.md:195-228`，实际检测效果：

```
实际案例：
发现 14 个异常

1. 192.168.10.135 | 分数: 0.89 | 510,823 连线 → AD Server 扫描
2. 192.168.20.56  | 分数: 0.82 | 394,143 连线 → DNS 滥用
3. 192.168.15.42  | 分数: 0.76 |  12,456 连线 → 端口扫描
```

注意：
- 第1个：510,823 连线（超高）
- 第3个：12,456 连线（不算高）

**但都被检测为异常！**

如果用固定阈值（如 > 10,000），可能：
- 漏掉某些真实异常（阈值太高）
- 误报大量正常流量（阈值太低）

### 总结对比

| 维度 | 规则判断 | Isolation Forest + 分类器 |
|------|---------|--------------------------|
| **阈值设定** | 人工定义，难以调优 | 自动学习，适应网络 |
| **适应性** | 固定规则，不能自适应 | 学习正常基线，动态调整 |
| **未知威胁** | 无法检测 | 可以检测 |
| **误报率** | 高（阈值难调） | 低（相对基线判断） |
| **可解释性** | 高（规则明确） | 中（分数 + 分类） |
| **维护成本** | 高（需要不断调整规则） | 低（定期重训练） |

### 最佳实践

系统采用的**混合方法**是最佳实践：

```python
# 第一阶段：机器学习检测异常（高召回率）
anomalies = isolation_forest.predict()  # 找出所有可疑的

# 第二阶段：规则分类威胁类型（可解释性）
for anomaly in anomalies:
    threat_type = classifier.classify(anomaly)  # 解释是什么威胁
```

这样既有 **ML 的自适应能力**，又有**规则的可解释性**！

---

## 3. YAML 中的 Threshold 用途

### Thresholds 的真实用途：生成二值特征 (Binary Features)

**配置位置**: `nad/config.yaml:60-65`

```yaml
thresholds:
  high_connection: 352
  large_flow: 7914975
  scanning_avg_bytes: 2200
  scanning_dsts: 3
  small_packet: 456
```

### 使用位置：特征工程阶段

**代码位置**: `nad/ml/feature_engineer.py:109-125`

```python
# 3. 二值特徵（行為標記）
thresholds = self.config.thresholds if self.config else {...}

# 使用阈值生成 5 个二值特征：
features['is_high_connection'] = 1 if features['flow_count'] > thresholds['high_connection'] else 0

features['is_scanning_pattern'] = 1 if (
    features['unique_dsts'] > thresholds['scanning_dsts'] and
    features['avg_bytes'] < thresholds['scanning_avg_bytes']
) else 0

features['is_small_packet'] = 1 if features['avg_bytes'] < thresholds['small_packet'] else 0

features['is_large_flow'] = 1 if features['max_bytes'] > thresholds['large_flow'] else 0
```

### 完整流程

```
原始数据 ──▶ 特征工程 ──▶ Isolation Forest ──▶ 异常分类
            │                  │                   │
            │                  │                   │
        使用 thresholds    使用全部17个特征      使用规则
        生成5个二值特征    (包括二值特征)
```

### 详细示例

#### 输入：原始聚合数据
```python
{
  'flow_count': 500,
  'avg_bytes': 300,
  'unique_dsts': 5,
  'max_bytes': 5000000
}
```

#### 处理：使用 thresholds 生成二值特征
```python
is_high_connection = 1 if 500 > 352 else 0        # = 1 ✓
is_small_packet = 1 if 300 < 456 else 0           # = 1 ✓
is_scanning_pattern = 1 if (5 > 3 and 300 < 2200) # = 1 ✓
is_large_flow = 1 if 5000000 > 7914975 else 0     # = 0 ✗
```

#### 输出：17 个特征（包括二值特征）
```python
[500, 300, 5, ..., 1, 1, 1, 0, ...]
```

#### Isolation Forest 阶段
```python
# 输入：17 维特征向量（包括上面的二值特征）
X = [flow_count, avg_bytes, unique_dsts, ...,
     is_high_connection, is_scanning_pattern, ...]

# Isolation Forest 综合判断
anomaly_score = model.predict(X)  # 0.85 (异常!)
```

### 为什么需要二值特征？

#### 作用 1: 增强 ML 模型的表达能力

Isolation Forest 能更好地学习到：
- 不仅是"flow_count 的值"
- 还有"是否超过高连线阈值"这个**行为特征**

```python
# 两个 IP 的对比：
IP A: flow_count=400, is_high_connection=1  # 刚好超过阈值
IP B: flow_count=350, is_high_connection=0  # 刚好低于阈值

# 数值差异小 (400 vs 350)
# 但行为特征不同 (1 vs 0)
# 帮助 ML 识别"临界点"的重要性
```

#### 作用 2: 捕获领域知识

这些阈值体现了**网络安全的经验**：
- `is_scanning_pattern`: 组合条件（目的地多 + 小封包）
- `is_likely_server_response`: 复杂的服务器识别逻辑

把人类经验编码成特征，让 ML 学习效果更好。

### Thresholds 如何设定？

#### 方法 1: 自适应计算（推荐）

使用 `calculate_adaptive_thresholds.py`：

```bash
# 基于历史数据的统计分布自动计算
python3 calculate_adaptive_thresholds.py --days 7

# 输出：
thresholds:
  high_connection: 352        # 95百分位数
  scanning_dsts: 3            # 90百分位数
  small_packet: 456           # 25百分位数
  large_flow: 7914975         # 99百分位数
```

**原理**：
```
分析过去 7 天的数据：
- flow_count 的分布: [10, 50, 100, 200, 500, ...]
- 95% 的数据 <= 352
- 所以设 high_connection = 352
- 意味着只有 5% 的数据会被标记为 "高连线"
```

#### 方法 2: 手动调整

```yaml
thresholds:
  high_connection: 1000  # 调高 → 更严格（少标记）
  high_connection: 100   # 调低 → 更宽松（多标记）
```

### 关键区别总结

| 阈值用途 | 常见误解 | 实际用途 |
|---------|---------|---------|
| **作用对象** | 直接判断异常 | 生成二值特征 |
| **使用阶段** | 检测阶段 | 特征工程阶段 |
| **影响范围** | 最终结果 | ML 输入特征 |
| **是否最终判断** | ✗ | ✗（只是 17 个特征之一） |

### 完整示例

```python
# 场景：一个 IP 的检测过程

# 1. 原始数据
raw_data = {'flow_count': 400, 'avg_bytes': 300, ...}

# 2. 特征工程（使用 thresholds）
features = feature_engineer.extract_features(raw_data)
# features = {
#   'flow_count': 400,
#   'avg_bytes': 300,
#   'is_high_connection': 1,  ← threshold 在这里使用
#   'is_small_packet': 1,     ← threshold 在这里使用
#   ...
# }

# 3. Isolation Forest（使用全部 17 个特征）
anomaly_score = isolation_forest.predict(features)
# anomaly_score = 0.75  ← ML 综合判断（不只看 threshold）

# 4. 如果异常，分类器判断类型（使用不同的规则）
if anomaly_score > 0.6:
    threat_type = classifier.classify(features)
    # threat_type = "PORT_SCAN"
    # 判断条件: unique_dst_ports > 100 and avg_bytes < 5000
    #          （这里的 100 和 5000 是分类器的规则，不是 yaml thresholds）
```

### 关键理解

**Thresholds 不是用来"检测异常"的！**

Thresholds 是用来：
1. 把连续值转成二值特征（0 或 1）
2. 作为 **17 个特征之一** 输入给 Isolation Forest
3. 帮助 ML 模型更好地学习模式

**真正检测异常的是 Isolation Forest**，它会综合考虑所有 17 个特征的复杂组合。

这样设计的好处：
- ✅ 保留了人类经验（通过二值特征）
- ✅ 发挥了 ML 的优势（多维度综合判断）
- ✅ 自适应能力强（threshold 可自动计算）

---

## 4. Classifier 是否有另一套 Threshold？

### 答案：是的！

Classifier **确实有另一套独立的 threshold**，而且目前是**硬编码在代码中**。

### 两套不同的 Thresholds

#### 1️⃣ Feature Engineering Thresholds (在 config.yaml)

```yaml
thresholds:
  high_connection: 352        # 用于生成二值特征
  scanning_dsts: 3
  scanning_avg_bytes: 2200
  small_packet: 456
  large_flow: 7914975
```

**用途**: 生成 5 个二值特征（`is_high_connection`, `is_scanning_pattern` 等）
**可配置**: ✅ 在 `nad/config.yaml` 中
**可自动计算**: ✅ 使用 `calculate_adaptive_thresholds.py`

---

#### 2️⃣ Classifier Thresholds (硬编码在代码中)

在 `nad/ml/anomaly_classifier.py` 中有**多组规则**：

##### PORT_SCAN (端口扫描)
```python
# 第 344-346 行
unique_dst_ports > 100 and      # 硬编码
avg_bytes < 5000 and            # 硬编码
dst_port_diversity > 0.5        # 硬编码
```

##### NETWORK_SCAN (网络扫描)
```python
# 第 362-365 行
unique_dsts > 50 and            # 硬编码
dst_diversity > 0.3 and         # 硬编码
flow_count > 1000 and           # 硬编码
avg_bytes < 50000               # 硬编码
```

##### DDoS 攻击
```python
# 第 398-400 行
flow_count > 10000 and          # 硬编码
avg_bytes < 500 and             # 硬编码
unique_dsts < 20                # 硬编码
```

##### DATA_EXFILTRATION (数据外泄)
```python
# 第 418-421 行
total_bytes > 1e9 and           # > 1GB，硬编码
unique_dsts <= 5 and            # 硬编码
dst_diversity < 0.1 and         # 硬编码
has_external                    # 逻辑判断
```

##### DNS_TUNNELING
```python
# 第 381-384 行
flow_count > 1000 and           # 硬编码
unique_dst_ports <= 2 and       # 硬编码
avg_bytes < 1000 and            # 硬编码
unique_dsts <= 5                # 硬编码
```

##### C2_COMMUNICATION
```python
# 第 436-438 行
unique_dsts == 1 and            # 硬编码
100 < flow_count < 1000 and     # 硬编码
1000 < avg_bytes < 100000       # 硬编码
```

**用途**: 将异常分类成具体威胁类型
**可配置**: ❌ **目前是硬编码，需要手动修改代码**
**可自动计算**: ❌ **没有自动优化机制（但有优化工具推荐）**

### 完整对比

| 特性 | Feature Thresholds | Classifier Thresholds |
|------|-------------------|----------------------|
| **位置** | `nad/config.yaml` | `nad/ml/anomaly_classifier.py` (硬编码) |
| **数量** | 5 个 | ~25 个（分散在 7 个威胁类型中） |
| **作用阶段** | 特征工程 | 威胁分类 |
| **可配置** | ✅ YAML 文件 | ❌ 需改代码 |
| **自动优化** | ✅ `calculate_adaptive_thresholds.py` | ⚠️ 有推荐工具但需手动应用 |
| **修改难度** | 简单 | 需要了解代码 |

### 如何调整 Classifier Thresholds？

#### 方法 1: 直接修改代码（目前唯一方法）

编辑 `nad/ml/anomaly_classifier.py`：

```python
def _is_ddos(self, features: Dict) -> bool:
    # 原来的阈值
    return (
        flow_count > 10000 and    # 修改这里
        avg_bytes < 500 and       # 修改这里
        unique_dsts < 20          # 修改这里
    )

    # 修改后（更严格的 DDoS 检测）
    return (
        flow_count > 5000 and     # 降低阈值，更敏感
        avg_bytes < 800 and       # 提高阈值，包含更多小包
        unique_dsts < 30          # 放宽目的地限制
    )
```

**缺点**:
- 需要修改代码
- 需要理解每个函数的逻辑
- 升级代码时可能被覆盖

#### 方法 2: 使用优化工具推荐（推荐！）

系统已有 `optimize_classifier_thresholds.py`！

**步骤**：

```bash
# 1. 运行优化工具，分析历史异常数据
python3 optimize_classifier_thresholds.py --days 7

# 输出示例：
# ========================================
# 推荐阈值：
# ========================================
#
# PORT_SCAN:
#   unique_dst_ports:
#     当前值: 100
#     推荐值: 85         ← 基于 P10 百分位
#     理由: 基于 PLOS ONE (2018) 端口扫描研究
#
#   avg_bytes:
#     当前值: 5000
#     推荐值: 3200       ← 基于 P75 百分位
#     理由: 端口扫描使用小封包
#
# DDOS:
#   flow_count:
#     当前值: 10000
#     推荐值: 7500       ← 基于实际数据统计
#     理由: 基于 MDPI Sensors (2023) DDoS 研究
```

**工作原理**：

```python
1. 收集过去 7 天的异常数据
2. 用当前分类器分类这些异常
3. 统计每种威胁类型的特征分布
4. 基于百分位数推荐新阈值

示例（DDoS）：
- 收集到 50 个被分类为 DDoS 的异常
- flow_count 分布: [7000, 8500, 9200, 12000, 15000, ...]
- P10 = 7500  ← 推荐作为新的 flow_count 阈值
- 理由：90% 的真实 DDoS 都 > 7500
```

**推荐依据**（基于学术研究）：

- PLOS ONE (2018) - 端口扫描研究
- GIAC (2016) - DNS 隧道检测
- MDPI Sensors (2023) - DDoS 检测
- TU Delft (2019) - 数据外泄检测
- Splunk Research - 网络扫描

**使用推荐值**：

```bash
# 2. 根据推荐结果，手动更新代码
vim nad/ml/anomaly_classifier.py

# 3. 修改对应的阈值
def _is_ddos(self, features: Dict) -> bool:
    return (
        flow_count > 7500 and     # 从 10000 改为 7500（推荐值）
        avg_bytes < 650 and       # 从 500 改为 650（推荐值）
        unique_dsts < 25          # 从 20 改为 25（推荐值）
    )
```

#### 方法 3: 配置化改进（需要开发）

**现状**: ❌ 不支持
**未来可以实现**: ✅

修改代码支持从配置文件读取：

```yaml
# nad/config.yaml (新增配置)
classifier_thresholds:
  port_scan:
    unique_dst_ports: 85      # 从优化工具得到的推荐值
    avg_bytes: 3200
    dst_port_diversity: 0.45

  ddos:
    flow_count: 7500
    avg_bytes: 650
    unique_dsts: 25
```

### 最佳实践流程

#### 初次部署：

```bash
# 1. 使用默认阈值运行 1-2 周
python3 realtime_detection.py --continuous

# 2. 收集足够的历史数据后，运行优化工具
python3 optimize_classifier_thresholds.py --days 7

# 3. 根据推荐值，手动更新代码中的阈值
vim nad/ml/anomaly_classifier.py

# 4. 重启检测服务
python3 realtime_detection.py --continuous
```

#### 定期维护：

```bash
# 每月运行一次优化工具
0 0 1 * * cd /path/to/snm_flow && python3 optimize_classifier_thresholds.py --days 30
```

### 完整对比总结

| Threshold 类型 | Feature Thresholds | Classifier Thresholds |
|---------------|-------------------|----------------------|
| **配置文件** | ✅ `nad/config.yaml` | ❌ 硬编码在 `.py` 文件 |
| **位置** | `thresholds:` 节点 | `anomaly_classifier.py` 各函数中 |
| **数量** | 5 个 | ~25 个（7 种威胁） |
| **用途** | 生成二值特征 | 威胁分类判断 |
| **自动计算** | ✅ `calculate_adaptive_thresholds.py` | ✅ `optimize_classifier_thresholds.py` |
| **输出** | 更新 `config.yaml` | **只提供推荐值**（需手动更新代码） |
| **调整频率** | 每周 | 每月 |
| **调整难度** | 简单（改 YAML） | 需要改代码 |

### 关键要点

1. **是的，Classifier 有另一套 thresholds**
2. **目前需要手动设定**（修改代码）
3. **但有工具可以推荐最佳值**（`optimize_classifier_thresholds.py`）
4. **推荐值基于学术研究和实际数据统计**
5. **建议定期运行优化工具，手动应用推荐值**

---

## 5. 优化逻辑详解

### 优化工具的完整流程

```
循环优化：

当前阈值 → 检测异常 → 分类威胁 → 统计特征分布 → 推荐新阈值
    ↑                                                      ↓
    └──────────────────── 应用推荐值 ────────────────────┘
```

### 第一步：数据收集（历史异常数据）

**代码位置**: `optimize_classifier_thresholds.py:66-149`

```
时间线：过去 7 天
    │
    ├── Day 1: 运行 Isolation Forest → 找到 50 个异常
    ├── Day 2: 运行 Isolation Forest → 找到 45 个异常
    ├── Day 3: 运行 Isolation Forest → 找到 60 个异常
    ├── ...
    └── Day 7: 运行 Isolation Forest → 找到 55 个异常

总计：收集到 ~350 个异常
```

**关键代码**：
```python
# 收集过去 7 天的异常
for day in range(7):
    anomalies = isolation_forest.predict()  # 使用 IF 检测异常

    for anomaly in anomalies:
        # 用当前分类器分类
        classification = classifier.classify(anomaly)

        # 存储：这个异常被分类为什么类型
        anomaly_features[classification['class']].append(anomaly)
```

### 第二步：威胁分组（按当前分类结果）

```
收集到的 350 个异常，按分类结果分组：

PORT_SCAN:           80 个
NETWORK_SCAN:        45 个
DDOS:                12 个
DNS_TUNNELING:       8 个
DATA_EXFILTRATION:   5 个
C2_COMMUNICATION:    3 个
NORMAL_HIGH_TRAFFIC: 150 个
UNKNOWN:             47 个
```

### 第三步：统计分析（每组的特征分布）

**代码位置**: `optimize_classifier_thresholds.py:151-199`

以 **DDoS** 为例，分析这 12 个被分类为 DDoS 的异常：

```python
# 提取 DDoS 组的所有特征值
ddos_anomalies = anomaly_features['DDOS']  # 12 个异常

# 提取关键特征
flow_counts = [a['flow_count'] for a in ddos_anomalies]
# flow_counts = [7500, 8200, 9500, 12000, 15000, 18000,
#                22000, 25000, 30000, 35000, 40000, 50000]

avg_bytes = [a['avg_bytes'] for a in ddos_anomalies]
# avg_bytes = [350, 420, 480, 520, 600, 650,
#              700, 750, 800, 850, 900, 1000]

unique_dsts = [a['unique_dsts'] for a in ddos_anomalies]
# unique_dsts = [5, 8, 10, 12, 15, 18, 20, 22, 25, 28, 30, 35]

# 计算统计量
statistics = {
    'flow_count': {
        'min': 7500,
        'max': 50000,
        'mean': 22708,
        'median': 18500,
        'p10': 7500,    ← 10% 分位数
        'p25': 9500,    ← 25% 分位数
        'p50': 18500,   ← 中位数
        'p75': 30000,   ← 75% 分位数
        'p90': 40000,   ← 90% 分位数
    },
    'avg_bytes': {...},
    'unique_dsts': {...}
}
```

### 第四步：推荐阈值（基于百分位数）

**代码位置**: `optimize_classifier_thresholds.py:201-373`

这是**核心逻辑**！

#### 逻辑 A：使用不同的百分位数

不同特征使用不同的百分位数策略：

```python
# DDoS 推荐逻辑（第 298-317 行）

recommendations['DDOS'] = {
    'flow_count': {
        'current': 10000,
        'recommended': int(features['flow_count']['p10']),  # 使用 P10
        'rationale': 'P10 值，DDoS 產生極高連線數'
    },
    'avg_bytes': {
        'current': 500,
        'recommended': int(features['avg_bytes']['p75']),   # 使用 P75
        'rationale': 'P75 值，SYN Flood 使用極小封包'
    },
    'unique_dsts': {
        'current': 20,
        'recommended': max(10, int(features['unique_dsts']['p90'])),  # 使用 P90
        'rationale': 'P90 值，攻擊目標集中'
    }
}
```

#### 为什么用不同的百分位数？

**场景：12 个真实的 DDoS 异常**

##### Feature 1: flow_count (连线数)
```
数据: [7500, 8200, 9500, 12000, 15000, 18000,
       22000, 25000, 30000, 35000, 40000, 50000]
      ↑
      P10 = 7500

使用 P10 的理由：
- 90% 的真实 DDoS 都 >= 7500
- 如果设为 P10 (7500)，可以捕获 90% 的 DDoS
- 比原来的 10000 更敏感（捕获更多）
```

##### Feature 2: avg_bytes (平均封包大小)
```
数据: [350, 420, 480, 520, 600, 650,
       700, 750, 800, 850, 900, 1000]
                                ↑
                              P75 = 750

使用 P75 的理由：
- 75% 的真实 DDoS 平均封包 <= 750
- 如果设为 P75 (750)，可以包含 75% 的典型 DDoS
- 比原来的 500 更宽松（减少漏报）
```

##### Feature 3: unique_dsts (目的地数量)
```
数据: [5, 8, 10, 12, 15, 18, 20, 22, 25, 28, 30, 35]
                                              ↑
                                            P90 = 30

使用 P90 的理由：
- 90% 的真实 DDoS 目的地 <= 30
- 如果设为 P90 (30)，覆盖绝大多数情况
- 比原来的 20 更宽松（包含更多模式）
```

### 百分位数选择策略

| 特征类型 | 使用百分位 | 理由 |
|---------|----------|------|
| **越高越可疑** (flow_count, unique_dst_ports) | P10 | 要求高门槛，提高召回率 |
| **越低越可疑** (avg_bytes) | P75 | 包含大部分小包情况 |
| **集中性特征** (unique_dsts) | P90 | 覆盖极端情况 |
| **分散性特征** (dst_diversity) | P25 | 确保足够分散 |

### 完整示例：DDoS 优化过程

#### 输入数据

```
过去 7 天，Isolation Forest 检测到 12 个异常被分类为 DDoS：

IP 1:  flow_count=7500,  avg_bytes=350,  unique_dsts=5
IP 2:  flow_count=8200,  avg_bytes=420,  unique_dsts=8
IP 3:  flow_count=9500,  avg_bytes=480,  unique_dsts=10
...
IP 12: flow_count=50000, avg_bytes=1000, unique_dsts=35
```

#### 统计分析

```python
flow_count 分布:
    min=7500, max=50000, mean=22708
    P10=7500, P25=9500, P50=18500, P75=30000, P90=40000

avg_bytes 分布:
    min=350, max=1000, mean=650
    P10=420, P25=520, P50=650, P75=750, P90=900

unique_dsts 分布:
    min=5, max=35, mean=19
    P10=8, P25=12, P50=18, P75=25, P90=30
```

#### 推荐结果

```
DDOS 阈值推荐：

1. flow_count:
   当前阈值: > 10000
   推荐阈值: > 7500      (P10)
   理由: 90% 的真实 DDoS >= 7500，降低阈值可捕获更多
   影响: 提高 25% 召回率
   参考: MDPI Sensors (2023) - DDoS Detection

2. avg_bytes:
   当前阈值: < 500
   推荐阈值: < 750       (P75)
   理由: 75% 的 DDoS 封包 <= 750，放宽阈值减少漏报
   影响: 包含更多 DDoS 变种

3. unique_dsts:
   当前阈值: < 20
   推荐阈值: < 30        (P90)
   理由: 90% 的 DDoS 目的地 <= 30
   影响: 覆盖分散型 DDoS
```

#### 应用推荐值

修改 `nad/ml/anomaly_classifier.py`:
```python
def _is_ddos(self, features: Dict) -> bool:
    return (
        flow_count > 7500 and    # 从 10000 改为 7500
        avg_bytes < 750 and      # 从 500 改为 750
        unique_dsts < 30         # 从 20 改为 30
    )
```

### 优化逻辑总结

#### 核心思想

**"从实际检测到的威胁中学习，调整阈值"**

#### 优势

1. **数据驱动**: 基于真实检测结果，不是拍脑袋
2. **统计基础**: 使用百分位数，有科学依据
3. **学术支持**: 参考学术论文的研究结果
4. **保守策略**: 使用 P10/P90 避免过于激进
5. **持续改进**: 定期运行，适应网络变化

#### 关键假设

⚠️ **这个方法有一个重要前提**：

```
假设：当前分类器已经能正确分类大部分异常

如果当前分类器错误很多（如误把正常流量分类为 DDoS）
→ 统计的数据会有偏差
→ 推荐的阈值也会有问题
```

**解决方法**：
1. 初始阶段：使用学术研究的默认值
2. 运行 1-2 周后：有足够数据时才运行优化
3. 人工审查：检查推荐值是否合理
4. 渐进式调整：不要一次改太多

### 实际应用建议

```bash
# 第 1 周：使用默认阈值
python3 realtime_detection.py --continuous

# 第 2-3 周：收集数据，不要调整

# 第 4 周：第一次优化
python3 optimize_classifier_thresholds.py --days 21

# 审查推荐值，谨慎应用：
# - 如果推荐值偏差 < 30%，可以采用
# - 如果推荐值偏差 > 50%，需要人工判断

# 每月优化一次
crontab -e
0 0 1 * * cd /path && python3 optimize_classifier_thresholds.py --days 30
```

### 学术研究参考

优化工具基于以下学术研究：

1. **Port Scan**: PLOS ONE (2018) - Detection of slow port scans in flow-based network traffic
   - https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0204507

2. **DNS Tunneling**: GIAC (2016) - Detecting DNS Tunneling
   - https://www.giac.org/paper/gcia/1116/detecting-dns-tunneling/108367

3. **DDoS Detection**: MDPI Sensors (2023) - Detection and Mitigation of SYN Flooding Attacks
   - https://www.mdpi.com/1424-8220/23/8/3817

4. **Data Exfiltration**: TU Delft (2019) - Automated data exfiltration detection using netflow metadata
   - https://repository.tudelft.nl/islandora/object/uuid:19aa873d-b38d-4133-bcf8-7c6c625af739

5. **C2 Detection**: ScienceDirect (2013) - Periodic behavior in botnet traffic
   - https://www.sciencedirect.com/science/article/pii/S2090123213001410

6. **Network Scan**: Splunk Research - Detection of Internal Horizontal Port Scan
   - https://research.splunk.com/network/1ff9eb9a-7d72-4993-a55e-59a839e607f1/

---

## 附录：相关文件索引

### 核心代码文件

- `nad/ml/anomaly_classifier.py` - 威胁分类器（包含硬编码的分类阈值）
- `nad/ml/feature_engineer.py` - 特征工程（使用 config.yaml 中的阈值生成二值特征）
- `nad/ml/isolation_forest_detector.py` - Isolation Forest 检测器
- `nad/config.yaml` - 主配置文件（包含特征工程阈值）

### 工具脚本

- `realtime_detection.py` - 实时异常检测脚本
- `train_isolation_forest.py` - 训练 Isolation Forest 模型
- `calculate_adaptive_thresholds.py` - 自动计算特征工程阈值
- `optimize_classifier_thresholds.py` - 优化分类器阈值（推荐值）
- `verify_anomaly.py` - 异常验证工具

### 文档

- `ISOLATION_FOREST_SUMMARY.md` - Isolation Forest 系统总结
- `ISOLATION_FOREST_GUIDE.md` - 完整使用指南
- `AI_ANOMALY_DETECTION.md` - AI 异常检测文档
- `ANOMALY_CLASSIFICATION_GUIDE.md` - 异常分类指南

---

**文档结束**

如需进一步了解或有任何问题，请参考相关代码文件和文档。
