# --exclude-servers 参数分析报告

## 参数功能

`--exclude-servers` 参数用于**过滤可能的服务器回应流量**，而**不是**根据设备类型（device_type）过滤。

## 核心判断逻辑

### 排除的对象：符合"服务器回应流量特征"的异常

该参数排除的是具有 `is_likely_server_response = 1` 特征的异常记录。

### 判断条件 (nad/ml/feature_engineer.py:129-135)

一个IP的流量被识别为"服务器回应"需要**同时满足**以下5个条件：

```python
features['is_likely_server_response'] = 1 if (
    features['src_port_diversity'] < 0.1 and     # ① 源端口很集中
    features['dst_port_diversity'] > 0.3 and     # ② 目的端口很分散
    features['unique_src_ports'] <= 100 and      # ③ 源端口数量少
    features['flow_count'] > 100 and             # ④ 连线数足够多
    features['avg_bytes'] < 50000                # ⑤ 平均流量不大
) else 0
```

### 条件详细说明

| 条件 | 阈值 | 含义 | 服务器回应的特征 |
|------|------|------|------------------|
| ① 源端口多样性 | < 0.1 | 源端口非常集中 | 服务器使用固定端口（如 DNS:53, LDAP:389, HTTPS:443） |
| ② 目的端口多样性 | > 0.3 | 目的端口很分散 | 客户端使用随机高位端口（ephemeral ports） |
| ③ 源端口数量 | ≤ 100 | 源端口种类少 | 服务通常只使用少数固定端口 |
| ④ 连线数 | > 100 | 连线数量多 | 服务器会回应大量客户端请求 |
| ⑤ 平均流量 | < 50KB | 单次传输不大 | DNS/LDAP/短连接Web等小流量回应 |

## 典型场景分析

### 会被排除的场景（服务器回应流量）

#### 场景1: DNS 服务器
```
IP: 192.168.10.5 (device_type: server_farm)
源端口: 53 (固定)
目的端口: 45123, 45234, 45345, ... (客户端随机端口)
连线数: 5000
平均流量: 500 bytes
```
**判断**: ✅ 符合服务器回应特征，会被排除

#### 场景2: LDAP/AD 服务器
```
IP: 192.168.10.10 (device_type: server_farm)
源端口: 389, 636 (LDAP/LDAPS)
目的端口: 50123, 50234, 50345, ... (客户端随机端口)
连线数: 2000
平均流量: 2KB
```
**判断**: ✅ 符合服务器回应特征，会被排除

#### 场景3: Web 服务器（短连接）
```
IP: 192.168.10.20 (device_type: server_farm)
源端口: 443, 80 (HTTPS/HTTP)
目的端口: 60123, 60234, 60345, ... (客户端随机端口)
连线数: 3000
平均流量: 30KB
```
**判断**: ✅ 符合服务器回应特征，会被排除

### 不会被排除的场景

#### 场景4: 扫描攻击（来自服务器网段）
```
IP: 192.168.10.100 (device_type: server_farm)
源端口: 45123, 45234, 45345, ... (随机端口，diversity > 0.1)
目的端口: 22, 23, 80, 443, 3389, ... (扫描多个端口)
连线数: 5000
平均流量: 200 bytes
```
**判断**: ❌ 不符合（源端口分散），**不会被排除**

#### 场景5: 数据外泄（来自服务器网段）
```
IP: 192.168.10.50 (device_type: server_farm)
源端口: 50123 (客户端行为)
目的端口: 443 (固定目标，diversity < 0.3)
连线数: 150
平均流量: 500KB (大流量)
```
**判断**: ❌ 不符合（目的端口集中、流量大），**不会被排除**

#### 场景6: C&C 通讯（来自IoT设备）
```
IP: 192.168.0.50 (device_type: iot)
源端口: 55123, 55234 (客户端随机端口)
目的端口: 8080 (C&C 服务器端口)
连线数: 200
平均流量: 5KB
```
**判断**: ❌ 不符合（目的端口集中），**不会被排除**

## 关键结论

### ❌ 错误理解
> "device_type 是 server 的 IP 都会被排除"

### ✅ 正确理解
> "表现出服务器回应流量特征的 IP（无论 device_type）都会被排除"

### 重要区别

| 维度 | device_type | is_likely_server_response |
|------|-------------|---------------------------|
| 判断依据 | **IP 地址范围**（静态配置） | **流量行为特征**（动态判断） |
| 判断时机 | 根据 device_mapping.yaml | 根据实际流量统计 |
| 范围 | 所有在 server_farm 网段的 IP | 只有符合5个条件的流量模式 |
| 用途 | 设备分类标签 | 过滤正常服务器回应 |

## 实际应用示例

### 查看当前环境的服务器回应流量

```bash
# 查看最近有哪些IP被识别为服务器回应
python3 test_port_improvement.py
```

### 对比效果

```bash
# 不过滤 - 看到所有异常（包括服务器回应）
python3 realtime_detection.py --minutes 30

# 过滤服务器回应 - 只看主动攻击/异常
python3 realtime_detection.py --minutes 30 --exclude-servers
```

### 训练模型时也可以使用

```bash
# 训练时排除服务器回应流量
python3 train_isolation_forest.py --days 7 --exclude-servers
```

## 为什么需要这个参数？

### 问题背景

在实际环境中，**服务器回应大量客户端请求**的正常行为可能会被 Isolation Forest 误判为异常：

- DNS 服务器每天回应数万次查询
- LDAP 服务器处理大量认证请求
- Web 服务器响应大量HTTP请求

这些都是**正常的服务器行为**，但因为连线数多、端口模式特殊，容易触发异常检测。

### 解决方案

通过 `--exclude-servers` 参数：
1. **训练阶段**：排除这些流量，让模型专注学习真正的异常
2. **检测阶段**：过滤这些已知的正常模式，减少误报

### 适用场景

✅ **建议使用** `--exclude-servers`：
- 环境中有大量活跃的服务器（DNS, LDAP, Web等）
- 关注主动攻击行为（扫描、外泄、C&C）
- 减少误报，提高检测精度

❌ **不建议使用**：
- 想要检测服务器本身的异常行为
- 需要监控所有类型的异常（包括服务器回应模式的变化）
- 初次分析，想看完整的异常分布

## 验证方法

### 1. 查看某个IP是否被识别为服务器回应

```python
from nad.ml.feature_engineer import FeatureEngineer

fe = FeatureEngineer()
features = fe.extract_features(aggregation_data)

if features['is_likely_server_response'] == 1:
    print("✅ 会被 --exclude-servers 排除")
else:
    print("❌ 不会被排除")
```

### 2. 查看详细特征值

```python
print(f"源端口多样性: {features['src_port_diversity']:.3f}")  # < 0.1 ?
print(f"目的端口多样性: {features['dst_port_diversity']:.3f}")  # > 0.3 ?
print(f"源端口数量: {features['unique_src_ports']}")  # <= 100 ?
print(f"连线数: {features['flow_count']}")  # > 100 ?
print(f"平均流量: {features['avg_bytes']}")  # < 50000 ?
```

## 配置文件

相关配置在 `nad/config.yaml`:

```yaml
features:
  enabled:
    - is_likely_server_response  # 启用此特征
```

特征工程实现在: `nad/ml/feature_engineer.py:129-135`

## 总结

- `--exclude-servers` **不是**根据 device_type 过滤
- 它是根据**流量行为特征**动态判断是否为"服务器回应模式"
- 一个 IP 即使 device_type 是 `server_farm`，如果表现出**主动扫描/攻击**行为，也**不会被排除**
- 反之，即使 device_type 是 `iot` 或 `station`，如果表现出**服务器回应**特征，也**会被排除**
- 这是一种**基于行为的智能过滤**，而不是简单的IP地址黑名单
