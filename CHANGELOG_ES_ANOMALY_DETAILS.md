# 异常检测记录增强更新日志

## 更新日期
2025-11-16

## 更新内容

### 1. 增强 Elasticsearch 索引字段 (nad/anomaly_logger.py)

在 `anomaly_detection-*` 索引中新增以下字段，用于保存完整的异常分析结果：

#### 新增字段

| 字段名 | 类型 | 说明 |
|--------|------|------|
| `behavior_features` | text | 行为特征标签（如：高連線數、掃描模式、小封包、大流量） |
| `indicators` | text | 关键指标列表（每行一个指标，以 `\n` 分隔） |
| `response_actions` | text | 建议响应行动（每行一个行动，以 `\n` 分隔） |

#### 原有威胁分类字段
- `threat_class` - 威胁类别（中文）
- `threat_class_en` - 威胁类别（英文）
- `threat_confidence` - 分类置信度
- `severity` - 严重性级别（CRITICAL, HIGH, MEDIUM, LOW）
- `priority` - 优先级（P0, P1, P2, P3）
- `description` - 威胁描述

### 2. 更新数据写入逻辑 (nad/anomaly_logger.py:170-235)

#### 修改 `log_anomalies_batch` 方法

1. **提取行为特征**
   ```python
   behaviors = []
   if anomaly.get('features', {}).get('is_high_connection'):
       behaviors.append("高連線數")
   if anomaly.get('features', {}).get('is_scanning_pattern'):
       behaviors.append("掃描模式")
   # ... 更多特征
   ```

2. **保存完整分类信息**
   ```python
   # 保存详细的关键指标（每行一个，便于展示）
   "indicators": '\n'.join(classification.get('indicators', [])),

   # 保存详细的响应建议（每行一个，便于展示）
   "response_actions": '\n'.join(classification.get('response', [])),

   # 保存行为特征
   "behavior_features": ', '.join(behaviors) if behaviors else None
   ```

### 3. 测试工具

#### `test_es_anomaly_data.py`
- 查询并显示最新的异常记录
- 验证所有字段是否正确保存
- 显示字段完整性统计

#### `reset_es_template.py`
- 删除旧的索引模板和数据
- 用于重置索引以应用新的字段定义

## 使用示例

### 1. 运行实时检测（持续模式）

```bash
python3 realtime_detection.py --continuous --minutes 10 --interval 5
```

数据将自动写入 Elasticsearch，包含完整的分析结果。

### 2. 查询验证数据

```bash
python3 test_es_anomaly_data.py
```

输出示例：
```
异常记录详情:
   检测时间: 2025-11-15 20:40:00 (本地时间)
   源IP: 192.168.10.25

   异常指标:
      异常分数: 0.6217
      置信度: 0.61
      连线数: 1,318

   行为特征: 高連線數

   威胁分类:
      类别: 未知異常 (Unknown Anomaly)
      置信度: 50%
      严重性: MEDIUM
      优先级: P2
      描述: 無法分類的異常行為

      关键指标:
         • 異常特徵組合不匹配已知模式

      建议行动:
         • 人工審查
         • 持續監控
         • 收集更多數據
         • 可能需要更新分類規則
```

### 3. 在 Kibana 中查看

1. 创建索引模式：`anomaly_detection-*`
2. 可视化字段：
   - `threat_class` - 威胁类别统计
   - `severity` - 严重性分布
   - `src_ip` - Top 异常 IP
   - `behavior_features` - 行为特征分析
   - `indicators` - 关键指标（需要分词）
   - `response_actions` - 响应建议（需要分词）

## 数据示例

### Elasticsearch 文档结构

```json
{
  "@timestamp": "2025-11-16T00:22:09.123Z",
  "detection_time": "2025-11-16T00:22:09.123Z",
  "time_bucket": "2025-11-15T12:40:00.000Z",
  "src_ip": "192.168.10.25",
  "device_type": "server_farm",

  "anomaly_score": 0.6217,
  "confidence": 0.61,
  "flow_count": 1318,
  "unique_dsts": 8,
  "unique_src_ports": 38,
  "unique_dst_ports": 56,
  "total_bytes": 61409536,
  "avg_bytes": 46595,

  "behavior_features": "高連線數",

  "threat_class": "未知異常",
  "threat_class_en": "Unknown Anomaly",
  "threat_confidence": 0.5,
  "severity": "MEDIUM",
  "priority": "P2",
  "description": "無法分類的異常行為",

  "indicators": "異常特徵組合不匹配已知模式",

  "response_actions": "人工審查\n持續監控\n收集更多數據\n可能需要更新分類規則"
}
```

## 注意事项

1. **首次使用需要重置索引**
   ```bash
   python3 reset_es_template.py
   ```
   这将删除旧的索引模板和数据，确保新字段定义生效。

2. **数据格式**
   - `indicators` 和 `response_actions` 使用 `\n` 分隔多个条目
   - `behavior_features` 使用 `, ` 分隔多个特征
   - 如果字段值为空列表或 None，则不写入该字段

3. **字段完整性**
   - 所有威胁分类字段（`threat_class`, `severity` 等）应该 100% 填充
   - `behavior_features` 仅在检测到行为特征时填充
   - `indicators` 和 `response_actions` 取决于威胁类别是否定义了这些信息

## 后续工作建议

1. **Kibana Dashboard**
   - 创建异常检测仪表板
   - 可视化威胁分布和趋势
   - 设置告警规则

2. **数据分析**
   - 统计各威胁类别的频率
   - 分析 Top 异常 IP 的历史记录
   - 评估响应行动的有效性

3. **优化改进**
   - 根据实际数据调整分类规则
   - 增加更多威胁类别
   - 优化关键指标的描述
