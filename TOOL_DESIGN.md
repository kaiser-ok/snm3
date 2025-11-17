# NetFlow 異常流量分析工具 - 系統設計規劃

## 專案概述

**專案名稱:** NetFlow Anomaly Detector (NAD)
**目標:** 自動化分析 NetFlow 數據，偵測網路異常行為並生成詳細報告
**語言:** Python 3.8+
**版本:** 1.0.0

---

## 一、系統架構設計

### 1.1 整體架構

```
┌─────────────────────────────────────────────────────────────┐
│                     CLI Interface                            │
│  (命令列工具 - 提供互動式和批次執行模式)                      │
└─────────────────┬───────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│                  Core Analysis Engine                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Data Fetcher │  │   Analyzer   │  │   Reporter   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────┬───────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│              Data Source Adapters                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ ElasticSearch│  │    MySQL     │  │  Cache Layer │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 核心模組

#### 模組 1: Data Layer (數據層)
- **ElasticSearchClient:** NetFlow 數據查詢
- **MySQLClient:** 設備資訊查詢
- **CacheManager:** 查詢結果快取 (Redis/本地快取)

#### 模組 2: Analysis Layer (分析層)
- **TrafficAnalyzer:** 流量統計分析
- **AnomalyDetector:** 異常檢測引擎
- **BehaviorClassifier:** 行為分類器
- **ThreatScorer:** 威脅評分系統

#### 模組 3: Reporting Layer (報告層)
- **ReportGenerator:** 多格式報告生成 (Markdown, HTML, JSON, PDF)
- **AlertManager:** 告警管理
- **NotificationService:** 通知服務 (Email, Webhook, Syslog)

#### 模組 4: Configuration Layer (配置層)
- **ConfigManager:** 配置文件管理
- **RuleEngine:** 規則引擎
- **ThresholdManager:** 閾值管理

---

## 二、異常檢測規則設計

### 2.1 檢測維度

#### A. 流量異常
```yaml
traffic_anomalies:
  - name: high_volume_flow
    description: 單一連線高流量
    threshold: 100MB
    severity: high

  - name: traffic_spike
    description: 流量突增
    method: statistical
    baseline: 7d_average
    multiplier: 3.0
    severity: medium
```

#### B. 連線異常
```yaml
connection_anomalies:
  - name: excessive_connections
    description: 單一IP高連線數
    threshold: 1000
    timeframe: 1h
    severity: high

  - name: connection_rate_spike
    description: 連線速率異常
    threshold: 100/sec
    severity: high
```

#### C. 掃描行為
```yaml
scanning_behaviors:
  - name: port_scanning
    description: 端口掃描
    conditions:
      - unique_destinations: ">50"
      - avg_bytes_per_flow: "<10KB"
      - connection_count: ">100"
    severity: critical

  - name: network_scanning
    description: 網路掃描
    conditions:
      - unique_destinations: ">100"
      - avg_bytes_per_flow: "<5KB"
    severity: critical
```

#### D. 協定異常
```yaml
protocol_anomalies:
  - name: dns_query_storm
    description: DNS查詢風暴
    protocol: UDP
    port: 53
    threshold: 1000/min
    severity: critical

  - name: unusual_protocol
    description: 異常協定使用
    whitelist: [6, 17, 1]  # TCP, UDP, ICMP
    severity: medium
```

#### E. 時間模式異常
```yaml
temporal_anomalies:
  - name: off_hours_activity
    description: 非工作時間異常活動
    work_hours: "08:00-18:00"
    weekdays: [1,2,3,4,5]
    threshold_multiplier: 2.0
    severity: medium
```

### 2.2 威脅評分系統

```python
threat_score_calculation:
  base_score: 0

  factors:
    - connection_count:
        weight: 0.3
        scale: logarithmic

    - unique_destinations:
        weight: 0.2
        scale: linear

    - avg_bytes_per_connection:
        weight: 0.15
        scale: inverse  # 越小越可疑

    - protocol_diversity:
        weight: 0.15

    - blacklist_match:
        weight: 0.2
        bonus: +50

  severity_levels:
    - low: 0-30
    - medium: 31-60
    - high: 61-80
    - critical: 81-100
```

---

## 三、配置文件設計

### 3.1 主配置文件 (config.yaml)

```yaml
# NetFlow Anomaly Detector Configuration
version: "1.0"

# 數據源配置
data_sources:
  elasticsearch:
    host: "localhost"
    port: 9200
    index_pattern: "radar_flow_collector-{date}"
    timeout: 30

  mysql:
    host: "127.0.0.1"
    port: 3306
    database: "Control_DB"
    user: "control_user"
    password: "gentrice"
    pool_size: 10

# 分析配置
analysis:
  default_timeframe: "1h"
  timezone: "Asia/Taipei"

  # 採樣策略 (可選，大數據量時使用)
  sampling:
    enabled: false
    rate: 0.1  # 10% 採樣

# 異常檢測閾值
thresholds:
  traffic:
    high_volume_flow: 104857600  # 100MB in bytes
    total_traffic_gb: 100

  connections:
    per_ip_per_hour: 1000
    per_second: 100

  scanning:
    unique_destinations: 50
    avg_bytes_threshold: 10240  # 10KB
    min_connections: 100

  dns:
    queries_per_minute: 1000
    queries_per_hour: 10000

# 報告配置
reporting:
  output_dir: "./reports"
  formats:
    - markdown
    - html
    - json

  retention_days: 30

  # 報告包含項目
  sections:
    - summary
    - top_talkers
    - anomalies
    - threat_assessment
    - recommendations

# 告警配置
alerting:
  enabled: true

  channels:
    email:
      enabled: false
      smtp_server: "smtp.example.com"
      from: "nad@example.com"
      to: ["admin@example.com"]

    webhook:
      enabled: false
      url: "https://hooks.example.com/nad"

    syslog:
      enabled: false
      server: "syslog.example.com"
      port: 514

  severity_filter: "medium"  # 只告警 medium 以上

# 快取配置
cache:
  enabled: true
  backend: "memory"  # memory, redis
  ttl: 300  # seconds

# 日誌配置
logging:
  level: "INFO"
  file: "./logs/nad.log"
  max_size: 10485760  # 10MB
  backup_count: 5
```

### 3.2 規則配置文件 (rules.yaml)

```yaml
# 異常檢測規則定義
rules:
  # 高優先級規則
  - id: "R001"
    name: "Port Scanning Detection"
    category: "scanning"
    severity: "critical"
    enabled: true

    conditions:
      - field: "unique_dst_ips"
        operator: ">"
        value: 50
      - field: "avg_bytes_per_flow"
        operator: "<"
        value: 10240
      - field: "flow_count"
        operator: ">"
        value: 100

    description: "檢測端口掃描行為"
    recommendation: "立即隔離來源IP並進行安全調查"

  - id: "R002"
    name: "DNS Query Storm"
    category: "protocol_abuse"
    severity: "critical"
    enabled: true

    conditions:
      - field: "dst_port"
        operator: "=="
        value: 53
      - field: "flow_count"
        operator: ">"
        value: 10000
        timeframe: "1h"

    description: "檢測DNS查詢風暴"
    recommendation: "檢查DNS配置和應用程式行為"

  - id: "R003"
    name: "High Connection Count"
    category: "connection"
    severity: "high"
    enabled: true

    conditions:
      - field: "connection_count"
        operator: ">"
        value: 1000
        timeframe: "1h"

    description: "單一IP異常高連線數"
    recommendation: "調查設備行為，確認是否為異常應用或惡意軟體"

  - id: "R004"
    name: "Large Single Flow"
    category: "traffic"
    severity: "high"
    enabled: true

    conditions:
      - field: "flow_bytes"
        operator: ">"
        value: 104857600  # 100MB

    description: "單一連線大量數據傳輸"
    recommendation: "確認是否為合法的大檔案傳輸或備份作業"

  - id: "R005"
    name: "Network Reconnaissance"
    category: "scanning"
    severity: "critical"
    enabled: true

    conditions:
      - field: "unique_dst_ips"
        operator: ">"
        value: 100
      - field: "unique_dst_ports"
        operator: ">"
        value: 10
      - field: "avg_bytes_per_flow"
        operator: "<"
        value: 5120

    description: "網路偵察行為"
    recommendation: "可能是攻擊前的偵察，立即調查並考慮隔離"

# 白名單
whitelists:
  ips:
    - "8.8.8.8"  # Google DNS
    - "1.1.1.1"  # Cloudflare DNS
    description: "已知的公共DNS伺服器"

  ports:
    - 80
    - 443
    - 53
    description: "常見合法端口"

  devices:
    - ip: "192.168.10.254"
      description: "主要閘道"
      allow_high_connections: true

# 黑名單 (惡意IP/已知威脅)
blacklists:
  ips:
    - "0.0.0.0/8"
    - "127.0.0.0/8"

  # 可整合外部威脅情報
  threat_feeds:
    enabled: false
    sources:
      - url: "https://feeds.example.com/malicious-ips"
        format: "text"
        update_interval: 3600
```

---

## 四、核心功能實作設計

### 4.1 目錄結構

```
netflow-anomaly-detector/
├── README.md
├── requirements.txt
├── setup.py
├── config/
│   ├── config.yaml
│   ├── rules.yaml
│   └── config.example.yaml
├── nad/
│   ├── __init__.py
│   ├── cli.py                    # CLI 入口
│   ├── core/
│   │   ├── __init__.py
│   │   ├── engine.py             # 分析引擎主控制器
│   │   ├── analyzer.py           # 流量分析器
│   │   ├── detector.py           # 異常檢測器
│   │   └── scorer.py             # 威脅評分器
│   ├── datasources/
│   │   ├── __init__.py
│   │   ├── elasticsearch.py      # ES 數據源
│   │   ├── mysql.py              # MySQL 數據源
│   │   └── cache.py              # 快取管理
│   ├── models/
│   │   ├── __init__.py
│   │   ├── traffic.py            # 流量數據模型
│   │   ├── device.py             # 設備數據模型
│   │   └── anomaly.py            # 異常數據模型
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── generator.py          # 報告生成器
│   │   ├── templates/            # 報告模板
│   │   │   ├── markdown.jinja2
│   │   │   ├── html.jinja2
│   │   │   └── json.jinja2
│   │   └── formatters.py         # 格式化工具
│   ├── alerting/
│   │   ├── __init__.py
│   │   ├── manager.py            # 告警管理器
│   │   └── channels/             # 通知渠道
│   │       ├── email.py
│   │       ├── webhook.py
│   │       └── syslog.py
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── config.py             # 配置管理
│   │   ├── logger.py             # 日誌工具
│   │   └── helpers.py            # 輔助函數
│   └── rules/
│       ├── __init__.py
│       ├── engine.py             # 規則引擎
│       └── evaluator.py          # 規則評估器
├── tests/
│   ├── __init__.py
│   ├── test_analyzer.py
│   ├── test_detector.py
│   └── test_rules.py
├── scripts/
│   ├── install.sh                # 安裝腳本
│   └── schedule_cron.sh          # Cron 排程腳本
└── logs/
    └── .gitkeep
```

### 4.2 核心類別設計

#### A. AnalysisEngine (分析引擎)

```python
class AnalysisEngine:
    """
    核心分析引擎，協調各個組件完成分析任務
    """

    def __init__(self, config: Config):
        self.config = config
        self.es_client = ElasticSearchClient(config.elasticsearch)
        self.mysql_client = MySQLClient(config.mysql)
        self.cache = CacheManager(config.cache)
        self.analyzer = TrafficAnalyzer()
        self.detector = AnomalyDetector(config.rules)
        self.scorer = ThreatScorer()
        self.reporter = ReportGenerator(config.reporting)

    def analyze(self, timeframe: str = "1h", **kwargs) -> AnalysisResult:
        """
        執行完整分析流程

        Args:
            timeframe: 分析時間範圍 (1h, 6h, 24h, 7d)
            **kwargs: 其他分析參數

        Returns:
            AnalysisResult: 分析結果對象
        """
        # 1. 數據收集
        traffic_data = self._fetch_traffic_data(timeframe)
        device_info = self._fetch_device_info()

        # 2. 流量分析
        statistics = self.analyzer.analyze(traffic_data)

        # 3. 異常檢測
        anomalies = self.detector.detect(statistics)

        # 4. 威脅評分
        threats = self.scorer.score(anomalies)

        # 5. 設備關聯
        enriched_threats = self._enrich_with_device_info(threats, device_info)

        # 6. 生成結果
        result = AnalysisResult(
            statistics=statistics,
            anomalies=anomalies,
            threats=enriched_threats,
            timeframe=timeframe
        )

        return result
```

#### B. AnomalyDetector (異常檢測器)

```python
class AnomalyDetector:
    """
    異常檢測器，根據規則檢測各類異常
    """

    def __init__(self, rules: RuleConfig):
        self.rule_engine = RuleEngine(rules)
        self.detectors = {
            'traffic': TrafficAnomalyDetector(),
            'connection': ConnectionAnomalyDetector(),
            'scanning': ScanningDetector(),
            'protocol': ProtocolAnomalyDetector(),
        }

    def detect(self, statistics: TrafficStatistics) -> List[Anomaly]:
        """
        執行異常檢測
        """
        anomalies = []

        # 依序執行各類檢測器
        for detector_name, detector in self.detectors.items():
            detected = detector.detect(statistics)
            anomalies.extend(detected)

        # 應用規則引擎過濾和評分
        filtered_anomalies = self.rule_engine.evaluate(anomalies)

        return filtered_anomalies
```

#### C. TrafficAnalyzer (流量分析器)

```python
class TrafficAnalyzer:
    """
    流量統計分析器
    """

    def analyze(self, traffic_data: List[FlowRecord]) -> TrafficStatistics:
        """
        分析流量數據，生成統計資訊
        """
        stats = TrafficStatistics()

        # 基礎統計
        stats.total_flows = len(traffic_data)
        stats.total_bytes = sum(f.in_bytes for f in traffic_data)
        stats.total_packets = sum(f.in_pkts for f in traffic_data)

        # Top N 統計
        stats.top_src_ips = self._get_top_sources(traffic_data)
        stats.top_dst_ips = self._get_top_destinations(traffic_data)
        stats.top_protocols = self._get_protocol_distribution(traffic_data)

        # 行為分析
        stats.ip_behaviors = self._analyze_ip_behaviors(traffic_data)

        return stats
```

---

## 五、CLI 介面設計

### 5.1 命令結構

```bash
# 基本使用
nad analyze                          # 分析過去1小時
nad analyze --timeframe 6h          # 分析過去6小時
nad analyze --start "2025-11-11 10:00" --end "2025-11-11 12:00"

# 指定 IP 分析
nad analyze-ip 192.168.10.135       # 分析特定IP
nad analyze-ip 192.168.10.135 --deep   # 深度分析

# 即時監控
nad monitor --interval 5m           # 每5分鐘分析一次

# 報告生成
nad report --format html            # 生成HTML報告
nad report --format json --output report.json

# 規則管理
nad rules list                      # 列出所有規則
nad rules test --rule-id R001       # 測試特定規則

# 配置管理
nad config show                     # 顯示當前配置
nad config validate                 # 驗證配置文件

# 基準線建立
nad baseline create --duration 7d   # 建立7天基準線
nad baseline update                 # 更新基準線
```

### 5.2 輸出格式

#### 終端輸出
```
╔══════════════════════════════════════════════════════════════╗
║         NetFlow Anomaly Detection Report                     ║
║         分析時間: 2025-11-11 12:00:00                        ║
║         時間範圍: 過去 1 小時                                 ║
╚══════════════════════════════════════════════════════════════╝

📊 流量總覽
─────────────────────────────────────────────────────────────
  總流量:     50.23 GB
  總封包數:   55,536,628
  總連線數:   1,825,780

🚨 發現異常: 3 個高風險, 5 個中風險
─────────────────────────────────────────────────────────────

🔴 [CRITICAL] Port Scanning Detected
  來源 IP:    192.168.10.135 (AD server)
  威脅評分:   95/100
  連線數:     510,823
  目標數:     107
  建議:       立即隔離並調查

🔴 [CRITICAL] DNS Query Storm
  來源 IP:    192.168.20.56
  威脅評分:   92/100
  DNS查詢:    214,318 次
  建議:       檢查DNS配置

⚠️  詳細報告已保存至: ./reports/anomaly_report_20251111_120000.html
```

---

## 六、實作階段規劃

### Phase 1: 核心功能 (Week 1-2)
- [ ] 建立專案結構
- [ ] 實作 ElasticSearch 和 MySQL 數據源
- [ ] 實作基礎流量分析器
- [ ] 實作簡單的異常檢測器
- [ ] 實作 Markdown 報告生成

### Phase 2: 規則引擎 (Week 3)
- [ ] 實作規則引擎
- [ ] 實作配置文件解析
- [ ] 實作各類異常檢測器
- [ ] 實作威脅評分系統

### Phase 3: CLI 與報告 (Week 4)
- [ ] 實作 CLI 介面
- [ ] 實作多格式報告 (HTML, JSON)
- [ ] 實作設備資訊關聯
- [ ] 實作快取機制

### Phase 4: 告警與監控 (Week 5)
- [ ] 實作告警管理器
- [ ] 實作通知渠道 (Email, Webhook)
- [ ] 實作即時監控模式
- [ ] 實作基準線功能

### Phase 5: 優化與測試 (Week 6)
- [ ] 性能優化
- [ ] 編寫單元測試
- [ ] 編寫文檔
- [ ] 安裝與部署腳本

---

## 七、技術選型

### 7.1 核心依賴

```txt
# requirements.txt
elasticsearch>=7.17.0,<8.0.0
PyMySQL>=1.0.0
click>=8.0.0              # CLI 框架
pyyaml>=6.0               # YAML 配置解析
jinja2>=3.0.0             # 報告模板
tabulate>=0.9.0           # 表格格式化
colorama>=0.4.0           # 終端顏色
python-dateutil>=2.8.0    # 日期處理
pandas>=1.3.0             # 數據分析
numpy>=1.21.0             # 數值計算
requests>=2.28.0          # HTTP 請求
redis>=4.0.0              # 快取 (可選)
```

### 7.2 可選增強功能

```txt
# 進階分析
scikit-learn>=1.0.0       # 機器學習異常檢測
matplotlib>=3.5.0         # 圖表生成
plotly>=5.0.0             # 互動式圖表

# 報告增強
weasyprint>=54.0          # PDF 生成
markdown>=3.4.0           # Markdown 處理

# 監控與告警
prometheus-client>=0.14.0 # Prometheus metrics
APScheduler>=3.9.0        # 任務排程
```

---

## 八、API 設計 (供程式調用)

```python
from nad import NetFlowAnalyzer

# 初始化
analyzer = NetFlowAnalyzer(config_file='config.yaml')

# 執行分析
result = analyzer.analyze(timeframe='1h')

# 訪問結果
print(f"發現 {len(result.anomalies)} 個異常")

for anomaly in result.get_critical_anomalies():
    print(f"[{anomaly.severity}] {anomaly.description}")
    print(f"  來源: {anomaly.source_ip}")
    print(f"  評分: {anomaly.threat_score}")

# 生成報告
analyzer.generate_report(result, format='html', output='report.html')

# 發送告警
if result.has_critical_anomalies():
    analyzer.send_alerts(result)
```

---

## 九、部署與維運

### 9.1 安裝

```bash
# 從源碼安裝
git clone https://github.com/your-org/netflow-anomaly-detector.git
cd netflow-anomaly-detector
pip install -e .

# 或使用 pip
pip install netflow-anomaly-detector

# 初始化配置
nad init --config-dir /etc/nad
```

### 9.2 排程執行 (Cron)

```bash
# 每小時執行一次分析
0 * * * * /usr/local/bin/nad analyze --quiet >> /var/log/nad/analysis.log 2>&1

# 每天生成日報
0 8 * * * /usr/local/bin/nad report --timeframe 24h --format html --email admin@example.com
```

### 9.3 Systemd 服務 (監控模式)

```ini
[Unit]
Description=NetFlow Anomaly Detector Monitor
After=network.target

[Service]
Type=simple
User=nad
ExecStart=/usr/local/bin/nad monitor --interval 5m
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

---

## 十、未來擴展方向

### 10.1 機器學習增強
- 使用 Isolation Forest 進行無監督異常檢測
- LSTM 時序預測流量趨勢
- 自動學習正常行為模式

### 10.2 視覺化儀表板
- Web UI 介面
- 即時流量監控圖表
- 異常事件時間軸

### 10.3 整合外部系統
- SIEM 系統整合 (Splunk, ELK)
- 威脅情報整合 (VirusTotal, AlienVault)
- 自動化響應 (封鎖 IP, 隔離設備)

### 10.4 分散式部署
- 支援多個 radar 節點
- 分散式分析處理
- 中央管理平台

---

## 十一、文檔與培訓

### 11.1 文檔需求
- [ ] 用戶手冊
- [ ] API 參考文檔
- [ ] 規則編寫指南
- [ ] 故障排除指南
- [ ] 最佳實踐文檔

### 11.2 範例與模板
- [ ] 常見異常案例庫
- [ ] 規則範例集
- [ ] 報告模板庫
- [ ] 配置範例

---

**規劃完成日期:** 2025-11-11
**預計開發週期:** 6 週
**維護者:** Network Security Team
