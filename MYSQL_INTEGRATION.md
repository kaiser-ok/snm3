# MySQL 整合說明

## 功能說明

`verify_anomaly.py` 已整合 MySQL 查詢功能，會自動從資料庫中查詢 IP 對應的設備名稱並顯示在報告中。

## 查詢來源

程式會依序查詢以下兩張表：
1. `Device` 表 - 網路設備（交換機、AP、伺服器等）
2. `ip_alias` 表 - IP 別名

## 顯示格式

如果查詢到設備名稱，會以下列格式顯示：
```
1. 192.168.10.135 (AD server)          →   856 次 (45.2%)
2. 192.168.10.90 (Flie server)         →   312 次 (16.5%)
3. 192.168.20.127                      →   198 次 (10.4%)
```

## 容錯機制

- 如果 PyMySQL 模組未安裝，程式仍可正常運行（不顯示設備名稱）
- 如果 MySQL 連線失敗，程式會靜默處理，不影響主要功能
- 查詢結果會快取，避免重複查詢相同 IP

## 安裝步驟

### 安裝 PyMySQL（如果尚未安裝）

系統已經有 Elasticsearch 和 NumPy，只需要安裝 PyMySQL：

```bash
sudo apt install python3-pymysql
```

或者如果您想使用最新版本：
```bash
python3 -m pip install pymysql --break-system-packages
```

## 使用方式

```bash
# 直接運行（不需要虛擬環境）
python3 verify_anomaly.py --ip 192.168.1.100 --minutes 30
```

## 配置檢查

確認 `nad/config.yaml` 中有正確的 MySQL 配置：
```yaml
mysql:
  host: localhost
  port: 3306
  user: control_user
  password: gentrice
  database: Control_DB
```

## 測試功能

可以使用以下命令測試 MySQL 整合：
```bash
python3 -c "
from nad.utils.config_loader import load_config
from elasticsearch import Elasticsearch
from verify_anomaly import AnomalyVerifier

config = load_config()
es = Elasticsearch([config.get('elasticsearch', {}).get('host', 'http://localhost:9200')], timeout=30)
verifier = AnomalyVerifier(es, config)

# 測試查詢
test_ips = ['192.168.10.135', '192.168.10.90', '192.168.20.127']
for test_ip in test_ips:
    result = verifier._format_ip_with_name(test_ip)
    print(f'{test_ip} -> {result}')
"
```

## 系統需求

- Python 3.x
- python3-pymysql (已安裝 ✓)
- elasticsearch (系統已有)
- numpy (系統已有)
- pyyaml (系統已有)
