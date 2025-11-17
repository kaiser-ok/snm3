# 網路管理系統 - 系統架構分析報告

一個蒐集網路訊息的系統：
1. 透過probe 蒐集網路上的廣播封包等資訊，這probe 叫做 radar ，蒐集了switch snmp 資料進行網路拓樸的分析，以及port 流量, fdb, arp 表等資訊的定期蒐集
2. 蒐集netflow 的資料
3. 蒐集syslog的資料

此系統的資料結構請參考”數據結構整理報告.md”


目標：分析netflow 有沒有什麼異常, netflow 會即時存到ES 資料庫中

現有的網路管理系統存在container中，必要時可以參考
 容器名稱: snm-admin-web_mysql映像檔: mariadb:10.6 (版本 10.6.23)

  ---
  🔌 連線資訊

  從主機連線

  - 主機 Port: 127.0.0.1:3306
  - 容器 Port: 3306
  - 網路 IP: 172.26.1.6
  - 網路名稱: snm-admin-web_default

  資料庫帳號資訊

  - Root 密碼: gentrice
  - 一般使用者: control_user
  - 使用者密碼: gentrice
  - 預設資料庫: Control_DB

  ---
  💾 重要路徑對應

  主機 → 容器掛載

  1. 資料庫資料目錄:
    - 主機: /docker/data/snm-admin-web/mysql
    - 容器: /var/lib/mysql
  2. 設定檔:
    - 主機: /docker/app/snm-admin-web/required-files/conf/mysql-custom.cnf
    - 容器: /etc/mysql/conf.d/custom.cnf
  3. 初始化 SQL 腳本:
    - 主機: /docker/app/snm-admin-web/required-files/db_sql
    - 容器: /docker-entrypoint-initdb.d

  ---
  🔑 登入方式

  方式 1: 從主機直接連線

  mysql -h 127.0.0.1 -P 3306 -u root -p
  # 密碼: gentrice

  或使用一般使用者：
  mysql -h 127.0.0.1 -P 3306 -u control_user -p Control_DB
  # 密碼: gentrice

  方式 2: 進入容器內執行

  sudo docker exec -it snm-admin-web_mysql bash
  mysql -u root -p
  # 密碼: gentrice



## 技術棧概述

- **時序數據：** ElasticSearch 7.17.28
  - 主機：localhost:9200
  - 叢集名稱：GSNM-ES
  - 索引模式：按日期分區 (YYYY.MM.DD 或 YYYY.MM)

- **結構化數據：** MySQL / MariaDB 10.6
  - 主機：127.0.0.1:3306
  - 資料庫：Control_DB
  - 用戶：control_user / gentrice





### 主要組件

#### 1. 資料庫連接設置

**ElasticSearch 連接：**
```javascript
const esClient = new Client({
  node: 'http://localhost:9200'
});
```

**MySQL 連接池：**
```javascript
const mysqlPool = mysql.createPool({
  host: '127.0.0.1',
  port: 3306,
  user: 'control_user',
  password: 'gentrice',
  database: 'Control_DB',
  connectionLimit: 10,
  queueLimit: 0
});
```







