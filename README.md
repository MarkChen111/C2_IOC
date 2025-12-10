# C2 IOC 威胁情报收集系统

这是一个自动化的威胁情报收集和合并系统，从多个公开来源收集恶意IP、C2服务器等IOC数据。

## 数据源

系统目前集成了16个公开威胁情报源，按质量分为三个等级：

### 🌟 优质数据源（8个）

| 数据源 | URL | 数据类型 | 采集方式 | 更新频率 | 数量/特点 |
|--------|-----|----------|----------|----------|-----------|
| **ThreatFox** | https://threatfox.abuse.ch/export/ | 页面表格数据 | 爬虫 | 每天更新 | 约800个C2 IP |
| **URLhaus** | https://urlhaus.abuse.ch/downloads/csv_online/ | 页面表格数据 | 爬虫 | 每天更新 | 传播恶意软件的URL，过去30天数据，需从URL提取IP |
| **AlienVault OTX** | https://otx.alienvault.com/ | API订阅 | API请求 | 实时更新 | 订阅优质IOC，每日约1000个 |
| **TweetFeed** | https://tweetfeed.live/api.html | API订阅 | API请求 | 每天更新 | 从Twitter收集的IOC |
| **IPsum** | https://github.com/stamparm/ipsum | IP列表 | 爬虫 | 每天更新 | 约2万个，至少在3个公开黑名单中出现 |
| **Montysecurity** | https://github.com/montysecurity/C2-Tracker | IP列表 | 爬虫 | 每天更新 | 约2000个，从Shodan搜索的C2 IP，含23种C2框架、62种恶意软件 |
| **NamePipes** | https://github.com/mthcht/awesome-lists | IP列表 | 爬虫 | 每天更新 | 从ThreatFox爬取5年C2数据，约5万条，近一个月约7000条 |
| ~~**Blocklist.de**~~ | https://www.blocklist.de/en/export.html | IP列表 | 直接下载 | 每天更新 | 约2万个，与C2关联小，**已弃用** |

### ⭐ 一般数据源（5个）

| 数据源 | URL | 数据类型 | 采集方式 | 更新频率 | 数量/特点 |
|--------|-----|----------|----------|----------|-----------|
| **FireHOL** | https://github.com/firehol/blocklist-ipsets | IP列表 | 爬虫 | 每天更新 | 约3万C2 IP |
| **C2IntelFeeds** | https://github.com/drb-ra/C2IntelFeeds | IP列表 | 爬虫 | 每天更新 | 近30天C2 IP，约3000个 |
| **EmergingThreats** | https://rules.emergingthreats.net/blockrules/ | IP列表 | 爬虫 | 每天更新 | 每天约400个受感染IP |
| **CINS Score** | https://cinsscore.com/list/ci-badguys.txt | IP列表 | 爬虫 | 每天更新 | 约15000个 |
| **Binary Defense** | https://www.binarydefense.com/banlist.txt | IP列表 | 爬虫 | 每天更新 | 约4000个 |

### 📋 一般数据源（3个）

| 数据源 | URL | 数据类型 | 采集方式 | 更新频率 | 数量/特点 |
|--------|-----|----------|----------|----------|-----------|
| **SNORT** | https://snort.org/downloads/ip-block-list | IP列表 | 爬虫 | 未知 | 约1600个 |
| **CyberCure** | https://api.cybercure.ai/feed/get_ips | IP列表 | 爬虫 | 未知 | 约5万个 |
| **GreenSnow** | https://blocklist.greensnow.co/greensnow.txt | IP列表 | 爬虫 | 未知 | 约7000个，监控扫描/暴力破解：FTP、SSH、SMTP等 |
| **ThreatView.io** | https://threatview.io/Downloads/ | IP列表 | 爬虫 | 未知 | 最近1个月约150个CobaltStrike C2 IP |

## 目录结构

```
C2_IOC/
├── controller.py           # 主控制脚本（合并所有数据）
├── Public_IOC/            # 各个数据源目录
│   ├── alienvault/
│   │   ├── code.py        # 数据采集脚本
│   │   └── data/          # 采集的数据
│   ├── urlhaus/
│   ├── tweetfeed/
│   ├── ...（其他数据源）
│   └── combine/           # 合并后的数据
└── README.md
```

## 使用方法

### 🚀 快速开始

```bash
# 1. 安装依赖
pip3 install --break-system-packages requests pyyaml

# 2. 配置API密钥（如果需要）
vim config.yaml

# 3. 运行每日自动更新
python3 run_daily_update.py

# 4. 查看结果
head -20 Public_IOC/combine/recent_high_risk_ips.csv | column -t -s $'\t'
```

### 1. 自动更新（推荐）

使用主控脚本自动采集所有数据源并合并：

```bash
# 运行每日更新（会依次运行所有16个数据源，然后自动合并）
python3 run_daily_update.py

# 查看运行日志
tail -f logs/ioc_collection.log
```

### 2. 单独运行某个数据源

进入对应目录运行采集脚本：

```bash
# 示例：采集URLhaus数据
cd Public_IOC/urlhaus
python3 code.py
```

### 3. 手动合并数据

运行合并脚本：

```bash
cd Public_IOC/combine
python3 combine.py
```

### 4. 配置管理

编辑项目根目录的 `config.yaml`：

```yaml
# 排除不需要的数据源
exclude_list:
  - SNORT
  - ipsum

# AlienVault配置
alienvault:
  api_key: "your_api_key_here"
  days: 7
  max_pages: 200

# 数据保留策略
data_retention:
  source_data_days: 7   # 数据源文件保留天数
  recent_months: 3      # recent.csv保留月数
```

### 5. 设置定时任务

每天自动运行：

```bash
# 使用crontab（每天凌晨2点）
(crontab -l 2>/dev/null; echo "0 2 * * * cd /path/to/C2_IOC && /usr/bin/python3 run_daily_update.py >> logs/daily_\$(date +\%Y\%m\%d).log 2>&1") | crontab -
```

## 数据格式

### 统一格式

所有合并后的数据使用以下统一格式（使用 `\t` 分隔）：

| 字段 | 说明 | 示例 |
|------|------|------|
| ip | IP地址（小写） | 192.168.1.1 |
| port | 端口（如果有） | 8080 |
| tag | 威胁类型标签 | AsyncRAT\|Cobalt Strike |
| ioc_source | IOC来源（数据源名称） | NamePipes\|urlhaus |
| first_seen_utc | IOC首次发现时间 | 2025-12-10 |
| crawl_date | 数据爬取时间 | 2025-12-10 |
| count | 出现在不同数据源的次数 | 5 |

### 时间格式

统一使用 `YYYY-MM-DD` 格式，例如：`2025-12-10`

### 字段说明

- **tag**: 威胁类型标签，如AsyncRAT、Cobalt Strike等（如果数据源没有提供，则为空）
- **ioc_source**: IOC的来源数据源名称（多个用|分隔）
- **first_seen_utc**: 威胁情报源记录的IOC首次发现时间
- **crawl_date**: 我们爬取数据的时间（即当天日期）
- **count**: 该IP在不同数据源中出现的次数，数值越高表示可信度越高

## 输出文件

合并后的数据保存在 `Public_IOC/combine/` 目录下：

| 文件 | 说明 | 数据范围 | 用途 |
|------|------|----------|------|
| `history.csv` | 所有历史数据 | 完整记录 | 历史分析、回溯调查 |
| `recent.csv` | 最近的活跃威胁 | 最近3个月 | 日常威胁监控 |
| `recent_high_risk_ips.csv` | 高危IP（多源验证） | 最近3个月，count≥3 | 直接应用于安全防护 🎯 |

**数据保留策略**：
- **history.csv**: 保存所有历史数据（完整记录）
- **recent.csv**: 只保留最近3个月的数据（`first_seen_utc` 和 `crawl_date` 都必须在3个月内）
- **recent_high_risk_ips.csv**: 只保留最近3个月内，且出现在3个或以上数据源的高危IP（count ≥ 3）
- **数据源目录**: 各数据源的 `data/` 目录只保留最近7天的文件
- **配置文件**: `config.yaml` 中可调整保留天数

**高危IP统计（recent_high_risk_ips.csv）**：
- count = 3: ~8,185条 (68%) - 高危
- count = 4: ~3,099条 (26%) - 很高危
- count = 5: ~682条 (6%) - 极高危
- count = 6: ~27条 (0.2%) - ⚠️ 超高危（出现在6个数据源）

## 数据源字段映射

系统会自动处理不同数据源的字段差异：

- 统一IP字段为小写
- 统一时间字段为 `first_seen_utc`
- 统一分隔符为 `\t`（制表符）
- 自动提取和转换日期格式

## 注意事项

1. **API密钥**: AlienVault OTX需要API密钥，请在 `Public_IOC/alienvault/code.py` 中配置
2. **请求频率**: 部分数据源可能有请求频率限制，建议适当设置延迟
3. **数据更新**: 建议每天运行一次采集脚本更新数据
4. **存储空间**: 合并后的数据可能较大，请确保有足够的磁盘空间

## 示例

### 查看合并数据

```bash
# 查看前10条记录
head -n 11 Public_IOC/combine/2025-12-10.csv | column -t -s $'\t'
```

### 统计高频IP

```bash
# 统计count>3的高可信度IP
awk -F'\t' '$6 > 3 {print $0}' Public_IOC/combine/2025-12-10.csv | wc -l
```

### 按数据源过滤

编辑 `controller.py` 中的 `EXCLUDE_LIST` 来排除不需要的数据源。

## 许可

本项目收集的数据来自公开的威胁情报源，请遵守各数据源的使用条款。

## 更新日志

- 2025-12-10: 初始版本，支持16个数据源
- 统一数据格式和字段命名
- 支持数据源排除功能
- 添加IP出现次数统计

