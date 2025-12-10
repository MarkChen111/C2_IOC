# C2 IOC 威胁情报收集系统

这是一个自动化的威胁情报收集和合并系统，从多个公开来源收集恶意IP、C2服务器等IOC数据。

## 数据源

系统目前支持以下17个公开威胁情报源：

1. **AlienVault OTX** - 开放威胁交换平台
2. **URLhaus** - 恶意URL数据库
3. **ThreatFox** - 威胁情报平台
4. **TweetFeed** - 来自Twitter的IOC
5. **IPsum** - IP威胁情报
6. **Montysecurity C2 Tracker** - C2服务器追踪
7. **NamePipes/ThreatFox** - IP端口威胁情报
8. **FireHOL** - IP黑名单（包含IP段展开）
9. **C2IntelFeeds** - C2情报Feed
10. **EmergingThreats** - 受感染IP列表
11. **CINS Score** - 恶意IP评分
12. **Binary Defense** - 威胁情报和封禁列表
13. **SNORT** - IP封禁列表
14. **CyberCure** - AI驱动的威胁情报
15. **GreenSnow** - 黑名单
16. **ThreatView.io** - CobaltStrike C2情报

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

### 1. 单独运行某个数据源

进入对应目录运行采集脚本：

```bash
# 示例：采集URLhaus数据
cd Public_IOC/urlhaus
python code.py
```

### 2. 合并所有数据源

运行合并脚本：

```bash
cd Public_IOC/combine
python3 combine.py
```

### 3. 配置管理

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

| 文件 | 说明 | 数据范围 |
|------|------|----------|
| `history.csv` | 所有历史数据 | 完整记录 |
| `recent.csv` | 最近的活跃数据 | 最近6个月 |

**数据保留策略**：
- **history.csv**: 保存所有历史数据（完整记录）
- **recent.csv**: 只保留最近6个月的数据（基于 `crawl_date`）
- **数据源目录**: 各数据源的 `data/` 目录只保留最近7天的文件
- 配置文件: `config.yaml` 中可调整保留天数

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

- 2025-12-10: 初始版本，支持17个数据源
- 统一数据格式和字段命名
- 支持数据源排除功能
- 添加IP出现次数统计

