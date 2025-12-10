#!/usr/bin/env python3
"""
IOC数据合并脚本
功能：
1. 统一所有IOC数据格式（\t分隔，IP小写，统一时间字段）
2. 合并所有数据源
3. 统计IP出现次数
4. 支持排除指定数据源
"""

import os
import sys
import csv
import glob
from datetime import datetime, timedelta
from collections import defaultdict

# 添加项目根目录到路径，以便导入logger_utils
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
sys.path.insert(0, ROOT_DIR)

try:
    from logger_utils import log_data_merge
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False
    print("[!] 警告: logger_utils模块未找到，统计信息将只输出到控制台")

# 尝试导入yaml，如果失败则使用默认配置
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    print("[!] 警告: PyYAML未安装，使用默认配置。运行 'pip3 install pyyaml' 安装。")

# =========================
# 加载配置文件
# =========================
def load_config():
    """加载yaml配置文件"""
    if not YAML_AVAILABLE:
        return {}
    
    # 配置文件在项目根目录（向上两级）
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(os.path.dirname(script_dir))
    config_file = os.path.join(root_dir, "config.yaml")
    
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"[!] 配置文件加载失败: {e}")
            return {}
    return {}

CONFIG = load_config()

# =========================
# 配置
# =========================
# 获取脚本所在目录和项目根目录
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))

PUBLIC_IOC_DIR = os.path.join(ROOT_DIR, "Public_IOC")
OUTPUT_DIR = SCRIPT_DIR  # 输出到当前目录（Public_IOC/combine）
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 当前日期（爬取时间）
CRAWL_DATE = datetime.now().strftime("%Y-%m-%d")

# 从配置文件读取排除列表
EXCLUDE_LIST = CONFIG.get('exclude_list', [])

# 从配置文件读取保留策略
DATA_RETENTION = CONFIG.get('data_retention', {})
SOURCE_DATA_DAYS = DATA_RETENTION.get('source_data_days', 7)  # 默认7天
RECENT_MONTHS = DATA_RETENTION.get('recent_months', 3)  # 默认3个月

# =========================
# 数据结构映射
# =========================
# 记录每个数据源的字段映射关系
SOURCE_MAPPING = {
    "alienvault": {
        "ip_field": "ip",
        "time_field": "first_seen_utc",
        "tag_field": "tag",
        "port_field": None,
        "delimiter": "\t"
    },
    "Binarydefense": {
        "ip_field": "ip",
        "time_field": None,
        "tag_field": None,  # 此数据源没有威胁类型标签
        "port_field": None,
        "delimiter": ","
    },
    "C2IntelFeeds": {
        "ip_field": "ip",
        "time_field": None,
        "tag_field": "tag",
        "port_field": "port",
        "delimiter": ","
    },
    "cinsscore": {
        "ip_field": "ip",
        "time_field": None,
        "tag_field": None,
        "port_field": None,
        "delimiter": ","
    },
    "CyberCure": {
        "ip_field": "ip",
        "time_field": None,
        "tag_field": None,
        "port_field": None,
        "delimiter": ","
    },
    "emergingthreats": {
        "ip_field": "ip",
        "time_field": None,
        "tag_field": None,
        "port_field": None,
        "delimiter": ","
    },
    "FireHOL": {
        "ip_field": "ip",
        "time_field": None,
        "tag_field": None,
        "port_field": None,
        "delimiter": ","
    },
    "greensnow": {
        "ip_field": "ip",
        "time_field": None,
        "tag_field": None,
        "port_field": None,
        "delimiter": ","
    },
    "ipsum": {
        "ip_field": "ip",
        "time_field": None,
        "tag_field": None,
        "port_field": None,
        "delimiter": ","
    },
    "Montysecurity": {
        "ip_field": "ip",
        "time_field": None,
        "tag_field": "tag",
        "port_field": None,
        "delimiter": "\t"
    },
    "NamePipes": {
        "ip_field": "ip",
        "time_field": "first_seen_utc",
        "tag_field": "malware_printable",
        "port_field": "port",
        "delimiter": ","
    },
    "SNORT": {
        "ip_field": "ip",
        "time_field": None,
        "tag_field": None,
        "port_field": None,
        "delimiter": ","
    },
    "threatfox": {
        "ip_field": "ip",
        "time_field": "first_seen_utc_date",
        "tag_field": "malware",
        "port_field": "port",
        "delimiter": ","
    },
    "threatview.io": {
        "ip_field": "ip",
        "time_field": "first_seen_utc",
        "tag_field": None,
        "port_field": None,
        "delimiter": ","
    },
    "tweetfeed": {
        "ip_field": "ip",
        "time_field": "date",
        "tag_field": "tags",
        "port_field": None,
        "delimiter": ","
    },
    "urlhaus": {
        "ip_field": "ip",
        "time_field": "last_online",
        "tag_field": "threat",
        "port_field": None,
        "delimiter": ","
    }
}

# =========================
# 辅助函数
# =========================

def cleanup_old_source_data(public_ioc_dir, days_to_keep):
    """清理各数据源data目录中的旧文件"""
    cutoff_date = (datetime.now() - timedelta(days=days_to_keep)).strftime("%Y-%m-%d")
    total_deleted = 0
    
    # 遍历所有数据源目录
    for source_dir in glob.glob(os.path.join(public_ioc_dir, "*/")):
        data_dir = os.path.join(source_dir, "data")
        if not os.path.exists(data_dir):
            continue
        
        source_name = os.path.basename(os.path.dirname(source_dir))
        
        # 查找所有CSV文件
        csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
        for csv_file in csv_files:
            filename = os.path.basename(csv_file)
            
            # 尝试从文件名提取日期
            # 支持格式: 2025-12-10.csv 或 2025_12_09.csv
            date_str = None
            if filename.count("-") >= 2:
                # 格式: 2025-12-10.csv
                parts = filename.replace(".csv", "").split("-")
                if len(parts) == 3:
                    date_str = "-".join(parts)
            elif filename.count("_") >= 2:
                # 格式: 2025_12_09.csv
                parts = filename.replace(".csv", "").split("_")
                if len(parts) == 3:
                    date_str = "-".join(parts)
            
            # 如果提取到日期且早于保留期限，则删除
            if date_str and date_str < cutoff_date:
                try:
                    os.remove(csv_file)
                    total_deleted += 1
                    print(f"    删除: {source_name}/{filename}")
                except Exception as e:
                    print(f"    删除失败: {csv_file} - {e}")
    
    if total_deleted > 0:
        print(f"[+] 共删除 {total_deleted} 个旧文件")
    else:
        print(f"[+] 没有需要删除的旧文件")


def normalize_date(date_str):
    """统一日期格式为 YYYY-MM-DD"""
    if not date_str or date_str.strip() == "":
        return ""
    
    date_str = date_str.strip()
    
    # 已经是 YYYY-MM-DD 格式
    if len(date_str) == 10 and date_str.count("-") == 2:
        return date_str
    
    # ISO格式 2025-12-08T13:20:01.633000
    if "T" in date_str:
        return date_str.split("T")[0]
    
    # 其他格式尝试解析
    try:
        # 尝试多种格式
        for fmt in ["%Y-%m-%d", "%Y/%m/%d", "%d/%m/%Y", "%m/%d/%Y"]:
            try:
                dt = datetime.strptime(date_str.split()[0], fmt)
                return dt.strftime("%Y-%m-%d")
            except:
                continue
    except:
        pass
    
    return date_str


def process_csv_file(file_path, source_name, mapping):
    """处理单个CSV文件"""
    results = []
    
    try:
        delimiter = mapping.get("delimiter", ",")
        
        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f, delimiter=delimiter)
            
            for row in reader:
                # 提取IP
                ip_field = mapping.get("ip_field")
                ip = row.get(ip_field, "").strip().lower() if ip_field else ""
                
                if not ip:
                    continue
                
                # 提取时间
                time_field = mapping.get("time_field")
                first_seen = row.get(time_field, "") if time_field else ""
                first_seen = normalize_date(first_seen)
                
                # 提取tag（威胁类型）- 如果数据源没有tag字段，则为空
                tag_field = mapping.get("tag_field")
                tag = row.get(tag_field, "").strip() if tag_field else ""
                
                # 提取端口
                port_field = mapping.get("port_field")
                port = row.get(port_field, "").strip() if port_field else ""
                
                results.append({
                    "ip": ip,
                    "port": port,
                    "tag": tag,  # 威胁类型（可能为空）
                    "first_seen_utc": first_seen,
                    "crawl_date": CRAWL_DATE,
                    "source": source_name  # IOC来源
                })
                
    except Exception as e:
        print(f"[!] 处理文件失败 {file_path}: {e}")
    
    return results


# =========================
# 主函数
# =========================

def main():
    print("[+] 开始合并IOC数据...")
    print(f"[+] 爬取日期: {CRAWL_DATE}")
    print(f"[+] 排除列表: {EXCLUDE_LIST if EXCLUDE_LIST else '无'}")
    
    # 存储所有数据
    all_data = []
    
    # IP统计 - key: (ip, port), value: {sources: set, tags: set, first_seen: str}
    ip_stats = defaultdict(lambda: {
        "sources": set(),  # IOC来源列表
        "tags": set(),     # 威胁类型标签列表
        "first_seen": ""   # 首次发现时间
    })
    
    # 遍历所有数据源
    for source_name, mapping in SOURCE_MAPPING.items():
        # 检查是否在排除列表中
        if source_name in EXCLUDE_LIST:
            print(f"[-] 跳过数据源: {source_name}")
            continue
        
        # 查找该数据源的data目录
        data_dir = os.path.join(PUBLIC_IOC_DIR, source_name, "data")
        
        if not os.path.exists(data_dir):
            print(f"[!] 数据目录不存在: {data_dir}")
            continue
        
        # 查找所有CSV文件
        csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
        
        if not csv_files:
            print(f"[!] 没有找到CSV文件: {data_dir}")
            continue
        
        print(f"[+] 处理数据源: {source_name} ({len(csv_files)} 个文件)")
        
        for csv_file in csv_files:
            records = process_csv_file(csv_file, source_name, mapping)
            
            for record in records:
                ip = record["ip"]
                port = record["port"]
                tag = record["tag"]
                first_seen = record["first_seen_utc"]
                source = record["source"]
                
                key = (ip, port if port else "")
                
                # 更新统计信息
                ip_stats[key]["sources"].add(source)  # 添加IOC来源
                if tag and tag.strip():  # 只添加非空的威胁类型标签
                    ip_stats[key]["tags"].add(tag)
                if first_seen and not ip_stats[key]["first_seen"]:
                    ip_stats[key]["first_seen"] = first_seen
                
                all_data.append(record)
    
    print(f"[+] 共收集 {len(all_data)} 条记录")
    print(f"[+] 去重后 {len(ip_stats)} 个唯一IP")
    
    # =========================
    # 读取已有的history.csv并合并（所有历史数据）
    # =========================
    history_csv_file = os.path.join(OUTPUT_DIR, "history.csv")
    recent_csv_file = os.path.join(OUTPUT_DIR, "recent.csv")
    
    # 计算时间边界
    months_ago = (datetime.now() - timedelta(days=RECENT_MONTHS * 30)).strftime("%Y-%m-%d")
    print(f"[+] {RECENT_MONTHS}个月前的日期: {months_ago}")
    
    # 读取已有的history.csv中的所有数据
    all_history_data = {}
    if os.path.exists(history_csv_file):
        print(f"[+] 读取已有的 history.csv...")
        with open(history_csv_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f, delimiter="\t")
            for row in reader:
                ip = row.get("ip", "").strip()
                port = row.get("port", "").strip()
                first_seen = row.get("first_seen_utc", "").strip()
                crawl_date = row.get("crawl_date", "").strip()
                
                key = (ip, port)
                if key not in all_history_data:
                    all_history_data[key] = {
                        "tags": set(row.get("tag", "").split("|")) if row.get("tag") else set(),
                        "sources": set(row.get("ioc_source", "").split("|")) if row.get("ioc_source") else set(),
                        "first_seen": first_seen,
                        "crawl_date": crawl_date
                    }
                    # 移除空字符串
                    all_history_data[key]["tags"].discard("")
                    all_history_data[key]["sources"].discard("")
    
    print(f"[+] 历史数据: {len(all_history_data)} 条")
    
    # 合并新数据到历史数据
    print(f"[+] 合并新数据到历史数据...")
    for (ip, port), stats in ip_stats.items():
        key = (ip, port)
        if key in all_history_data:
            # 合并标签和来源
            all_history_data[key]["tags"].update(stats["tags"])
            all_history_data[key]["sources"].update(stats["sources"])
            # 更新爬取日期为最新
            all_history_data[key]["crawl_date"] = CRAWL_DATE
            # 如果新数据有first_seen且旧数据没有，或新数据的first_seen更早
            if stats["first_seen"]:
                if not all_history_data[key]["first_seen"] or stats["first_seen"] < all_history_data[key]["first_seen"]:
                    all_history_data[key]["first_seen"] = stats["first_seen"]
        else:
            # 新数据
            all_history_data[key] = stats
            all_history_data[key]["crawl_date"] = CRAWL_DATE
    
    print(f"[+] 合并后历史数据总数: {len(all_history_data)} 条")
    
    # =========================
    # 写入history.csv（所有历史数据）
    # =========================
    print(f"[+] 写入 history.csv...")
    with open(history_csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(["ip", "port", "tag", "ioc_source", "first_seen_utc", "crawl_date", "count"])
        
        for (ip, port), stats in sorted(all_history_data.items()):
            count = len(stats["sources"])
            tags = "|".join(sorted(stats["tags"])) if stats["tags"] else ""
            sources = "|".join(sorted(stats["sources"]))
            first_seen = stats.get("first_seen", "")
            crawl_date = stats.get("crawl_date", CRAWL_DATE)
            
            writer.writerow([ip, port, tags, sources, first_seen, crawl_date, count])
    
    # =========================
    # 写入recent.csv（最近N个月的数据）
    # =========================
    print(f"[+] 写入 recent.csv (最近{RECENT_MONTHS}个月)...")
    recent_count = 0
    with open(recent_csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(["ip", "port", "tag", "ioc_source", "first_seen_utc", "crawl_date", "count"])
        
        for (ip, port), stats in sorted(all_history_data.items()):
            # 过滤：first_seen_utc 和 crawl_date 都必须在最近N个月内（或为空）
            crawl_date = stats.get("crawl_date", "")
            first_seen = stats.get("first_seen", "")
            
            # 检查是否满足时间条件（两个都必须在范围内，如果字段存在的话）
            is_recent = True  # 默认通过
            
            # 如果有first_seen_utc且早于N个月，则排除
            if first_seen and first_seen < months_ago:
                is_recent = False
            
            # 如果有crawl_date且早于N个月，则排除
            if crawl_date and crawl_date < months_ago:
                is_recent = False
            
            if is_recent:
                count = len(stats["sources"])
                tags = "|".join(sorted(stats["tags"])) if stats["tags"] else ""
                sources = "|".join(sorted(stats["sources"]))
                
                writer.writerow([ip, port, tags, sources, first_seen, crawl_date, count])
                recent_count += 1
    
    # =========================
    # 写入recent_high_risk_ips.csv（高危IP，count >= 3）
    # =========================
    high_risk_csv_file = os.path.join(OUTPUT_DIR, "recent_high_risk_ips.csv")
    print(f"[+] 写入 recent_high_risk_ips.csv (count >= 3 的高危数据)...")
    high_risk_count = 0
    
    with open(high_risk_csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(["ip", "port", "tag", "ioc_source", "first_seen_utc", "crawl_date", "count"])
        
        for (ip, port), stats in sorted(all_history_data.items()):
            # 过滤：时间条件 + count >= 3
            crawl_date = stats.get("crawl_date", "")
            first_seen = stats.get("first_seen", "")
            count = len(stats["sources"])
            
            # 检查时间条件
            is_recent = True
            if first_seen and first_seen < months_ago:
                is_recent = False
            if crawl_date and crawl_date < months_ago:
                is_recent = False
            
            # 只保留最近的且count >= 3的数据
            if is_recent and count >= 3:
                tags = "|".join(sorted(stats["tags"])) if stats["tags"] else ""
                sources = "|".join(sorted(stats["sources"]))
                
                writer.writerow([ip, port, tags, sources, first_seen, crawl_date, count])
                high_risk_count += 1
    
    print(f"[+] 合并完成！")
    print(f"[+] history.csv: {len(all_history_data)} 条（所有历史数据）")
    print(f"[+] recent.csv: {recent_count} 条（最近{RECENT_MONTHS}个月）")
    print(f"[+] recent_high_risk_ips.csv: {high_risk_count} 条（高危数据，count >= 3）")
    
    # =========================
    # 清理各数据源的旧数据
    # =========================
    print(f"\n[+] 清理各数据源目录的旧数据（保留{SOURCE_DATA_DAYS}天）...")
    cleanup_old_source_data(PUBLIC_IOC_DIR, SOURCE_DATA_DAYS)
    
    # =========================
    # 统计信息并记录到日志
    # =========================
    source_count = defaultdict(int)
    for record in all_data:
        source_count[record["source"]] += 1
    
    total_records = len(all_data)
    unique_ips = len(ip_stats)
    source_num = len(set(r['source'] for r in all_data))
    
    # 记录到日志文件
    if LOGGER_AVAILABLE:
        log_data_merge(
            total_records=total_records,
            unique_ips=unique_ips,
            source_count=source_num,
            history_count=len(all_history_data),
            recent_count=recent_count,
            source_stats=dict(source_count)
        )
    else:
        # 如果日志模块不可用，输出到控制台
        print(f"\n=== 统计信息 ===")
        print(f"总记录数: {total_records}")
        print(f"唯一IP数: {unique_ips}")
        print(f"数据源数: {source_num}")
        print(f"\n=== 各数据源贡献 ===")
        for source, count in sorted(source_count.items(), key=lambda x: x[1], reverse=True):
            print(f"{source}: {count}")


if __name__ == "__main__":
    main()

