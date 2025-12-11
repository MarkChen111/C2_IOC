import os
import csv
import requests
import ipaddress
from datetime import datetime

# =========================
# 1. 基本配置
# =========================
FIREHOL_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset"
# 获取脚本所在目录
script_dir = os.path.dirname(os.path.abspath(__file__))
SAVE_DIR = os.path.join(script_dir, "data")

# 创建目录（如果不存在）
os.makedirs(SAVE_DIR, exist_ok=True)

# 生成今日文件名
today_str = datetime.now().strftime("%Y-%m-%d")
save_path = os.path.join(SAVE_DIR, f"{today_str}.csv")

# =========================
# 2. 获取数据
# =========================
print("[+] 正在拉取 FireHOL 数据...")
resp = requests.get(FIREHOL_URL, timeout=30)
resp.raise_for_status()

# 按行分割文本
lines = resp.text.splitlines()

# =========================
# 3. 处理并展开IP段
# =========================
output_rows = []
output_rows.append(["ip"])

count = 0
skipped = 0

print("[+] 开始处理IP地址和IP段...")

for line in lines:
    line = line.strip()
    
    # 跳过空行和注释行（以#开头）
    if not line or line.startswith("#"):
        continue
    
    try:
        # 检查是否包含CIDR格式（即是否有斜杠）
        if "/" in line:
            # 这是一个IP段，需要展开
            network = ipaddress.ip_network(line, strict=False)
            
            # 如果IP段太大，只提取网络地址本身，避免内存溢出
            # 对于小的IP段（/24或更小的掩码，即主机位>=8），进行展开
            if network.prefixlen >= 24:
                for ip in network.hosts():
                    output_rows.append([str(ip)])
                    count += 1
            else:
                # 对于大的IP段，只记录网络地址
                output_rows.append([str(network.network_address)])
                count += 1
                skipped += network.num_addresses - 1
        else:
            # 这是一个单独的IP地址
            # 验证IP地址格式
            ip = ipaddress.ip_address(line)
            output_rows.append([str(ip)])
            count += 1
            
    except ValueError:
        # 无效的IP地址或格式，跳过
        continue

# =========================
# 4. 写入结果
# =========================
with open(save_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerows(output_rows)

print(f"[+] 处理完成，共提取 {count} 条 IP")
if skipped > 0:
    print(f"[!] 注意：{skipped} 个大IP段的主机地址未完全展开（仅保留网络地址）")
print(f"[+] 文件已保存：{save_path}")

