import os
import csv
import re
import requests
from datetime import datetime
from urllib.parse import urlparse

# =========================
# 1. 基本配置
# =========================
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_online/"
SAVE_DIR = "Public_IOC/urlhaus/data"

# 创建目录（如果不存在）
os.makedirs(SAVE_DIR, exist_ok=True)

# 生成今日文件名
today_str = datetime.now().strftime("%Y-%m-%d")
save_path = os.path.join(SAVE_DIR, f"{today_str}.csv")

# =========================
# 2. 获取数据
# =========================
print("[+] 正在拉取 URLhaus 数据...")
resp = requests.get(URLHAUS_CSV_URL, timeout=30)
resp.raise_for_status()

lines = resp.text.splitlines()

# =========================
# 3. 过滤注释 & 解析 CSV
# =========================
data_lines = []
for line in lines:
    if not line.startswith("#") and line.strip():
        data_lines.append(line)

reader = csv.reader(data_lines)

# 跳过表头
header = next(reader)

# =========================
# 4. IP 提取函数
# =========================
ip_pattern = re.compile(
    r"\b((25[0-5]|2[0-4]\d|[0-1]?\d?\d)\.){3}"
    r"(25[0-5]|2[0-4]\d|[0-1]?\d?\d)\b"
)

def extract_ip_from_url(url):
    parsed = urlparse(url)
    host = parsed.hostname
    if host and ip_pattern.fullmatch(host):
        return host
    return ""

# =========================
# 5. 处理并写入结果
# =========================
output_rows = []
output_rows.append(["url", "last_online", "threat", "tags", "ip"])

count = 0

for row in reader:
    try:
        url = row[2]
        url_status = row[3]
        last_online_raw = row[4]
        threat = row[5]
        tags = row[6]

        # 只要 online
        if url_status != "online":
            continue

        # last_online 只保留日期
        last_online = last_online_raw.split(" ")[0]

        # 提取 IP
        ip = extract_ip_from_url(url)

        output_rows.append([url, last_online, threat, tags, ip])
        count += 1

    except Exception as e:
        # 出现异常时跳过该行
        continue

# 写入 CSV
with open(save_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerows(output_rows)

print(f"[+] 处理完成，共提取 {count} 条在线 IOC")
print(f"[+] 文件已保存：{save_path}")
