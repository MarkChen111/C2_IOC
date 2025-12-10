import os
import csv
import requests
from datetime import datetime

# =========================
# 1. 基本配置
# =========================
THREATFOX_CSV_URL = "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/IP/Threatfox/threatfox_ip_ports_list.csv"
SAVE_DIR = "Public_IOC/NamePipes/data"
TEMP_FILE = "temp_threatfox.csv"

# 创建目录（如果不存在）
os.makedirs(SAVE_DIR, exist_ok=True)

# 生成今日文件名
today_str = datetime.now().strftime("%Y-%m-%d")
save_path = os.path.join(SAVE_DIR, f"{today_str}.csv")

# =========================
# 2. 下载数据
# =========================
print("[+] 正在下载 ThreatFox 数据...")
resp = requests.get(THREATFOX_CSV_URL, timeout=60)
resp.raise_for_status()

# 保存临时文件
with open(TEMP_FILE, "w", encoding="utf-8") as f:
    f.write(resp.text)

print("[+] 下载完成，开始解析...")

# =========================
# 3. 解析CSV并提取数据
# =========================
output_rows = []
output_rows.append(["first_seen_utc", "malware_printable", "confidence_level", "ip", "port"])

count = 0

with open(TEMP_FILE, "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    
    for row in reader:
        try:
            # 获取 first_seen_utc 并只保留年月日
            first_seen_utc = row.get("first_seen_utc", "")
            if first_seen_utc:
                # 格式可能是 "2025-12-10 06:01:54"，只取日期部分
                date_only = first_seen_utc.split(" ")[0]
            else:
                date_only = ""
            
            # 获取其他字段
            malware_printable = row.get("malware_printable", "")
            confidence_level = row.get("confidence_level", "")
            dest_ip = row.get("dest_ip", "")
            dest_port = row.get("dest_port", "")
            
            output_rows.append([date_only, malware_printable, confidence_level, dest_ip, dest_port])
            count += 1
            
        except Exception as e:
            # 出现异常时跳过该行
            continue

# =========================
# 4. 写入结果
# =========================
with open(save_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerows(output_rows)

# =========================
# 5. 删除临时文件
# =========================
if os.path.exists(TEMP_FILE):
    os.remove(TEMP_FILE)
    print("[+] 临时文件已删除")

print(f"[+] 处理完成，共提取 {count} 条 IOC")
print(f"[+] 文件已保存：{save_path}")

