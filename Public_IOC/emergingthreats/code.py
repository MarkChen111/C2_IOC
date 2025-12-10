import os
import csv
import requests
from datetime import datetime

# =========================
# 1. 基本配置
# =========================
EMERGINGTHREATS_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
SAVE_DIR = "Public_IOC/emergingthreats/data"

# 创建目录（如果不存在）
os.makedirs(SAVE_DIR, exist_ok=True)

# 生成今日文件名
today_str = datetime.now().strftime("%Y-%m-%d")
save_path = os.path.join(SAVE_DIR, f"{today_str}.csv")

# =========================
# 2. 获取数据
# =========================
print("[+] 正在拉取 EmergingThreats 数据...")
resp = requests.get(EMERGINGTHREATS_URL, timeout=30)
resp.raise_for_status()

# 按行分割文本
lines = resp.text.splitlines()

# =========================
# 3. 处理并写入结果
# =========================
output_rows = []
output_rows.append(["ip"])

count = 0

for line in lines:
    line = line.strip()
    # 跳过空行
    if not line:
        continue
    
    # 每行就是一个IP地址
    output_rows.append([line])
    count += 1

# 写入 CSV
with open(save_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerows(output_rows)

print(f"[+] 处理完成，共提取 {count} 条 IOC")
print(f"[+] 文件已保存：{save_path}")

