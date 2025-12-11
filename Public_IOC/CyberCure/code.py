import os
import csv
import requests
from datetime import datetime

# =========================
# 1. 基本配置
# =========================
CYBERCURE_URL = "https://api.cybercure.ai/feed/get_ips?type=csv"
# 获取脚本所在目录
script_dir = os.path.dirname(os.path.abspath(__file__))
SAVE_DIR = os.path.join(script_dir, "data")
TEMP_FILE = "temp_cybercure.csv"

# 创建目录（如果不存在）
os.makedirs(SAVE_DIR, exist_ok=True)

# 生成今日文件名
today_str = datetime.now().strftime("%Y-%m-%d")
save_path = os.path.join(SAVE_DIR, f"{today_str}.csv")

# =========================
# 2. 下载数据
# =========================
print("[+] 正在下载 CyberCure 数据...")
resp = requests.get(CYBERCURE_URL, timeout=60)
resp.raise_for_status()

# 保存临时文件
with open(TEMP_FILE, "w", encoding="utf-8") as f:
    f.write(resp.text)

print("[+] 下载完成，开始解析...")

# =========================
# 3. 解析数据（所有IP在一行中，用逗号分隔）
# =========================
output_rows = []
output_rows.append(["ip"])

count = 0

# 读取文件内容
with open(TEMP_FILE, "r", encoding="utf-8") as f:
    content = f.read().strip()
    
    # 按逗号分割所有IP
    ips = content.split(",")
    
    for ip in ips:
        ip = ip.strip()
        # 跳过空字符串
        if not ip:
            continue
        
        output_rows.append([ip])
        count += 1

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

