import os
import csv
import requests
from datetime import datetime

# =========================
# 1. 基本配置
# =========================
C2INTEL_CSV_URL = "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPPortC2s.csv"
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
print("[+] 正在拉取 C2IntelFeeds 数据...")
resp = requests.get(C2INTEL_CSV_URL, timeout=30)
resp.raise_for_status()

# 按行分割文本
lines = resp.text.splitlines()

# =========================
# 3. 解析CSV并提取数据
# =========================
output_rows = []
output_rows.append(["ip", "port", "tag"])

count = 0

for line in lines:
    line = line.strip()
    
    # 跳过空行和注释行（以#开头的表头）
    if not line or line.startswith("#ip"):
        continue
    
    try:
        # 使用逗号分割CSV
        parts = line.split(",")
        
        if len(parts) >= 3:
            ip = parts[0].strip()
            port = parts[1].strip()
            tag = parts[2].strip()
            
            output_rows.append([ip, port, tag])
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

print(f"[+] 处理完成，共提取 {count} 条 IOC")
print(f"[+] 文件已保存：{save_path}")

