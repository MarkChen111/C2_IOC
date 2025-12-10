import os
import csv
import requests
from datetime import datetime

# =========================
# 1. 基本配置
# =========================
SNORT_URL = "https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/043/940/original/ip-filter.blf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAU7AK5ITMMFKW2CPY%2F20251210%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20251210T121617Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=7a7475495ac8881c88ea256f490eba73cc16872fe2a51ed01f70855f85b2c4ba"
SAVE_DIR = "Public_IOC/SNORT/data"

# 创建目录（如果不存在）
os.makedirs(SAVE_DIR, exist_ok=True)

# 生成今日文件名
today_str = datetime.now().strftime("%Y-%m-%d")
save_path = os.path.join(SAVE_DIR, f"{today_str}.csv")

# =========================
# 2. 获取数据
# =========================
print("[+] 正在拉取 SNORT IP Block List 数据...")
resp = requests.get(SNORT_URL, timeout=30)
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
    
    # 跳过空行和注释行（以#开头）
    if not line or line.startswith("#"):
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

