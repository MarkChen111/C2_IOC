import os
import csv
import requests
from datetime import datetime

# =========================
# 1. 基本配置
# =========================
THREATVIEW_URL = "https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt"
SAVE_DIR = "Public_IOC/threatview.io/data"

# 创建目录（如果不存在）
os.makedirs(SAVE_DIR, exist_ok=True)

# 生成今日文件名
today_str = datetime.now().strftime("%Y-%m-%d")
save_path = os.path.join(SAVE_DIR, f"{today_str}.csv")

# =========================
# 2. 获取数据
# =========================
print("[+] 正在拉取 ThreatView.io 数据...")
resp = requests.get(THREATVIEW_URL, timeout=30)
resp.raise_for_status()

# 按行分割文本
lines = resp.text.splitlines()

# =========================
# 3. 解析并提取数据
# =========================
output_rows = []
output_rows.append(["ip", "first_seen_utc"])

count = 0

# 月份名称到数字的映射
month_map = {
    'January': '01', 'February': '02', 'March': '03', 'April': '04',
    'May': '05', 'June': '06', 'July': '07', 'August': '08',
    'September': '09', 'October': '10', 'November': '11', 'December': '12'
}

for line in lines:
    line = line.strip()
    
    # 跳过空行和注释行（以#开头）
    if not line or line.startswith("#"):
        continue
    
    try:
        # 使用逗号分割CSV行
        parts = line.split(",")
        
        if len(parts) >= 2:
            ip = parts[0].strip()
            date_str = parts[1].strip()
            
            # 解析日期格式 "02 November 2025 07:29 PM UTC"
            # 只提取日期部分，格式转换为 YYYY-MM-DD
            date_parts = date_str.split()
            if len(date_parts) >= 3:
                day = date_parts[0].zfill(2)  # 补零到两位数
                month_name = date_parts[1]
                year = date_parts[2]
                
                # 将月份名称转换为数字
                month = month_map.get(month_name, '01')
                
                # 组合成 YYYY-MM-DD 格式
                formatted_date = f"{year}-{month}-{day}"
                
                output_rows.append([ip, formatted_date])
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

