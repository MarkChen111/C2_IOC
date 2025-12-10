import os
import csv
import requests
from datetime import datetime

# =========================
# 1. 基本配置
# =========================
TWEETFEED_API_URL = "https://api.tweetfeed.live/v1/week/ip"
SAVE_DIR = "Public_IOC/tweetfeed/data"

# 创建目录（如果不存在）
os.makedirs(SAVE_DIR, exist_ok=True)

# 生成今日文件名
today_str = datetime.now().strftime("%Y-%m-%d")
save_path = os.path.join(SAVE_DIR, f"{today_str}.csv")

# =========================
# 2. 获取数据
# =========================
print("[+] 正在拉取 TweetFeed 数据...")
resp = requests.get(TWEETFEED_API_URL, timeout=30)
resp.raise_for_status()

data = resp.json()

# =========================
# 3. 处理并写入结果
# =========================
output_rows = []
output_rows.append(["ip", "tags", "date"])

count = 0

for item in data:
    try:
        # 获取 IP
        ip = item.get("value", "")
        
        # 获取 tags，如果是列表则用逗号连接，如果为空则保留空字符串
        tags = item.get("tags", [])
        if isinstance(tags, list):
            # 去掉每个tag中的#号
            tags_cleaned = [tag.replace("#", "") for tag in tags]
            tags_str = ",".join(tags_cleaned) if tags_cleaned else ""
        else:
            tags_str = str(tags).replace("#", "")
        
        # 获取日期并只保留年月日部分
        date_raw = item.get("date", "")
        date = date_raw.split(" ")[0] if date_raw else ""
        
        output_rows.append([ip, tags_str, date])
        count += 1
        
    except Exception as e:
        # 出现异常时跳过该行
        continue

# 写入 CSV
with open(save_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerows(output_rows)

print(f"[+] 处理完成，共提取 {count} 条 IOC")
print(f"[+] 文件已保存：{save_path}")

