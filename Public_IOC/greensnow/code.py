import os
import csv
import time
import requests
from datetime import datetime

# =========================
# 1. 基本配置
# =========================
GREENSNOW_URL = "https://blocklist.greensnow.co/greensnow.txt"
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
print("[+] 正在拉取 GreenSnow 数据...")

def get_with_retry(url, retries=4, timeout=30, backoff=2):
    """请求失败时自动重试，降低临时 5xx 导致的采集失败。"""
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            last_error = e
            if attempt == retries:
                break
            sleep_seconds = backoff ** (attempt - 1)
            print(f"[!] 请求失败，第 {attempt}/{retries} 次：{e}，{sleep_seconds} 秒后重试...")
            time.sleep(sleep_seconds)
    raise last_error


resp = get_with_retry(GREENSNOW_URL)

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

