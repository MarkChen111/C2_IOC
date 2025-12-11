import os
import sys
import csv
import requests
from datetime import datetime

# 添加项目根目录到路径
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
sys.path.insert(0, ROOT_DIR)

try:
    from logger_utils import log_data_collection
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False

# =========================
# 1. 基本配置
# =========================
SOURCE_NAME = "ipsum"
IPSUM_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"
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
try:
    print("[+] 正在拉取 IPsum 数据...")
    resp = requests.get(IPSUM_URL, timeout=30)
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
    
    # 记录到日志
    if LOGGER_AVAILABLE:
        log_data_collection(SOURCE_NAME, "success", count)

except Exception as e:
    error_msg = str(e)
    print(f"[-] 错误: {error_msg}")
    
    # 记录失败到日志
    if LOGGER_AVAILABLE:
        log_data_collection(SOURCE_NAME, "failed", 0, error_msg)
    
    sys.exit(1)

