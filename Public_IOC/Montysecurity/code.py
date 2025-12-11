import os
import csv
import requests
from datetime import datetime

# =========================
# 1. 基本配置
# =========================
GITHUB_BASE_URL = "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/"
# 获取脚本所在目录
script_dir = os.path.dirname(os.path.abspath(__file__))
SAVE_DIR = os.path.join(script_dir, "data")

# 创建目录（如果不存在）
os.makedirs(SAVE_DIR, exist_ok=True)

# 生成今日文件名
today_str = datetime.now().strftime("%Y-%m-%d")
save_path = os.path.join(SAVE_DIR, f"{today_str}.csv")

# =========================
# 2. 定义所有要抓取的C2类型
# =========================
C2_TAGS = [
    "7777 Botnet",
    "Ares RAT C2",
    "AsyncRAT",
    "BitRAT",
    "BlackNet Botnet",
    "Brute Ratel C4",
    "BurpSuite",
    "Caldera C2",
    "Cobalt Strike C2",
    "Covenant C2",
    "DarkComet Trojan",
    "DcRAT",
    "Deimos C2",
    "Gh0st RAT Trojan",
    "GoPhish",
    "Hak5 Cloud C2",
    "Havoc C2",
    "Hookbot",
    "Metasploit Framework C2",
    "MobSF",
    "Mozi Botnet",
    "Mythic C2",
    "NanoCore RAT Trojan",
    "NetBus Trojan",
    "NimPlant C2",
    "Orcus RAT Trojan",
    "PANDA C2",
    "Pantegana C2",
    "Posh C2",
    "Quasar RAT",
    "RedGuard C2",
    "Remcos RAT",
    "Sectop RAT",
    "ShadowPad",
    "Sliver C2",
    "SpiceRAT",
    "SpyAgent",
    "Supershell C2",
    "Unam Web Panel",
    "Villain C2",
    "Viper C2",
    "XMRig Monero Cryptominer",
    "XtremeRAT Trojan",
    "njRAT Trojan"
]

# =========================
# 3. 获取数据
# =========================
output_rows = []
output_rows.append(["ip", "tag"])

total_count = 0

for tag in C2_TAGS:
    # 将tag转换为URL格式的文件名
    # 例如: "7777 Botnet" -> "7777%20Botnet%20IPs.txt"
    filename = tag.replace(" ", "%20") + "%20IPs.txt"
    url = GITHUB_BASE_URL + filename
    
    print(f"[+] 正在拉取 {tag} 数据...")
    
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        
        # 按行分割文本
        lines = resp.text.splitlines()
        
        count = 0
        for line in lines:
            line = line.strip()
            # 跳过空行和注释行
            if not line or line.startswith("#"):
                continue
            
            # 每行是一个IP地址
            output_rows.append([line, tag])
            count += 1
        
        total_count += count
        print(f"    └─ 成功提取 {count} 条 IP")
        
    except requests.exceptions.RequestException as e:
        print(f"    └─ 获取失败: {e}")
        continue

# =========================
# 4. 写入结果（使用制表符分隔）
# =========================
with open(save_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f, delimiter='\t')
    writer.writerows(output_rows)

print(f"\n[+] 处理完成，共提取 {total_count} 条 IOC")
print(f"[+] 文件已保存：{save_path}")

