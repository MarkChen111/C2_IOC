import requests
import time
import sys
import os
from datetime import datetime

# 尝试导入yaml
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    print("[!] 警告: PyYAML未安装，使用默认配置")

# =========================
# 加载配置
# =========================
def load_config():
    """从项目根目录的config.yaml加载配置"""
    if not YAML_AVAILABLE:
        return {}
    
    # 获取项目根目录（向上两级）
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(os.path.dirname(script_dir))
    config_file = os.path.join(root_dir, "config.yaml")
    
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                return config.get('alienvault', {})
        except Exception as e:
            print(f"[!] 配置文件加载失败: {e}")
            return {}
    return {}

CONFIG = load_config()

# =========================
# 基础配置
# =========================

API_KEY = CONFIG.get('api_key')
if not API_KEY:
    print("[!] 错误: 未配置 AlienVault API Key！")
    print("[!] 请在 config.yaml 中配置 alienvault.api_key")
    sys.exit(1)

# 近几天的数据
DAYS = CONFIG.get('days', 7)

# 最多翻多少页，防止一次拉太深
MAX_PAGES = CONFIG.get('max_pages', 200)

ACTIVITY_URL = "https://otx.alienvault.com/api/v1/pulses/activity"
PULSE_DETAIL_URL = "https://otx.alienvault.com/api/v1/pulses/{}"

HEADERS = {
    "X-OTX-API-KEY": API_KEY,
    "User-Agent": "Mozilla/5.0"
}

# 获取脚本所在目录
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "data")

# 确保 data 目录存在
os.makedirs(DATA_DIR, exist_ok=True)

# 使用日期作为文件名
today_str = datetime.now().strftime("%Y-%m-%d")
LOG_FILE = os.path.join(DATA_DIR, f"otx_{today_str}.log")
PULSES_FILE = os.path.join(DATA_DIR, f"pulses_{today_str}.csv")
MAP_FILE = os.path.join(DATA_DIR, f"{today_str}.csv")

# =========================
# 日志函数（带时间戳）
# =========================

def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    line = f"[{ts}] {msg}"
    # print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

# =========================
# 时间解析（兼容 OTX 格式）
# =========================

def parse_otx_time(t):
    if not t:
        return 0
    t = t.replace("Z", "").split(".")[0]
    try:
        return int(time.mktime(time.strptime(t, "%Y-%m-%dT%H:%M:%S")))
    except Exception:
        return 0

# =========================
# 文件头初始化
# =========================

def ensure_headers():
    if not os.path.exists(PULSES_FILE):
        with open(PULSES_FILE, "a+", encoding="utf-8") as f:
            f.write("pulse_id\tfirst_seen_utc\tname\ttags\tipv4_count\n")

    if not os.path.exists(MAP_FILE):
        with open(MAP_FILE, "a+", encoding="utf-8") as f:
            f.write("ip\tfirst_seen_utc\ttag\n")

# =========================
# 主逻辑
# =========================

def main():
    ensure_headers()

    now = int(time.time())
    since_ts = now - DAYS * 24 * 3600

    log("========== OTX Last 3 Months (IP Only) 启动 ==========")
    log(f"时间窗口起点: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(since_ts))}")
    log(f"最大翻页数: {MAX_PAGES}")

    last_id = None
    page = 0
    pulses_seen = set()  # 防止 activity 重复

    while page < MAX_PAGES:
        params = {"limit": 20}
        if last_id:
            params["after"] = last_id

        try:
            r = requests.get(ACTIVITY_URL, headers=HEADERS, params=params, timeout=30)
            data = r.json()
            print(data)
        except Exception as e:
            log(f"[ERROR] activity 接口异常: {e}")
            time.sleep(5)
            continue

        results = data.get("results", [])
        if not results:
            log("[INFO] activity 无更多数据，结束")
            break

        # log(f"[DEBUG] 正在处理第 {page + 1} 页，Pulse 数量: {len(results)}")

        stop_flag = False

        for pulse in results:
            pid = pulse.get("id")
            last_id = pid

            created_raw = pulse.get("created")
            created_ts = parse_otx_time(created_raw)
            
            # 转换为YYYY-MM-DD格式
            if created_raw:
                created_str = created_raw.split("T")[0] if "T" in created_raw else created_raw
            else:
                created_str = ""

            # 翻到 3 个月之前就停止（activity 为倒序）
            if created_ts and created_ts < since_ts:
                # log("[INFO] 已翻到 3 个月之前的数据，停止扫描")
                stop_flag = True
                break

            if pid in pulses_seen:
                continue
            pulses_seen.add(pid)

            name = (pulse.get("name", "") or "").replace("\t", " ")
            tags_str = " ".join(pulse.get("tags", []))
            tags_safe = tags_str.replace("\t", " ")

            # 拉 Pulse 详情
            try:
                d = requests.get(
                    PULSE_DETAIL_URL.format(pid),
                    headers=HEADERS,
                    timeout=30
                ).json()
            except Exception as e:
                # log(f"[ERROR] Pulse 详情获取失败: {pid} | {e}")
                continue

            ipv4_list = []

            for ind in d.get("indicators", []):
                if ind.get("type") == "IPv4":
                    ip = ind.get("indicator", "").strip().lower()  # IP转小写
                    if not ip:
                        continue
                    ipv4_list.append(ip)

                    # ✅ 写 IP映射，只保留ip, first_seen_utc, tag（name）
                    with open(MAP_FILE, "a", encoding="utf-8") as mf:
                        mf.write(f"{ip}\t{created_str}\t{name}\n")

                    log(f"[IP] {ip} | pulse={pid}")

            # ✅ 只有“确实有 IPv4”的 Pulse 才写入 pulses 文件
            if ipv4_list:
                ipv4_count = len(set(ipv4_list))
                with open(PULSES_FILE, "a", encoding="utf-8") as pf:
                    pf.write(
                        f"{pid}\t{created_str}\t{name}\t{tags_safe}\t{ipv4_count}\n"
                    )

            time.sleep(0.2)

        if stop_flag:
            break

        page += 1
        time.sleep(1)

    log("========== 扫描结束 ==========")

# =========================
# 入口
# =========================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("⚠️ 手动中断")
        sys.exit(0)
