import os
import csv
import requests
from datetime import datetime
import re

# =========================
# 1. 基本配置
# =========================
# SNORT 下载页面（需要从这里获取最新的下载链接）
SNORT_DOWNLOAD_PAGE = "https://snort.org/downloads/ip-block-list"

# 当前有效的 SNORT URL（备用，带AWS签名，可能每天变化）
# ⚠️  如果下面的 URL 过期（403 Forbidden），请按以下步骤更新:
#     1. 访问 https://snort.org/downloads/ip-block-list
#     2. 点击下载按钮，复制实际的下载 URL
#     3. 替换下面的 SNORT_URL_FALLBACK 值
#     4. 更新日期注释
# 
# 更新日期: 2025-12-11
# URL 格式示例: https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/043/957/original/ip-filter.blf?X-Amz-...
SNORT_URL_FALLBACK = "https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/043/957/original/ip-filter.blf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAU7AK5ITMMFKW2CPY%2F20251211%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20251211T074339Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=1f9b3cc48a05cf7a72bcc71740baca593134a3b978c04a8bba2c31fb591d7471"

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
print("[+] 正在从 SNORT 下载页面获取最新链接...")

SNORT_URL = None

try:
    # 方案1: 尝试从官网页面提取最新链接
    page_resp = requests.get(SNORT_DOWNLOAD_PAGE, timeout=30)
    page_resp.raise_for_status()
    
    # 从页面中提取 S3 下载链接（多种匹配模式）
    patterns = [
        r'href=["\']([^"\']*snort-org-site\.s3\.amazonaws\.com/production/document_files/files/[^"\']*ip-filter\.blf[^"\']*)["\']',
        r'(https://snort-org-site\.s3\.amazonaws\.com/production/document_files/files/\d+/\d+/\d+/original/ip-filter\.blf\?[^\s<>"\']+)',
        r'(https://snort-org-site\.s3\.amazonaws\.com[^\s<>"\']*ip-filter\.blf[^\s<>"\']*)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, page_resp.text)
        if match:
            SNORT_URL = match.group(1)
            print(f"[+] 成功从官网提取下载链接")
            break
    
    if not SNORT_URL:
        print("[!] 未能从官网提取链接，尝试使用备用 URL...")
        SNORT_URL = SNORT_URL_FALLBACK

except Exception as e:
    print(f"[!] 访问官网失败: {e}")
    print("[!] 尝试使用备用 URL...")
    SNORT_URL = SNORT_URL_FALLBACK

# 方案2: 使用提取到的URL或备用URL下载数据
try:
    print(f"[+] 下载链接: {SNORT_URL[:120]}...")
    print("[+] 正在下载 SNORT IP Block List 数据...")
    
    resp = requests.get(SNORT_URL, timeout=30, allow_redirects=True)
    resp.raise_for_status()
    
    # 检查是否返回了HTML而不是文本数据
    content_preview = resp.text.strip()[:200]
    if content_preview.startswith('<!DOCTYPE') or content_preview.startswith('<html'):
        print("[!] 返回的是HTML页面而不是数据文件")
        print(f"[!] 内容预览: {content_preview[:100]}")
        print("[!] ⚠️  备用 URL 已过期，请手动更新 SNORT_URL_FALLBACK")
        print(f"[!] ⚠️  访问 {SNORT_DOWNLOAD_PAGE} 获取最新链接")
        exit(1)
    
    # 按行分割文本
    lines = resp.text.splitlines()
    
    # 验证数据格式（应该是IP地址列表）
    if len(lines) == 0:
        print("[!] 下载的文件为空")
        exit(1)
    
    print(f"[+] 下载成功，共 {len(lines)} 行数据")
    
except requests.exceptions.HTTPError as e:
    if e.response.status_code == 403:
        print(f"[!] 403 Forbidden - AWS签名已过期")
        print(f"[!] ⚠️  请手动更新代码中的 SNORT_URL_FALLBACK")
        print(f"[!] ⚠️  访问 {SNORT_DOWNLOAD_PAGE} 获取最新链接")
    else:
        print(f"[!] HTTP错误: {e}")
    exit(1)
    
except Exception as e:
    print(f"[!] 下载失败: {e}")
    print("[!] SNORT 数据源可能需要手动更新 URL")
    exit(1)

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

