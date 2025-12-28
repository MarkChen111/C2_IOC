import os
import csv
import requests
from datetime import datetime
import re
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

# =========================
# 1. 基本配置
# =========================
# SNORT 条款页面（需要点击Accept才能获取下载链接）
SNORT_TERMS_PAGE = "https://snort.org/downloads/ip-block-list/terms"

# 获取脚本所在目录
script_dir = os.path.dirname(os.path.abspath(__file__))
SAVE_DIR = os.path.join(script_dir, "data")

# 创建目录（如果不存在）
os.makedirs(SAVE_DIR, exist_ok=True)

# 生成今日文件名
today_str = datetime.now().strftime("%Y-%m-%d")
save_path = os.path.join(SAVE_DIR, f"{today_str}.csv")

# =========================
# 2. 使用 Selenium 自动获取下载链接
# =========================
def get_snort_download_url():
    """
    使用 Selenium 自动访问条款页面，点击Accept按钮，获取真实下载链接
    支持 macOS 和 Linux 环境
    """
    print("[+] 正在启动浏览器自动化...")
    
    # 配置 Chrome 选项（兼容 Linux 和 macOS）
    chrome_options = Options()
    chrome_options.add_argument('--headless')  # 无头模式
    chrome_options.add_argument('--no-sandbox')  # Linux 必需
    chrome_options.add_argument('--disable-dev-shm-usage')  # Linux 必需
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--disable-software-rasterizer')
    chrome_options.add_argument('--disable-extensions')
    chrome_options.add_argument('--disable-setuid-sandbox')
    chrome_options.add_argument('--window-size=1920,1080')
    chrome_options.add_argument('--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
    
    # 忽略证书错误
    chrome_options.add_argument('--ignore-certificate-errors')
    chrome_options.add_argument('--ignore-ssl-errors')
    
    driver = None
    try:
        # 初始化 WebDriver
        driver = webdriver.Chrome(options=chrome_options)
        
        print(f"[+] 访问条款页面: {SNORT_TERMS_PAGE}")
        driver.get(SNORT_TERMS_PAGE)
        
        # 等待页面加载
        time.sleep(2)
        
        # 查找并点击 Accept 按钮
        print("[+] 查找 Accept 按钮...")
        wait = WebDriverWait(driver, 10)
        
        # 尝试多种可能的按钮选择器
        accept_button = None
        selectors = [
            "//a[contains(text(), 'Accept')]",
            "//button[contains(text(), 'Accept')]",
            "//input[@value='Accept']",
            "//a[contains(@class, 'accept')]",
            "//button[contains(@class, 'accept')]",
        ]
        
        for selector in selectors:
            try:
                accept_button = wait.until(
                    EC.element_to_be_clickable((By.XPATH, selector))
                )
                if accept_button:
                    print(f"[+] 找到 Accept 按钮: {selector}")
                    break
            except:
                continue
        
        if not accept_button:
            print("[!] 未找到 Accept 按钮")
            return None
        
        # 点击按钮
        print("[+] 点击 Accept 按钮...")
        accept_button.click()
        
        # 等待重定向
        time.sleep(3)
        
        # 获取当前 URL（应该是 S3 下载链接）
        current_url = driver.current_url
        print(f"[+] 重定向后的 URL: {current_url[:120]}...")
        
        # 验证 URL 是否是 S3 链接
        if 'snort-org-site.s3.amazonaws.com' in current_url and 'ip-filter.blf' in current_url:
            print("[+] 成功获取下载链接")
            return current_url
        else:
            print(f"[!] 获取的 URL 不是预期的下载链接: {current_url}")
            return None
            
    except Exception as e:
        print(f"[!] Selenium 自动化失败: {e}")
        return None
        
    finally:
        if driver:
            driver.quit()
            print("[+] 浏览器已关闭")

# 获取下载链接
print("[+] 正在获取 SNORT 下载链接...")
SNORT_URL = get_snort_download_url()

if not SNORT_URL:
    print("[!] 无法自动获取下载链接")
    print("[!] 请检查:")
    print("    1. Chrome 浏览器是否已安装")
    print("    2. ChromeDriver 是否已安装并在 PATH 中")
    print(f"    3. 手动访问 {SNORT_TERMS_PAGE} 检查页面结构是否变化")
    exit(1)

# =========================
# 3. 下载数据
# =========================
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
        print("[!] ⚠️  下载链接可能已失效")
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
        print(f"[!] ⚠️  请重新运行脚本获取新的下载链接")
    else:
        print(f"[!] HTTP错误: {e}")
    exit(1)
    
except Exception as e:
    print(f"[!] 下载失败: {e}")
    exit(1)

# =========================
# 4. 处理并写入结果
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

