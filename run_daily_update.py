#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C2 IOC 每日自动更新脚本

功能：
1. 依次运行所有数据源的 code.py 脚本
2. 自动合并数据到 history.csv 和 recent.csv
3. 清理过期的数据源文件
4. 记录运行日志

使用方法：
    python3 run_daily_update.py
    
定时任务示例（crontab）：
    # 每天凌晨2点运行
    0 2 * * * cd /path/to/C2_IOC && python3 run_daily_update.py >> logs/daily_update.log 2>&1
"""

import os
import sys
import subprocess
import time
from datetime import datetime
import glob

# 项目根目录
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
PUBLIC_IOC_DIR = os.path.join(PROJECT_ROOT, "Public_IOC")
COMBINE_SCRIPT = os.path.join(PUBLIC_IOC_DIR, "combine", "combine.py")
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")

# 确保日志目录存在
os.makedirs(LOG_DIR, exist_ok=True)

# 所有数据源目录（按字母顺序）
DATA_SOURCES = [
    "alienvault",
    "Binarydefense",
    "C2IntelFeeds",
    "cinsscore",
    "CyberCure",
    "emergingthreats",
    "FireHOL",
    "greensnow",
    "ipsum",
    "Montysecurity",
    "NamePipes",
    "SNORT",
    "threatfox",
    "threatview.io",
    "tweetfeed",
    "urlhaus",
]


def log(message, level="INFO"):
    """打印日志信息"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")
    sys.stdout.flush()


def run_command(command, cwd=None, timeout=300):
    """运行命令并返回结果"""
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"命令超时（{timeout}秒）"
    except Exception as e:
        return -1, "", str(e)


def collect_data_from_source(source_name):
    """运行单个数据源的采集脚本"""
    source_dir = os.path.join(PUBLIC_IOC_DIR, source_name)
    code_file = os.path.join(source_dir, "code.py")
    
    if not os.path.exists(code_file):
        log(f"⚠️  {source_name}: code.py 不存在", "WARN")
        return False
    
    log(f"📥 开始采集: {source_name}")
    start_time = time.time()
    
    # 运行采集脚本
    returncode, stdout, stderr = run_command(
        f"python3 code.py",
        cwd=source_dir,
        timeout=3600  # 5分钟超时
    )
    
    elapsed = time.time() - start_time
    
    if returncode == 0:
        log(f"✅ {source_name}: 采集成功 ({elapsed:.1f}秒)", "SUCCESS")
        return True
    else:
        log(f"❌ {source_name}: 采集失败 (返回码: {returncode})", "ERROR")
        if stderr:
            log(f"   错误信息: {stderr.strip()}", "ERROR")
        return False


def combine_all_data():
    """运行数据合并脚本"""
    log("🔄 开始合并所有数据源...")
    start_time = time.time()
    
    combine_dir = os.path.dirname(COMBINE_SCRIPT)
    returncode, stdout, stderr = run_command(
        "python3 combine.py",
        cwd=combine_dir,
        timeout=6000  # 10分钟超时
    )
    
    elapsed = time.time() - start_time
    
    if returncode == 0:
        log(f"✅ 数据合并成功 ({elapsed:.1f}秒)", "SUCCESS")
        
        # 提取并显示关键统计信息
        if stdout:
            for line in stdout.split("\n"):
                if "本次采集记录数" in line or "历史数据总数" in line or "最近数据数量" in line:
                    log(f"   {line.strip()}")
        return True
    else:
        log(f"❌ 数据合并失败 (返回码: {returncode})", "ERROR")
        if stderr:
            log(f"   错误信息: {stderr.strip()}", "ERROR")
        return False


def check_output_files():
    """检查输出文件是否存在并显示信息"""
    combine_dir = os.path.join(PUBLIC_IOC_DIR, "combine")
    history_file = os.path.join(combine_dir, "history.csv")
    recent_file = os.path.join(combine_dir, "recent.csv")
    
    log("📊 检查输出文件...")
    
    if os.path.exists(history_file):
        size = os.path.getsize(history_file) / 1024 / 1024  # MB
        with open(history_file, 'r') as f:
            lines = sum(1 for _ in f) - 1  # 减去标题行
        log(f"   history.csv: {lines:,} 条记录, {size:.1f} MB")
    else:
        log("   ⚠️  history.csv 不存在", "WARN")
    
    if os.path.exists(recent_file):
        size = os.path.getsize(recent_file) / 1024 / 1024  # MB
        with open(recent_file, 'r') as f:
            lines = sum(1 for _ in f) - 1  # 减去标题行
        log(f"   recent.csv: {lines:,} 条记录, {size:.1f} MB")
    else:
        log("   ⚠️  recent.csv 不存在", "WARN")


def main():
    """主函数"""
    log("=" * 60)
    log("🚀 C2 IOC 每日更新任务开始")
    log("=" * 60)
    
    total_start = time.time()
    
    # 统计信息
    success_count = 0
    fail_count = 0
    failed_sources = []
    
    # 第一步：采集所有数据源
    log(f"\n📋 第1步：采集数据（共 {len(DATA_SOURCES)} 个数据源）")
    log("-" * 60)
    
    for i, source in enumerate(DATA_SOURCES, 1):
        log(f"[{i}/{len(DATA_SOURCES)}] 处理: {source}")
        if collect_data_from_source(source):
            success_count += 1
        else:
            fail_count += 1
            failed_sources.append(source)
        
        # 避免请求过快，休息1秒
        if i < len(DATA_SOURCES):
            time.sleep(1)
    
    log("-" * 60)
    log(f"✅ 采集完成: 成功 {success_count}, 失败 {fail_count}")
    
    if failed_sources:
        log(f"⚠️  失败的数据源: {', '.join(failed_sources)}", "WARN")
    
    # 第二步：合并数据
    log(f"\n📋 第2步：合并数据")
    log("-" * 60)
    
    if combine_all_data():
        log("✅ 数据合并成功")
    else:
        log("❌ 数据合并失败", "ERROR")
        sys.exit(1)
    
    # 第三步：检查输出文件
    log(f"\n📋 第3步：检查输出文件")
    log("-" * 60)
    check_output_files()
    
    # 总结
    total_elapsed = time.time() - total_start
    log("\n" + "=" * 60)
    log(f"🎉 每日更新任务完成！总耗时: {total_elapsed:.1f}秒")
    log(f"📊 数据采集: {success_count}/{len(DATA_SOURCES)} 成功")
    log(f"📅 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log("=" * 60)
    
    # 如果有失败的数据源，返回非零退出码
    if fail_count > 0:
        log(f"⚠️  注意：有 {fail_count} 个数据源采集失败", "WARN")
        sys.exit(1)
    
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\n⚠️  用户中断任务", "WARN")
        sys.exit(130)
    except Exception as e:
        log(f"❌ 发生未预期的错误: {e}", "ERROR")
        import traceback
        traceback.print_exc()
        sys.exit(1)

