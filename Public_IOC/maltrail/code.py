#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Maltrail 威胁情报采集脚本

来源:
  - https://github.com/stamparm/maltrail/tree/master/trails/static/malicious
  - https://github.com/stamparm/maltrail/tree/master/trails/static/malware

从上述目录全部 .txt 中提取 IPv4（支持纯 IP、IP:port、IP/path），输出为当日 CSV。
"""

import csv
import io
import ipaddress
import os
import re
import shutil
import tarfile
import tempfile
from datetime import datetime

import requests

# =========================
# 1. 基本配置
# =========================
MALTRAIL_TARBALL_URL = "https://codeload.github.com/stamparm/maltrail/tar.gz/master"
TRAIL_DIRS = ("trails/static/malicious", "trails/static/malware")

script_dir = os.path.dirname(os.path.abspath(__file__))
SAVE_DIR = os.path.join(script_dir, "data")
os.makedirs(SAVE_DIR, exist_ok=True)

today_str = datetime.now().strftime("%Y-%m-%d")
save_path = os.path.join(SAVE_DIR, f"{today_str}.csv")

# 行首 IPv4，可选 :port，可选 /path
IP_LINE_RE = re.compile(
    r"^(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
    r"(?::(?P<port>\d{1,5}))?"
    r"(?:/.*)?$"
)


def is_valid_ipv4(ip_str):
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ValueError:
        return False


def extract_trails(tarball_bytes, dest_dir):
    """从 tarball 中仅解压 malicious / malware 目录下的 .txt"""
    extracted = 0
    with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile() or not member.name.endswith(".txt"):
                continue

            # 去掉顶层目录名，例如 maltrail-master/...
            parts = member.name.split("/", 1)
            if len(parts) < 2:
                continue
            rel_path = parts[1]

            if not any(rel_path.startswith(d + "/") for d in TRAIL_DIRS):
                continue

            # 安全解压：限制写出路径
            out_path = os.path.join(dest_dir, rel_path)
            out_dir = os.path.dirname(out_path)
            os.makedirs(out_dir, exist_ok=True)

            src = tar.extractfile(member)
            if src is None:
                continue
            with open(out_path, "wb") as f:
                f.write(src.read())
            extracted += 1

    return extracted


def parse_trail_file(file_path, category, tag):
    """解析单个 trail 文件，返回 [(ip, port, tag), ...]"""
    rows = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                # 去掉行尾注释
                if " #" in line:
                    line = line.split(" #", 1)[0].strip()

                match = IP_LINE_RE.match(line)
                if not match:
                    continue

                ip = match.group("ip")
                port = match.group("port") or ""
                if not is_valid_ipv4(ip):
                    continue

                rows.append((ip, port, f"{category}/{tag}"))
    except OSError as e:
        print(f"    └─ 读取失败 {file_path}: {e}")

    return rows


def main():
    print("[+] 正在下载 Maltrail trails（malicious + malware）...")
    resp = requests.get(MALTRAIL_TARBALL_URL, timeout=180)
    resp.raise_for_status()
    print(f"[+] 下载完成，大小约 {len(resp.content) / 1024 / 1024:.1f} MB")

    tmp_dir = tempfile.mkdtemp(prefix="maltrail_")
    try:
        print("[+] 解压 trails/static/{malicious,malware} 下的 .txt ...")
        file_count = extract_trails(resp.content, tmp_dir)
        print(f"[+] 共解压 {file_count} 个 .txt 文件")

        output_rows = [["ip", "port", "tag"]]
        seen = set()
        total = 0

        for category in ("malicious", "malware"):
            root = os.path.join(tmp_dir, "trails", "static", category)
            if not os.path.isdir(root):
                print(f"[!] 目录不存在: {root}")
                continue

            txt_files = sorted(
                f for f in os.listdir(root) if f.endswith(".txt")
            )
            print(f"[+] 解析 {category}: {len(txt_files)} 个文件")

            cat_count = 0
            for filename in txt_files:
                tag = filename[:-4]
                file_path = os.path.join(root, filename)
                for ip, port, full_tag in parse_trail_file(file_path, category, tag):
                    key = (ip, port, full_tag)
                    if key in seen:
                        continue
                    seen.add(key)
                    output_rows.append([ip, port, full_tag])
                    total += 1
                    cat_count += 1

            print(f"    └─ {category}: 提取 {cat_count} 条 IP 记录")

        with open(save_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(output_rows)

        print(f"\n[+] 处理完成，共提取 {total} 条 IOC（去重后）")
        print(f"[+] 文件已保存：{save_path}")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
