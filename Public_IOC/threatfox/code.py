#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import csv
import sys
import os
from datetime import datetime
from urllib.request import urlopen, Request

URL = "https://threatfox.abuse.ch/export/json/recent/"
SAVE_DIR = "threatfox/data"


def fetch_threatfox_recent():
    """获取 ThreatFox recent 导出，并展开为 IOC 记录列表。"""
    req = Request(URL, headers={"User-Agent": "Mozilla/5.0"})
    with urlopen(req, timeout=60) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        data = json.loads(raw)

    records = []

    # 顶层是 dict：{"1672089": [ {...}, {...} ], "1672088": [ {...} ], ...}
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        records.append(item)
            elif isinstance(v, dict):
                records.append(v)

    # 顶层直接是 list 的情况（顺手也兼容一下）
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                records.append(item)

    if not records:
        print("[-] Unexpected JSON structure from ThreatFox", file=sys.stderr)
        print("    type(data):", type(data), file=sys.stderr)
        if isinstance(data, dict):
            print("    keys:", list(data.keys())[:10], file=sys.stderr)
        raise ValueError("Cannot find IOC list in ThreatFox JSON")

    return records


def parse_iocs(raw_iocs):
    """
    只保留 ioc_type 为 ip / ip:port 的记录，抽出：
    ip, port, malware, confidence_level, first_seen_utc_date(YYYY-MM-DD)
    """
    results = []

    for item in raw_iocs:
        if not isinstance(item, dict):
            continue

        # 字段名在你给的 JSON 里是 ioc_value
        ioc = (
            item.get("ioc_value")
            or item.get("ioc")
            or item.get("indicator")
            or item.get("value")
            or ""
        )
        ioc_type = item.get("ioc_type") or item.get("type") or ""

        if not ioc:
            continue

        # 只要 IP / IP:PORT，其它像 domain 我们直接跳过
        if ioc_type not in ("ip", "ip:port"):
            continue

        ip = ioc
        port = ""

        if ioc_type == "ip:port" and ":" in ioc:
            ip, port = ioc.rsplit(":", 1)

        malware = item.get("malware") or item.get("malware_printable") or ""
        confidence = item.get("confidence_level", "")

        first_seen_raw = (
            item.get("first_seen_utc")
            or item.get("first_seen")
            or ""
        )
        first_seen_date = first_seen_raw[:10] if len(first_seen_raw) >= 10 else first_seen_raw

        results.append({
            "ip": ip,
            "port": port,
            "malware": malware,
            "confidence_level": confidence,
            "first_seen_utc_date": first_seen_date,
        })

    return results


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def main():
    try:
        raw_iocs = fetch_threatfox_recent()
    except Exception as e:
        print(f"[-] Failed to fetch data from ThreatFox: {e}", file=sys.stderr)
        sys.exit(1)

    parsed = parse_iocs(raw_iocs)

    ensure_dir(SAVE_DIR)

    today_str = datetime.now().strftime("%Y-%m-%d")
    output_file = os.path.join(SAVE_DIR, f"{today_str}.csv")

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ip",
            "port",
            "malware",
            "confidence_level",
            "first_seen_utc_date",
        ])
        for row in parsed:
            writer.writerow([
                row["ip"],
                row["port"],
                row["malware"],
                row["confidence_level"],
                row["first_seen_utc_date"],
            ])

    print(f"[+] Saved {len(parsed)} C2 records to: {output_file}")


if __name__ == "__main__":
    main()
