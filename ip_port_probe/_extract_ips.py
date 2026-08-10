#!/usr/bin/env python3
"""从 recent_high_risk_ips.csv 提取去重后的 IP 列表。"""
import csv
import sys

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_csv> <output_txt>")
        sys.exit(1)

    input_csv, output_txt = sys.argv[1], sys.argv[2]
    ips: set[str] = set()

    with open(input_csv, encoding="utf-8") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            ip = row.get("ip", "").strip()
            if ip:
                ips.add(ip)

    with open(output_txt, "w") as f:
        f.write("\n".join(sorted(ips)) + "\n")

    print(f"  提取了 {len(ips)} 个唯一 IP → {output_txt}")


if __name__ == "__main__":
    main()
