#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generate_report.py — 生成 IP 端口映射报告和 Top 10 HTTP/TLS 端口统计

输入:
  scan_results.csv    — 端口扫描结果 (ip, ports_set)
  http_results.jsonl  — HTTP 探测结果 (zgrab2 兼容格式)
  tls_results.jsonl   — TLS  探测结果 (zgrab2 兼容格式)

输出 1: ip_port_mapping.json
  {
    "1.2.3.4": {
      "open_ports": [80, 443, 8080],
      "http_ports": [80, 8080],
      "tls_ports":  [443]
    },
    ...
  }

输出 2: top10_http_tls_ports.json  (机器可读)
输出 3: top10_http_tls_ports.txt   (人类可读)
"""

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path


# ---------------------------------------------------------------------------
# 加载数据
# ---------------------------------------------------------------------------

def load_scan_results(path: str) -> dict[str, list[int]]:
    ip_ports: dict[str, list[int]] = {}
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ip = row.get("ip", "").strip()
            raw = row.get("ports_set", "").strip()
            if not ip or not raw:
                continue
            try:
                ports = [int(p) for p in raw.split(",") if p.strip()]
                if ports:
                    ip_ports[ip] = sorted(set(ports))
            except ValueError:
                continue
    return ip_ports


def load_detected_pairs(jsonl_path: str, protocol: str) -> set[tuple[str, int]]:
    """
    从 zgrab2 兼容 JSONL 中读取探测成功的 (ip, port) 集合。
    成功条件: data.<protocol>.status == "success"
    """
    detected: set[tuple[str, int]] = set()
    try:
        with open(jsonl_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    ip   = rec.get("ip", "")
                    port = rec.get("port", 0)
                    proto_data = rec.get("data", {}).get(protocol, {})
                    if proto_data.get("status") == "success":
                        detected.add((ip, int(port)))
                except (json.JSONDecodeError, ValueError, KeyError):
                    continue
    except FileNotFoundError:
        print(f"[WARN] 文件不存在，跳过: {jsonl_path}", file=sys.stderr)
    return detected


# ---------------------------------------------------------------------------
# 生成报告
# ---------------------------------------------------------------------------

def build_mapping(
    ip_ports: dict[str, list[int]],
    http_pairs: set[tuple[str, int]],
    tls_pairs:  set[tuple[str, int]],
) -> tuple[dict, Counter, Counter]:
    """
    构建 IP → 端口映射，同时统计 HTTP / TLS 端口频率。
    返回 (mapping_dict, http_counter, tls_counter)
    """
    mapping: dict = {}
    http_ctr: Counter = Counter()
    tls_ctr:  Counter = Counter()

    for ip, ports in sorted(ip_ports.items()):
        http_ports = sorted(p for p in ports if (ip, p) in http_pairs)
        tls_ports  = sorted(p for p in ports if (ip, p) in tls_pairs)

        mapping[ip] = {
            "open_ports": ports,
            "http_ports": http_ports,
            "tls_ports":  tls_ports,
        }
        http_ctr.update(http_ports)
        tls_ctr.update(tls_ports)

    return mapping, http_ctr, tls_ctr


def write_ip_port_mapping(mapping: dict, out_path: Path) -> None:
    """
    输出 1: IP-端口映射 JSON。
    格式设计原则: 一行一个 IP，端口列表内联，文件大但可流式处理。
    """
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("{\n")
        items = list(mapping.items())
        for idx, (ip, data) in enumerate(items):
            comma = "," if idx < len(items) - 1 else ""
            # 每个 IP 占两行，端口内联，便于 grep/jq 等工具直接使用
            f.write(
                f'  {json.dumps(ip)}: {{'
                f'"open_ports":{json.dumps(data["open_ports"])},'
                f'"http_ports":{json.dumps(data["http_ports"])},'
                f'"tls_ports":{json.dumps(data["tls_ports"])}'
                f'}}{comma}\n'
            )
        f.write("}\n")
    print(f"  [输出1] ip_port_mapping.json → {out_path}  ({len(mapping):,} 条)")


def write_top10_reports(
    http_ctr: Counter,
    tls_ctr:  Counter,
    total_ips: int,
    out_dir: Path,
) -> None:
    """输出 2 & 3: Top 10 HTTP/TLS 端口统计 (JSON + 文本)"""

    def _top10(ctr: Counter) -> list[dict]:
        return [
            {
                "rank":       rank,
                "port":       port,
                "ip_count":   count,
                "percentage": round(count / total_ips * 100, 2) if total_ips else 0.0,
            }
            for rank, (port, count) in enumerate(ctr.most_common(10), start=1)
        ]

    data = {
        "total_ips_scanned":     total_ips,
        "total_ports_with_http": sum(http_ctr.values()),
        "total_ports_with_tls":  sum(tls_ctr.values()),
        "top10_http_ports":      _top10(http_ctr),
        "top10_tls_ports":       _top10(tls_ctr),
    }

    # JSON
    json_path = out_dir / "top10_http_tls_ports.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  [输出2] top10_http_tls_ports.json → {json_path}")

    # 人类可读文本
    txt_path = out_dir / "top10_http_tls_ports.txt"
    with open(txt_path, "w", encoding="utf-8") as f:
        _w = f.write

        def section(title: str, rows: list[dict]) -> None:
            _w(f"\n{title}\n")
            _w(f"{'─' * 46}\n")
            _w(f"  {'Rank':<6}{'Port':<10}{'IP Count':>10}{'  Percentage':>14}\n")
            _w(f"{'─' * 46}\n")
            if not rows:
                _w("  (无数据)\n")
                return
            for r in rows:
                _w(f"  #{r['rank']:<5}{r['port']:<10}{r['ip_count']:>10,}  {r['percentage']:>10.2f}%\n")

        _w("=" * 46 + "\n")
        _w("   Top-10 HTTP / TLS 端口频率报告\n")
        _w("=" * 46 + "\n")
        _w(f"\n  扫描 IP 总数     : {total_ips:>10,}\n")
        _w(f"  HTTP 端口命中总数: {data['total_ports_with_http']:>10,}\n")
        _w(f"  TLS  端口命中总数: {data['total_ports_with_tls']:>10,}\n")

        section("【HTTP 端口 Top 10】", data["top10_http_ports"])
        section("【TLS  端口 Top 10】", data["top10_tls_ports"])
        _w("\n" + "=" * 46 + "\n")

    print(f"  [输出3] top10_http_tls_ports.txt  → {txt_path}")

    # 终端预览
    print()
    print("  ── HTTP Top 10 ──")
    for r in data["top10_http_ports"]:
        print(f"    #{r['rank']}  Port {r['port']:<6}  {r['ip_count']:>6,} IPs  ({r['percentage']}%)")
    print()
    print("  ── TLS Top 10 ──")
    for r in data["top10_tls_ports"]:
        print(f"    #{r['rank']}  Port {r['port']:<6}  {r['ip_count']:>6,} IPs  ({r['percentage']}%)")


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="生成 IP 端口映射和 Top 10 统计报告")
    parser.add_argument("--scan-results",  required=True, help="scan_results.csv")
    parser.add_argument("--http-results",  required=True, help="http_results.jsonl")
    parser.add_argument("--tls-results",   required=True, help="tls_results.jsonl")
    parser.add_argument("--output-dir",    required=True, help="输出目录")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"加载扫描结果: {args.scan_results}")
    ip_ports = load_scan_results(args.scan_results)
    if not ip_ports:
        print("扫描结果为空，请先执行端口扫描步骤。")
        sys.exit(1)

    print(f"加载 HTTP 探测结果: {args.http_results}")
    http_pairs = load_detected_pairs(args.http_results, "http")

    print(f"加载 TLS 探测结果: {args.tls_results}")
    tls_pairs = load_detected_pairs(args.tls_results, "tls")

    print("构建映射表和统计...")
    mapping, http_ctr, tls_ctr = build_mapping(ip_ports, http_pairs, tls_pairs)

    write_ip_port_mapping(mapping, out_dir / "ip_port_mapping.json")
    write_top10_reports(http_ctr, tls_ctr, len(mapping), out_dir)


if __name__ == "__main__":
    main()
