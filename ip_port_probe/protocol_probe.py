#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
protocol_probe.py — 异步 HTTP / TLS 协议探测

对端口扫描发现的每个 ip:port 并发发起 HTTP 连接尝试和 TLS 握手尝试，
输出 zgrab2 兼容的 JSONL 格式结果（每行一个 JSON 对象）。

输入: scan_results.csv  (列: ip, ports_set)
      ports_set 为英文逗号分隔的端口号字符串，例如 "80,443,8080"

输出:
  http_results.jsonl  — 每个 ip:port 的 HTTP 探测结果
  tls_results.jsonl   — 每个 ip:port 的 TLS 探测结果

zgrab2 兼容格式示例 (HTTP 成功):
  {"ip":"1.2.3.4","port":80,"data":{"http":{"status":"success","result":{...}}}}

zgrab2 兼容格式示例 (探测失败):
  {"ip":"1.2.3.4","port":8080,"data":{"http":{"status":"failure","error":"..."}}}

用法:
  python3 protocol_probe.py \\
      --scan-results data/scan_results.csv \\
      --http-out     data/http_results.jsonl \\
      --tls-out      data/tls_results.jsonl \\
      --concurrency  500 \\
      --timeout      10
"""

import argparse
import asyncio
import csv
import json
import ssl
import sys
import time
from pathlib import Path
from typing import Optional

try:
    import aiohttp
except ImportError:
    print("错误: 缺少 aiohttp，请运行: pip3 install aiohttp")
    sys.exit(1)


# ---------------------------------------------------------------------------
# 解析扫描结果
# ---------------------------------------------------------------------------

def load_scan_results(path: str) -> dict[str, list[int]]:
    """读取 scan_results.csv，返回 {ip: [port, ...]}"""
    ip_ports: dict[str, list[int]] = {}
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get("ip", "").strip()
            ports_raw = row.get("ports_set", "").strip()
            if not ip or not ports_raw:
                continue
            try:
                ports = [int(p) for p in ports_raw.split(",") if p.strip()]
                if ports:
                    ip_ports[ip] = sorted(set(ports))
            except ValueError:
                continue
    return ip_ports


# ---------------------------------------------------------------------------
# 协议探测
# ---------------------------------------------------------------------------

async def probe_http(
    session: "aiohttp.ClientSession",
    ip: str,
    port: int,
    timeout: int,
) -> dict:
    """
    尝试向 ip:port 发送 HTTP GET /。
    返回 zgrab2 兼容的 data.http 字典。
    """
    url = f"http://{ip}:{port}/"
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=False,
            ssl=False,
        ) as resp:
            server = resp.headers.get("Server", "")
            content_type = resp.headers.get("Content-Type", "")
            return {
                "status": "success",
                "result": {
                    "status_code": resp.status,
                    "server": server,
                    "content_type": content_type,
                },
            }
    except aiohttp.ClientResponseError as e:
        # HTTP 级别错误（如 4xx/5xx 仍算 HTTP 服务存在）
        return {
            "status": "success",
            "result": {"status_code": e.status, "server": "", "content_type": ""},
        }
    except asyncio.TimeoutError:
        return {"status": "failure", "error": "timeout"}
    except aiohttp.ClientConnectorError as e:
        return {"status": "failure", "error": f"connection_refused: {e.os_error}"}
    except aiohttp.ServerDisconnectedError:
        return {"status": "failure", "error": "server_disconnected"}
    except Exception as e:
        return {"status": "failure", "error": str(e)[:120]}


async def probe_tls(ip: str, port: int, timeout: int) -> dict:
    """
    尝试与 ip:port 完成 TLS 握手（不校验证书）。
    返回 zgrab2 兼容的 data.tls 字典。
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx),
            timeout=timeout,
        )
        ssl_obj: Optional[ssl.SSLObject] = writer.get_extra_info("ssl_object")
        cipher = writer.get_extra_info("cipher")          # (name, proto, bits)
        tls_version = ssl_obj.version() if ssl_obj else None
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return {
            "status": "success",
            "result": {
                "version": tls_version,
                "cipher_name": cipher[0] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
            },
        }
    except asyncio.TimeoutError:
        return {"status": "failure", "error": "timeout"}
    except ssl.SSLError as e:
        return {"status": "failure", "error": f"ssl_error: {e.reason}"}
    except ConnectionRefusedError:
        return {"status": "failure", "error": "connection_refused"}
    except OSError as e:
        return {"status": "failure", "error": f"os_error: {e.strerror}"}
    except Exception as e:
        return {"status": "failure", "error": str(e)[:120]}


# ---------------------------------------------------------------------------
# 并发调度
# ---------------------------------------------------------------------------

async def run_all_probes(
    ip_ports: dict[str, list[int]],
    http_out: str,
    tls_out: str,
    concurrency: int,
    timeout: int,
) -> None:
    total_pairs = sum(len(p) for p in ip_ports.values())
    print(f"  目标数: {len(ip_ports):,} 个 IP，{total_pairs:,} 个 ip:port 对")
    print(f"  并发数: {concurrency}，超时: {timeout}s")

    sem = asyncio.Semaphore(concurrency)
    http_lines: list[str] = []
    tls_lines: list[str] = []
    completed = 0
    start = time.monotonic()

    def _record(ip: str, port: int, proto: str, probe_data: dict) -> str:
        return json.dumps({"ip": ip, "port": port, "data": {proto: probe_data}},
                          ensure_ascii=False)

    async def probe_one(session: "aiohttp.ClientSession", ip: str, port: int) -> None:
        nonlocal completed
        async with sem:
            h_data, t_data = await asyncio.gather(
                probe_http(session, ip, port, timeout),
                probe_tls(ip, port, timeout),
            )
        http_lines.append(_record(ip, port, "http", h_data))
        tls_lines.append(_record(ip, port, "tls",  t_data))

        completed += 1
        if completed % 500 == 0 or completed == total_pairs:
            elapsed = time.monotonic() - start
            rate = completed / elapsed if elapsed else 0
            eta  = (total_pairs - completed) / rate if rate else 0
            print(
                f"\r  进度: {completed:>7,}/{total_pairs:,}"
                f"  ({completed * 100 / total_pairs:5.1f}%)"
                f"  速率: {rate:6.0f}/s  ETA: {eta:5.0f}s",
                end="", flush=True,
            )

    connector = aiohttp.TCPConnector(
        limit=concurrency,
        limit_per_host=5,
        ssl=False,
        enable_cleanup_closed=True,
    )
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            probe_one(session, ip, port)
            for ip, ports in ip_ports.items()
            for port in ports
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    print()  # 换行

    elapsed_total = time.monotonic() - start
    http_ok = sum(1 for l in http_lines if '"status": "success"' in l or '"status":"success"' in l)
    tls_ok  = sum(1 for l in tls_lines  if '"status": "success"' in l or '"status":"success"' in l)

    print(f"  总耗时: {elapsed_total:.1f}s")
    print(f"  HTTP 服务识别: {http_ok:,} 个端口")
    print(f"  TLS  服务识别: {tls_ok:,}  个端口")

    Path(http_out).write_text("\n".join(http_lines) + "\n", encoding="utf-8")
    Path(tls_out ).write_text("\n".join(tls_lines)  + "\n", encoding="utf-8")
    print(f"  HTTP 结果 → {http_out}")
    print(f"  TLS  结果 → {tls_out}")


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="异步 HTTP/TLS 协议探测（输出格式兼容 zgrab2 JSONL）"
    )
    parser.add_argument("--scan-results", required=True,
                        help="端口扫描结果 CSV (列: ip, ports_set)")
    parser.add_argument("--http-out", required=True,
                        help="HTTP 探测结果输出路径 (.jsonl)")
    parser.add_argument("--tls-out",  required=True,
                        help="TLS  探测结果输出路径 (.jsonl)")
    parser.add_argument("--concurrency", type=int, default=500,
                        help="最大并发连接数 (默认 500)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="单次连接超时秒数 (默认 10)")
    args = parser.parse_args()

    print(f"加载扫描结果: {args.scan_results}")
    ip_ports = load_scan_results(args.scan_results)
    if not ip_ports:
        print("扫描结果为空，请先执行端口扫描步骤。")
        sys.exit(1)

    # 创建输出目录（如不存在）
    Path(args.http_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.tls_out ).parent.mkdir(parents=True, exist_ok=True)

    asyncio.run(
        run_all_probes(
            ip_ports,
            args.http_out,
            args.tls_out,
            args.concurrency,
            args.timeout,
        )
    )


if __name__ == "__main__":
    main()
