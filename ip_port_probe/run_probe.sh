#!/usr/bin/env bash
# =============================================================================
# run_probe.sh — 全端口扫描 + HTTP/TLS 协议探测 主入口
#
# 流程:
#   Step 1  端口扫描    → masscan (优先) 或 项目内置 raw-socket SYN 扫描器
#   Step 2  协议探测    → protocol_probe.py (async HTTP/TLS，输出格式兼容 zgrab2)
#   Step 3  生成报告    → generate_report.py
#
# 输出 (output/ 目录):
#   ip_port_mapping.json       — IP → {open_ports, http_ports, tls_ports}
#   top10_http_tls_ports.json  — Top 10 HTTP/TLS 端口统计 (JSON)
#   top10_http_tls_ports.txt   — Top 10 HTTP/TLS 端口统计 (人类可读)
#
# 可选环境变量:
#   MASSCAN_RATE      masscan 发包速率 (pps)，默认 50000
#   PROBE_CONCURRENCY 协议探测并发连接数，默认 500
#   PROBE_TIMEOUT     协议探测超时(秒)，默认 10
#   SCAN_RESULTS      直接指定已有扫描结果 CSV，跳过端口扫描步骤
#                     CSV 格式: ip,ports_set (ports_set 为逗号分隔端口列表)
#
# 依赖:
#   必选: python3, pip install aiohttp
#   端口扫描二选一: masscan  |  sudo + 项目内 utility_scan/tcp_syn/scanner.py
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DATA_DIR="$SCRIPT_DIR/data"
OUTPUT_DIR="$SCRIPT_DIR/output"
CSV_FILE="$PROJECT_ROOT/Public_IOC/all_res_combine/recent_high_risk_ips.csv"

mkdir -p "$DATA_DIR" "$OUTPUT_DIR"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# =============================================================================
# Step 1: 端口扫描
# =============================================================================
SCAN_RESULTS="${SCAN_RESULTS:-$DATA_DIR/scan_results.csv}"

if [[ -f "$SCAN_RESULTS" ]]; then
    log "检测到已有扫描结果: $SCAN_RESULTS，跳过端口扫描步骤"
    log "  如需重新扫描，请删除该文件后重新运行"

elif command -v masscan &>/dev/null; then
    # ---- masscan 路径 ----
    log "Step 1/3: 使用 masscan 进行全端口扫描 (1-65535)"
    IP_FILE="$DATA_DIR/ips.txt"
    MASSCAN_RAW="$DATA_DIR/masscan_raw.txt"
    MASSCAN_RATE="${MASSCAN_RATE:-50000}"

    log "  提取唯一 IP..."
    python3 "$SCRIPT_DIR/_extract_ips.py" "$CSV_FILE" "$IP_FILE"

    log "  启动 masscan (rate=$MASSCAN_RATE pps)..."
    log "  IP 数量: $(wc -l < "$IP_FILE" | tr -d ' ')，全端口扫描预计耗时较长"
    masscan \
        -iL "$IP_FILE" \
        -p 1-65535 \
        --rate "$MASSCAN_RATE" \
        --output-format list \
        --output-file "$MASSCAN_RAW" \
        --exclude 255.255.255.255

    log "  解析 masscan 输出 → $SCAN_RESULTS"
    python3 - <<PYEOF
import csv
from collections import defaultdict
ip_ports = defaultdict(set)
with open("$MASSCAN_RAW") as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()           # open tcp PORT IP TIMESTAMP
        if len(parts) >= 4 and parts[0] == 'open':
            try:
                ip_ports[parts[3]].add(int(parts[2]))
            except (ValueError, IndexError):
                pass
with open("$SCAN_RESULTS", 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['ip', 'ports_set'])
    for ip in sorted(ip_ports):
        w.writerow([ip, ','.join(map(str, sorted(ip_ports[ip])))])
print(f"  {len(ip_ports)} 个 IP 有开放端口 → $SCAN_RESULTS")
PYEOF

else
    # ---- 项目内置 raw-socket SYN 扫描器路径 ----
    log "Step 1/3: masscan 未安装，回退到项目内置 TCP SYN 扫描器"
    log "  (安装 masscan: brew install masscan)"
    SCANNER="$PROJECT_ROOT/utility_scan/tcp_syn/scanner.py"

    if [[ ! -f "$SCANNER" ]]; then
        log "错误: 既无 masscan，也未找到 $SCANNER"
        exit 1
    fi

    log "  需要 root 权限，调用 sudo..."
    sudo python3 - <<PYEOF
import sys, importlib.util, logging, os
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s',
                    handlers=[logging.StreamHandler(),
                              logging.FileHandler("$DATA_DIR/scan.log")])
spec = importlib.util.spec_from_file_location("scanner", "$SCANNER")
mod  = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
scanner = mod.RawSocketSYNScanner(
    input_csv  = "$CSV_FILE",
    output_csv = "$SCAN_RESULTS",
    send_workers=100, recv_workers=10, batch_size=100, timeout=2.0
)
scanner.run()
PYEOF
fi

echo ""
# =============================================================================
# Step 2: HTTP / TLS 协议探测
# =============================================================================
log "Step 2/3: HTTP/TLS 协议探测"
python3 "$SCRIPT_DIR/protocol_probe.py" \
    --scan-results "$SCAN_RESULTS" \
    --http-out     "$DATA_DIR/http_results.jsonl" \
    --tls-out      "$DATA_DIR/tls_results.jsonl" \
    --concurrency  "${PROBE_CONCURRENCY:-500}" \
    --timeout      "${PROBE_TIMEOUT:-10}"

echo ""
# =============================================================================
# Step 3: 生成报告
# =============================================================================
log "Step 3/3: 生成报告"
python3 "$SCRIPT_DIR/generate_report.py" \
    --scan-results "$SCAN_RESULTS" \
    --http-results "$DATA_DIR/http_results.jsonl" \
    --tls-results  "$DATA_DIR/tls_results.jsonl" \
    --output-dir   "$OUTPUT_DIR"

echo ""
log "========================================"
log "完成！输出文件："
log "  $OUTPUT_DIR/ip_port_mapping.json"
log "  $OUTPUT_DIR/top10_http_tls_ports.json"
log "  $OUTPUT_DIR/top10_http_tls_ports.txt"
log "========================================"
