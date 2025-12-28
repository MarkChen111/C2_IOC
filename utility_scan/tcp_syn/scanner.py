#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高性能TCP SYN半开扫描脚本
使用scapy批量发送SYN包 + 异步嗅探响应
按端口批次扫描: 先扫描所有IP的某个端口,再扫描下一个端口
需要root权限运行
"""

import csv
import os
import sys
from pathlib import Path
from datetime import datetime
import time
import logging
from collections import defaultdict
from scapy.all import IP, TCP, send, sniff, conf
import threading
import queue

# 禁用scapy的详细输出
conf.verb = 0

# 日志将在main函数中配置
logger = logging.getLogger(__name__)


class FastSYNScanner:
    def __init__(self, input_csv, output_csv, pps=1000, batch_size=1000, timeout=2.0):
        """
        初始化扫描器
        
        Args:
            input_csv: 输入CSV文件路径
            output_csv: 输出CSV文件路径 (最终结果: ip, ports_set)
            pps: 每秒发包数 (packets per second)
            batch_size: 批量写入大小,每扫描多少个结果写入一次
            timeout: 等待响应超时时间(秒)
        """
        self.input_csv = input_csv
        self.output_csv = output_csv
        self.pps = pps
        self.batch_size = batch_size
        self.timeout = timeout
        
        # 中间结果文件 (ip, port)
        self.temp_results_file = Path(output_csv).parent / 'temp_scan_results.csv'
        
        self.scanned_count = 0
        self.total_count = 0
        self.results_buffer = []  # 结果缓冲区
        self.buffer_lock = threading.Lock()  # 缓冲区锁
        
        # 常见端口列表 (1-65535)
        self.ports = list(range(1, 65536))
        
        # 响应队列
        self.response_queue = queue.Queue()
        self.stop_sniffing = threading.Event()
        
    def read_ips_from_csv(self):
        """
        从CSV文件读取IP并去重
        
        Returns:
            list: 去重后的IP列表
        """
        ips = set()
        
        try:
            with open(self.input_csv, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f, delimiter='\t')
                for row in reader:
                    ip = row.get('ip', '').strip()
                    if ip and ip != 'ip':  # 跳过空值和标题行
                        ips.add(ip)
            
            logger.info(f"从CSV文件读取到 {len(ips)} 个唯一IP地址")
            return sorted(list(ips))
        
        except Exception as e:
            logger.error(f"读取CSV文件失败: {e}")
            return []
    
    def packet_handler(self, pkt):
        """
        处理接收到的数据包
        """
        try:
            # 检查是否是TCP SYN-ACK响应
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                tcp_layer = pkt[TCP]
                ip_layer = pkt[IP]
                
                # SYN-ACK标志 (flags=0x12 或 SA)
                if tcp_layer.flags == 0x12:
                    src_ip = ip_layer.src
                    src_port = tcp_layer.sport
                    self.response_queue.put((src_ip, src_port))
        except Exception as e:
            pass
    
    def start_sniffer(self):
        """
        启动数据包嗅探线程
        """
        def sniffer_thread():
            # 只捕获TCP SYN-ACK包
            sniff(
                filter="tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack != 0",
                prn=self.packet_handler,
                store=0,
                stop_filter=lambda x: self.stop_sniffing.is_set()
            )
        
        thread = threading.Thread(target=sniffer_thread, daemon=True)
        thread.start()
        logger.info("数据包嗅探器已启动")
        return thread
    
    def send_syn_packets(self, ips, port):
        """
        批量发送SYN包
        
        Args:
            ips: IP列表
            port: 端口号
        """
        packets = []
        for ip in ips:
            # 构造SYN包
            pkt = IP(dst=ip)/TCP(dport=port, flags='S', sport=12345)
            packets.append(pkt)
        
        # 计算发送间隔
        interval = 1.0 / self.pps if self.pps > 0 else 0
        
        # 批量发送
        logger.info(f"开始发送 {len(packets)} 个SYN包到端口 {port}")
        for pkt in packets:
            send(pkt, verbose=0)
            if interval > 0:
                time.sleep(interval)
    
    def add_result_to_buffer(self, ip, port):
        """
        将扫描结果添加到缓冲区
        
        Args:
            ip: IP地址
            port: 端口号
        """
        with self.buffer_lock:
            self.results_buffer.append((ip, port))
            
            # 如果缓冲区达到批量大小,写入文件
            if len(self.results_buffer) >= self.batch_size:
                self.flush_buffer()
    
    def flush_buffer(self):
        """
        将缓冲区的结果批量写入临时CSV文件
        注意: 调用此方法前应该已经获取了buffer_lock
        """
        if not self.results_buffer:
            return
        
        try:
            # 追加写入CSV文件
            file_exists = os.path.exists(self.temp_results_file)
            
            with open(self.temp_results_file, 'a', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                
                # 如果文件不存在,写入标题行
                if not file_exists:
                    writer.writerow(['ip', 'port'])
                
                # 批量写入所有结果
                for ip, port in self.results_buffer:
                    writer.writerow([ip, port])
            
            logger.info(f"已批量写入 {len(self.results_buffer)} 条扫描结果到临时文件")
            self.results_buffer.clear()
        
        except Exception as e:
            logger.error(f"批量保存结果失败: {e}")
    
    def scan_port_batch(self, ips, port):
        """
        扫描所有IP的某个端口
        
        Args:
            ips: IP列表
            port: 端口号
        """
        logger.info(f"开始扫描端口 {port} (共 {len(ips)} 个IP)")
        start_time = time.time()
        
        # 清空响应队列
        while not self.response_queue.empty():
            try:
                self.response_queue.get_nowait()
            except queue.Empty:
                break
        
        # 发送SYN包
        self.send_syn_packets(ips, port)
        
        # 等待响应
        logger.info(f"等待 {self.timeout} 秒收集响应...")
        time.sleep(self.timeout)
        
        # 收集响应
        open_count = 0
        while not self.response_queue.empty():
            try:
                ip, response_port = self.response_queue.get_nowait()
                if response_port == port:  # 确保是当前扫描的端口
                    self.add_result_to_buffer(ip, port)
                    open_count += 1
            except queue.Empty:
                break
        
        self.scanned_count += len(ips)
        elapsed = time.time() - start_time
        logger.info(f"端口 {port} 扫描完成 - 发现 {open_count} 个开放 - 耗时 {elapsed:.1f}秒 - "
                   f"进度: {self.scanned_count}/{self.total_count} ({self.scanned_count*100/self.total_count:.1f}%)")
    
    def merge_results(self):
        """
        合并临时结果文件,生成最终的 scan_results.csv
        格式: ip, ports_set (端口从大到小排序,逗号分隔)
        """
        logger.info("开始合并扫描结果...")
        
        if not os.path.exists(self.temp_results_file):
            logger.warning("临时结果文件不存在,无法合并")
            return
        
        # 读取所有结果并按IP分组
        ip_ports = defaultdict(set)
        
        try:
            with open(self.temp_results_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    ip = row['ip']
                    port = int(row['port'])
                    ip_ports[ip].add(port)
            
            logger.info(f"读取到 {len(ip_ports)} 个IP的扫描结果")
            
            # 写入最终结果文件
            with open(self.output_csv, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ip', 'ports_set'])
                
                for ip in sorted(ip_ports.keys()):
                    ports = sorted(ip_ports[ip], reverse=True)  # 从大到小排序
                    ports_str = ','.join(map(str, ports))
                    writer.writerow([ip, ports_str])
            
            logger.info(f"结果已合并到: {self.output_csv}")
            
            # 删除临时文件
            os.remove(self.temp_results_file)
            logger.info("临时文件已删除")
        
        except Exception as e:
            logger.error(f"合并结果失败: {e}")
    
    def run(self):
        """
        执行扫描任务
        """
        logger.info("=" * 60)
        logger.info("开始高性能TCP SYN半开扫描任务")
        logger.info(f"输入文件: {self.input_csv}")
        logger.info(f"输出文件: {self.output_csv}")
        logger.info(f"发包速率: {self.pps} packets/sec")
        logger.info(f"响应超时: {self.timeout}秒")
        logger.info("=" * 60)
        
        # 读取IP列表
        ips = self.read_ips_from_csv()
        
        if not ips:
            logger.error("没有找到有效的IP地址")
            return
        
        # 计算总扫描次数
        self.total_count = len(ips) * len(self.ports)
        start_time = time.time()
        
        logger.info(f"待扫描: {len(ips)} 个IP × {len(self.ports)} 个端口 = {self.total_count:,} 次扫描")
        
        # 删除旧的临时文件
        if os.path.exists(self.temp_results_file):
            os.remove(self.temp_results_file)
            logger.info("已删除旧的临时结果文件")
        
        # 启动嗅探器
        sniffer_thread = self.start_sniffer()
        time.sleep(1)  # 等待嗅探器启动
        
        try:
            # 按端口批次扫描: 先扫描所有IP的端口1,再扫描端口2...
            for port in self.ports:
                self.scan_port_batch(ips, port)
        finally:
            # 停止嗅探
            self.stop_sniffing.set()
            logger.info("正在停止嗅探器...")
        
        # 扫描完成后,写入剩余的结果
        with self.buffer_lock:
            self.flush_buffer()
        
        # 合并结果
        self.merge_results()
        
        # 计算总耗时
        total_time = time.time() - start_time
        hours = int(total_time // 3600)
        minutes = int((total_time % 3600) // 60)
        seconds = int(total_time % 60)
        
        logger.info("=" * 60)
        logger.info("扫描任务完成!")
        logger.info(f"总共扫描: {self.scanned_count:,} 次")
        logger.info(f"总耗时: {hours}小时 {minutes}分钟 {seconds}秒")
        if total_time > 0:
            logger.info(f"平均速度: {self.scanned_count/total_time:.0f} 次/秒")
        logger.info(f"结果已保存到: {self.output_csv}")
        logger.info("=" * 60)


def main():
    """主函数"""
    # 检查是否有root权限
    if os.geteuid() != 0:
        print("错误: SYN扫描需要root权限")
        print("请使用 sudo 运行此脚本:")
        print(f"  sudo python3 {sys.argv[0]}")
        sys.exit(1)
    
    # 获取脚本所在目录
    script_dir = Path(__file__).parent
    
    # 配置日志 - 保存到脚本所在目录
    log_file = script_dir / 'tcp_syn_scan.log'
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    
    # 设置输入输出文件路径
    input_csv = script_dir.parent.parent / 'Public_IOC' / 'all_res_combine' / 'recent_high_risk_ips.csv'
    
    # 创建data目录(如果不存在)
    data_dir = script_dir / 'data'
    data_dir.mkdir(exist_ok=True)
    
    output_csv = data_dir / 'scan_results.csv'
    
    logger.info(f"日志文件: {log_file}")
    
    # 检查输入文件是否存在
    if not input_csv.exists():
        logger.error(f"输入文件不存在: {input_csv}")
        sys.exit(1)
    
    # 创建扫描器并运行
    # pps=1000: 每秒发送1000个包 (可根据网络情况调整到5000+)
    # batch_size=1000: 每扫描1000个开放端口写入一次
    # timeout=2.0: 等待响应2秒
    scanner = FastSYNScanner(
        input_csv=str(input_csv),
        output_csv=str(output_csv),
        pps=1000,
        batch_size=1000,
        timeout=2.0
    )
    
    scanner.run()


if __name__ == '__main__':
    main()
