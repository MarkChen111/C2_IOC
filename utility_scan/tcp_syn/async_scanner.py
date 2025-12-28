#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
超高性能异步TCP SYN扫描脚本
使用asyncio + 原始socket实现，性能极致
按端口批次扫描: 先扫描所有IP的某个端口,再扫描下一个端口
需要root权限运行
"""

import csv
import os
import sys
from pathlib import Path
import time
import logging
from collections import defaultdict
import socket
import struct
import random
import asyncio

# 日志将在main函数中配置
logger = logging.getLogger(__name__)


class AsyncRawSocketScanner:
    def __init__(self, input_csv, output_csv, concurrency=10000, batch_size=100, timeout=2.0):
        """
        初始化扫描器
        
        Args:
            input_csv: 输入CSV文件路径
            output_csv: 输出CSV文件路径
            concurrency: 异步并发数
            batch_size: 批量写入大小
            timeout: 等待响应超时时间(秒)
        """
        self.input_csv = input_csv
        self.output_csv = output_csv
        self.concurrency = concurrency
        self.batch_size = batch_size
        self.timeout = timeout
        
        # 中间结果文件
        self.temp_results_file = Path(output_csv).parent / 'temp_scan_results.csv'
        
        self.scanned_count = 0
        self.total_count = 0
        self.results_buffer = []
        
        # 端口列表
        self.ports = list(range(1, 65536))
        
        # 响应收集
        self.current_port = None
        self.current_open_ips = set()
        
        # socket
        self.send_socket = None
        self.recv_socket = None
        self.stop_receiving = False
        
    def read_ips_from_csv(self):
        """从CSV文件读取IP并去重"""
        ips = set()
        try:
            with open(self.input_csv, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f, delimiter='\t')
                for row in reader:
                    ip = row.get('ip', '').strip()
                    if ip and ip != 'ip':
                        ips.add(ip)
            logger.info(f"从CSV文件读取到 {len(ips)} 个唯一IP地址")
            return sorted(list(ips))
        except Exception as e:
            logger.error(f"读取CSV文件失败: {e}")
            return []
    
    def checksum(self, data):
        """计算校验和"""
        if len(data) % 2 != 0:
            data += b'\x00'
        s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff
    
    def create_syn_packet(self, src_ip, dst_ip, dst_port):
        """创建TCP SYN包"""
        # TCP头部
        src_port = random.randint(10000, 65535)
        seq = random.randint(0, 0xffffffff)
        ack_seq = 0
        doff = 5
        flags = 0x02  # SYN
        window = socket.htons(5840)
        check = 0
        urg_ptr = 0
        
        # TCP伪头部
        src_addr = socket.inet_aton(src_ip)
        dst_addr = socket.inet_aton(dst_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = 20
        
        pseudo_header = struct.pack('!4s4sBBH', src_addr, dst_addr, placeholder, protocol, tcp_length)
        
        tcp_header = struct.pack('!HHLLBBHHH',
                                src_port, dst_port, seq, ack_seq,
                                (doff << 4), flags, window, check, urg_ptr)
        
        check = self.checksum(pseudo_header + tcp_header)
        tcp_header = struct.pack('!HHLLBBH',
                                src_port, dst_port, seq, ack_seq,
                                (doff << 4), flags, window) + struct.pack('H', check) + struct.pack('!H', urg_ptr)
        
        # IP头部
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 40
        ip_id = random.randint(0, 65535)
        ip_frag_off = 0
        ip_ttl = 64
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0
        
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        ip_header = struct.pack('!BBHHHBBH4s4s',
                               ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
                               ip_ttl, ip_proto, ip_check, src_addr, dst_addr)
        
        ip_check = self.checksum(ip_header)
        ip_header = struct.pack('!BBHHHBB',
                               ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
                               ip_ttl, ip_proto) + struct.pack('H', ip_check) + struct.pack('!4s4s', src_addr, dst_addr)
        
        return ip_header + tcp_header
    
    def get_local_ip(self):
        """获取本机IP地址"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    async def send_syn(self, dst_ip, dst_port, src_ip):
        """异步发送SYN包"""
        try:
            packet = self.create_syn_packet(src_ip, dst_ip, dst_port)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self.send_socket.sendto, packet, (dst_ip, 0))
        except Exception as e:
            pass
    
    async def receive_responses(self):
        """异步接收响应"""
        loop = asyncio.get_event_loop()
        
        while not self.stop_receiving:
            try:
                # 在线程池中执行阻塞的recv操作
                data, addr = await loop.run_in_executor(
                    None,
                    lambda: self.recv_socket.recvfrom(65535)
                )
                
                # 解析响应
                if len(data) < 40:
                    continue
                
                # 解析IP头部
                ip_header = data[0:20]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                protocol = iph[6]
                src_ip = socket.inet_ntoa(iph[8])
                
                if protocol != 6:  # 只处理TCP
                    continue
                
                # 解析TCP头部
                tcp_header = data[20:40]
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                src_port = tcph[0]
                flags = tcph[5]
                
                # 检查SYN-ACK
                if (flags & 0x12) == 0x12:
                    if self.current_port and src_port == self.current_port:
                        self.current_open_ips.add(src_ip)
            
            except Exception as e:
                await asyncio.sleep(0.001)
    
    async def add_result_to_buffer(self, ip, port):
        """添加结果到缓冲区"""
        self.results_buffer.append((ip, port))
        if len(self.results_buffer) >= self.batch_size:
            await self.flush_buffer()
    
    async def flush_buffer(self):
        """批量写入文件"""
        if not self.results_buffer:
            return
        
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._flush_buffer_sync)
        except Exception as e:
            logger.error(f"写入文件失败: {e}")
    
    def _flush_buffer_sync(self):
        """同步写入文件"""
        try:
            file_exists = os.path.exists(self.temp_results_file)
            with open(self.temp_results_file, 'a', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(['ip', 'port'])
                for ip, port in self.results_buffer:
                    writer.writerow([ip, port])
            logger.info(f"已批量写入 {len(self.results_buffer)} 条扫描结果")
            self.results_buffer.clear()
        except Exception as e:
            logger.error(f"写入失败: {e}")
    
    async def scan_port_batch(self, ips, port, src_ip):
        """异步扫描所有IP的某个端口"""
        logger.info(f"开始扫描端口 {port} (共 {len(ips)} 个IP)")
        start_time = time.time()
        
        # 设置当前端口并清空结果
        self.current_port = port
        self.current_open_ips.clear()
        
        # 创建信号量控制并发
        semaphore = asyncio.Semaphore(self.concurrency)
        
        async def send_with_semaphore(ip):
            async with semaphore:
                await self.send_syn(ip, port, src_ip)
        
        # 并发发送所有SYN包
        tasks = [send_with_semaphore(ip) for ip in ips]
        await asyncio.gather(*tasks)
        
        # 等待响应
        await asyncio.sleep(self.timeout)
        
        # 处理结果
        open_ips = self.current_open_ips.copy()
        for ip in open_ips:
            await self.add_result_to_buffer(ip, port)
        
        open_count = len(open_ips)
        self.scanned_count += len(ips)
        elapsed = time.time() - start_time
        
        logger.info(f"端口 {port} 扫描完成 - 发现 {open_count} 个开放 - 耗时 {elapsed:.1f}秒 - "
                   f"进度: {self.scanned_count}/{self.total_count} ({self.scanned_count*100/self.total_count:.1f}%)")
    
    def merge_results(self):
        """合并临时结果文件"""
        logger.info("开始合并扫描结果...")
        if not os.path.exists(self.temp_results_file):
            logger.warning("临时结果文件不存在")
            return
        
        ip_ports = defaultdict(set)
        try:
            with open(self.temp_results_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    ip = row['ip']
                    port = int(row['port'])
                    ip_ports[ip].add(port)
            
            logger.info(f"读取到 {len(ip_ports)} 个IP的扫描结果")
            
            with open(self.output_csv, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ip', 'ports_set'])
                for ip in sorted(ip_ports.keys()):
                    ports = sorted(ip_ports[ip], reverse=True)
                    ports_str = ','.join(map(str, ports))
                    writer.writerow([ip, ports_str])
            
            logger.info(f"结果已合并到: {self.output_csv}")
            os.remove(self.temp_results_file)
            logger.info("临时文件已删除")
        except Exception as e:
            logger.error(f"合并结果失败: {e}")
    
    async def run_async(self):
        """异步执行扫描任务"""
        logger.info("=" * 60)
        logger.info("开始超高性能异步TCP SYN扫描")
        logger.info(f"输入文件: {self.input_csv}")
        logger.info(f"输出文件: {self.output_csv}")
        logger.info(f"并发数: {self.concurrency}")
        logger.info("=" * 60)
        
        ips = self.read_ips_from_csv()
        if not ips:
            logger.error("没有找到有效的IP地址")
            return
        
        self.total_count = len(ips) * len(self.ports)
        start_time = time.time()
        
        logger.info(f"待扫描: {len(ips)} 个IP × {len(self.ports)} 个端口 = {self.total_count:,} 次")
        
        if os.path.exists(self.temp_results_file):
            os.remove(self.temp_results_file)
        
        # 获取本机IP
        src_ip = self.get_local_ip()
        logger.info(f"本机IP: {src_ip}")
        
        # 创建原始socket
        try:
            self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.recv_socket.settimeout(0.1)
            logger.info("原始socket创建成功")
        except PermissionError:
            logger.error("需要root权限创建原始socket")
            return
        
        # 启动接收任务
        recv_task = asyncio.create_task(self.receive_responses())
        logger.info("接收任务已启动")
        
        try:
            # 按端口批次扫描
            for port in self.ports:
                await self.scan_port_batch(ips, port, src_ip)
        finally:
            self.stop_receiving = True
            await asyncio.sleep(0.5)
            recv_task.cancel()
            try:
                await recv_task
            except asyncio.CancelledError:
                pass
            self.send_socket.close()
            self.recv_socket.close()
        
        if self.results_buffer:
            await self.flush_buffer()
        
        self.merge_results()
        
        total_time = time.time() - start_time
        hours = int(total_time // 3600)
        minutes = int((total_time % 3600) // 60)
        seconds = int(total_time % 60)
        
        logger.info("=" * 60)
        logger.info("扫描任务完成!")
        logger.info(f"总耗时: {hours}小时 {minutes}分钟 {seconds}秒")
        if total_time > 0:
            logger.info(f"平均速度: {self.scanned_count/total_time:.0f} 次/秒")
        logger.info(f"结果已保存到: {self.output_csv}")
        logger.info("=" * 60)
    
    def run(self):
        """运行扫描器"""
        asyncio.run(self.run_async())


def main():
    """主函数"""
    if os.geteuid() != 0:
        print("错误: 需要root权限")
        print(f"请使用: sudo python3 {sys.argv[0]}")
        sys.exit(1)
    
    script_dir = Path(__file__).parent
    log_file = script_dir / 'async_tcp_syn_scan.log'
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    
    input_csv = script_dir.parent.parent / 'Public_IOC' / 'all_res_combine' / 'recent_high_risk_ips.csv'
    data_dir = script_dir / 'data'
    data_dir.mkdir(exist_ok=True)
    output_csv = data_dir / 'scan_results.csv'
    
    logger.info(f"日志文件: {log_file}")
    
    if not input_csv.exists():
        logger.error(f"输入文件不存在: {input_csv}")
        sys.exit(1)
    
    # concurrency=10000: 10000个异步并发
    # batch_size=100: 批量写入100条
    # timeout=2.0: 等待2秒
    scanner = AsyncRawSocketScanner(
        input_csv=str(input_csv),
        output_csv=str(output_csv),
        concurrency=10000,
        batch_size=100,
        timeout=2.0
    )
    
    scanner.run()


if __name__ == '__main__':
    main()

