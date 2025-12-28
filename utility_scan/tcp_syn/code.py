#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高性能TCP端口扫描脚本
使用原始socket进行TCP连接扫描,大幅提高扫描速度
按端口批次扫描: 先扫描所有IP的某个端口,再扫描下一个端口
"""

import csv
import socket
import os
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import time
import logging
import threading
from collections import defaultdict

# 日志将在main函数中配置
logger = logging.getLogger(__name__)


class FastTCPScanner:
    def __init__(self, input_csv, output_csv, max_workers=500, batch_size=100, timeout=1.0):
        """
        初始化扫描器
        
        Args:
            input_csv: 输入CSV文件路径
            output_csv: 输出CSV文件路径 (最终结果: ip, ports_set)
            max_workers: 并发扫描线程数 (建议500-1000)
            batch_size: 批量写入大小,每扫描多少个结果写入一次
            timeout: 单个端口连接超时时间(秒)
        """
        self.input_csv = input_csv
        self.output_csv = output_csv
        self.max_workers = max_workers
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
    
    def scan_port(self, ip, port):
        """
        扫描单个IP的单个端口
        
        Args:
            ip: IP地址
            port: 端口号
            
        Returns:
            tuple: (ip, port) 如果端口开放, 否则返回 None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                return (ip, port)
            return None
        
        except socket.timeout:
            return None
        except socket.error:
            return None
        except Exception as e:
            return None
    
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
        open_count = 0
        
        # 使用线程池并发扫描
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 提交所有扫描任务
            future_to_ip = {executor.submit(self.scan_port, ip, port): ip 
                          for ip in ips}
            
            # 处理完成的任务
            for future in as_completed(future_to_ip):
                try:
                    result = future.result()
                    if result:  # 端口开放
                        ip, port = result
                        self.add_result_to_buffer(ip, port)
                        open_count += 1
                        self.scanned_count += 1
                except Exception as e:
                    pass
                
                self.scanned_count += 1
        
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
        logger.info("开始高性能TCP端口扫描任务")
        logger.info(f"输入文件: {self.input_csv}")
        logger.info(f"输出文件: {self.output_csv}")
        logger.info(f"并发数: {self.max_workers}")
        logger.info(f"超时时间: {self.timeout}秒")
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
        
        # 按端口批次扫描: 先扫描所有IP的端口1,再扫描端口2...
        for port in self.ports:
            self.scan_port_batch(ips, port)
        
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
        logger.info(f"平均速度: {self.scanned_count/total_time:.0f} 次/秒")
        logger.info(f"结果已保存到: {self.output_csv}")
        logger.info("=" * 60)


def main():
    """主函数"""
    # 获取脚本所在目录
    script_dir = Path(__file__).parent
    
    # 配置日志 - 保存到脚本所在目录
    log_file = script_dir / 'tcp_scan.log'
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
    # max_workers=500: 500个并发线程,大幅提高扫描速度
    # batch_size=100: 每扫描100个开放端口写入一次
    # timeout=1.0: 每个端口1秒超时
    scanner = FastTCPScanner(
        input_csv=str(input_csv),
        output_csv=str(output_csv),
        max_workers=500,
        batch_size=100,
        timeout=1.0
    )
    
    scanner.run()


if __name__ == '__main__':
    main()
