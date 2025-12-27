#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nmap全端口TCP扫描脚本
用于扫描CSV文件中的所有IP地址的全端口(1-65535)
"""

import csv
import subprocess
import json
import os
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import time
import logging
import threading

# 日志将在main函数中配置
logger = logging.getLogger(__name__)


class NmapScanner:
    def __init__(self, input_csv, output_csv, max_workers=4, batch_size=100):
        """
        初始化扫描器
        
        Args:
            input_csv: 输入CSV文件路径
            output_csv: 输出CSV文件路径
            max_workers: 并发扫描线程数
            batch_size: 批量写入大小,每扫描多少个IP写入一次
        """
        self.input_csv = input_csv
        self.output_csv = output_csv
        self.max_workers = max_workers
        self.batch_size = batch_size
        self.scanned_count = 0
        self.total_count = 0
        self.results_buffer = []  # 结果缓冲区
        self.buffer_lock = threading.Lock()  # 缓冲区锁
        
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
    
    def scan_ip(self, ip, scan_date):
        """
        使用nmap扫描单个IP的全端口
        
        Args:
            ip: 要扫描的IP地址
            scan_date: 扫描日期
            
        Returns:
            tuple: (ip, ports_list, scan_date) 或 (ip, [], scan_date) 如果扫描失败
        """
        try:
            # nmap参数说明:
            # -p-: 扫描所有端口(1-65535)
            # -sT: TCP连接扫描(不需要root权限)
            # -T3: 时序模板(0-5,3是默认值,平衡速度和准确性)
            # --max-retries 1: 最多重试1次
            # --host-timeout 5m: 单个主机超时时间5分钟
            # --min-rate 100: 最小发包速率100包/秒
            # --max-rate 300: 最大发包速率300包/秒
            # -oX -: 输出XML格式到标准输出
            # --open: 只显示开放的端口
            
            cmd = [
                'nmap',
                '-p-',              # 全端口扫描
                '-sT',              # TCP连接扫描
                '-T3',              # 时序模板3(正常速度)
                '--max-retries', '1',  # 最多重试1次
                '--host-timeout', '5m',  # 单主机超时5分钟
                '--min-rate', '100',     # 最小速率
                '--max-rate', '300',     # 最大速率
                '-oX', '-',         # XML输出到标准输出
                '--open',           # 只显示开放端口
                ip
            ]
            
            logger.info(f"[{scan_date}] 开始扫描 {ip}")
            start_time = time.time()
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=360  # 6分钟超时
            )
            
            elapsed = time.time() - start_time
            
            # 解析nmap XML输出
            ports = self.parse_nmap_output(result.stdout)
            
            self.scanned_count += 1
            progress = (self.scanned_count / self.total_count) * 100
            
            if ports:
                logger.info(f"[{scan_date}] [{self.scanned_count}/{self.total_count}] {ip} 扫描完成 "
                          f"({progress:.1f}%) - 发现 {len(ports)} 个开放端口 - "
                          f"耗时 {elapsed:.1f}秒")
            else:
                logger.info(f"[{scan_date}] [{self.scanned_count}/{self.total_count}] {ip} 扫描完成 "
                          f"({progress:.1f}%) - 无开放端口 - 耗时 {elapsed:.1f}秒")
            
            return (ip, ports, scan_date)
        
        except subprocess.TimeoutExpired:
            logger.warning(f"[{scan_date}] 扫描 {ip} 超时")
            self.scanned_count += 1
            return (ip, [], scan_date)
        
        except Exception as e:
            logger.error(f"[{scan_date}] 扫描 {ip} 失败: {e}")
            self.scanned_count += 1
            return (ip, [], scan_date)
    
    def parse_nmap_output(self, xml_output):
        """
        解析nmap的XML输出,提取开放的端口
        
        Args:
            xml_output: nmap的XML格式输出
            
        Returns:
            list: 端口号列表,从大到小排序
        """
        ports = []
        
        try:
            # 简单的XML解析,提取端口号
            import re
            # 匹配 <port protocol="tcp" portid="端口号"><state state="open"
            pattern = r'<port protocol="tcp" portid="(\d+)">.*?<state state="open"'
            matches = re.findall(pattern, xml_output, re.DOTALL)
            
            ports = [int(port) for port in matches]
            # 从大到小排序
            ports.sort(reverse=True)
        
        except Exception as e:
            logger.error(f"解析nmap输出失败: {e}")
        
        return ports
    
    def add_result_to_buffer(self, ip, ports, scan_date):
        """
        将扫描结果添加到缓冲区
        
        Args:
            ip: IP地址
            ports: 端口列表
            scan_date: 扫描日期
        """
        with self.buffer_lock:
            self.results_buffer.append((ip, ports, scan_date))
            
            # 如果缓冲区达到批量大小,写入文件
            if len(self.results_buffer) >= self.batch_size:
                self.flush_buffer()
    
    def flush_buffer(self):
        """
        将缓冲区的结果批量写入CSV文件
        注意: 调用此方法前应该已经获取了buffer_lock
        """
        if not self.results_buffer:
            return
        
        try:
            # 追加写入CSV文件
            file_exists = os.path.exists(self.output_csv)
            
            with open(self.output_csv, 'a', encoding='utf-8', newline='') as f:
                writer = csv.writer(f, delimiter='\t', quoting=csv.QUOTE_NONE, escapechar='\\')
                
                # 如果文件不存在,写入标题行
                if not file_exists:
                    writer.writerow(['ip', 'ports', 'scan_date'])
                
                # 批量写入所有结果
                for ip, ports, scan_date in self.results_buffer:
                    ports_str = ','.join(map(str, ports)) if ports else ''
                    writer.writerow([ip, ports_str, scan_date])
            
            logger.info(f"已批量写入 {len(self.results_buffer)} 条扫描结果到文件")
            self.results_buffer.clear()
        
        except Exception as e:
            logger.error(f"批量保存结果失败: {e}")
    
    def run(self):
        """
        执行扫描任务
        """
        # 获取当前日期 (年-月-日格式)
        scan_date = datetime.now().strftime('%Y-%m-%d')
        
        logger.info("=" * 60)
        logger.info("开始Nmap全端口扫描任务")
        logger.info(f"扫描日期: {scan_date}")
        logger.info(f"输入文件: {self.input_csv}")
        logger.info(f"输出文件: {self.output_csv}")
        logger.info(f"并发数: {self.max_workers}")
        logger.info("=" * 60)
        
        # 读取IP列表
        ips = self.read_ips_from_csv()
        
        if not ips:
            logger.error("没有找到有效的IP地址")
            return
        
        self.total_count = len(ips)
        start_time = time.time()
        
        # 如果输出文件已存在,读取已扫描的IP
        scanned_ips = set()
        if os.path.exists(self.output_csv):
            try:
                with open(self.output_csv, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f, delimiter='\t')
                    for row in reader:
                        scanned_ips.add(row['ip'])
                logger.info(f"发现已扫描的IP: {len(scanned_ips)} 个,将跳过")
            except Exception as e:
                logger.warning(f"读取已扫描结果失败: {e}")
        
        # 过滤掉已扫描的IP
        ips_to_scan = [ip for ip in ips if ip not in scanned_ips]
        
        if not ips_to_scan:
            logger.info("所有IP已扫描完成")
            return
        
        logger.info(f"待扫描IP数量: {len(ips_to_scan)}")
        self.total_count = len(ips_to_scan)
        
        # 使用线程池并发扫描
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 提交所有扫描任务
            future_to_ip = {executor.submit(self.scan_ip, ip, scan_date): ip 
                          for ip in ips_to_scan}
            
            # 处理完成的任务
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result_ip, ports, result_scan_date = future.result()
                    # 添加到缓冲区(每100个自动写入)
                    self.add_result_to_buffer(result_ip, ports, result_scan_date)
                except Exception as e:
                    logger.error(f"处理 {ip} 的结果时出错: {e}")
        
        # 扫描完成后,写入剩余的结果
        with self.buffer_lock:
            self.flush_buffer()
        
        # 计算总耗时
        total_time = time.time() - start_time
        hours = int(total_time // 3600)
        minutes = int((total_time % 3600) // 60)
        seconds = int(total_time % 60)
        
        logger.info("=" * 60)
        logger.info(f"扫描任务完成! (扫描日期: {scan_date})")
        logger.info(f"总共扫描: {self.scanned_count} 个IP")
        logger.info(f"总耗时: {hours}小时 {minutes}分钟 {seconds}秒")
        logger.info(f"平均每个IP耗时: {total_time/self.scanned_count:.1f}秒")
        logger.info(f"结果已保存到: {self.output_csv}")
        logger.info("=" * 60)


def main():
    """主函数"""
    # 获取脚本所在目录
    script_dir = Path(__file__).parent
    
    # 配置日志 - 保存到脚本所在目录
    log_file = script_dir / 'nmap_scan.log'
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
    
    # 检查nmap是否安装
    try:
        subprocess.run(['nmap', '--version'], 
                      capture_output=True, 
                      check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.error("nmap未安装或不在PATH中,请先安装nmap")
        logger.error("macOS: brew install nmap")
        logger.error("Ubuntu/Debian: sudo apt-get install nmap")
        logger.error("CentOS/RHEL: sudo yum install nmap")
        sys.exit(1)
    
    # 创建扫描器并运行
    # max_workers=4: 4个并发线程,匹配你的4核CPU
    # batch_size=100: 每扫描100个IP写入一次
    scanner = NmapScanner(
        input_csv=str(input_csv),
        output_csv=str(output_csv),
        max_workers=4,
        batch_size=100
    )
    
    scanner.run()


if __name__ == '__main__':
    main()
