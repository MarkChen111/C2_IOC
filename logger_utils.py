#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一日志工具模块

提供全局的日志记录功能，所有脚本共享同一个日志文件
"""

import os
import logging
from datetime import datetime

# 日志文件路径（项目根目录下的 logs/ioc_collection.log）
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(SCRIPT_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "ioc_collection.log")

# 创建全局logger
_logger = None


def get_logger(name="IOC_COLLECTOR"):
    """获取全局日志记录器"""
    global _logger
    
    if _logger is not None:
        return _logger
    
    # 创建logger
    _logger = logging.getLogger(name)
    _logger.setLevel(logging.INFO)
    
    # 避免重复添加handler
    if _logger.handlers:
        return _logger
    
    # 创建文件handler
    file_handler = logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    
    # 创建控制台handler（可选，用于调试）
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # 创建formatter
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # 添加handler
    _logger.addHandler(file_handler)
    _logger.addHandler(console_handler)
    
    return _logger


def log_data_collection(source_name, status, record_count=0, error_msg=""):
    """
    记录数据采集情况
    
    Args:
        source_name: 数据源名称
        status: 状态（success/failed）
        record_count: 采集到的记录数
        error_msg: 错误信息（如果有）
    """
    logger = get_logger()
    
    if status == "success":
        logger.info(f"[{source_name}] 采集成功 - 获取 {record_count} 条记录")
    else:
        logger.error(f"[{source_name}] 采集失败 - {error_msg}")


def log_data_merge(total_records, unique_ips, source_count, history_count, recent_count, source_stats):
    """
    记录数据合并情况
    
    Args:
        total_records: 总记录数
        unique_ips: 唯一IP数
        source_count: 数据源数量
        history_count: history.csv记录数
        recent_count: recent.csv记录数
        source_stats: 各数据源贡献统计 {source: count}
    """
    logger = get_logger()
    
    logger.info("=" * 60)
    logger.info("数据合并统计")
    logger.info("-" * 60)
    logger.info(f"总记录数: {total_records:,}")
    logger.info(f"唯一IP数: {unique_ips:,}")
    logger.info(f"数据源数: {source_count}")
    logger.info(f"history.csv: {history_count:,} 条")
    logger.info(f"recent.csv: {recent_count:,} 条")
    logger.info("-" * 60)
    logger.info("各数据源贡献:")
    
    # 按数量排序
    for source, count in sorted(source_stats.items(), key=lambda x: x[1], reverse=True):
        logger.info(f"  {source}: {count:,}")
    
    logger.info("=" * 60)


def log_separator():
    """记录分隔线"""
    logger = get_logger()
    logger.info("")


if __name__ == "__main__":
    # 测试
    logger = get_logger()
    logger.info("日志系统测试")
    log_data_collection("test_source", "success", 100)
    log_data_collection("test_source2", "failed", 0, "Network timeout")
    
    source_stats = {
        "source1": 1000,
        "source2": 500,
        "source3": 300
    }
    log_data_merge(1800, 1500, 3, 1800, 1500, source_stats)

