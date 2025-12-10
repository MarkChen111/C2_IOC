#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
日志包装器

为数据采集脚本提供简单的日志包装功能
只需在脚本最后添加几行代码即可自动记录日志
"""

import os
import sys
from logger_utils import log_data_collection


def wrap_collection_script(source_name, main_func):
    """
    包装数据采集脚本
    
    使用方法:
    ```python
    # 在你的code.py末尾添加：
    if __name__ == "__main__":
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
        from logger_wrapper import wrap_collection_script
        
        wrap_collection_script("source_name", main)
    ```
    
    Args:
        source_name: 数据源名称
        main_func: 主函数，应该返回采集到的记录数
    """
    try:
        # 执行主函数
        count = main_func()
        
        # 记录成功
        log_data_collection(source_name, "success", count if count else 0)
        
        return 0
        
    except Exception as e:
        # 记录失败
        error_msg = str(e)
        log_data_collection(source_name, "failed", 0, error_msg)
        print(f"[-] 错误: {error_msg}")
        
        return 1


def log_collection(source_name):
    """
    装饰器版本的日志记录
    
    使用方法:
    ```python
    from logger_wrapper import log_collection
    
    @log_collection("source_name")
    def main():
        # 你的代码
        count = 100  # 采集到的记录数
        return count
    ```
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                count = func(*args, **kwargs)
                log_data_collection(source_name, "success", count if count else 0)
                return count
            except Exception as e:
                error_msg = str(e)
                log_data_collection(source_name, "failed", 0, error_msg)
                print(f"[-] 错误: {error_msg}")
                raise
        return wrapper
    return decorator

