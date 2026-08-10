#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CyberCure 数据源已停用。

原接口 https://api.cybercure.ai/ 长期不可用，本脚本不再发起任何网络请求。
保留此文件仅为目录结构兼容；每日任务已不再调度本数据源。
"""
import sys


def main():
    print("[*] CyberCure: 数据源已停用，跳过采集。")


if __name__ == "__main__":
    main()
    sys.exit(0)
