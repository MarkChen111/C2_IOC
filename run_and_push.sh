#!/bin/bash

cd /home/chenxu/C2_IOC/ || exit 1

# 拉取最新代码（可选，如果你的脚本会修改代码本身）
git pull origin main  # 或 master，根据你的默认分支调整

# 运行 Python 脚本
/usr/bin/python3 run_daily_update.py

# 添加所有变更（包括新生成的文件）
git add .

# 提交（如果无变更，commit 会失败，但没关系）
git commit -m "[Auto] Daily update on $(date '+%Y-%m-%d %H:%M:%S')" || true

# 推送到远程仓库
git push origin main  # 同样注意分支名


