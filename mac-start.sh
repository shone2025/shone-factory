#!/bin/bash
# ShoneFactory Token Key - macOS 启动脚本

cd "$(dirname "$0")"

# 检测 Python
if command -v python3 &> /dev/null; then
    python3 launcher.py
elif command -v python &> /dev/null; then
    python launcher.py
else
    echo "========================================"
    echo "  ShoneFactory Token Key"
    echo "========================================"
    echo ""
    echo "  [错误] 未找到 Python"
    echo ""
    echo "  请先安装 Python 3.8+"
    echo ""
    echo "  安装方法:"
    echo "    brew install python@3.11"
    echo ""
    echo "  或访问: https://www.python.org/downloads/"
    echo ""
    read -p "  按 Enter 键退出..."
fi
