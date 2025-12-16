#!/bin/bash
# ShoneFactory Token Key - macOS 启动脚本

cd "$(dirname "$0")"

PORT=8765

# 检查并释放端口
check_and_kill_port() {
    PID=$(lsof -ti:$PORT 2>/dev/null)
    if [ -n "$PID" ]; then
        echo "  端口 $PORT 被占用，正在释放..."
        kill -9 $PID 2>/dev/null
        sleep 1
        echo "  端口已释放"
    fi
}

# 检测 Python
if command -v python3 &> /dev/null; then
    check_and_kill_port
    python3 shone_client_web.py
elif command -v python &> /dev/null; then
    check_and_kill_port
    python shone_client_web.py
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
