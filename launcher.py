#!/usr/bin/env python3
"""
ShoneFactory Token Key - 启动引导程序
检测环境并启动主程序
"""

import os
import sys
import subprocess
import platform

def get_os_type():
    """获取操作系统类型"""
    system = platform.system()
    if system == "Windows":
        return "windows"
    elif system == "Darwin":
        return "macos"
    elif system == "Linux":
        return "linux"
    return "unknown"

def check_python():
    """检测 Python 环境"""
    try:
        version = sys.version_info
        if version.major >= 3 and version.minor >= 8:
            return True, f"Python {version.major}.{version.minor}.{version.micro}"
        return False, f"Python 版本过低: {version.major}.{version.minor}"
    except:
        return False, "未检测到 Python"

def check_tkinter():
    """检测 Tkinter/Tcl 兼容性（macOS 专用）"""
    if platform.system() != "Darwin":
        return True, "非 macOS 系统"

    # 使用子进程检测，避免主进程崩溃
    test_code = '''
import sys
try:
    import tkinter as tk
    root = tk.Tk()
    root.withdraw()
    tcl_version = root.tk.call('info', 'patchlevel')
    root.destroy()
    print(f"OK:{tcl_version}")
    sys.exit(0)
except Exception as e:
    print(f"ERROR:{e}")
    sys.exit(1)
'''
    try:
        result = subprocess.run(
            [sys.executable, '-c', test_code],
            capture_output=True,
            text=True,
            timeout=10
        )
        output = result.stdout.strip() + result.stderr.strip()

        if result.returncode == 0 and output.startswith("OK:"):
            tcl_version = output.split(":", 1)[1]
            return True, f"Tcl/Tk {tcl_version}"
        elif "macOS" in output and "required" in output:
            return False, "Tcl/Tk 版本与 macOS 不兼容"
        elif result.returncode != 0:
            # 检查是否是 Abort trap（C 层面崩溃）
            if result.returncode in [-6, 134]:  # SIGABRT
                return False, "Tcl/Tk 版本与 macOS 不兼容"
            return False, f"Tkinter 检测失败 (退出码: {result.returncode})"
        return True, "Tkinter 可用"
    except subprocess.TimeoutExpired:
        return False, "Tkinter 检测超时"
    except Exception as e:
        return False, f"检测错误: {e}"

def check_factory():
    """检测 Factory 安装"""
    os_type = get_os_type()
    
    if os_type == "windows":
        factory_path = os.path.join(os.environ.get('USERPROFILE', ''), '.factory')
    else:
        factory_path = os.path.expanduser('~/.factory')
    
    if os.path.exists(factory_path):
        return True, factory_path
    
    # 检测 droid 命令是否可用
    try:
        result = subprocess.run(['droid', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return True, factory_path
    except:
        pass
    
    return False, factory_path

def get_install_commands():
    """获取安装命令"""
    os_type = get_os_type()
    
    commands = {
        "python": {
            "windows": [
                "# 方法1: 使用 winget (推荐)",
                "winget install Python.Python.3.11",
                "",
                "# 方法2: 下载安装包",
                "# 访问 https://www.python.org/downloads/windows/"
            ],
            "macos": [
                "# 方法1: 使用 Homebrew (推荐)",
                "brew install python@3.11",
                "",
                "# 方法2: 下载安装包",
                "# 访问 https://www.python.org/downloads/macos/"
            ],
            "linux": [
                "# Ubuntu/Debian",
                "sudo apt update && sudo apt install python3 python3-tk",
                "",
                "# CentOS/RHEL",
                "sudo yum install python3 python3-tkinter",
                "",
                "# Arch Linux",
                "sudo pacman -S python python-tk"
            ]
        },
        "factory": {
            "windows": [
                "# 使用 npm 安装 (需要 Node.js)",
                "npm install -g @anthropic/droid",
                "",
                "# 或下载安装包",
                "# 访问 https://factory.ai/download"
            ],
            "macos": [
                "# 方法1: 使用 Homebrew",
                "brew install factory",
                "",
                "# 方法2: 使用 npm",
                "npm install -g @anthropic/droid",
                "",
                "# 方法3: 下载安装包",
                "# 访问 https://factory.ai/download"
            ],
            "linux": [
                "# 使用 npm 安装",
                "npm install -g @anthropic/droid",
                "",
                "# 或下载安装包",
                "# 访问 https://factory.ai/download"
            ]
        }
    }
    
    return commands.get("python", {}).get(os_type, []), commands.get("factory", {}).get(os_type, [])

def print_header():
    """打印标题"""
    print("=" * 60)
    print("  ShoneFactory Token Key - 环境检测")
    print("=" * 60)
    print()

def print_status(name, ok, message):
    """打印状态"""
    status = "✓" if ok else "✗"
    color_ok = "\033[92m" if ok else "\033[91m"
    color_reset = "\033[0m"
    
    # Windows 终端可能不支持 ANSI 颜色
    if platform.system() == "Windows":
        print(f"  [{status}] {name}: {message}")
    else:
        print(f"  [{color_ok}{status}{color_reset}] {name}: {message}")

def main():
    print_header()

    os_type = get_os_type()
    print(f"  操作系统: {platform.system()} ({os_type})")
    print()

    # 检测 Python
    python_ok, python_msg = check_python()
    print_status("Python", python_ok, python_msg)

    # 检测 Factory
    factory_ok, factory_path = check_factory()
    factory_msg = f"已安装 ({factory_path})" if factory_ok else "未检测到"
    print_status("Factory", factory_ok, factory_msg)

    print()

    # 获取安装命令
    python_cmds, factory_cmds = get_install_commands()

    if not python_ok:
        print("-" * 60)
        print("  Python 安装方法:")
        print("-" * 60)
        for cmd in python_cmds:
            print(f"  {cmd}")
        print()

    if not factory_ok:
        print("-" * 60)
        print("  Factory 安装方法:")
        print("-" * 60)
        for cmd in factory_cmds:
            print(f"  {cmd}")
        print()

    if python_ok and factory_ok:
        print("-" * 60)
        print("  ✓ 环境检测通过，正在启动 Web 版程序...")
        print("-" * 60)
        print()

        # 启动 Web 版主程序
        script_dir = os.path.dirname(os.path.abspath(__file__))
        main_script = os.path.join(script_dir, 'shone_client_web.py')

        if os.path.exists(main_script):
            os.execv(sys.executable, [sys.executable, main_script])
        else:
            print(f"  错误: 找不到主程序 {main_script}")
            return 1
    else:
        print("-" * 60)
        print("  请先安装缺失的组件，然后重新运行此程序")
        print("-" * 60)
        try:
            input("\n  按 Enter 键退出...")
        except EOFError:
            pass  # 非交互模式下忽略
        return 1

    return 0

if __name__ == '__main__':
    sys.exit(main())
