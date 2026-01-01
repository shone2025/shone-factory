#!/usr/bin/env python3
"""
ShoneFactory Token Key - 启动引导程序
检测环境、自动更新并启动主程序
"""

import os
import sys
import subprocess
import platform
import json
import ssl
import urllib.request
import urllib.error
import shutil
from pathlib import Path

# 云端配置
_CLOUD_URL = "https://sfk.shonekey.top"
_CLIENT_KEY = "shone-factory-client-2024"
_LOCAL_VERSION = "3.3.9"  # 当前本地版本

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

def check_version():
    """检查云端版本"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # 不使用代理
        no_proxy_handler = urllib.request.ProxyHandler({})
        opener = urllib.request.build_opener(no_proxy_handler, urllib.request.HTTPSHandler(context=ctx))
        
        req = urllib.request.Request(
            f"{_CLOUD_URL}/api/version",
            headers={
                'User-Agent': 'ShoneFactory-Client/1.0',
                'Accept': 'application/json',
                'X-Client-Key': _CLIENT_KEY
            },
            method='GET'
        )
        
        with opener.open(req, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get('success') and data.get('version'):
                return data['version']
    except Exception as e:
        print(f"  [!] 版本检查失败: {e}")
    return None

def compare_versions(local, remote):
    """比较版本号，返回 True 表示需要更新"""
    try:
        local_parts = [int(x) for x in local.replace('v', '').split('.')]
        remote_parts = [int(x) for x in remote.replace('v', '').split('.')]
        
        # 补齐长度
        while len(local_parts) < 3:
            local_parts.append(0)
        while len(remote_parts) < 3:
            remote_parts.append(0)
        
        for i in range(3):
            if remote_parts[i] > local_parts[i]:
                return True
            elif remote_parts[i] < local_parts[i]:
                return False
        return False
    except:
        return False

def download_update():
    """从云端下载最新客户端代码"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        no_proxy_handler = urllib.request.ProxyHandler({})
        opener = urllib.request.build_opener(no_proxy_handler, urllib.request.HTTPSHandler(context=ctx))
        
        req = urllib.request.Request(
            f"{_CLOUD_URL}/api/download-client",
            headers={
                'User-Agent': 'ShoneFactory-Client/1.0',
                'Accept': 'application/json',
                'X-Client-Key': _CLIENT_KEY
            },
            method='GET'
        )
        
        with opener.open(req, timeout=30) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get('success') and data.get('code'):
                return data['code']
    except Exception as e:
        print(f"  [!] 下载更新失败: {e}")
    return None

def apply_update(code):
    """应用更新 - 替换 shone_client_web.py"""
    try:
        script_dir = Path(__file__).parent
        main_script = script_dir / 'shone_client_web.py'
        backup_script = script_dir / 'shone_client_web.py.bak'
        
        # 备份旧版本
        if main_script.exists():
            if backup_script.exists():
                backup_script.unlink()
            shutil.copy(main_script, backup_script)
        
        # 写入新版本
        with open(main_script, 'w', encoding='utf-8') as f:
            f.write(code)
        
        return True
    except Exception as e:
        print(f"  [!] 应用更新失败: {e}")
        # 尝试恢复备份
        try:
            if backup_script.exists():
                shutil.copy(backup_script, main_script)
        except:
            pass
        return False

def auto_update():
    """自动更新流程"""
    print("  [*] 检查更新...")
    
    version_info = check_version()
    if not version_info:
        print("  [!] 无法获取版本信息，跳过更新检查")
        return False
    
    remote_version = version_info.get('current', version_info.get('latest', '0.0.0'))
    
    if compare_versions(_LOCAL_VERSION, remote_version):
        print(f"  [*] 发现新版本: {_LOCAL_VERSION} -> {remote_version}")
        print("  [*] 正在下载更新...")
        
        code = download_update()
        if code:
            print("  [*] 正在应用更新...")
            if apply_update(code):
                print(f"  [✓] 更新成功！已升级到 v{remote_version}")
                return True
            else:
                print("  [!] 更新失败，将使用当前版本")
        else:
            print("  [!] 下载失败，将使用当前版本")
    else:
        print(f"  [✓] 当前已是最新版本 (v{_LOCAL_VERSION})")
    
    return False

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
        # 自动更新检查
        print("-" * 60)
        auto_update()
        print("-" * 60)
        print()
        
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
