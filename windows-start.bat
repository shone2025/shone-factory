@echo off
chcp 65001 >nul
cd /d "%~dp0"
title SFK Token Manager - 请勿关闭此窗口

echo ========================================
echo   SFK Token Manager - Starting...
echo ========================================
echo.
color 0A
echo   重要提示: 请勿关闭此窗口!
echo   关闭窗口会导致账号无法自动刷新
echo ========================================
echo.
color 07

REM Check Python and run
where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo   服务运行中... 最小化窗口即可
    echo.
    python shone_client_web.py
    echo.
    color 0C
    echo   ========================================
    echo   [警告] 服务已停止!
    echo   账号可能无法自动刷新,请重新启动
    echo   ========================================
    color 07
    pause
    goto :end
)

where python3 >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo   服务运行中... 最小化窗口即可
    echo.
    python3 shone_client_web.py
    echo.
    color 0C
    echo   ========================================
    echo   [警告] 服务已停止!
    echo   账号可能无法自动刷新,请重新启动
    echo   ========================================
    color 07
    pause
    goto :end
)

echo   [ERROR] Python not found
echo.
echo   Please install Python 3.8+
echo.
echo   Method 1: winget install Python.Python.3.11
echo.
echo   Method 2: https://www.python.org/downloads/windows/
echo.
pause

:end
