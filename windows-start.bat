@echo off
chcp 65001 >nul
cd /d "%~dp0"

set PORT=8765

REM Check and kill process on port
echo   检查端口 %PORT%...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%PORT%" ^| findstr "LISTENING"') do (
    echo   端口 %PORT% 被占用，正在释放...
    taskkill /F /PID %%a >nul 2>nul
    timeout /t 1 >nul
    echo   端口已释放
)

REM Check Python and run
where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    python shone_client_web.py
    goto :end
)

where python3 >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    python3 shone_client_web.py
    goto :end
)

echo ========================================
echo   ShoneFactory Token Key
echo ========================================
echo.
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
