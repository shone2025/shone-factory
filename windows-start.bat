@echo off
chcp 65001 >nul
cd /d "%~dp0"

REM Check Python and run launcher
where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    python launcher.py
    goto :end
)

where python3 >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    python3 launcher.py
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
