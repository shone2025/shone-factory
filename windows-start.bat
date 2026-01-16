@echo off
cd /d "%~dp0"
title SFK Token Manager - DO NOT CLOSE

echo ========================================
echo   SFK Token Manager - Starting...
echo ========================================
echo.
echo   IMPORTANT: DO NOT CLOSE THIS WINDOW!
echo   Closing will stop account auto-refresh
echo ========================================
echo.

REM Check Python and run
where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo   Service running... You can minimize this window
    echo.
    python shone_client_web.py
    echo.
    echo   ========================================
    echo   [WARNING] Service stopped!
    echo   Accounts may fail to auto-refresh
    echo   Please restart the client
    echo   ========================================
    pause
    goto :end
)

where python3 >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo   Service running... You can minimize this window
    echo.
    python3 shone_client_web.py
    echo.
    echo   ========================================
    echo   [WARNING] Service stopped!
    echo   Accounts may fail to auto-refresh
    echo   Please restart the client
    echo   ========================================
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
