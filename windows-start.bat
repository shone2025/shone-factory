@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ========================================
echo   SFK Token Manager - Starting...
echo ========================================
echo.

REM Check Python and run
where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    python shone_client_web.py
    if %ERRORLEVEL% NEQ 0 (
        echo.
        echo   [ERROR] Script execution failed
        pause
    )
    goto :end
)

where python3 >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    python3 shone_client_web.py
    if %ERRORLEVEL% NEQ 0 (
        echo.
        echo   [ERROR] Script execution failed
        pause
    )
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
