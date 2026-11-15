@echo off
chcp 65001 >nul
cd /d "%~dp0"
rem Self-elevate: fltmc only works when elevated, and it is quieter than net session
fltmc >nul 2>&1
if errorlevel 1 (
    echo [elevate] not administrator - requesting UAC ...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
echo Installing sysguard driver...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
echo.
pause
