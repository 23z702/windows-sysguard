@echo off
cd /d "%~dp0.."
rem Self-elevate: loading a driver needs admin; fltmc fails fast when not elevated
fltmc >nul 2>&1
if errorlevel 1 (
    echo [elevate] not administrator - requesting UAC ...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0loadtest.ps1"
echo.
pause
