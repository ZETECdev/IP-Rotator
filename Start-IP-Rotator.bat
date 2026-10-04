@echo off
:: IP Rotator - double-click, self-elevates and starts the rotator
NET FILE >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
  exit /b
)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0IP-Rotator.ps1"
pause
