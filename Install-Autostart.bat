@echo off
:: IP Rotator - installs auto-start (asks for admin once)
NET FILE >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
  exit /b
)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-Autostart.ps1"
pause
