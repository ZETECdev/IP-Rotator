@echo off
:: IP Rotator - emergency network reset (self-elevates, no reboot needed)
NET FILE >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
  exit /b
)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Reset-Network.ps1"
pause
