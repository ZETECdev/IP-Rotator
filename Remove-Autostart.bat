@echo off
:: IP Rotator - removes auto-start
NET FILE >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
  exit /b
)
schtasks /delete /tn "IP Rotator" /f
echo Done: auto-start removed.
pause
