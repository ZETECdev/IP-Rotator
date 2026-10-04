@echo off
REM Descarga todos los perfiles WireGuard (reanudable, con pausas por rate-limit)
REM Uso: doble clic. Pide usuario/clave (no se guardan). No cerrar hasta "Done."
cd /d "%~dp0"
C:\Python314\python.exe -u tools\Download-Profiles.py --out profiles --per-country 2 --delay 2
echo.
echo Terminado. Revisa profiles\*.conf
pause
