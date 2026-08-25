@echo off
echo Zatrzymywanie serwera Dominik Studio...
taskkill /FI "WINDOWTITLE eq Dominik Studio Server" /T /F >nul 2>&1
echo.
echo Serwer zostal zatrzymany.
pause
