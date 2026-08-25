@echo off
title Dominik Studio - Launcher
cd /d "%~dp0"

echo.
echo ==========================================
echo       DOMINIK STUDIO - START
echo ==========================================
echo.
echo Uruchamiam serwer Node.js...
echo.

start "Dominik Studio Server" cmd /k "cd /d ""%~dp0"" && title Dominik Studio Server && npm.cmd start"

timeout /t 3 /nobreak >nul

start "" "http://localhost:3000"

echo.
echo Przegladarka zostala uruchomiona.
echo Serwer dziala w osobnym oknie.
echo.
pause
