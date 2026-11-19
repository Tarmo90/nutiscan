@echo off
title Nutiscan Web UI
set "OLI=C:\Users\tarmo\OpenBot\Agents\agent-fe7aaccd-958f-4c21-ab83-1c4aeccbf83e\Nutiscan"
set "PY=C:\Python315\python.exe"
cd /d "%OLI%"
echo.
echo   Nutiscan 2.0 - veebiliides
echo   =========================
echo.

netstat -ano | findstr ":8822 " | findstr "LISTENING" >nul
if %errorlevel%==0 (
  echo   Server juba töotab. Avan brauseri...
  start "" http://127.0.0.1:8822/
  timeout /t 2 >nul
  exit /b 0
)

if not exist "%PY%" set "PY=python"
echo   Kavritan serveri ja avan brauseri: http://127.0.0.1:8822/
echo   Sulgemiseks vajuta Ctrl+C.
echo.
start "" http://127.0.0.1:8822/
"%PY%" "%OLI%\webui\run.py" --port 8822 --no-browser
pause
