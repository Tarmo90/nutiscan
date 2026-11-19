@echo off
title Nutiscan Web UI
cd /d "%~dp0"
echo Kavritan Nutiscan veebiliidese...
echo Avan brauseri aadressil http://127.0.0.1:8822/
echo Sulgemiseks vajuta Ctrl+C voi sulge see aken.
echo.
py -3 webui\run.py --port 8822
if errorlevel 1 python webui\run.py --port 8822
pause
