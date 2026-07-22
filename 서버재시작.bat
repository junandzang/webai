@echo off
chcp 65001 >nul
cd /d "%~dp0"
title operator-site 재시작
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0svc.ps1" -Action restart
echo.
pause
