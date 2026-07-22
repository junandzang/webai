@echo off
chcp 65001 >nul
cd /d "%~dp0"
title operator-site 중지
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0svc.ps1" -Action stop
echo.
pause
