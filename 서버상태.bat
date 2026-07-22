@echo off
chcp 65001 >nul
cd /d "%~dp0"
title operator-site 상태
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0svc.ps1" -Action status
echo.
pause
