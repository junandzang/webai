@echo off
REM SolidStep 스타일 콘솔 (8100 포트) 실행
REM 이 창을 닫으면 서버도 종료됩니다.
cd /d "%~dp0"
title operator-site 8100
echo [operator-site] http://localhost:8100  (종료: Ctrl+C)
python -m uvicorn app_cce:app --host 127.0.0.1 --port 8100
pause
