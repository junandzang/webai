@echo off
REM 운영자 사이트 (8000 포트) 실행
REM 이 창을 닫으면 서버도 종료됩니다.
cd /d "%~dp0"
title operator-site 8000
echo [operator-site] http://localhost:8000  (종료: Ctrl+C)
python -m uvicorn app:app --host 127.0.0.1 --port 8000
pause
