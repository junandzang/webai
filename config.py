"""애플리케이션 설정. 실제 값은 같은 폴더의 .env 파일에서 읽는다."""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

# MariaDB 접속 정보 (로컬 PC)
DB = dict(
    host=os.getenv("DB_HOST", "127.0.0.1"),
    port=int(os.getenv("DB_PORT", "3306")),
    user=os.getenv("DB_USER", "root"),
    password=os.getenv("DB_PASSWORD", ""),
    database=os.getenv("DB_NAME", "AI"),
    charset="utf8mb4",
)

# DB 이름 (init_db.py에서 CREATE DATABASE에 사용)
DB_NAME = os.getenv("DB_NAME", "AI")

# 세션 쿠키 서명용 시크릿 키. 운영 환경에서는 반드시 .env에서 지정하세요.
SESSION_SECRET = os.getenv("SESSION_SECRET", "dev-only-insecure-secret")

# 초기 운영자 계정 (init_db.py 실행 시 시드)
INITIAL_ADMIN_USERNAME = os.getenv("INITIAL_ADMIN_USERNAME", "admin")
INITIAL_ADMIN_PASSWORD = os.getenv("INITIAL_ADMIN_PASSWORD", "admin1234")
