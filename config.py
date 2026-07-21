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

# ===== 보안검사(스캔) 설정 =====

# nmap 실행 파일 경로. 비우면 PATH와 기본 설치경로에서 자동 탐색한다.
NMAP_PATH = os.getenv("NMAP_PATH", "")

# NVD(CVE) 실시간 조회 설정.
#  - NVD_API_KEY: 있으면 요청 한도가 늘어난다(선택).
#  - NVD_CA_BUNDLE: 사내 프록시 CA 인증서(.pem) 경로. 지정 시 그 CA로 검증한다.
#  - NVD_INSECURE: "1"이면 TLS 검증을 생략한다(비권장, 기본 off).
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
NVD_CA_BUNDLE = os.getenv("NVD_CA_BUNDLE", "")
NVD_INSECURE = os.getenv("NVD_INSECURE", "") == "1"
