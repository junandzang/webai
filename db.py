"""DB 접속 및 운영자 계정 관련 헬퍼."""

import bcrypt
import pymysql

import config


def get_conn():
    """AI 데이터베이스에 연결된 PyMySQL 커넥션을 반환한다."""
    return pymysql.connect(
        host=config.DB["host"],
        port=config.DB["port"],
        user=config.DB["user"],
        password=config.DB["password"],
        database=config.DB["database"],
        charset=config.DB["charset"],
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )


def hash_password(plain: str) -> str:
    """평문 비밀번호를 bcrypt 해시(문자열)로 반환한다."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """평문 비밀번호가 저장된 해시와 일치하는지 검증한다."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def get_operator(username: str):
    """username으로 운영자 1건을 조회한다. 없으면 None."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, username, password_hash FROM operators WHERE username = %s",
                (username,),
            )
            return cur.fetchone()


def create_operator(username: str, password: str) -> bool:
    """운영자 계정을 생성한다. 이미 존재하면 False, 생성하면 True."""
    hashed = hash_password(password)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT IGNORE INTO operators (username, password_hash) VALUES (%s, %s)",
                (username, hashed),
            )
            return cur.rowcount > 0


def update_password(username: str, new_password: str) -> bool:
    """운영자의 비밀번호를 새 해시로 갱신한다. 갱신되면 True."""
    hashed = hash_password(new_password)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE operators SET password_hash = %s WHERE username = %s",
                (hashed, username),
            )
            return cur.rowcount > 0
