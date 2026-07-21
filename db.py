"""DB 접속, 운영자 계정, 서버 목록 관련 헬퍼."""

import bcrypt
import pymysql

import config

# 서버 상태 코드 -> 표시 문구
SERVER_STATUS = {"ok": "정상", "check": "점검", "down": "중지"}


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


# ===== 서버 =====


def list_groups():
    """서버 그룹별 대수 집계. 사이드바 메뉴에 사용한다."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT group_name,
                       COUNT(*)                                    AS total,
                       SUM(status = 'ok')                          AS ok,
                       SUM(status = 'check')                       AS `check`,
                       SUM(status = 'down')                        AS down_cnt
                FROM servers
                GROUP BY group_name
                ORDER BY group_name
                """
            )
            rows = cur.fetchall()
    # SUM()은 Decimal로 오므로 int로 정규화한다.
    for row in rows:
        for key in ("total", "ok", "check", "down_cnt"):
            row[key] = int(row[key] or 0)
    return rows


def list_servers(group_name: str = None):
    """그룹에 속한 서버 목록. group_name이 None이면 전체를 반환한다."""
    sql = (
        "SELECT id, group_name, name, ip, os, role, status, sort_order "
        "FROM servers "
    )
    params = ()
    if group_name:
        sql += "WHERE group_name = %s "
        params = (group_name,)
    sql += "ORDER BY sort_order, name"

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()


def get_server(server_id: int):
    """id로 서버 1건을 조회한다. 없으면 None."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, group_name, name, ip, os, role, status, sort_order "
                "FROM servers WHERE id = %s",
                (server_id,),
            )
            return cur.fetchone()


def status_summary():
    """전체 서버의 상태별 집계. 상단 통계 카드에 사용한다."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)              AS total,
                       SUM(status = 'ok')    AS ok,
                       SUM(status = 'check') AS `check`,
                       SUM(status = 'down')  AS down_cnt
                FROM servers
                """
            )
            row = cur.fetchone()
    return {key: int(row[key] or 0) for key in ("total", "ok", "check", "down_cnt")}


def create_server(group_name, name, ip, os_name, role, status):
    """서버를 등록한다. (성공여부, 메시지) 튜플을 반환한다."""
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO servers (group_name, name, ip, os, role, status) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (group_name, name, ip, os_name, role, status),
                )
        return True, "서버가 등록되었습니다."
    except pymysql.err.IntegrityError:
        return False, "이미 존재하는 서버명입니다."


def update_server(server_id, group_name, name, ip, os_name, role, status):
    """서버 정보를 수정한다. (성공여부, 메시지) 튜플을 반환한다."""
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE servers "
                    "SET group_name = %s, name = %s, ip = %s, os = %s, "
                    "    role = %s, status = %s "
                    "WHERE id = %s",
                    (group_name, name, ip, os_name, role, status, server_id),
                )
        return True, "서버 정보가 수정되었습니다."
    except pymysql.err.IntegrityError:
        return False, "이미 존재하는 서버명입니다."


def delete_server(server_id: int) -> bool:
    """서버를 삭제한다. 삭제되면 True."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM servers WHERE id = %s", (server_id,))
            return cur.rowcount > 0
