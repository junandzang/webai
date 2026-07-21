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


def _ensure_group(cur, group_name: str):
    """그룹명을 레지스트리에 등록한다 (이미 있으면 무시).

    서버 등록·수정에서 새 그룹명이 들어와도 사이드바 목록과 어긋나지 않게 한다.
    """
    cur.execute(
        "INSERT IGNORE INTO server_groups (name) VALUES (%s)", (group_name,)
    )


def list_groups():
    """서버 그룹 목록과 그룹별 대수 집계. 사이드바 메뉴에 사용한다.

    server_groups를 기준으로 LEFT JOIN 하므로 서버가 0대인 그룹도 포함된다.
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT g.name                   AS group_name,
                       COUNT(s.id)              AS total,
                       SUM(s.status = 'ok')     AS ok,
                       SUM(s.status = 'check')  AS `check`,
                       SUM(s.status = 'down')   AS down_cnt
                FROM server_groups g
                LEFT JOIN servers s ON s.group_name = g.name
                GROUP BY g.id, g.name, g.sort_order
                ORDER BY g.sort_order, g.name
                """
            )
            rows = cur.fetchall()
    # COUNT/SUM은 Decimal 또는 None으로 오므로 int로 정규화한다.
    for row in rows:
        for key in ("total", "ok", "check", "down_cnt"):
            row[key] = int(row[key] or 0)
    return rows


def create_group(name: str):
    """빈 서버 그룹을 만든다. (성공여부, 메시지) 튜플을 반환한다."""
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO server_groups (name) VALUES (%s)", (name,)
                )
        return True, "그룹이 추가되었습니다."
    except pymysql.err.IntegrityError:
        return False, "이미 존재하는 그룹명입니다."


def delete_group(name: str):
    """빈 그룹을 삭제한다. 서버가 남아 있으면 거부한다.

    (성공여부, 메시지) 튜플을 반환한다.
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS c FROM servers WHERE group_name = %s", (name,)
            )
            used = cur.fetchone()["c"]
            if used:
                return False, f"서버가 {used}대 남아 있어 삭제할 수 없습니다."

            cur.execute("DELETE FROM server_groups WHERE name = %s", (name,))
            if cur.rowcount == 0:
                return False, "존재하지 않는 그룹입니다."
    return True, "그룹이 삭제되었습니다."


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
                _ensure_group(cur, group_name)
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
                _ensure_group(cur, group_name)
        return True, "서버 정보가 수정되었습니다."
    except pymysql.err.IntegrityError:
        return False, "이미 존재하는 서버명입니다."


def rename_group(old_name: str, new_name: str):
    """그룹에 속한 서버들의 group_name을 일괄 변경한다.

    대상 이름의 그룹이 이미 있으면 두 그룹이 합쳐진다.
    (성공여부, 메시지) 튜플을 반환한다.
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 서버가 0대인 빈 그룹도 이름을 바꿀 수 있어야 하므로 레지스트리를 기준으로 본다.
            cur.execute(
                "SELECT COUNT(*) AS c FROM server_groups WHERE name = %s", (old_name,)
            )
            if cur.fetchone()["c"] == 0:
                return False, "존재하지 않는 그룹입니다."

            # 대상 이름이 이미 쓰이고 있으면 두 그룹이 합쳐진다.
            cur.execute(
                "SELECT COUNT(*) AS c FROM server_groups "
                "WHERE name = %s AND name <> %s",
                (new_name, old_name),
            )
            merged = cur.fetchone()["c"] > 0

            cur.execute(
                "UPDATE servers SET group_name = %s WHERE group_name = %s",
                (new_name, old_name),
            )

            if merged:
                # 대상 그룹 행이 이미 있으므로 옛 행은 지운다 (UNIQUE 충돌 방지).
                cur.execute("DELETE FROM server_groups WHERE name = %s", (old_name,))
            else:
                cur.execute(
                    "UPDATE server_groups SET name = %s WHERE name = %s",
                    (new_name, old_name),
                )

    if merged:
        return True, f"기존 '{new_name}' 그룹으로 합쳐졌습니다."
    return True, "그룹명이 변경되었습니다."


def delete_server(server_id: int) -> bool:
    """서버를 삭제한다. 삭제되면 True."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM servers WHERE id = %s", (server_id,))
            return cur.rowcount > 0
