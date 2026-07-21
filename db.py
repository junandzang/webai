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


def update_server_os(server_id: int, os_name: str):
    """스캔으로 파악한 OS를 서버 레코드에 반영한다."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE servers SET os = %s WHERE id = %s", (os_name, server_id)
            )


# ===== 보안검사(스캔) =====


def create_scan(server_id: int, target_ip: str) -> int:
    """스캔 레코드를 만들고 scan_id를 반환한다."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO scans (server_id, target_ip, status) "
                "VALUES (%s, %s, 'queued')",
                (server_id, target_ip),
            )
            return cur.lastrowid


def set_scan_running(scan_id: int):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE scans SET status = 'running' WHERE id = %s", (scan_id,)
            )


def set_scan_error(scan_id: int, message: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE scans SET status = 'error', error_message = %s, "
                "finished_at = NOW() WHERE id = %s",
                (message[:255], scan_id),
            )


def set_scan_done(scan_id: int, os_detected: str, scan_source: str, counts: dict,
                  score: float = None):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE scans SET status = 'done', os_detected = %s, "
                "scan_source = %s, crit = %s, high = %s, med = %s, low = %s, "
                "info = %s, score = %s, finished_at = NOW() WHERE id = %s",
                (
                    os_detected[:120], scan_source,
                    counts.get("critical", 0), counts.get("high", 0),
                    counts.get("medium", 0), counts.get("low", 0),
                    counts.get("info", 0), score, scan_id,
                ),
            )


# 심각도별 점수 가중치 (점수 계산·위험도 표기에 공용)
SEVERITY_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
# 우리 위험도 -> SolidStep 5단계 라벨
SEVERITY_KO = {"critical": "최상", "high": "상", "medium": "중",
               "low": "하", "info": "최하"}
# 체크 결과 -> SolidStep 3분류
RESULT_GROUP = {"fail": "취약", "warn": "취약", "info": "수동 점검", "pass": "양호"}


def compute_score(checks) -> float:
    """체크리스트로 0~100 점수를 계산한다.

    심각도 가중치 기준, 양호(pass)·정보(info) 항목이 차지하는 비율을 점수로 본다.
    취약(fail/warn)이 많고 심각할수록 점수가 낮아진다.
    """
    total = 0.0
    got = 0.0
    for c in checks:
        w = SEVERITY_WEIGHT.get(c["severity"], 1)
        total += w
        if c["result"] in ("pass", "info"):
            got += w
    if total == 0:
        return 100.0
    return round(100.0 * got / total, 1)


def add_check(scan_id: int, check: dict):
    """체크리스트 항목 1건을 저장한다."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO scan_checks "
                "(scan_id, category, title, severity, result, port, "
                " detail, evidence, remediation, cve_ids, ref_url) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    scan_id, check["category"], check["title"][:200],
                    check["severity"], check["result"], check.get("port"),
                    check.get("detail", ""), check.get("evidence", ""),
                    check.get("remediation", ""),
                    ",".join(check.get("cve_ids", []))[:255],
                    check.get("ref_url", "")[:255],
                ),
            )


def latest_scan(server_id: int):
    """서버의 가장 최근 스캔 1건을 반환한다. 없으면 None.

    'running' 상태인데 서버 재시작 등으로 방치된 오래된 스캔은
    error로 간주해 표시한다(조회 시 상태 보정).
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM scans WHERE server_id = %s "
                "ORDER BY id DESC LIMIT 1",
                (server_id,),
            )
            return cur.fetchone()


def get_scan(scan_id: int):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scans WHERE id = %s", (scan_id,))
            return cur.fetchone()


def findings_by_severity(severity: str):
    """전체 서버의 최신 완료 스캔에서 주어진 심각도의 취약/주의 항목을 모은다.

    각 항목에 어느 서버인지(server_id, server_name, group_name, target_ip)를 붙여 반환한다.
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT c.*, sv.id AS server_id, sv.name AS server_name,
                       sv.group_name AS group_name, s.target_ip AS target_ip
                FROM scan_checks c
                JOIN scans s ON s.id = c.scan_id
                JOIN (
                    SELECT server_id, MAX(id) AS mid
                    FROM scans WHERE status = 'done'
                    GROUP BY server_id
                ) t ON s.id = t.mid
                JOIN servers sv ON sv.id = s.server_id
                WHERE c.severity = %s AND c.result IN ('fail', 'warn')
                ORDER BY sv.group_name, sv.name, c.id
                """,
                (severity,),
            )
            return cur.fetchall()


def severity_totals():
    """서버별 최신 완료 스캔의 심각도 합계. 대시보드 요약에 사용한다."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COALESCE(SUM(s.crit),0) AS crit,
                       COALESCE(SUM(s.high),0) AS high,
                       COALESCE(SUM(s.med),0)  AS med,
                       COALESCE(SUM(s.low),0)  AS low
                FROM scans s
                JOIN (
                    SELECT server_id, MAX(id) AS mid
                    FROM scans WHERE status = 'done'
                    GROUP BY server_id
                ) t ON s.id = t.mid
                """
            )
            row = cur.fetchone()
    return {k: int(row[k] or 0) for k in ("crit", "high", "med", "low")}


def get_scan_checks(scan_id: int):
    """스캔의 체크리스트 항목을 심각도 높은 순으로 반환한다."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM scan_checks WHERE scan_id = %s "
                "ORDER BY FIELD(severity,'critical','high','medium','low','info'), "
                "         FIELD(result,'fail','warn','info','pass'), id",
                (scan_id,),
            )
            return cur.fetchall()


# ===== SolidStep(8100) UI 전용 조회 =====

# category -> 항목 코드 접두사
_CODE_PREFIX = {"os": "OS", "port": "NET", "service": "SVC",
                "web": "WEB", "db": "DB", "account": "ACC"}


def scans_overview(group_name: str = None):
    """자산별 최신 완료 스캔 요약. 자산 정보/진단 결과 목록에 사용한다.

    서버 전체를 반환하되, 완료된 스캔이 있으면 점수·위험도·수집일시를 붙인다.
    """
    sql = (
        "SELECT sv.id, sv.name, sv.group_name, sv.ip, sv.os, sv.role, sv.status, "
        "       s.id AS scan_id, s.status AS scan_status, s.score, "
        "       s.crit, s.high, s.med, s.low, s.info, s.os_detected, "
        "       s.scan_source, s.finished_at "
        "FROM servers sv "
        "LEFT JOIN ( "
        "  SELECT server_id, MAX(id) AS mid FROM scans WHERE status='done' "
        "  GROUP BY server_id "
        ") t ON t.server_id = sv.id "
        "LEFT JOIN scans s ON s.id = t.mid "
    )
    params = ()
    if group_name:
        sql += "WHERE sv.group_name = %s "
        params = (group_name,)
    sql += "ORDER BY sv.sort_order, sv.name"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()


def scan_report(scan_id: int):
    """보고서 상세보기용 묶음: 스캔 메타 + 서버 + 분류된 체크리스트.

    반환: {"scan":..., "server":..., "checks":[...], "groups":{"취약":[...],...},
           "risk":{"최상":n,...}} 또는 None.
    각 check에 code(항목코드)·sev_ko(위험도 한글)·group_ko(분류) 필드를 덧붙인다.
    """
    scan = get_scan(scan_id)
    if scan is None:
        return None
    server = get_server(scan["server_id"])
    checks = get_scan_checks(scan_id)

    groups = {"취약": [], "수동 점검": [], "양호": []}
    risk = {"최상": 0, "상": 0, "중": 0, "하": 0, "최하": 0}
    counters = {}
    for c in checks:
        prefix = _CODE_PREFIX.get(c["category"], "GEN")
        counters[prefix] = counters.get(prefix, 0) + 1
        c["code"] = f"{prefix}-{counters[prefix]:02d}"
        c["sev_ko"] = SEVERITY_KO.get(c["severity"], c["severity"])
        c["group_ko"] = RESULT_GROUP.get(c["result"], "기타")
        groups.setdefault(c["group_ko"], []).append(c)
        if c["result"] in ("fail", "warn"):
            risk[c["sev_ko"]] = risk.get(c["sev_ko"], 0) + 1

    return {"scan": scan, "server": server, "checks": checks,
            "groups": groups, "risk": risk}
