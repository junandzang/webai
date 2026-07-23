"""DB 접속, 운영자 계정, 서버 목록 관련 헬퍼."""

import math

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
        "SELECT id, group_name, name, ip, os, role, status, sort_order, "
        "       ssh_port, ssh_user, db_port, db_user, "
        "       ssh_password_enc IS NOT NULL AS ssh_pw_set, "
        "       db_password_enc IS NOT NULL AS db_pw_set, "
        "       can_os, can_db, can_web "
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


def get_server_by_name(name: str):
    """서버명으로 1건 조회. 등록 직후 id를 얻을 때 쓴다."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, name FROM servers WHERE name = %s", (name,))
            return cur.fetchone()


def get_server(server_id: int):
    """id로 서버 1건을 조회한다. 없으면 None."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, group_name, name, ip, os, role, status, sort_order, "
                "       ssh_port, ssh_user, db_port, db_user, "
                "       ssh_password_enc IS NOT NULL AS ssh_pw_set, "
                "       db_password_enc IS NOT NULL AS db_pw_set, "
                "       can_os, can_db, can_web "
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


def add_audit(actor, action, target="", detail="", ip=""):
    """감사 로그를 남긴다. 자격증명은 절대 전달하지 않는다."""
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO audit_log (actor, action, target, detail, ip) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (str(actor)[:50], str(action)[:40], str(target)[:120],
                     str(detail)[:255], str(ip)[:45]),
                )
    except Exception:
        pass  # 감사 로그 실패가 기능을 막지 않도록 한다


def list_audit(limit=200):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT %s", (int(limit),)
            )
            return cur.fetchall()


# ===== 서버 자격증명 암복호화 =====
#
# SSH/DB 비밀번호는 평문으로 두지 않고 Fernet으로 암호화해 저장한다.
# 키는 .env의 CRED_KEY이며 저장소에 커밋되지 않는다.


def _fernet():
    if not config.CRED_KEY:
        return None
    try:
        from cryptography.fernet import Fernet
        return Fernet(config.CRED_KEY.encode())
    except Exception:
        return None


def encrypt_secret(plain: str):
    """평문 비밀번호를 암호문 bytes로. 빈 값이거나 키가 없으면 None."""
    if not plain:
        return None
    f = _fernet()
    if f is None:
        return None
    return f.encrypt(plain.encode("utf-8"))


def decrypt_secret(blob):
    """저장된 암호문을 평문으로. 실패하면 빈 문자열."""
    if not blob:
        return ""
    f = _fernet()
    if f is None:
        return ""
    try:
        if isinstance(blob, str):
            blob = blob.encode("utf-8")
        return f.decrypt(blob).decode("utf-8")
    except Exception:
        return ""


def get_server_credentials(server_id: int):
    """스캔에 쓸 자격증명을 복호화해 반환한다. 저장된 게 없으면 빈 dict.

    반환값은 스캐너에서만 쓰이며 화면·API로 내보내지 않는다.
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT ssh_port, ssh_user, ssh_password_enc, "
                "       db_port, db_user, db_password_enc "
                "FROM servers WHERE id = %s",
                (server_id,),
            )
            row = cur.fetchone()
    if not row:
        return {}

    creds = {}
    if (row["ssh_user"] or "").strip():
        creds["ssh"] = {
            "port": row["ssh_port"] or 22,
            "user": row["ssh_user"].strip(),
            "password": decrypt_secret(row["ssh_password_enc"]),
        }
    if (row["db_user"] or "").strip():
        creds["db"] = {
            "port": row["db_port"] or 3306,
            "user": row["db_user"].strip(),
            "password": decrypt_secret(row["db_password_enc"]),
        }
    return creds


def save_server_credentials(server_id, ssh_port, ssh_user, ssh_password,
                            db_port, db_user, db_password):
    """서버의 SSH/DB 자격증명을 저장한다.

    비밀번호가 빈 문자열이면 **기존 값을 유지**한다(화면에서 비밀번호를 다시
    내려보내지 않으므로, 수정 시 비워두면 그대로 두는 동작).
    """
    sets = ["ssh_port = %s", "ssh_user = %s", "db_port = %s", "db_user = %s"]
    params = [int(ssh_port or 22), (ssh_user or "").strip()[:64],
              int(db_port or 3306), (db_user or "").strip()[:64]]

    if ssh_password:
        sets.append("ssh_password_enc = %s")
        params.append(encrypt_secret(ssh_password))
    if db_password:
        sets.append("db_password_enc = %s")
        params.append(encrypt_secret(db_password))

    params.append(server_id)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE servers SET " + ", ".join(sets) + " WHERE id = %s", params
            )


def credential_status(server_id: int):
    """화면 표시용. 비밀번호 자체는 절대 반환하지 않고 설정 여부만 알려준다."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT ssh_port, ssh_user, db_port, db_user, "
                "       ssh_password_enc IS NOT NULL AS ssh_pw_set, "
                "       db_password_enc IS NOT NULL AS db_pw_set, "
                "       can_os, can_db, can_web "
                "FROM servers WHERE id = %s",
                (server_id,),
            )
            return cur.fetchone() or {}


def update_server_caps(server_id: int, can_os: bool, can_db: bool, can_web: bool):
    """마지막 진단에서 접근에 성공한 경로(OS/DB/WEB)를 서버에 기록한다."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE servers SET can_os = %s, can_db = %s, can_web = %s "
                "WHERE id = %s",
                (int(bool(can_os)), int(bool(can_db)), int(bool(can_web)), server_id),
            )


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
                  score: float = None, authed: int = 0):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE scans SET status = 'done', os_detected = %s, "
                "scan_source = %s, crit = %s, high = %s, med = %s, low = %s, "
                "info = %s, score = %s, authed = %s, finished_at = NOW() "
                "WHERE id = %s",
                (
                    os_detected[:120], scan_source,
                    counts.get("critical", 0), counts.get("high", 0),
                    counts.get("medium", 0), counts.get("low", 0),
                    counts.get("info", 0), score, authed, scan_id,
                ),
            )


# 우리 위험도 -> SolidStep 5단계 라벨
SEVERITY_KO = {"critical": "최상", "high": "상", "medium": "중",
               "low": "하", "info": "최하"}
# 체크 결과 -> SolidStep 3분류
RESULT_GROUP = {"fail": "취약", "warn": "취약", "info": "수동 점검", "pass": "양호"}

# 점수 감점: 취약 항목 1건당 심각도별 기본 감점 점수.
# 아래 점감 곡선을 통과하면 첫 건이 가장 크게 깎이고 이후는 완만해지므로,
# "1건만 있어도 확실히 티가 나도록" 건당 가중치를 넉넉히 잡는다.
SEVERITY_PENALTY = {"critical": 40.0, "high": 12.0, "medium": 5.0, "low": 2.0, "info": 0.0}
# 결과별 감점 계수 (확정 취약보다 '주의'는 가볍게)
RESULT_FACTOR = {"fail": 1.0, "warn": 0.6}
# 심각도 tier별 감점 한계치(soft cap).
# 하드 컷이 아니라 점감(diminishing) 방식으로 적용한다:
#     감점 = cap x (1 - e^(-raw/cap))
# 지적이 늘수록 감점 증가폭이 줄어들어, 항목이 많아도 0점으로 눌리지 않으면서
# "4건짜리 서버"와 "15건짜리 서버"의 차이는 그대로 유지된다.
SEVERITY_CAP = {"critical": 55.0, "high": 45.0, "medium": 20.0, "low": 15.0, "info": 0.0}


def compute_score(checks) -> float:
    """체크리스트로 0~100 점수를 계산한다.

    100점에서 시작해 취약(fail/warn) 항목마다 심각도별로 감점한다.
    심각할수록 크게, 낮은 등급은 조금만 깎이며, '하' 등급은 총 감점에
    상한을 둬(SEVERITY_CAP) 열린 포트가 많아도 점수가 무너지지 않는다.
    양호(pass)·수동 점검(info)은 감점하지 않는다.
    """
    tier_penalty = {}
    for c in checks:
        factor = RESULT_FACTOR.get(c["result"], 0.0)  # pass/info -> 0
        if not factor:
            continue
        sev = c["severity"]
        tier_penalty[sev] = tier_penalty.get(sev, 0.0) + \
            SEVERITY_PENALTY.get(sev, 1.0) * factor

    penalty = 0.0
    for sev, raw in tier_penalty.items():
        cap = SEVERITY_CAP.get(sev, 20.0)
        if cap <= 0:
            continue
        # 점감 적용: 처음 몇 건은 크게, 이후로는 완만하게 깎인다.
        penalty += cap * (1.0 - math.exp(-raw / cap))

    return round(max(0.0, 100.0 - penalty), 1)


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
    """스캔의 체크리스트 항목을 (조정된) 심각도 높은 순으로 반환한다.

    각 항목에 effective severity('severity' 필드를 담당자 조정값으로 덮어씀)와
    원래 진단값('orig_severity'), 조정 여부('overridden')를 붙인다.
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT *, "
                "  COALESCE(severity_override, severity) AS eff_severity "
                "FROM scan_checks WHERE scan_id = %s "
                "ORDER BY FIELD(COALESCE(severity_override, severity),"
                "               'critical','high','medium','low','info'), "
                "         FIELD(result,'fail','warn','info','pass'), id",
                (scan_id,),
            )
            rows = cur.fetchall()
    for r in rows:
        r["orig_severity"] = r["severity"]
        r["overridden"] = bool(r.get("severity_override"))
        # 화면·집계는 조정값을 우선한다.
        r["severity"] = r["eff_severity"]
    return rows


def set_check_severity(check_id: int, level):
    """체크 항목의 위험도를 담당자가 조정한다. level이 빈 값이면 원복.

    (성공여부, scan_id) 를 반환한다. 조정 후 스캔 점수·집계를 다시 계산한다.
    """
    level = (level or "").strip().lower()
    if level and level not in SEVERITY_PENALTY:
        return False, None
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT scan_id FROM scan_checks WHERE id = %s", (check_id,))
            row = cur.fetchone()
            if not row:
                return False, None
            scan_id = row["scan_id"]
            cur.execute(
                "UPDATE scan_checks SET severity_override = %s WHERE id = %s",
                (level or None, check_id),
            )
    recompute_scan(scan_id)
    return True, scan_id


def recompute_scan(scan_id: int):
    """조정된 위험도를 반영해 스캔의 심각도 집계·점수를 다시 계산한다."""
    checks = get_scan_checks(scan_id)   # severity가 이미 조정값으로 덮여 있음
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for c in checks:
        if c["result"] in ("fail", "warn"):
            counts[c["severity"]] = counts.get(c["severity"], 0) + 1
    scored = any(c["result"] in ("pass", "fail", "warn") for c in checks)
    score = compute_score(checks) if scored else None
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE scans SET crit=%s, high=%s, med=%s, low=%s, info=%s, "
                "score=%s WHERE id=%s",
                (counts["critical"], counts["high"], counts["medium"],
                 counts["low"], counts["info"], score, scan_id),
            )


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
        "       sv.ssh_port, sv.ssh_user, sv.db_port, sv.db_user, "
        "       sv.ssh_password_enc IS NOT NULL AS ssh_pw_set, "
        "       sv.db_password_enc IS NOT NULL AS db_pw_set, "
        "       sv.can_os, sv.can_db, sv.can_web, "
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
