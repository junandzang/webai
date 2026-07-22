"""계정 기반 심층 점검 (credentialed audit).

대상 서버에 실제로 접속해 내부 설정을 확인한다. nmap 네트워크 스캔이
'밖에서 보이는 노출'만 본다면, 여기서는 계정·권한·설정까지 들여다본다.

원칙:
  - 자격증명은 **인자로만 받아 메모리에서 쓰고** 반환값·로그에 남기지 않는다.
    (DB/파일에 저장하지 않는다)
  - 모든 조회는 **읽기 전용**이다. 설정 변경·쓰기는 하지 않는다.
  - 접속 실패는 오류가 아니라 info 항목으로 남겨 스캔 자체는 계속되게 한다.

반환 항목은 rules.py의 체크 항목 dict와 동일한 형식이다.
"""

import socket

import pymysql

from rules import REF, _item

CONNECT_TIMEOUT = 8
SSH_CMD_TIMEOUT = 15

# 로컬 전용으로 간주하는 호스트 값
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


# ===== MySQL / MariaDB =====


def audit_mysql(host, port, user, password):
    """DB 계정으로 접속해 계정·권한·설정 취약점을 점검한다."""
    try:
        conn = pymysql.connect(
            host=host, port=int(port), user=user, password=password,
            connect_timeout=CONNECT_TIMEOUT,
            cursorclass=pymysql.cursors.DictCursor,
        )
    except Exception as e:
        # 자격증명 오류·차단 등은 정보 항목으로 남기고 진행한다.
        return [_item(
            "db", f"DB 계정 점검 불가 ({port}/tcp)", "info", "info",
            f"DB에 접속하지 못해 계정 기반 점검을 수행하지 못했습니다. 사유: {_safe_err(e)}",
            "포트·방화벽·계정 권한을 확인한 뒤 다시 시도하세요.",
            port=int(port),
        )]

    checks = []
    try:
        with conn:
            with conn.cursor() as cur:
                version = _scalar(cur, "SELECT VERSION() AS v", "v") or ""
                checks.append(_item(
                    "db", f"DB 버전 확인: {version}", "info", "pass",
                    f"계정 점검으로 확인한 정확한 버전입니다: {version}",
                    "보안 패치가 적용된 최신 버전을 유지하세요.",
                    port=int(port), evidence=version, ref_url=REF["mysql"],
                ))
                checks.extend(_mysql_accounts(cur, port))
                checks.extend(_mysql_settings(cur, port))
    except Exception as e:
        checks.append(_item(
            "db", "DB 점검 중 오류", "info", "info",
            f"일부 점검을 마치지 못했습니다: {_safe_err(e)}",
            "점검 계정에 mysql 스키마 조회 권한이 있는지 확인하세요.",
            port=int(port),
        ))
    return checks


def _scalar(cur, sql, key, params=()):
    cur.execute(sql, params)
    row = cur.fetchone()
    return row[key] if row else None


def _mysql_user_columns(cur):
    """mysql.user에 실제로 존재하는 컬럼 집합. 버전별 차이를 흡수한다."""
    try:
        cur.execute(
            "SELECT COLUMN_NAME AS c FROM information_schema.columns "
            "WHERE TABLE_SCHEMA='mysql' AND TABLE_NAME='user'"
        )
        return {r["c"].lower() for r in cur.fetchall()}
    except Exception:
        return set()


def _mysql_locked_accounts(cur, cols):
    """잠긴 계정 집합 {(user, host)}. MariaDB는 global_priv JSON, MySQL은 컬럼."""
    locked = set()
    # MariaDB 10.4+ : mysql.global_priv 의 JSON
    try:
        cur.execute(
            "SELECT User, Host, JSON_VALUE(Priv,'$.account_locked') AS locked "
            "FROM mysql.global_priv"
        )
        for r in cur.fetchall():
            if str(r.get("locked")) in ("1", "true", "True"):
                locked.add((r["User"], r["Host"]))
        return locked
    except Exception:
        pass
    # MySQL 5.7+ : mysql.user.account_locked
    if "account_locked" in cols:
        try:
            cur.execute("SELECT User, Host, account_locked FROM mysql.user")
            for r in cur.fetchall():
                if (r.get("account_locked") or "").upper() == "Y":
                    locked.add((r["User"], r["Host"]))
        except Exception:
            pass
    return locked


def _mysql_accounts(cur, port):
    """mysql.user 기반 계정 점검.

    역할(role)과 잠긴 계정은 로그인에 쓰이지 않으므로 점검 대상에서 제외한다.
    (MariaDB의 PUBLIC 역할, mariadb.sys 잠금 계정 등이 오탐으로 잡히지 않게)
    """
    checks = []
    cols = _mysql_user_columns(cur)
    locked = _mysql_locked_accounts(cur, cols)

    # 버전에 따라 없는 컬럼이 있으므로 존재하는 것만 조회한다.
    wanted = ["User", "Host", "plugin", "authentication_string", "Password",
              "Super_priv", "Grant_priv", "File_priv", "is_role"]
    select = [c for c in wanted if c.lower() in cols] or ["User", "Host"]
    cur.execute(f"SELECT {', '.join(select)} FROM mysql.user")
    rows = cur.fetchall()

    users = []
    for r in rows:
        r.setdefault("Password", "")
        r.setdefault("authentication_string", "")
        r.setdefault("plugin", "")
        r["_locked"] = (r["User"], r["Host"]) in locked
        r["_is_role"] = (r.get("is_role") or "N") == "Y"
        # 역할·잠긴 계정은 실제 로그인 계정이 아니므로 제외
        if not r["_is_role"] and not r["_locked"]:
            users.append(r)

    def label(u):
        return f"{u['User'] or '(익명)'}@{u['Host']}"

    # 1) 빈 비밀번호 계정 (소켓/잠금 인증 플러그인은 제외)
    locked_plugins = {"auth_socket", "unix_socket", "mysql_no_login", "invalid_password"}
    empty_pw = [u for u in users
                if not (u.get("authentication_string") or "").strip()
                and not (u.get("Password") or "").strip()
                and (u.get("plugin") or "") not in locked_plugins
                and (u["User"] or "") != ""]
    if empty_pw:
        checks.append(_item(
            "account", f"빈 비밀번호 DB 계정 {len(empty_pw)}건", "critical", "fail",
            "비밀번호 없이 로그인 가능한 계정이 있습니다: "
            + ", ".join(label(u) for u in empty_pw[:8]),
            "해당 계정에 강한 비밀번호를 설정하거나 삭제하세요. "
            "ALTER USER 'user'@'host' IDENTIFIED BY '<강한 비밀번호>';",
            port=int(port), evidence="\n".join(label(u) for u in empty_pw),
            ref_url=REF["mysql"],
        ))

    # 2) 익명 계정
    anon = [u for u in users if (u["User"] or "") == ""]
    if anon:
        checks.append(_item(
            "account", f"익명 DB 계정 {len(anon)}건", "critical", "fail",
            "사용자명이 비어 있는 익명 계정이 존재합니다: "
            + ", ".join(label(u) for u in anon),
            "DROP USER ''@'host'; 로 익명 계정을 제거하세요.",
            port=int(port), evidence="\n".join(label(u) for u in anon),
            ref_url=REF["mysql"],
        ))

    # 3) root 원격 접속 허용
    remote_root = [u for u in users
                   if (u["User"] or "").lower() == "root" and u["Host"] not in LOCAL_HOSTS]
    if remote_root:
        checks.append(_item(
            "account", f"root 원격 접속 허용 {len(remote_root)}건", "high", "fail",
            "관리자(root) 계정이 로컬 외 호스트에서 접속 가능합니다: "
            + ", ".join(label(u) for u in remote_root),
            "root는 localhost로만 제한하세요. 원격 관리가 필요하면 전용 계정을 만들고 "
            "접속 가능 호스트를 특정 IP로 좁히세요.",
            port=int(port), evidence="\n".join(label(u) for u in remote_root),
            ref_url=REF["mysql"],
        ))

    # 4) 와일드카드 호스트(%) 계정
    wildcard = [u for u in users if u["Host"] == "%"]
    if wildcard:
        checks.append(_item(
            "account", f"모든 IP 허용(%) 계정 {len(wildcard)}건", "high", "fail",
            "어느 IP에서든 접속 가능한 계정이 있습니다: "
            + ", ".join(label(u) for u in wildcard[:8]),
            "접속 호스트를 애플리케이션 서버 IP로 제한하세요.",
            port=int(port), evidence="\n".join(label(u) for u in wildcard),
            ref_url=REF["mysql"],
        ))

    # 5) 과도한 권한 보유 계정 (root 제외)
    powerful = [u for u in users
                if (u["User"] or "").lower() != "root"
                and (u.get("Super_priv") == "Y" or u.get("Grant_priv") == "Y"
                     or u.get("File_priv") == "Y")]
    if powerful:
        checks.append(_item(
            "account", f"과도한 권한 보유 계정 {len(powerful)}건", "high", "fail",
            "SUPER/GRANT/FILE 권한을 가진 일반 계정이 있습니다: "
            + ", ".join(label(u) for u in powerful[:8])
            + ". FILE 권한은 서버 파일 읽기·쓰기로 이어질 수 있습니다.",
            "최소 권한 원칙에 따라 불필요한 SUPER·GRANT·FILE 권한을 회수하세요. "
            "REVOKE SUPER, FILE ON *.* FROM 'user'@'host';",
            port=int(port), evidence="\n".join(label(u) for u in powerful),
            ref_url=REF["mysql"],
        ))

    # 6) 취약한 인증 플러그인
    old_auth = [u for u in users if (u.get("plugin") or "") == "mysql_old_password"]
    if old_auth:
        checks.append(_item(
            "account", "구식 인증 플러그인 사용", "medium", "fail",
            "mysql_old_password는 취약한 해시를 사용합니다: "
            + ", ".join(label(u) for u in old_auth),
            "caching_sha2_password 또는 mysql_native_password로 전환하세요.",
            port=int(port), evidence="\n".join(label(u) for u in old_auth),
            ref_url=REF["mysql"],
        ))

    if not any(c["result"] == "fail" for c in checks):
        checks.append(_item(
            "account", "DB 계정 설정 양호", "info", "pass",
            f"점검한 {len(users)}개 계정에서 빈 비밀번호·익명·원격 root·과도한 권한이 "
            "발견되지 않았습니다.",
            "계정 정책을 계속 유지하세요.",
            port=int(port), ref_url=REF["mysql"],
        ))
    return checks


def _mysql_settings(cur, port):
    """전역 변수 기반 설정 점검."""
    checks = []

    def var(name):
        try:
            cur.execute("SHOW VARIABLES LIKE %s", (name,))
            row = cur.fetchone()
            return (row or {}).get("Value")
        except Exception:
            return None

    # secure_file_priv 미설정 → 임의 경로 파일 접근
    sfp = var("secure_file_priv")
    if sfp is not None and sfp.strip() == "":
        checks.append(_item(
            "db", "secure_file_priv 미설정", "high", "fail",
            "FILE 권한 계정이 서버의 임의 경로를 읽고 쓸 수 있습니다.",
            "my.cnf에 secure_file_priv=/var/lib/mysql-files 처럼 전용 디렉터리를 지정하세요.",
            port=int(port), evidence=f"secure_file_priv='{sfp}'", ref_url=REF["mysql"],
        ))

    # local_infile
    if (var("local_infile") or "").upper() == "ON":
        checks.append(_item(
            "db", "local_infile 활성화", "medium", "fail",
            "LOAD DATA LOCAL INFILE로 클라이언트 파일이 읽힐 수 있습니다.",
            "필요하지 않으면 local_infile=0 으로 비활성화하세요.",
            port=int(port), evidence="local_infile=ON", ref_url=REF["mysql"],
        ))

    # 전송 구간 암호화
    have_ssl = (var("have_ssl") or var("have_openssl") or "").upper()
    require_ssl = (var("require_secure_transport") or "").upper()
    if have_ssl != "YES":
        checks.append(_item(
            "db", "DB 전송 구간 미암호화", "medium", "fail",
            "SSL/TLS가 비활성화되어 쿼리와 자격증명이 평문으로 오갑니다.",
            "서버 인증서를 설정해 TLS를 활성화하고, require_secure_transport=ON으로 강제하세요.",
            port=int(port), evidence=f"have_ssl={have_ssl or '없음'}", ref_url=REF["mysql"],
        ))
    elif require_ssl != "ON":
        checks.append(_item(
            "db", "TLS 강제 미적용", "low", "warn",
            "TLS를 지원하지만 평문 접속도 허용됩니다.",
            "require_secure_transport=ON 으로 암호화 접속만 허용하세요.",
            port=int(port), evidence=f"require_secure_transport={require_ssl or 'OFF'}",
            ref_url=REF["mysql"],
        ))

    # test 데이터베이스
    try:
        cur.execute("SHOW DATABASES LIKE 'test'")
        if cur.fetchone():
            checks.append(_item(
                "db", "기본 test 데이터베이스 존재", "low", "warn",
                "기본 생성되는 test DB는 누구나 접근 가능한 경우가 많습니다.",
                "DROP DATABASE test; 로 제거하세요.",
                port=int(port), evidence="test", ref_url=REF["mysql"],
            ))
    except Exception:
        pass

    return checks


# ===== SSH (Linux 호스트) =====


def audit_ssh(host, port, user, password):
    """SSH로 접속해 OS·계정정책·권한을 점검한다. 읽기 전용 명령만 실행."""
    try:
        import paramiko
    except ImportError:
        return [_item(
            "os", "SSH 점검 불가 (paramiko 미설치)", "info", "info",
            "SSH 점검 라이브러리가 설치되지 않았습니다.",
            "pip install paramiko 후 다시 시도하세요.",
        )]

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host, port=int(port), username=user, password=password,
            timeout=CONNECT_TIMEOUT, banner_timeout=CONNECT_TIMEOUT,
            auth_timeout=CONNECT_TIMEOUT, look_for_keys=False, allow_agent=False,
        )
    except Exception as e:
        return [_item(
            "os", f"SSH 접속 불가 ({port}/tcp)", "info", "info",
            f"SSH로 접속하지 못해 호스트 내부 점검을 수행하지 못했습니다. 사유: {_safe_err(e)}",
            "SSH 포트가 열려 있는지, 방화벽에서 이 서버의 접근을 허용하는지, "
            "계정/비밀번호가 맞는지 확인하세요.",
            port=int(port), ref_url=REF["ssh"],
        )]

    checks = []
    try:
        checks.extend(_ssh_os(client))
        checks.extend(_ssh_accounts(client))
        checks.extend(_ssh_sshd(client, port))
        checks.extend(_ssh_permissions(client))
    except Exception as e:
        checks.append(_item(
            "os", "SSH 점검 중 오류", "info", "info",
            f"일부 점검을 마치지 못했습니다: {_safe_err(e)}",
            "점검 계정 권한을 확인하세요.",
        ))
    finally:
        client.close()
    return checks


def _run(client, cmd):
    """읽기 전용 명령 실행 후 stdout을 반환한다. 실패 시 빈 문자열."""
    try:
        _in, out, _err = client.exec_command(cmd, timeout=SSH_CMD_TIMEOUT)
        return out.read().decode("utf-8", "replace").strip()
    except Exception:
        return ""


def _ssh_os(client):
    """정확한 배포판·커널 버전 수집 (원격 지문으로는 특정이 어려웠던 부분)."""
    checks = []
    pretty = ""
    osr = _run(client, "cat /etc/os-release 2>/dev/null")
    for line in osr.splitlines():
        if line.startswith("PRETTY_NAME="):
            pretty = line.split("=", 1)[1].strip().strip('"')
            break
    kernel = _run(client, "uname -r")

    if pretty or kernel:
        label = pretty or "Linux"
        checks.append(_item(
            "os", f"운영체제 확인: {label}", "info", "pass",
            f"계정 점검으로 확인한 정확한 OS입니다. 커널 {kernel or '미상'}.",
            "OS 보안 업데이트를 최신 상태로 유지하세요.",
            evidence=f"{osr}\nkernel: {kernel}"[:400],
        ))
        # 지원 종료(EOL) 여부는 rules의 EOL 표로 판정
        from rules import EOL_OS_MARKERS
        low = label.lower()
        for marker, desc in EOL_OS_MARKERS:
            if marker in low:
                checks.append(_item(
                    "os", f"지원 종료(EOL) OS: {label}", "high", "fail",
                    desc + " 보안 패치를 받지 못합니다.",
                    "지원 기간 내 버전으로 업그레이드하세요.",
                    evidence=label, ref_url=REF["eol"],
                ))
                break
    return checks


def _ssh_accounts(client):
    checks = []
    # UID 0 계정 (root 외 존재 시 위험)
    uid0 = [x for x in _run(client, "awk -F: '($3==0){print $1}' /etc/passwd").split() if x]
    extra = [u for u in uid0 if u != "root"]
    if extra:
        checks.append(_item(
            "account", f"root 권한(UID 0) 계정 추가 존재: {', '.join(extra)}",
            "critical", "fail",
            "root와 동일한 UID 0을 가진 계정이 있어 우회 관리자 접근이 가능합니다.",
            "해당 계정의 UID를 일반 범위로 변경하거나 삭제하세요.",
            evidence=" ".join(uid0),
        ))

    # 빈 비밀번호 계정 (shadow 읽기 권한이 있을 때만)
    empty = [x for x in _run(
        client, "awk -F: '($2==\"\"){print $1}' /etc/shadow 2>/dev/null").split() if x]
    if empty:
        checks.append(_item(
            "account", f"빈 비밀번호 계정 {len(empty)}건", "critical", "fail",
            "비밀번호 없이 로그인 가능한 계정: " + ", ".join(empty),
            "passwd로 비밀번호를 설정하거나 계정을 잠그세요(usermod -L).",
            evidence=" ".join(empty),
        ))

    # 비밀번호 정책
    maxd = _run(client, "grep -E '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}'")
    minlen = _run(client, "grep -E '^PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}'")
    weak = []
    if maxd.isdigit() and int(maxd) > 90:
        weak.append(f"최대 사용기간 {maxd}일")
    if minlen.isdigit() and int(minlen) < 8:
        weak.append(f"최소 길이 {minlen}자")
    if weak:
        checks.append(_item(
            "account", "비밀번호 정책 미흡", "medium", "fail",
            "권장 기준에 미달합니다: " + ", ".join(weak) + ".",
            "/etc/login.defs에서 PASS_MAX_DAYS 90 이하, PASS_MIN_LEN 8 이상으로 조정하세요.",
            evidence=f"PASS_MAX_DAYS={maxd} PASS_MIN_LEN={minlen}",
        ))
    return checks


def _ssh_sshd(client, port):
    checks = []
    conf = _run(client, "cat /etc/ssh/sshd_config 2>/dev/null")
    if not conf:
        return checks

    def directive(name, default=""):
        for line in conf.splitlines():
            s = line.strip()
            if s and not s.startswith("#") and s.split()[0].lower() == name.lower():
                parts = s.split()
                return parts[1] if len(parts) > 1 else default
        return default

    permit_root = (directive("PermitRootLogin", "prohibit-password") or "").lower()
    if permit_root in ("yes", "without-password"):
        checks.append(_item(
            "account", "SSH root 직접 로그인 허용", "high", "fail",
            f"PermitRootLogin {permit_root} 로 설정되어 root로 바로 접속할 수 있습니다.",
            "PermitRootLogin no 로 바꾸고 일반 계정 로그인 후 sudo를 사용하세요.",
            port=int(port), evidence=f"PermitRootLogin {permit_root}", ref_url=REF["ssh"],
        ))

    pw_auth = (directive("PasswordAuthentication", "yes") or "").lower()
    if pw_auth == "yes":
        checks.append(_item(
            "account", "SSH 비밀번호 인증 허용", "medium", "warn",
            "키 기반 인증 대신 비밀번호 인증이 허용되어 무차별 대입에 노출됩니다.",
            "공개키 인증으로 전환한 뒤 PasswordAuthentication no 로 설정하세요.",
            port=int(port), evidence=f"PasswordAuthentication {pw_auth}", ref_url=REF["ssh"],
        ))
    return checks


def _ssh_permissions(client):
    checks = []
    out = _run(client, "stat -c '%n %a' /etc/passwd /etc/shadow 2>/dev/null")
    bad = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        name, mode = parts
        if name.endswith("/shadow") and mode not in ("000", "400", "600", "640"):
            bad.append(f"{name} {mode}")
        if name.endswith("/passwd") and mode not in ("644", "444"):
            bad.append(f"{name} {mode}")
    if bad:
        checks.append(_item(
            "os", "주요 계정 파일 권한 과다", "high", "fail",
            "권한이 느슨한 파일: " + ", ".join(bad),
            "chmod 644 /etc/passwd, chmod 600 /etc/shadow 로 조정하세요.",
            evidence=out[:300],
        ))
    return checks


def _safe_err(e):
    """예외 메시지에서 자격증명이 새지 않도록 짧게 정리한다."""
    msg = str(e)
    return (msg[:120] + "…") if len(msg) > 120 else msg
