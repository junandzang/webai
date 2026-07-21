"""보안 점검 규칙 엔진 (오프라인).

nmap 스캔 결과(열린 포트/서비스/버전/NSE 스크립트 출력)를 받아
체크리스트 항목 리스트로 변환한다. 인터넷 없이 동작한다.

각 체크리스트 항목(dict) 형식:
    {
        "category": "os|port|service|web|db|account",
        "title":    str,
        "severity": "critical|high|medium|low|info",
        "result":   "fail|warn|pass|info",
        "port":     int | None,
        "detail":   str,          # 문제 상세
        "evidence": str,          # 근거(배너/스크립트 출력)
        "remediation": str,       # 조치 방법
        "cve_ids":  [str, ...],   # NVD 병합 전에는 보통 빈 리스트
    }
"""

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEVERITY_LABEL = {
    "critical": "심각",
    "high": "높음",
    "medium": "보통",
    "low": "낮음",
    "info": "정보",
}
RESULT_LABEL = {"fail": "취약", "warn": "주의", "pass": "양호", "info": "정보"}
CATEGORY_LABEL = {
    "os": "운영체제",
    "port": "열린 포트",
    "service": "서비스",
    "web": "웹",
    "db": "데이터베이스",
    "account": "계정 탈취",
}

# 평문(비암호화) 인증을 쓰는 위험한 서비스: 포트 -> (이름, 설명)
PLAINTEXT_SERVICES = {
    21: ("FTP", "인증정보와 데이터가 평문으로 오가 도청 시 계정이 탈취될 수 있습니다."),
    23: ("Telnet", "모든 통신이 평문이라 도청만으로 관리자 계정이 탈취됩니다."),
    25: ("SMTP", "STARTTLS 없이 노출되면 자격증명이 평문으로 노출될 수 있습니다."),
    110: ("POP3", "평문 인증 시 메일 계정이 도청으로 탈취될 수 있습니다."),
    143: ("IMAP", "평문 인증 시 메일 계정이 도청으로 탈취될 수 있습니다."),
}

# 외부에 노출되면 위험한 원격 관리 서비스: 포트 -> (이름, 심각도, 설명)
REMOTE_ADMIN_SERVICES = {
    22: ("SSH", "medium", "무차별 대입(brute-force) 공격의 표적이 됩니다."),
    3389: ("RDP", "high", "무차별 대입과 BlueKeep 등 원격 코드 실행 취약점의 표적입니다."),
    5900: ("VNC", "high", "약한 인증이 많아 화면·계정 탈취로 이어질 수 있습니다."),
    5985: ("WinRM", "medium", "원격 관리 인터페이스가 외부에 노출되어 있습니다."),
}

# 데이터베이스 서비스: 포트 -> (이름, 무인증 확인용 NSE 스크립트 id or None)
DB_SERVICES = {
    3306: ("MySQL/MariaDB", None),
    5432: ("PostgreSQL", None),
    1433: ("Microsoft SQL Server", "ms-sql-info"),
    1521: ("Oracle DB", None),
    27017: ("MongoDB", "mongodb-info"),
    6379: ("Redis", "redis-info"),
    9200: ("Elasticsearch", None),
    11211: ("Memcached", None),
    5984: ("CouchDB", None),
}

WEB_PORTS = {80, 8080, 8000, 8888, 443, 8443}
HTTPS_PORTS = {443, 8443}

# 지원 종료(EOL)된 대표 OS 버전. (부분 문자열, 설명)
EOL_OS_MARKERS = [
    ("windows server 2008", "Windows Server 2008/R2는 지원 종료되어 보안 패치가 없습니다."),
    ("windows server 2012", "Windows Server 2012/R2는 지원 종료되었습니다."),
    ("windows 7", "Windows 7은 지원 종료되었습니다."),
    ("ubuntu 14.04", "Ubuntu 14.04는 지원 종료되었습니다."),
    ("ubuntu 16.04", "Ubuntu 16.04는 표준 지원이 종료되었습니다."),
    ("ubuntu 18.04", "Ubuntu 18.04는 표준 지원이 종료되었습니다."),
    ("centos 6", "CentOS 6는 지원 종료되었습니다."),
    ("centos 7", "CentOS 7은 2024-06 지원 종료되었습니다."),
    ("centos 8", "CentOS 8은 조기 지원 종료되었습니다."),
    ("debian 8", "Debian 8(jessie)은 지원 종료되었습니다."),
    ("debian 9", "Debian 9(stretch)은 지원 종료되었습니다."),
]


def _sev_max(a, b):
    """두 심각도 중 더 높은 쪽을 반환한다."""
    return a if SEVERITY_ORDER.index(a) >= SEVERITY_ORDER.index(b) else b


def _item(category, title, severity, result, detail, remediation,
          port=None, evidence="", cve_ids=None, ref_url=""):
    return {
        "category": category,
        "title": title,
        "severity": severity,
        "result": result,
        "port": port,
        "detail": detail,
        "evidence": evidence,
        "remediation": remediation,
        "cve_ids": cve_ids or [],
        "ref_url": ref_url,
    }


# 조치 시 참고할 공식/신뢰 문서 URL
REF = {
    "plaintext": "https://owasp.org/www-community/vulnerabilities/Insecure_Transport",
    "ftp_anon": "https://datatracker.ietf.org/doc/html/rfc2577",
    "ssh": "https://infosec.mozilla.org/guidelines/openssh",
    "rdp": "https://learn.microsoft.com/windows-server/remote/remote-desktop-services/security-guidance",
    "vnc": "https://www.realvnc.com/en/connect/docs/security.html",
    "tls": "https://ssl-config.mozilla.org/",
    "headers": "https://owasp.org/www-project-secure-headers/",
    "firewall": "https://www.cisecurity.org/controls",
    "eol": "https://endoflife.date/",
    "mysql": "https://mariadb.com/kb/en/securing-mariadb/",
    "postgresql": "https://www.postgresql.org/docs/current/runtime-config-connection.html",
    "mssql": "https://learn.microsoft.com/sql/relational-databases/security/securing-sql-server",
    "oracle": "https://docs.oracle.com/en/database/oracle/oracle-database/",
    "mongodb": "https://www.mongodb.com/docs/manual/administration/security-checklist/",
    "redis": "https://redis.io/docs/latest/operate/oss_and_stack/management/security/",
    "elasticsearch": "https://www.elastic.co/guide/en/elasticsearch/reference/current/secure-cluster.html",
    "db_generic": "https://www.cisecurity.org/cis-benchmarks",
}

# DB 제품별 보안 가이드 URL (표시명 -> REF 키)
_DB_REF = {
    "MySQL/MariaDB": "mysql", "PostgreSQL": "postgresql",
    "Microsoft SQL Server": "mssql", "Oracle DB": "oracle",
    "MongoDB": "mongodb", "Redis": "redis", "Elasticsearch": "elasticsearch",
}


def _script_output(port, script_id):
    """포트 dict에서 특정 NSE 스크립트의 출력 문자열을 찾는다. 없으면 None."""
    for s in port.get("scripts", []):
        if s["id"] == script_id:
            return s["output"] or ""
    return None


def build_checklist(scan):
    """스캔 결과 dict를 체크리스트 항목 리스트로 변환한다.

    scan 형식(scanner.parse_nmap_xml 반환):
        {
            "reachable": bool,
            "os": str,
            "ports": [
                {"port": int, "state": "open|closed|filtered",
                 "service": str, "product": str, "version": str,
                 "tunnel": str,  # "ssl" 등
                 "scripts": [{"id": str, "output": str}, ...]},
                ...
            ],
        }
    """
    checks = []
    if not scan.get("reachable"):
        checks.append(_item(
            "port", "대상에 접근할 수 없음", "info", "info",
            "호스트가 응답하지 않거나 모든 포트가 필터링되어 점검을 진행할 수 없습니다.",
            "IP·방화벽·네트워크 경로를 확인하세요.",
        ))
        return checks

    open_ports = [p for p in scan["ports"] if p["state"] == "open"]

    checks.append(_check_os(scan.get("os", ""), open_ports, scan.get("os_evidence", "")))
    checks.extend(_check_ports(open_ports))
    checks.extend(_check_web(open_ports))
    checks.extend(_check_db(open_ports))

    if not any(c["result"] in ("fail", "warn") for c in checks):
        checks.append(_item(
            "port", "위험한 노출 없음", "info", "pass",
            "점검한 범위에서 위험하게 노출된 포트·서비스가 발견되지 않았습니다.",
            "정기적으로 재점검하세요.",
        ))
    return checks


def _server_versions(open_ports):
    """탐지된 주요 서버 소프트웨어 버전 요약 문자열. (근거로 사용)"""
    seen = []
    for p in open_ports:
        prod = p.get("product", "")
        if prod:
            label = (prod + " " + p.get("version", "")).strip()
            if label not in seen:
                seen.append(label)
    return ", ".join(seen)


def _check_os(os_text, open_ports, os_evidence=""):
    versions = _server_versions(open_ports)
    ver_note = f" 탐지된 주요 서비스 버전: {versions}." if versions else ""
    evidence = "\n".join(x for x in (os_evidence, versions and ("서비스: " + versions)) if x)

    if not os_text:
        return _item(
            "os", "OS 식별 실패", "info", "info",
            "OS 계열을 특정하지 못했습니다." + ver_note,
            "정확한 배포판/버전은 대상 서버에서 직접 확인하세요.",
            evidence=evidence,
        )
    low = os_text.lower()
    for marker, desc in EOL_OS_MARKERS:
        if marker in low:
            return _item(
                "os", f"지원 종료(EOL) OS: {os_text}", "high", "fail",
                desc + " 신규 취약점이 발견돼도 보안 패치를 받지 못합니다." + ver_note,
                "지원 기간 내인 최신 LTS/릴리스로 업그레이드하고, 이관 전까지는 접근 통제·"
                "가상 패치(WAF/IPS)로 위험을 완화하세요. endoflife.date에서 각 제품의 "
                "지원 종료일을 확인할 수 있습니다.",
                evidence=evidence, ref_url=REF["eol"],
            )
    return _item(
        "os", f"운영체제: {os_text}", "info", "pass",
        "OS 계열을 확인했습니다. 정확한 커널·배포판 버전은 원격 지문만으로는 "
        "특정이 어려우니(앞단 보안 프록시/방화벽 영향) 서버에서 직접 확인을 권장합니다."
        + ver_note,
        "OS와 주요 서비스의 보안 업데이트를 최신 상태로 유지하세요.",
        evidence=evidence,
    )


def _svc_str(p):
    parts = [p.get("product", ""), p.get("version", "")]
    s = " ".join(x for x in parts if x).strip()
    return s or p.get("service", "") or "unknown"


def _check_ports(open_ports):
    checks = []
    for p in open_ports:
        port = p["port"]
        evidence = f"{port}/tcp {_svc_str(p)}"

        # 평문 인증 서비스
        if port in PLAINTEXT_SERVICES:
            name, desc = PLAINTEXT_SERVICES[port]
            # 익명 FTP 허용은 계정 탈취(critical)로 승격
            if port == 21:
                anon = _script_output(p, "ftp-anon")
                if anon and "Anonymous FTP login allowed" in anon:
                    checks.append(_item(
                        "account", f"익명 FTP 로그인 허용 ({port}/tcp)",
                        "critical", "fail",
                        "인증 없이 FTP에 접속할 수 있어 파일 열람·업로드로 이어질 수 있습니다.",
                        "vsftpd는 vsftpd.conf에서 anonymous_enable=NO로 익명 접속을 끄고, "
                        "ProFTPD는 <Anonymous> 블록을 제거하세요. 파일 전송은 SFTP(22) 또는 "
                        "명시적 FTPS(TLS)로 전환하고, 데몬을 재시작해 반영하세요.",
                        port=port, evidence=anon.strip(), ref_url=REF["ftp_anon"],
                    ))
            checks.append(_item(
                "port", f"평문 인증 서비스 노출: {name} ({port}/tcp)",
                "high", "fail", desc,
                f"{name}는 자격증명을 평문으로 전송합니다. 서비스를 끄거나 암호화된 대체 "
                "프로토콜(FTP→SFTP/FTPS, Telnet→SSH, SMTP/POP3/IMAP→STARTTLS 또는 "
                "SSL 포트 465/993/995)로 전환하고, 방화벽으로 신뢰 대역만 허용하세요.",
                port=port, evidence=evidence, ref_url=REF["plaintext"],
            ))
            continue

        # 원격 관리 서비스
        if port in REMOTE_ADMIN_SERVICES:
            name, sev, desc = REMOTE_ADMIN_SERVICES[port]
            result = "warn" if sev == "medium" else "fail"
            ref = REF["rdp"] if port == 3389 else (
                REF["vnc"] if port == 5900 else REF["ssh"])
            remediation = (
                "방화벽/보안그룹에서 접근 출발지 IP를 화이트리스트로 제한하고, "
                "가능하면 VPN·베스천(점프) 호스트 뒤로 옮기세요. 강한 인증과 MFA를 적용하고, "
                "fail2ban 등으로 무차별 대입을 차단하세요.")
            if port == 22:
                remediation += (" SSH는 PasswordAuthentication no(키 기반 인증) + "
                                "PermitRootLogin no로 sshd_config를 강화하세요.")
            elif port == 3389:
                remediation += (" RDP는 네트워크 수준 인증(NLA)을 켜고 최신 보안 패치를 "
                                "적용하세요(BlueKeep 등).")
            item = _item(
                "port", f"원격 관리 노출: {name} ({port}/tcp)", sev, result,
                f"{desc} 인터넷에 직접 노출돼 있으면 계정 탈취 위험이 커집니다.",
                remediation, port=port, evidence=evidence, ref_url=ref,
            )
            # 약한 SSH 알고리즘
            if port == 22:
                algos = _script_output(p, "ssh2-enum-algos") or ""
                weak = [w for w in ("arcfour", "3des", "diffie-hellman-group1", "hmac-md5")
                        if w in algos.lower()]
                if weak:
                    item["severity"] = "high"
                    item["result"] = "fail"
                    item["detail"] += f" 약한 암호 알고리즘 사용: {', '.join(weak)}."
                    item["remediation"] += (
                        " sshd_config의 Ciphers/MACs/KexAlgorithms에서 arcfour·3des·"
                        "hmac-md5·diffie-hellman-group1을 제거하고 최신 알고리즘만 허용하세요.")
            checks.append(item)
            continue

        # 그 외 열린 포트는 정보성으로 기록 (DB/WEB은 별도 처리)
        if port not in DB_SERVICES and port not in WEB_PORTS:
            checks.append(_item(
                "port", f"열린 포트 {port}/tcp ({p.get('service', 'unknown')})",
                "low", "warn",
                "불필요하게 열린 포트는 공격 표면을 넓힙니다.",
                f"{port}/tcp에서 동작하는 서비스가 꼭 필요한지 확인하고, 불필요하면 "
                "해당 서비스를 중지하거나 방화벽에서 차단하세요. 필요하다면 접근 출발지 "
                "IP를 제한하세요.",
                port=port, evidence=evidence, ref_url=REF["firewall"],
            ))
    return checks


def _check_web(open_ports):
    checks = []
    web = [p for p in open_ports if p["port"] in WEB_PORTS
           or p.get("service", "").startswith("http")]
    if not web:
        return checks

    has_https = any(p["port"] in HTTPS_PORTS or p.get("tunnel") == "ssl" for p in web)
    has_plain_http = any(p["port"] not in HTTPS_PORTS and p.get("tunnel") != "ssl"
                         for p in web)

    for p in web:
        port = p["port"]
        is_tls = port in HTTPS_PORTS or p.get("tunnel") == "ssl"
        evidence = f"{port}/tcp {_svc_str(p)}"

        # 취약한 TLS 프로토콜/암호
        if is_tls:
            ciphers = _script_output(p, "ssl-enum-ciphers") or ""
            weak = [w for w in ("SSLv3", "TLSv1.0", "TLSv1.1") if w in ciphers]
            if weak or " C\n" in ciphers or "least strength: C" in ciphers:
                checks.append(_item(
                    "web", f"취약한 TLS 설정 ({port}/tcp)", "high", "fail",
                    f"오래된 프로토콜/약한 암호가 허용됩니다: {', '.join(weak) or '약한 암호군'}.",
                    "SSLv3·TLS 1.0/1.1을 비활성화하고 TLS 1.2 이상만 허용하세요. "
                    "RC4·3DES·NULL·EXPORT 암호군을 제거하고 최신 암호군만 남기세요. "
                    "Mozilla SSL Configuration Generator로 서버(nginx/Apache/HAProxy)별 "
                    "설정을 생성해 적용할 수 있습니다.",
                    port=port, evidence=(ciphers[:400] or evidence), ref_url=REF["tls"],
                ))
            else:
                checks.append(_item(
                    "web", f"HTTPS 제공 ({port}/tcp)", "info", "pass",
                    "TLS로 암호화된 웹 서비스입니다.",
                    "인증서 만료와 최신 TLS 설정을 주기적으로 점검하세요.",
                    port=port, evidence=evidence,
                ))

        # 보안 헤더 누락
        headers = _script_output(p, "http-security-headers")
        if headers is not None:
            missing = [h for h in ("Strict-Transport-Security", "Content-Security-Policy",
                                   "X-Frame-Options", "X-Content-Type-Options")
                       if h not in headers]
            if missing:
                checks.append(_item(
                    "web", f"보안 헤더 누락 ({port}/tcp)", "low", "warn",
                    "누락된 헤더: " + ", ".join(missing) + ".",
                    "웹 서버 설정에 보안 응답 헤더를 추가하세요. 예: "
                    "Strict-Transport-Security(HSTS), Content-Security-Policy, "
                    "X-Frame-Options: DENY, X-Content-Type-Options: nosniff. "
                    "nginx는 add_header, Apache는 Header set 지시자로 적용합니다.",
                    port=port, evidence=headers[:300], ref_url=REF["headers"],
                ))

    if has_plain_http and not has_https:
        checks.append(_item(
            "web", "HTTPS 미적용 (평문 HTTP)", "medium", "fail",
            "웹 서비스가 암호화 없이 제공되어 로그인 정보가 도청될 수 있습니다.",
            "Let's Encrypt 등으로 TLS 인증서를 발급해 HTTPS를 적용하고, "
            "HTTP(80)는 301로 HTTPS(443)로 리다이렉트하세요. 적용 후 HSTS 헤더로 "
            "브라우저가 항상 HTTPS를 쓰도록 강제하세요.",
            ref_url=REF["tls"],
        ))
    return checks


def _check_db(open_ports):
    checks = []
    for p in open_ports:
        port = p["port"]
        if port not in DB_SERVICES:
            continue
        name, unauth_script = DB_SERVICES[port]
        evidence = f"{port}/tcp {_svc_str(p)}"

        # 무인증 접근 확인 (Redis/Mongo 등) → 계정 탈취(critical)
        if unauth_script:
            out = _script_output(p, unauth_script)
            # 스크립트가 정보를 반환했다면 인증 없이 응답했다는 뜻이다.
            if out and out.strip():
                low = out.lower()
                unauth = ("authentication" not in low and "requirepass" not in low
                          and "unauthorized" not in low and "access denied" not in low)
                if unauth:
                    unauth_fix = {
                        "Redis": "redis.conf에 requirepass(또는 ACL)를 설정하고 "
                                 "bind 127.0.0.1 및 protected-mode yes로 외부 접근을 막으세요.",
                        "MongoDB": "security.authorization: enabled로 인증을 켜고 관리자 계정을 "
                                   "만든 뒤 bindIp를 내부 대역으로 제한하세요.",
                    }.get(name, f"{name}에 인증을 설정하세요.")
                    checks.append(_item(
                        "account", f"무인증 {name} 접근 가능 ({port}/tcp)",
                        "critical", "fail",
                        f"인증 없이 {name}에 접속해 데이터를 읽을 수 있습니다. 계정·데이터 탈취로 직결됩니다.",
                        unauth_fix + " 그리고 방화벽에서 외부 접근을 차단하세요.",
                        port=port, evidence=out[:300],
                        ref_url=REF.get(_DB_REF.get(name, "db_generic")),
                    ))
                    continue

        checks.append(_item(
            "db", f"데이터베이스 노출: {name} ({port}/tcp)", "high", "fail",
            f"{name} 포트가 외부에서 접근 가능합니다. 무차별 대입·데이터 유출 위험이 있습니다.",
            f"{name} 포트를 애플리케이션 서버 IP로만 허용하도록 방화벽/보안그룹을 좁히고, "
            "리슨 주소(bind-address 등)를 내부 인터페이스로 제한하세요. 강한 비밀번호·최소 권한 "
            "계정 정책을 적용하고 기본 계정을 비활성화하세요.",
            port=port, evidence=evidence,
            ref_url=REF.get(_DB_REF.get(name, "db_generic")),
        ))
    return checks


def worst_severity(checks):
    """취약/주의로 판정된 항목 중 가장 높은 심각도를 반환한다. 없으면 'info'."""
    worst = "info"
    for c in checks:
        if c["result"] in ("fail", "warn"):
            worst = _sev_max(worst, c["severity"])
    return worst
