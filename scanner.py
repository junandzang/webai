"""보안검사 오케스트레이터.

nmap을 실행해 대상 서버를 스캔하고, 결과를 규칙 엔진(rules.py)과
NVD 조회(nvd.py)로 체크리스트화한 뒤 DB에 저장한다.
백그라운드 스레드에서 run_scan(scan_id, server_id, ip)로 호출된다.
"""

import os
import shutil
import subprocess
import xml.etree.ElementTree as ET

import config
import db
import nvd
import rules

# 스캔할 상위 포트 수와 실행할 NSE 스크립트
TOP_PORTS = "200"
NSE_SCRIPTS = (
    "banner,ssl-enum-ciphers,ftp-anon,ssh2-enum-algos,"
    "http-security-headers,redis-info,mongodb-info,ms-sql-info"
)
# 대상 1대 스캔 상한 (초). NSE 포함이라 넉넉히 준다.
SCAN_TIMEOUT = 240

# NVD 조회를 걸 대표 서비스(제품이 있는 포트) 상한
NVD_MAX_LOOKUPS = 6


def find_nmap():
    """nmap 실행 파일 경로를 찾는다. 없으면 None."""
    if config.NMAP_PATH and os.path.isfile(config.NMAP_PATH):
        return config.NMAP_PATH
    found = shutil.which("nmap")
    if found:
        return found
    for p in (
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ):
        if os.path.isfile(p):
            return p
    return None


def run_nmap(nmap_path, ip):
    """nmap을 실행해 XML 문자열을 반환한다. 실패 시 예외."""
    cmd = [
        nmap_path,
        "-sT",              # TCP connect 스캔
        "-sV",              # 서비스/버전 탐지
        "-O",               # OS 지문 (가능하면). 안 되면 nmap이 건너뛰고 계속 진행
        "--osscan-guess",   # 정확한 매치가 없어도 근접 추정을 반환
        "-Pn",              # 핑 생략 (방화벽이 ICMP를 막아도 스캔)
        "--top-ports", TOP_PORTS,
        "--script", NSE_SCRIPTS,
        "--host-timeout", f"{SCAN_TIMEOUT}s",
        "-oX", "-",         # XML을 stdout으로
        ip,
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=SCAN_TIMEOUT + 30,
    )
    if not proc.stdout.strip():
        raise RuntimeError(proc.stderr.strip() or "nmap이 출력을 내지 않았습니다.")
    return proc.stdout


def parse_nmap_xml(xml_text):
    """nmap XML을 규칙 엔진이 쓰는 dict로 변환한다."""
    root = ET.fromstring(xml_text)
    host = root.find("host")
    result = {"reachable": False, "os": "", "ports": []}
    if host is None:
        return result

    status = host.find("status")
    state = status.get("state") if status is not None else None

    ports_el = host.find("ports")
    os_hints = []
    if ports_el is not None:
        for port in ports_el.findall("port"):
            st = port.find("state")
            svc = port.find("service")
            scripts = [
                {"id": s.get("id", ""), "output": s.get("output", "")}
                for s in port.findall("script")
            ]
            entry = {
                "port": int(port.get("portid")),
                "state": st.get("state") if st is not None else "unknown",
                "service": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "tunnel": svc.get("tunnel", "") if svc is not None else "",
                "scripts": scripts,
            }
            result["ports"].append(entry)
            # 서비스 배너/버전에 담긴 배포판 힌트 수집 (최후 보조용)
            if svc is not None:
                for field in ("extrainfo", "version", "product"):
                    val = svc.get(field) or ""
                    if val:
                        os_hints.append(val)

    result["os"] = _detect_os(host, os_hints)
    result["os_evidence"] = _os_evidence(host)

    # -Pn이라 host state는 대개 up이다. 포트 정보가 하나라도 있어야
    # 실제로 스캔이 된 것으로 본다(전부 필터링되면 ports가 비어 있음).
    result["reachable"] = state == "up" and len(result["ports"]) > 0
    return result


def _os_evidence(host):
    """nmap -O 상위 추정치를 근거 문자열로 만든다."""
    os_el = host.find("./os")
    if os_el is None:
        return ""
    guesses = [
        f"{m.get('name')} ({m.get('accuracy')}%)"
        for m in os_el.findall("osmatch")[:4]
    ]
    return "nmap -O 추정: " + ", ".join(guesses) if guesses else ""


# 배너에 나타나는 배포판 키워드 (표시명)
_DISTRO_MARKERS = [
    ("ubuntu", "Ubuntu"), ("debian", "Debian"), ("centos", "CentOS"),
    ("red hat", "Red Hat"), ("rhel", "RHEL"), ("rocky", "Rocky Linux"),
    ("almalinux", "AlmaLinux"), ("alma", "AlmaLinux"), ("fedora", "Fedora"),
    ("amazon linux", "Amazon Linux"), ("suse", "SUSE"), ("alpine", "Alpine"),
    ("gentoo", "Gentoo"), ("freebsd", "FreeBSD"),
]


# 임베디드/오탐이 잦아 커널 라벨로 신뢰하지 않을 osmatch 이름 키워드
_NOISY_OS_NAMES = ("openwrt", "android", "nintendo", "hp ", "embedded",
                   "router", "webcam", "printer", "switch")


def _detect_os(host, os_hints):
    """OS를 판정한다. 우선순위: 배너 배포판 > nmap -O 지문 > 미상.

    Avast 프록시 등 오탐을 부르는 'Service Info: OS'는 무시하고,
    -O는 osfamily(계열)만 신뢰하며 구체적 커널 라벨은 깨끗한 Linux 매치에서만 취한다.
    """
    hint_text = " ".join(os_hints)
    low = hint_text.lower()

    # 0) 배너에 배포판이 그대로 있으면 가장 구체적이고 정확하다.
    distro = ""
    for key, label in _DISTRO_MARKERS:
        if key in low:
            distro = label
            break

    # 1) -O 지문 집계: 계열(osfamily)만 신뢰한다.
    #    커널/버전 라벨은 실행마다 흔들리고(2.4.18, 3.2-4.14, OpenWrt…) 앞단
    #    보안 프록시가 있으면 특히 부정확하므로 OS 문자열에 넣지 않는다.
    #    (상세 추정치는 os_evidence로 따로 보여준다.)
    families = []
    os_el = host.find("./os")
    if os_el is not None:
        for m in os_el.findall("osmatch"):
            for oc in m.findall("osclass"):
                fam = oc.get("osfamily") or ""
                if fam:
                    families.append(fam)

    family = max(set(families), key=families.count) if families else ""

    # 2) 조합해서 표기 (배너 배포판이 있으면 가장 구체적)
    if family.lower() == "linux" or (not family and distro):
        return f"Linux ({distro})" if distro else "Linux"
    if family and family.lower() != "linux":
        return family  # Windows/BSD 등은 계열만 신뢰

    # 3) -O도 배너도 없으면 미상
    return f"Linux ({distro})" if distro else ""


def _enrich_with_nvd(checks, scan_result):
    """열린 서비스의 제품/버전으로 NVD를 조회해 CVE를 병합한다.

    반환: "nvd"(조회 성공) 또는 "offline"(실패/차단).
    """
    open_ports = [p for p in scan_result["ports"] if p["state"] == "open"]
    targets = []
    for p in open_ports:
        if p.get("product"):
            kw = (p["product"] + " " + p.get("version", "")).strip()
            targets.append((p["port"], kw))
    # OS도 조회 대상에 포함
    if scan_result.get("os"):
        targets.insert(0, (None, scan_result["os"]))

    if not targets:
        return "offline"
    if not nvd.available():
        return "offline"

    source = "offline"
    for port, kw in targets[:NVD_MAX_LOOKUPS]:
        cves = nvd.lookup(kw)
        if not cves:
            continue
        source = "nvd"
        ids = [c["id"] for c in cves]
        top = cves[0]
        # 관련 체크 항목에 CVE를 붙이고, 없으면 새 항목을 만든다.
        attached = False
        for c in checks:
            if port is not None and c.get("port") == port:
                c["cve_ids"] = list(dict.fromkeys(c["cve_ids"] + ids))
                attached = True
        if not attached:
            sev = _nvd_sev(top)
            rules_item = {
                "category": "os" if port is None else "service",
                "title": f"알려진 취약점(CVE) 발견: {kw}",
                "severity": sev,
                "result": "fail" if sev in ("critical", "high") else "warn",
                "port": port,
                "detail": f"{top['id']} ({top.get('severity') or '?'}, "
                          f"CVSS {top.get('score')}): {top.get('summary', '')}",
                "evidence": ", ".join(ids),
                "remediation": f"{kw}를 보안 패치가 적용된 최신 버전으로 업데이트하세요. "
                               "NVD 링크에서 영향 버전과 CVSS·완화책을 확인하세요.",
                "cve_ids": ids,
                "ref_url": f"https://nvd.nist.gov/vuln/detail/{top['id']}",
            }
            checks.append(rules_item)
    return source


def _run_credentialed(ip, creds, reachable=None):
    """자격증명이 주어진 항목만 계정 기반 점검을 수행한다.

    creds 예: {"db": {"port":3306,"user":"...","password":"..."},
               "ssh": {"port":22,"user":"...","password":"..."}}
    reachable: nmap이 외부에서 열려 있다고 확인한 포트 집합.
    자격증명은 여기서만 쓰이고 반환값·DB에 남기지 않는다.
    """
    import credaudit

    out = []
    ssh = creds.get("ssh")
    if ssh and ssh.get("user"):
        out.extend(credaudit.audit_ssh(ip, ssh.get("port") or 22,
                                       ssh["user"], ssh.get("password") or "",
                                       reachable=reachable))
    dbc = creds.get("db")
    if dbc and dbc.get("user"):
        out.extend(credaudit.audit_mysql(ip, dbc.get("port") or 3306,
                                         dbc["user"], dbc.get("password") or ""))
    return out


def _nvd_sev(cve):
    sev = (cve.get("severity") or "").lower()
    if sev in ("critical", "high", "medium", "low"):
        return "high" if sev == "critical" else sev
    score = cve.get("score") or 0
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def run_scan(scan_id, server_id, ip, creds=None):
    """백그라운드 스레드 엔트리. 스캔을 수행하고 결과를 DB에 기록한다.

    creds가 주어지면 계정 기반 심층 점검(credaudit)을 함께 수행해 같은
    체크리스트에 합친다. creds는 메모리에서만 쓰이고 저장하지 않는다.
    """
    try:
        db.set_scan_running(scan_id)

        nmap_path = find_nmap()
        if not nmap_path:
            db.set_scan_error(
                scan_id,
                "nmap을 찾을 수 없습니다. 설치 후 .env의 NMAP_PATH를 지정하세요.",
            )
            return

        xml_text = run_nmap(nmap_path, ip)
        scan_result = parse_nmap_xml(xml_text)

        checks = rules.build_checklist(scan_result)
        source = _enrich_with_nvd(checks, scan_result)

        # 계정 기반 심층 점검 (자격증명이 주어졌을 때만)
        authed = 0
        if creds:
            import credaudit
            # nmap이 외부에서 열려 있다고 확인한 포트 → LISTEN 목록과 대조해
            # '실제로 밖에서 닿는 포트'를 가려낸다.
            reachable = {p["port"] for p in scan_result["ports"] if p["state"] == "open"}
            checks.extend(_run_credentialed(ip, creds, reachable))
            authed = 1
            # SSH로 정확한 OS를 확인했으면 그 값을 우선한다.
            for c in checks:
                if c["category"] == "os" and c["title"].startswith(credaudit.OS_OK_PREFIX):
                    scan_result["os"] = c["title"].split(":", 1)[1].strip()
                    break

        # 이 서버에 실제로 접근 가능한 경로를 기록한다 (OS/DB/WEB)
        import credaudit as _ca
        can_os = any(c["title"].startswith(_ca.OS_OK_PREFIX) for c in checks)
        can_db = any(c["title"].startswith(_ca.DB_OK_PREFIX) for c in checks)
        can_web = any(
            p["state"] == "open"
            and (p["port"] in rules.WEB_PORTS or p.get("service", "").startswith("http"))
            for p in scan_result["ports"]
        )
        db.update_server_caps(server_id, can_os, can_db, can_web)

        # OS를 파악했으면 서버 레코드에 반영
        if scan_result.get("os"):
            db.update_server_os(server_id, scan_result["os"])

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for c in checks:
            db.add_check(scan_id, c)
            if c["result"] in ("fail", "warn"):
                counts[c["severity"]] += 1

        # 접근 불가한 대상은 점수를 매기지 않는다(미진단 표시). 점검이 안 됐는데
        # 취약이 0건이라고 100점으로 보이면 오해를 준다.
        score = db.compute_score(checks) if scan_result.get("reachable") else None

        db.set_scan_done(
            scan_id,
            os_detected=scan_result.get("os", ""),
            scan_source=source,
            counts=counts,
            score=score,
            authed=authed,
        )
    except subprocess.TimeoutExpired:
        db.set_scan_error(scan_id, "스캔이 시간 초과되었습니다.")
    except Exception as e:  # 스캔 실패는 사용자 메시지로 정리
        db.set_scan_error(scan_id, f"스캔 실패: {e}")
