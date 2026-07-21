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
        "-sT",              # TCP connect 스캔 (관리자 권한 불필요)
        "-sV",              # 서비스/버전 탐지
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
            # 서비스 지문에 담긴 OS 힌트 수집
            if svc is not None and svc.get("ostype"):
                os_hints.append(svc.get("ostype"))
            if svc is not None and svc.get("extrainfo"):
                info = svc.get("extrainfo")
                if any(k in info for k in ("Ubuntu", "Debian", "CentOS", "Win")):
                    os_hints.append(info)

    # nmap -O를 안 쓰므로 osmatch 대신 서비스 지문/스크립트로 OS 추정
    osmatch = host.find("./os/osmatch")
    if osmatch is not None:
        result["os"] = osmatch.get("name", "")
    elif os_hints:
        # 가장 많이 등장한 힌트 사용
        result["os"] = max(set(os_hints), key=os_hints.count)

    # -Pn이라 host state는 대개 up이다. 포트 정보가 하나라도 있어야
    # 실제로 스캔이 된 것으로 본다(전부 필터링되면 ports가 비어 있음).
    result["reachable"] = state == "up" and len(result["ports"]) > 0
    return result


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
                "remediation": "해당 제품/버전을 보안 패치가 적용된 최신 버전으로 업데이트하세요.",
                "cve_ids": ids,
            }
            checks.append(rules_item)
    return source


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


def run_scan(scan_id, server_id, ip):
    """백그라운드 스레드 엔트리. 스캔을 수행하고 결과를 DB에 기록한다."""
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

        # OS를 파악했으면 서버 레코드에 반영
        if scan_result.get("os"):
            db.update_server_os(server_id, scan_result["os"])

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for c in checks:
            db.add_check(scan_id, c)
            if c["result"] in ("fail", "warn"):
                counts[c["severity"]] += 1

        db.set_scan_done(
            scan_id,
            os_detected=scan_result.get("os", ""),
            scan_source=source,
            counts=counts,
        )
    except subprocess.TimeoutExpired:
        db.set_scan_error(scan_id, "스캔이 시간 초과되었습니다.")
    except Exception as e:  # 스캔 실패는 사용자 메시지로 정리
        db.set_scan_error(scan_id, f"스캔 실패: {e}")
