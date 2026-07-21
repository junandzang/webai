"""NVD(National Vulnerability Database) 실시간 CVE 조회.

제품/버전 키워드로 NVD REST API를 질의해 상위 CVE를 가져온다.
사내 프록시·TLS 오류·타임아웃 등으로 실패하면 조용히 빈 결과를 반환하고,
호출부는 오프라인 규칙 결과만으로 계속 진행한다(기능이 항상 동작).
"""

import json
import ssl
import urllib.parse
import urllib.request

import config

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = 8


def _ssl_context():
    if config.NVD_INSECURE:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if config.NVD_CA_BUNDLE:
        return ssl.create_default_context(cafile=config.NVD_CA_BUNDLE)
    return ssl.create_default_context()


def available():
    """NVD 조회를 시도해볼 수 있는 상태인지 가볍게 확인한다."""
    return _probe()


def _probe():
    try:
        _query({"resultsPerPage": "1"})
        return True
    except Exception:
        return False


def _query(params):
    url = NVD_URL + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "operator-site-scanner"})
    if config.NVD_API_KEY:
        req.add_header("apiKey", config.NVD_API_KEY)
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ssl_context()) as r:
        return json.loads(r.read().decode("utf-8"))


def lookup(keyword, limit=5):
    """키워드(예: 'OpenSSH 8.9')로 CVE 상위 N건을 조회한다.

    성공 시 [{"id","score","severity","summary"}], 실패 시 [] 를 반환한다.
    """
    if not keyword or not keyword.strip():
        return []
    try:
        data = _query({
            "keywordSearch": keyword.strip(),
            "resultsPerPage": str(limit),
        })
    except Exception:
        return []

    out = []
    for v in data.get("vulnerabilities", [])[:limit]:
        cve = v.get("cve", {})
        cid = cve.get("id", "")
        # 영어 설명 추출
        summary = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                summary = d.get("value", "")
                break
        score, sev = _cvss(cve.get("metrics", {}))
        out.append({
            "id": cid,
            "score": score,
            "severity": sev,
            "summary": summary[:300],
        })
    return out


def _cvss(metrics):
    """metrics 블록에서 대표 CVSS 점수와 심각도를 뽑는다."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            m = arr[0]
            data = m.get("cvssData", {})
            score = data.get("baseScore")
            sev = (m.get("baseSeverity") or data.get("baseSeverity") or "").lower()
            return score, sev
    return None, ""
