"""운영자 로그인 웹사이트 (FastAPI).

실행:  python -m uvicorn app:app --reload --port 8000
"""

import secrets
import threading
import time
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

import config
import db
import scanner
from db import (
    SERVER_STATUS,
    create_group,
    create_scan,
    create_server,
    delete_group,
    delete_server,
    get_operator,
    findings_by_severity,
    get_scan_checks,
    get_server,
    latest_scan,
    list_groups,
    list_servers,
    rename_group,
    scans_overview,
    severity_totals,
    status_summary,
    update_password,
    update_server,
    verify_password,
)
from rules import CATEGORY_LABEL, RESULT_LABEL, SEVERITY_LABEL

BASE_DIR = Path(__file__).resolve().parent

SESSION_EXPIRED = "세션이 만료되었습니다. 다시 로그인해주세요."

# ===== 로그인 시도 제한 (무차별 대입 방지) =====
LOGIN_MAX_TRIES = 5          # 이 횟수를 넘기면
LOGIN_LOCK_SECONDS = 300     # 이 시간(초) 동안 잠근다
_login_fails = {}            # {키: [실패횟수, 마지막실패시각]}


def _client_ip(request: Request) -> str:
    return (request.client.host if request.client else "") or ""


def _login_key(request: Request, username: str) -> str:
    return f"{_client_ip(request)}|{username.lower()}"


def _login_locked(key: str):
    """잠겨 있으면 남은 초를 반환, 아니면 0."""
    rec = _login_fails.get(key)
    if not rec:
        return 0
    tries, last = rec
    if tries < LOGIN_MAX_TRIES:
        return 0
    remain = int(LOGIN_LOCK_SECONDS - (time.time() - last))
    if remain <= 0:
        _login_fails.pop(key, None)
        return 0
    return remain


def _login_failed(key: str):
    tries, _last = _login_fails.get(key, (0, 0))
    _login_fails[key] = (tries + 1, time.time())


def _login_ok(key: str):
    _login_fails.pop(key, None)


# ===== CSRF =====
# 세션에 토큰을 두고, 상태를 바꾸는 POST 요청에서 헤더/폼 값과 대조한다.


def _csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


async def _csrf_ok(request: Request) -> bool:
    sent = request.headers.get("X-CSRF-Token", "")
    if not sent:
        try:
            form = await request.form()
            sent = str(form.get("csrf_token", ""))
        except Exception:
            sent = ""
    expected = request.session.get("csrf", "")
    return bool(expected) and secrets.compare_digest(sent, expected)

# servers.group_name 컬럼 길이와 맞춘다.
GROUP_NAME_MAX = 50

app = FastAPI(title="운영자 사이트")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

# CSRF: 상태를 바꾸는 POST는 X-CSRF-Token 헤더를 요구한다.
# 화면의 모든 상태 변경은 fetch()로 이뤄지므로 헤더 방식으로 충분하다.
# (로그인 폼은 일반 form POST라 예외 — 세션이 아직 없다)
CSRF_EXEMPT = {"/login"}


@app.middleware("http")
async def csrf_guard(request: Request, call_next):
    if request.method == "POST" and request.url.path not in CSRF_EXEMPT:
        if not await _csrf_ok(request):
            return JSONResponse(
                {"ok": False, "message": "요청이 유효하지 않습니다. 새로고침 후 다시 시도하세요."},
                status_code=403,
            )
    return await call_next(request)


# SessionMiddleware를 마지막에 추가해 가장 바깥에 두어야
# 위 csrf_guard에서 request.session을 읽을 수 있다.
app.add_middleware(SessionMiddleware, secret_key=config.SESSION_SECRET)

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if request.session.get("username"):
        return RedirectResponse("/dashboard", status_code=303)
    return RedirectResponse("/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if request.session.get("username"):
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": None, "username": ""},
    )


@app.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    username: str = Form(default=""),
    password: str = Form(default=""),
):
    username = username.strip()

    # 빈 입력 검증
    if not username or not password:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": "아이디와 비밀번호를 모두 입력해주세요.",
                "username": username,
            },
            status_code=400,
        )

    # 무차별 대입 방지: 연속 실패 시 일정 시간 잠근다.
    key = _login_key(request, username)
    locked = _login_locked(key)
    if locked:
        db.add_audit(username, "login_locked", ip=_client_ip(request),
                     detail=f"{locked}초 남음")
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": f"로그인 시도가 많아 잠겼습니다. {locked}초 후 다시 시도하세요.",
                "username": username,
            },
            status_code=429,
        )

    # 계정 조회 및 비밀번호 검증
    operator = get_operator(username)
    if operator is None or not verify_password(password, operator["password_hash"]):
        _login_failed(key)
        db.add_audit(username, "login_fail", ip=_client_ip(request))
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": "아이디 또는 비밀번호가 올바르지 않습니다.",
                "username": username,
            },
            status_code=401,
        )

    # 로그인 성공: 세션 설정
    _login_ok(key)
    request.session["username"] = operator["username"]
    _csrf_token(request)          # 이 세션의 CSRF 토큰 발급
    db.add_audit(operator["username"], "login", ip=_client_ip(request))
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, group: str = ""):
    username = request.session.get("username")
    if not username:
        return RedirectResponse("/login", status_code=303)

    groups = list_groups()
    group_names = [g["group_name"] for g in groups]

    # 요청한 그룹이 없으면 첫 번째 그룹을 기본 선택한다.
    selected = group if group in group_names else (group_names[0] if group_names else "")
    servers = list_servers(selected) if selected else []
    selected_group = next((g for g in groups if g["group_name"] == selected), None)

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "username": username,
            "groups": groups,
            "selected": selected,
            "selected_group": selected_group,
            "servers": servers,
            "summary": status_summary(),
            "sev_totals": severity_totals(),
            "status_labels": SERVER_STATUS,
        },
    )


@app.post("/change-password")
def change_password(
    request: Request,
    current_password: str = Form(default=""),
    new_password: str = Form(default=""),
    confirm_password: str = Form(default=""),
):
    username = request.session.get("username")
    if not username:
        return JSONResponse({"ok": False, "message": SESSION_EXPIRED}, status_code=401)

    if not current_password or not new_password or not confirm_password:
        return JSONResponse(
            {"ok": False, "message": "모든 항목을 입력해주세요."}, status_code=400
        )

    operator = get_operator(username)
    if operator is None or not verify_password(
        current_password, operator["password_hash"]
    ):
        return JSONResponse(
            {"ok": False, "message": "현재 비밀번호가 올바르지 않습니다."},
            status_code=400,
        )

    if new_password != confirm_password:
        return JSONResponse(
            {"ok": False, "message": "새 비밀번호가 서로 일치하지 않습니다."},
            status_code=400,
        )

    if len(new_password) < 4:
        return JSONResponse(
            {"ok": False, "message": "새 비밀번호는 4자 이상이어야 합니다."},
            status_code=400,
        )

    if new_password == current_password:
        return JSONResponse(
            {"ok": False, "message": "새 비밀번호가 현재 비밀번호와 동일합니다."},
            status_code=400,
        )

    update_password(username, new_password)
    return JSONResponse({"ok": True, "message": "비밀번호가 변경되었습니다."})


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ===== 서버 관리 API =====


def _validate_server_form(group_name, name, status):
    """서버 입력값을 검증한다. 문제가 없으면 None, 있으면 오류 메시지를 반환한다."""
    if not group_name or not name:
        return "그룹명과 서버명은 필수입니다."
    if status not in SERVER_STATUS:
        return "상태값이 올바르지 않습니다."
    return None


@app.post("/api/servers")
def api_create_server(
    request: Request,
    group_name: str = Form(default=""),
    name: str = Form(default=""),
    ip: str = Form(default=""),
    os_name: str = Form(default=""),
    role: str = Form(default=""),
    status: str = Form(default="ok"),
    ssh_port: str = Form(default="22"),
    ssh_user: str = Form(default=""),
    ssh_password: str = Form(default=""),
    db_port: str = Form(default="3306"),
    db_user: str = Form(default=""),
    db_password: str = Form(default=""),
):
    if not request.session.get("username"):
        return JSONResponse({"ok": False, "message": SESSION_EXPIRED}, status_code=401)

    group_name, name = group_name.strip(), name.strip()
    error = _validate_server_form(group_name, name, status)
    if error:
        return JSONResponse({"ok": False, "message": error}, status_code=400)

    ok, message = create_server(
        group_name, name, ip.strip(), os_name.strip(), role.strip(), status
    )
    if ok:
        # 방금 만든 서버에 자격증명을 붙인다(비밀번호는 암호화 저장).
        new = db.get_server_by_name(name)
        if new:
            db.save_server_credentials(
                new["id"], ssh_port, ssh_user, ssh_password,
                db_port, db_user, db_password,
            )
    return JSONResponse({"ok": ok, "message": message}, status_code=200 if ok else 400)


@app.post("/api/servers/{server_id}")
def api_update_server(
    request: Request,
    server_id: int,
    group_name: str = Form(default=""),
    name: str = Form(default=""),
    ip: str = Form(default=""),
    os_name: str = Form(default=""),
    role: str = Form(default=""),
    status: str = Form(default="ok"),
    ssh_port: str = Form(default="22"),
    ssh_user: str = Form(default=""),
    ssh_password: str = Form(default=""),
    db_port: str = Form(default="3306"),
    db_user: str = Form(default=""),
    db_password: str = Form(default=""),
):
    if not request.session.get("username"):
        return JSONResponse({"ok": False, "message": SESSION_EXPIRED}, status_code=401)

    group_name, name = group_name.strip(), name.strip()
    error = _validate_server_form(group_name, name, status)
    if error:
        return JSONResponse({"ok": False, "message": error}, status_code=400)

    ok, message = update_server(
        server_id, group_name, name, ip.strip(), os_name.strip(), role.strip(), status
    )
    if ok:
        # 비밀번호를 비워두면 기존 저장값을 유지한다.
        db.save_server_credentials(
            server_id, ssh_port, ssh_user, ssh_password,
            db_port, db_user, db_password,
        )
        # 자격증명 변경은 감사 대상. 비밀번호 값 자체는 기록하지 않는다.
        if ssh_password or db_password:
            db.add_audit(request.session["username"], "cred_update", target=name,
                         ip=_client_ip(request),
                         detail=f"ssh={bool(ssh_password)} db={bool(db_password)}")
    return JSONResponse({"ok": ok, "message": message}, status_code=200 if ok else 400)


@app.post("/api/servers/{server_id}/delete")
def api_delete_server(request: Request, server_id: int):
    if not request.session.get("username"):
        return JSONResponse({"ok": False, "message": SESSION_EXPIRED}, status_code=401)

    if not delete_server(server_id):
        return JSONResponse(
            {"ok": False, "message": "이미 삭제된 서버입니다."}, status_code=404
        )
    return JSONResponse({"ok": True, "message": "서버가 삭제되었습니다."})


def _validate_group_name(name):
    """그룹명을 검증한다. 문제가 없으면 None, 있으면 오류 메시지를 반환한다."""
    if not name:
        return "그룹명을 입력해주세요."
    if len(name) > GROUP_NAME_MAX:
        return f"그룹명은 {GROUP_NAME_MAX}자 이하여야 합니다."
    return None


@app.post("/api/groups")
def api_create_group(request: Request, name: str = Form(default="")):
    if not request.session.get("username"):
        return JSONResponse({"ok": False, "message": SESSION_EXPIRED}, status_code=401)

    name = name.strip()
    error = _validate_group_name(name)
    if error:
        return JSONResponse({"ok": False, "message": error}, status_code=400)

    ok, message = create_group(name)
    return JSONResponse({"ok": ok, "message": message}, status_code=200 if ok else 400)


@app.post("/api/groups/delete")
def api_delete_group(request: Request, name: str = Form(default="")):
    if not request.session.get("username"):
        return JSONResponse({"ok": False, "message": SESSION_EXPIRED}, status_code=401)

    name = name.strip()
    if not name:
        return JSONResponse(
            {"ok": False, "message": "그룹명을 입력해주세요."}, status_code=400
        )

    ok, message = delete_group(name)
    if ok:
        return JSONResponse({"ok": True, "message": message})
    # 존재하지 않으면 404, 서버가 남아 있어 거부한 경우는 400
    status = 404 if "존재하지 않는" in message else 400
    return JSONResponse({"ok": False, "message": message}, status_code=status)


@app.post("/api/groups/rename")
def api_rename_group(
    request: Request,
    old_name: str = Form(default=""),
    new_name: str = Form(default=""),
):
    if not request.session.get("username"):
        return JSONResponse({"ok": False, "message": SESSION_EXPIRED}, status_code=401)

    old_name, new_name = old_name.strip(), new_name.strip()
    error = _validate_group_name(new_name) or _validate_group_name(old_name)
    if error:
        return JSONResponse({"ok": False, "message": error}, status_code=400)
    if old_name == new_name:
        return JSONResponse(
            {"ok": False, "message": "기존 그룹명과 동일합니다."}, status_code=400
        )

    ok, message = rename_group(old_name, new_name)
    return JSONResponse({"ok": ok, "message": message}, status_code=200 if ok else 404)


# ===== 보안검사(스캔) =====


def _scan_status_payload(scan):
    """폴링 응답/템플릿에서 공통으로 쓰는 스캔 요약 dict."""
    if not scan:
        return {"status": "none"}
    return {
        "status": scan["status"],
        "scan_id": scan["id"],
        "target_ip": scan["target_ip"],
        "os_detected": scan["os_detected"],
        "scan_source": scan["scan_source"],
        "error_message": scan["error_message"],
        "score": scan["score"],
        "counts": {
            "critical": scan["crit"], "high": scan["high"], "med": scan["med"],
            "low": scan["low"], "info": scan["info"],
        },
    }


@app.post("/api/servers/{server_id}/scan")
def api_start_scan(request: Request, server_id: int):
    if not request.session.get("username"):
        return JSONResponse({"ok": False, "message": SESSION_EXPIRED}, status_code=401)

    server = get_server(server_id)
    if server is None:
        return JSONResponse(
            {"ok": False, "message": "존재하지 않는 서버입니다."}, status_code=404
        )
    ip = (server["ip"] or "").strip()
    if not ip:
        return JSONResponse(
            {"ok": False, "message": "이 서버에 IP가 없습니다. 먼저 IP를 입력하세요."},
            status_code=400,
        )

    # _start_scan을 그대로 쓴다. 저장된 SSH/DB 자격증명이 있으면 계정 기반
    # 심층 점검까지 함께 수행된다(일괄 검사와 동일한 경로).
    ok, _reason = _start_scan(
        server_id, request.session["username"], _client_ip(request)
    )
    if not ok:
        return JSONResponse(
            {"ok": False, "message": "검사를 시작하지 못했습니다."}, status_code=400
        )

    creds = db.get_server_credentials(server_id)
    msg = "계정 점검을 포함해 검사를 시작했습니다." if creds else "보안검사를 시작했습니다."
    scan = latest_scan(server_id)
    return JSONResponse(
        {"ok": True, "message": msg, "scan_id": scan["id"] if scan else None}
    )


@app.get("/api/servers/{server_id}/scan/status")
def api_scan_status(request: Request, server_id: int):
    if not request.session.get("username"):
        return JSONResponse({"ok": False, "message": SESSION_EXPIRED}, status_code=401)
    return JSONResponse(_scan_status_payload(latest_scan(server_id)))


def _score_color(score):
    if score is None:
        return "none"
    if score >= 90:
        return "good"
    if score >= 80:
        return "fair"
    if score >= 60:
        return "warn"
    return "bad"


def _start_scan(server_id: int, actor: str = "", actor_ip: str = ""):
    """서버 1대 진단을 시작한다. (성공여부, 사유) 반환. 백그라운드 실행.

    서버에 SSH/DB 자격증명이 저장돼 있으면 계정 기반 심층 점검까지 함께 수행한다.
    """
    server = get_server(server_id)
    if server is None:
        return False, "없음"
    ip = (server["ip"] or "").strip()
    if not ip:
        return False, "IP 없음"
    current = latest_scan(server_id)
    if current and current["status"] in ("queued", "running"):
        return True, "진행 중"

    creds = db.get_server_credentials(server_id) or None
    scan_id = create_scan(server_id, ip)
    threading.Thread(
        target=scanner.run_scan, args=(scan_id, server_id, ip, creds), daemon=True
    ).start()
    db.add_audit(actor, "scan_start", target=server["name"], ip=actor_ip,
                 detail="계정 점검 포함" if creds else "네트워크 스캔")
    return True, "시작"


@app.post("/api/servers/{server_id}/scan/credentialed")
def api_scan_credentialed(
    request: Request,
    server_id: int,
    ssh_port: str = Form(default=""),
    ssh_user: str = Form(default=""),
    ssh_password: str = Form(default=""),
    db_port: str = Form(default=""),
    db_user: str = Form(default=""),
    db_password: str = Form(default=""),
):
    """계정 기반 심층 점검.

    자격증명은 DB·파일·로그 어디에도 저장하지 않고, 이 요청으로 시작된
    백그라운드 스캔에서 메모리로만 사용한다.
    """
    if not request.session.get("username"):
        return JSONResponse({"ok": False, "message": SESSION_EXPIRED}, status_code=401)

    server = get_server(server_id)
    if server is None:
        return JSONResponse(
            {"ok": False, "message": "존재하지 않는 서버입니다."}, status_code=404
        )
    ip = (server["ip"] or "").strip()
    if not ip:
        return JSONResponse(
            {"ok": False, "message": "이 서버에 IP가 없습니다."}, status_code=400
        )

    creds = {}
    if ssh_user.strip():
        creds["ssh"] = {
            "port": int(ssh_port) if ssh_port.strip().isdigit() else 22,
            "user": ssh_user.strip(), "password": ssh_password,
        }
    if db_user.strip():
        creds["db"] = {
            "port": int(db_port) if db_port.strip().isdigit() else 3306,
            "user": db_user.strip(), "password": db_password,
        }
    if not creds:
        return JSONResponse(
            {"ok": False, "message": "SSH 또는 DB 계정 중 하나는 입력해야 합니다."},
            status_code=400,
        )

    current = latest_scan(server_id)
    if current and current["status"] in ("queued", "running"):
        return JSONResponse(
            {"ok": True, "message": "이미 검사가 진행 중입니다.", "scan_id": current["id"]}
        )

    scan_id = create_scan(server_id, ip)
    threading.Thread(
        target=scanner.run_scan, args=(scan_id, server_id, ip, creds), daemon=True
    ).start()
    # 응답에 자격증명을 절대 포함하지 않는다.
    return JSONResponse(
        {"ok": True, "message": "계정 점검을 시작했습니다.", "scan_id": scan_id}
    )


@app.get("/diagnosis", response_class=HTMLResponse)
def diagnosis(request: Request):
    if not request.session.get("username"):
        return RedirectResponse("/login", status_code=303)

    rows = scans_overview()  # 전체 서버 + 최신 스캔 요약
    for r in rows:
        r["score_color"] = _score_color(r["score"])

    scored = [r["score"] for r in rows if r["score"] is not None]
    avg_score = round(sum(scored) / len(scored), 1) if scored else None

    return templates.TemplateResponse(
        request=request,
        name="diagnosis.html",
        context={
            "username": request.session["username"],
            "groups": list_groups(),
            "selected": "",
            "active_page": "diagnosis",
            "assets": rows,
            "avg_score": avg_score,
            "scored_count": len(scored),
            "status_labels": SERVER_STATUS,
        },
    )


@app.post("/api/scan/bulk")
def api_scan_bulk(request: Request, server_ids: str = Form(default="")):
    if not request.session.get("username"):
        return JSONResponse({"ok": False, "message": SESSION_EXPIRED}, status_code=401)

    ids = [int(x) for x in server_ids.split(",") if x.strip().isdigit()]
    if not ids:
        return JSONResponse(
            {"ok": False, "message": "진단할 서버를 선택하세요."}, status_code=400
        )

    actor = request.session["username"]
    actor_ip = _client_ip(request)
    started, skipped = [], []
    for sid in ids:
        ok, _reason = _start_scan(sid, actor, actor_ip)
        (started if ok else skipped).append(sid)

    return JSONResponse({
        "ok": True,
        "started": started,
        "skipped": skipped,
        "message": f"{len(started)}대 진단을 시작했습니다."
                   + (f" ({len(skipped)}대는 IP 없음 등으로 제외)" if skipped else ""),
    })


@app.get("/servers/{server_id}", response_class=HTMLResponse)
def server_report(request: Request, server_id: int):
    if not request.session.get("username"):
        return RedirectResponse("/login", status_code=303)

    server = get_server(server_id)
    if server is None:
        return RedirectResponse("/dashboard", status_code=303)

    scan = latest_scan(server_id)
    checks = get_scan_checks(scan["id"]) if scan else []
    # 카테고리별로 묶어 화면에서 섹션으로 표시
    grouped = {}
    for c in checks:
        grouped.setdefault(c["category"], []).append(c)

    return templates.TemplateResponse(
        request=request,
        name="scan.html",
        context={
            "username": request.session["username"],
            "groups": list_groups(),
            "selected": server["group_name"],
            "server": server,
            "scan": scan,
            "grouped": grouped,
            "category_label": CATEGORY_LABEL,
            "severity_label": SEVERITY_LABEL,
            "result_label": RESULT_LABEL,
        },
    )


@app.get("/findings", response_class=HTMLResponse)
def findings(request: Request, severity: str = "high"):
    if not request.session.get("username"):
        return RedirectResponse("/login", status_code=303)

    if severity not in SEVERITY_LABEL:
        severity = "high"
    items = findings_by_severity(severity)

    return templates.TemplateResponse(
        request=request,
        name="findings.html",
        context={
            "username": request.session["username"],
            "groups": list_groups(),
            "selected": "",
            "severity": severity,
            "items": items,
            "category_label": CATEGORY_LABEL,
            "severity_label": SEVERITY_LABEL,
        },
    )
