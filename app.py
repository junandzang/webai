"""운영자 로그인 웹사이트 (FastAPI).

실행:  python -m uvicorn app:app --reload --port 8000
"""

import threading
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
    get_scan_checks,
    get_server,
    latest_scan,
    list_groups,
    list_servers,
    rename_group,
    status_summary,
    update_password,
    update_server,
    verify_password,
)
from rules import CATEGORY_LABEL, RESULT_LABEL, SEVERITY_LABEL

BASE_DIR = Path(__file__).resolve().parent

SESSION_EXPIRED = "세션이 만료되었습니다. 다시 로그인해주세요."

# servers.group_name 컬럼 길이와 맞춘다.
GROUP_NAME_MAX = 50

app = FastAPI(title="운영자 사이트")
app.add_middleware(SessionMiddleware, secret_key=config.SESSION_SECRET)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

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

    # 계정 조회 및 비밀번호 검증
    operator = get_operator(username)
    if operator is None or not verify_password(password, operator["password_hash"]):
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
    request.session["username"] = operator["username"]
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

    # 이미 진행 중인 스캔이 있으면 중복 실행하지 않는다.
    current = latest_scan(server_id)
    if current and current["status"] in ("queued", "running"):
        return JSONResponse(
            {"ok": True, "message": "이미 스캔이 진행 중입니다.", "scan_id": current["id"]}
        )

    scan_id = create_scan(server_id, ip)
    # 백그라운드 스레드에서 실행 (요청은 즉시 반환)
    threading.Thread(
        target=scanner.run_scan, args=(scan_id, server_id, ip), daemon=True
    ).start()
    return JSONResponse(
        {"ok": True, "message": "보안검사를 시작했습니다.", "scan_id": scan_id}
    )


@app.get("/api/servers/{server_id}/scan/status")
def api_scan_status(request: Request, server_id: int):
    if not request.session.get("username"):
        return JSONResponse({"ok": False, "message": SESSION_EXPIRED}, status_code=401)
    return JSONResponse(_scan_status_payload(latest_scan(server_id)))


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
