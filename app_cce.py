"""SolidStep 스타일 보안진단 콘솔 (FastAPI, 포트 8100).

기존 8000 앱과 같은 MariaDB·스캔 엔진을 공유하는 별도 UI다.

실행:  python -m uvicorn app_cce:app --port 8100
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

BASE_DIR = Path(__file__).resolve().parent
SESSION_EXPIRED = "세션이 만료되었습니다. 다시 로그인해주세요."
GROUP_NAME_MAX = 50

# 이미지에 맞춰 정적으로 채우는 표시값 (우리 데이터에 없는 항목)
DIAG_TEMPLATE = "SKBB_2026"
DIAG_NAME = "26년_정기진단_IT"
AGENT_VERSION = "2.50.12"

# 상단 탭 (자산 정보/진단 결과만 실제 구현, 나머지는 준비 중)
TOP_TABS = [
    ("assets", "자산 정보", "/assets"),
    ("results", "진단 결과", "/results"),
    ("action", "조치 관리", "/placeholder/조치 관리"),
    ("approval", "결재 관리", "/placeholder/결재 관리"),
    ("history", "작업 내역", "/placeholder/작업 내역"),
    ("log", "로그", "/placeholder/로그"),
]

app = FastAPI(title="SolidStep 보안진단")
app.add_middleware(SessionMiddleware, secret_key=config.SESSION_SECRET)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static_cce"), name="static")

templates = Jinja2Templates(directory=str(BASE_DIR / "templates_cce"))


def _logged_in(request: Request) -> bool:
    return bool(request.session.get("username"))


def _score_color(score):
    """점수 → 색상 키(자산 카드 점수 박스). 높을수록 좋음."""
    if score is None:
        return "none"
    if score >= 90:
        return "good"
    if score >= 80:
        return "fair"
    if score >= 60:
        return "warn"
    return "bad"


def _base_ctx(request: Request, group: str, active_tab: str):
    """셸(그룹 패널·대상 목록·탭)에 공통으로 필요한 컨텍스트."""
    groups = db.list_groups()
    group_names = [g["group_name"] for g in groups]
    selected = group if group in group_names else ""
    servers = db.list_servers(selected) if selected else db.list_servers()
    # 그룹 클릭 시 머무를 탭 (자산/진단결과). 그 외는 자산 정보로.
    base_link = "/results" if active_tab == "results" else "/assets"
    return {
        "request": request,
        "username": request.session.get("username", ""),
        "groups": groups,
        "selected": selected,
        "base_link": base_link,
        "targets": servers,
        "server_count": len(db.list_servers()),
        "target_count": len(servers),
        "group_count": len(groups),
        "top_tabs": TOP_TABS,
        "active_tab": active_tab,
        "agent_version": AGENT_VERSION,
        "diag_template": DIAG_TEMPLATE,
        "diag_name": DIAG_NAME,
    }


# ===== 인증 =====


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if _logged_in(request):
        return RedirectResponse("/assets", status_code=303)
    return RedirectResponse("/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if _logged_in(request):
        return RedirectResponse("/assets", status_code=303)
    return templates.TemplateResponse(
        request=request, name="login_cce.html",
        context={"error": None, "username": ""},
    )


@app.post("/login", response_class=HTMLResponse)
def login_submit(request: Request, username: str = Form(default=""),
                 password: str = Form(default="")):
    username = username.strip()
    if not username or not password:
        return templates.TemplateResponse(
            request=request, name="login_cce.html",
            context={"error": "아이디와 비밀번호를 모두 입력해주세요.", "username": username},
            status_code=400,
        )
    operator = db.get_operator(username)
    if operator is None or not db.verify_password(password, operator["password_hash"]):
        return templates.TemplateResponse(
            request=request, name="login_cce.html",
            context={"error": "아이디 또는 비밀번호가 올바르지 않습니다.", "username": username},
            status_code=401,
        )
    request.session["username"] = operator["username"]
    return RedirectResponse("/assets", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ===== 자산 정보 =====


@app.get("/assets", response_class=HTMLResponse)
def assets(request: Request, group: str = ""):
    if not _logged_in(request):
        return RedirectResponse("/login", status_code=303)

    ctx = _base_ctx(request, group, "assets")
    rows = db.scans_overview(ctx["selected"] or None)
    for r in rows:
        r["score_color"] = _score_color(r["score"])
    scored = [r["score"] for r in rows if r["score"] is not None]
    ctx.update({
        "assets": rows,
        "avg_score": round(sum(scored) / len(scored), 1) if scored else None,
    })
    return templates.TemplateResponse(request=request, name="assets.html", context=ctx)


# ===== 진단 결과 =====


@app.get("/results", response_class=HTMLResponse)
def results(request: Request, group: str = ""):
    if not _logged_in(request):
        return RedirectResponse("/login", status_code=303)

    ctx = _base_ctx(request, group, "results")
    rows = db.scans_overview(ctx["selected"] or None)
    for r in rows:
        r["score_color"] = _score_color(r["score"])
    ctx["assets"] = rows
    return templates.TemplateResponse(request=request, name="results.html", context=ctx)


# ===== 보고서 상세보기 =====


@app.get("/report/{scan_id}", response_class=HTMLResponse)
def report(request: Request, scan_id: int):
    if not _logged_in(request):
        return RedirectResponse("/login", status_code=303)

    data = db.scan_report(scan_id)
    if data is None:
        return RedirectResponse("/results", status_code=303)

    return templates.TemplateResponse(
        request=request, name="report.html",
        context={
            "request": request,
            "username": request.session.get("username", ""),
            "scan": data["scan"],
            "server": data["server"],
            "checks": data["checks"],
            "groups": data["groups"],
            "risk": data["risk"],
            "score_color": _score_color(data["scan"]["score"]),
            "diag_template": DIAG_TEMPLATE,
            "diag_name": DIAG_NAME,
        },
    )


# ===== 진단 실행 (기존 nmap 엔진 재사용) =====


@app.post("/api/scan/{server_id}")
def api_scan(request: Request, server_id: int):
    if not _logged_in(request):
        return JSONResponse({"ok": False, "message": SESSION_EXPIRED}, status_code=401)

    server = db.get_server(server_id)
    if server is None:
        return JSONResponse({"ok": False, "message": "존재하지 않는 자산입니다."},
                            status_code=404)
    ip = (server["ip"] or "").strip()
    if not ip:
        return JSONResponse({"ok": False, "message": "이 자산에 IP가 없습니다."},
                            status_code=400)

    current = db.latest_scan(server_id)
    if current and current["status"] in ("queued", "running"):
        return JSONResponse({"ok": True, "message": "이미 진단이 진행 중입니다.",
                             "scan_id": current["id"]})

    scan_id = db.create_scan(server_id, ip)
    threading.Thread(target=scanner.run_scan, args=(scan_id, server_id, ip),
                     daemon=True).start()
    return JSONResponse({"ok": True, "message": "진단을 시작했습니다.", "scan_id": scan_id})


@app.get("/api/scan/{server_id}/status")
def api_scan_status(request: Request, server_id: int):
    if not _logged_in(request):
        return JSONResponse({"ok": False, "message": SESSION_EXPIRED}, status_code=401)
    scan = db.latest_scan(server_id)
    if not scan:
        return JSONResponse({"status": "none"})
    return JSONResponse({
        "status": scan["status"],
        "scan_id": scan["id"],
        "score": scan["score"],
        "counts": {"critical": scan["crit"], "high": scan["high"],
                   "med": scan["med"], "low": scan["low"]},
    })


# ===== 자산 그룹 관리 (기존 db 함수 재사용) =====


def _validate_group_name(name):
    if not name:
        return "그룹명을 입력해주세요."
    if len(name) > GROUP_NAME_MAX:
        return f"그룹명은 {GROUP_NAME_MAX}자 이하여야 합니다."
    return None


@app.post("/api/groups")
def api_create_group(request: Request, name: str = Form(default="")):
    if not _logged_in(request):
        return JSONResponse({"ok": False, "message": SESSION_EXPIRED}, status_code=401)
    name = name.strip()
    error = _validate_group_name(name)
    if error:
        return JSONResponse({"ok": False, "message": error}, status_code=400)
    ok, message = db.create_group(name)
    return JSONResponse({"ok": ok, "message": message}, status_code=200 if ok else 400)


@app.post("/api/groups/rename")
def api_rename_group(request: Request, old_name: str = Form(default=""),
                     new_name: str = Form(default="")):
    if not _logged_in(request):
        return JSONResponse({"ok": False, "message": SESSION_EXPIRED}, status_code=401)
    old_name, new_name = old_name.strip(), new_name.strip()
    error = _validate_group_name(new_name) or _validate_group_name(old_name)
    if error:
        return JSONResponse({"ok": False, "message": error}, status_code=400)
    if old_name == new_name:
        return JSONResponse({"ok": False, "message": "기존 그룹명과 동일합니다."},
                            status_code=400)
    ok, message = db.rename_group(old_name, new_name)
    return JSONResponse({"ok": ok, "message": message}, status_code=200 if ok else 404)


@app.post("/api/groups/delete")
def api_delete_group(request: Request, name: str = Form(default="")):
    if not _logged_in(request):
        return JSONResponse({"ok": False, "message": SESSION_EXPIRED}, status_code=401)
    name = name.strip()
    if not name:
        return JSONResponse({"ok": False, "message": "그룹명을 입력해주세요."},
                            status_code=400)
    ok, message = db.delete_group(name)
    if ok:
        return JSONResponse({"ok": True, "message": message})
    status = 404 if "존재하지 않는" in message else 400
    return JSONResponse({"ok": False, "message": message}, status_code=status)


# ===== 준비 중 (미구현 탭) =====


@app.get("/placeholder/{name}", response_class=HTMLResponse)
def placeholder(request: Request, name: str):
    if not _logged_in(request):
        return RedirectResponse("/login", status_code=303)
    ctx = _base_ctx(request, "", "")
    ctx["placeholder_name"] = name
    return templates.TemplateResponse(request=request, name="placeholder.html", context=ctx)
