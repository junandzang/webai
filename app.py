"""운영자 로그인 웹사이트 (FastAPI).

실행:  python -m uvicorn app:app --reload --port 8000
"""

from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

import config
from db import get_operator, update_password, verify_password

BASE_DIR = Path(__file__).resolve().parent

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
def dashboard(request: Request):
    username = request.session.get("username")
    if not username:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"username": username},
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
        return JSONResponse(
            {"ok": False, "message": "세션이 만료되었습니다. 다시 로그인해주세요."},
            status_code=401,
        )

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
