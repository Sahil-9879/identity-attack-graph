from pathlib import Path
from urllib.parse import quote
from fastapi import FastAPI, Form, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from . import auth
from .api import router

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"

app = FastAPI(title="Identity Attack Graph", version="0.1.0")
app.add_middleware(
    SessionMiddleware,
    secret_key=auth.get_secret_key(),
    session_cookie="iag_session",
    max_age=60 * 60 * 24 * 30,   # 30 days
    same_site="lax",
    https_only=False,            # Render terminates TLS before us
)
app.include_router(router)
app.mount("/static", StaticFiles(directory=FRONTEND), name="static")


# ---------------------------------------------------------------- pages

@app.get("/")
def landing():
    return FileResponse(FRONTEND / "landing.html")


@app.get("/app")
def app_page():
    return FileResponse(FRONTEND / "index.html")


@app.head("/")
def head_root():
    return Response(status_code=200)


@app.head("/api/health")
def head_health():
    return Response(status_code=200)


# ---------------------------------------------------------------- auth

@app.api_route("/livez", methods=["GET", "HEAD"])
def livez():
    return Response(status_code=200)


@app.get("/profile")
def profile_page():
    return FileResponse(FRONTEND / "profile.html")


@app.get("/login")
def login_page(request: Request, next: str = "/app"):
    return FileResponse(FRONTEND / "login.html")


@app.post("/login")
def login_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    next: str = Form("/app"),
):
    safe_next = next if next.startswith("/") and not next.startswith("//") else "/app"

    # Try a real user account first, then the shared-password fallback.
    user = auth.authenticate(username, password)
    if user is None:
        user = auth.authenticate_shared(password)
    if user is None:
        return RedirectResponse(
            f"/login?next={quote(safe_next, safe='')}&error=1",
            status_code=303,
        )
    auth.login_session(request, user)
    return RedirectResponse(safe_next, status_code=303)


@app.post("/register")
def register_submit(
    request: Request,
    email: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    next: str = Form("/app"),
):
    safe_next = next if next.startswith("/") and not next.startswith("//") else "/app"
    try:
        user = auth.register_user(email, username, password)
    except auth.AuthError as e:
        return RedirectResponse(
            f"/register?next={quote(safe_next, safe='')}&error={e.code}",
            status_code=303,
        )
    auth.login_session(request, user)
    return RedirectResponse(safe_next, status_code=303)


@app.get("/register")
def register_page():
    return FileResponse(FRONTEND / "register.html")


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)
