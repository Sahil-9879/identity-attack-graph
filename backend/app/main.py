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
    # Guard against open redirect: only allow relative paths
    safe_next = next if next.startswith("/") and not next.startswith("//") else "/app"

    if not auth.check_credentials(username, password):
        # Redirect back to login with an error flag — the page renders the message
        return RedirectResponse(
            f"/login?next={quote(safe_next, safe='')}&error=1",
            status_code=303,
        )

    request.session["user"] = username
    return RedirectResponse(safe_next, status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)
