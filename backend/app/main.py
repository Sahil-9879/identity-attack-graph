from pathlib import Path
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
    if not auth.check_credentials(username, password):
        # Simple HTML error page — no template engine needed
        return HTMLResponse(
            f"""<!DOCTYPE html><html><head><title>Login failed</title>
            <link rel="stylesheet" href="/static/styles.css"></head>
            <body style="display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#0b1017">
              <div style="max-width:340px;padding:24px;border:1px solid #1f2c3c;background:#121924">
                <h1 style="color:#ef4444;font-size:16px;margin:0 0 12px">Login failed</h1>
                <p style="color:#6d7f96;font-size:12px;margin:0 0 16px">Wrong username or password.</p>
                <a href="/login?next={next}" style="color:#4fd1c5;font-size:12px">← Try again</a>
              </div>
            </body></html>""",
            status_code=401,
        )
    request.session["user"] = username
    # Guard against open redirect: only allow relative paths
    safe_next = next if next.startswith("/") and not next.startswith("//") else "/app"
    return RedirectResponse(safe_next, status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)
