from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api import router

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"

app = FastAPI(title="Identity Attack Graph", version="0.1.0")
app.include_router(router)
app.mount("/static", StaticFiles(directory=FRONTEND), name="static")


@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")
