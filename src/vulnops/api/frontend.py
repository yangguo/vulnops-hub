from __future__ import annotations

from pathlib import Path

from fastapi import HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# src/vulnops/api/frontend.py -> parents[3] is the repo root (or /app in Docker)
DIST: Path | None = Path(__file__).resolve().parents[3] / "frontend" / "dist"


def _dist_dir() -> Path | None:
    if DIST is not None and (DIST / "index.html").is_file():
        return DIST
    return None


def frontend_index_response() -> FileResponse | None:
    dist = _dist_dir()
    if dist is None:
        return None
    return FileResponse(dist / "index.html")


def mount_frontend(app) -> None:
    """Serve the built SPA. Must be called AFTER all API routers are registered."""
    dist = _dist_dir()
    if dist is None:
        return
    app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str):
        if full_path.startswith(("api/", "health", "docs", "openapi.json")):
            raise HTTPException(status_code=404, detail="Not Found")
        candidate = (dist / full_path).resolve()
        if candidate.is_file() and str(candidate).startswith(str(dist)):
            return FileResponse(candidate)
        return FileResponse(dist / "index.html")
