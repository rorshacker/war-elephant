from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .audit import UnsignedCheckpointSigner
from .db import Database
from .discovery import recover_interrupted, tcp_probe
from .routes import register
from .settings import Settings
from .vault import Vault


def create_app(settings: Settings | None = None, directory_client=None, probe=None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.lab_root.mkdir(parents=True, exist_ok=True)
    settings.stig_dir.mkdir(parents=True, exist_ok=True)
    settings.backup_dir.mkdir(parents=True, exist_ok=True)
    database = Database(settings.db_path)
    database.migrate(Path(__file__).resolve().parent / "migrations")
    recover_interrupted(database)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        app.state.db.close()

    app = FastAPI(title="War Elephant", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.db = database
    app.state.vault = Vault(settings.vault_path)
    app.state.directory_client = directory_client
    app.state.probe = probe or tcp_probe
    app.state.after_intent = None
    app.state.after_write = None
    app.state.signer = UnsignedCheckpointSigner()
    register(app)
    static = Path(__file__).resolve().parent / "static"
    index = static / "index.html"
    if index.exists():
        app.mount("/", StaticFiles(directory=static, html=True), name="ui")
    else:
        @app.get("/")
        def missing_ui():
            return JSONResponse(
                {
                    "service": "fleetguard",
                    "ui": "React bundle is not built. API is available under /api.",
                }
            )
    return app
