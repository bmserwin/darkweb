"""Evidence-First Forensic Platform - FastAPI application entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from .api import endpoints
from .config import settings
from .models.database import init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s :: %(message)s",
)
logger = logging.getLogger("forensic")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    settings.ensure_dirs()
    init_db()
    logger.info(
        "%s v%s ready | db=%s | onion=%s | clearnet=%s",
        settings.app_name, settings.version, settings.sqlite_path,
        settings.mock_onion_base_url, settings.mock_clearnet_base_url,
    )
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description=(
        "Offline, evidence-first dark-web threat intelligence platform.\n\n"
        "Every ingestion anchors raw payloads into an append-only SHA-256 "
        "Merkle ledger, then correlates deterministic identifiers across four "
        "independent signals before any attribution is proposed to an analyst."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Graph payloads and ledger dumps are JSON-heavy and compress ~5:1; the
# dashboard bundle is static and hashed, so one gzip pass pays for itself
# immediately on every load.
app.add_middleware(GZipMiddleware, minimum_size=1024)

app.include_router(endpoints.router, prefix="/api")


@app.get("/api/health", tags=["system"])
def health() -> dict:
    """Liveness probe used by docker-compose healthchecks."""
    return {
        "status": "online",
        "service": settings.app_name,
        "version": settings.version,
        "case_reference": settings.case_reference,
    }
