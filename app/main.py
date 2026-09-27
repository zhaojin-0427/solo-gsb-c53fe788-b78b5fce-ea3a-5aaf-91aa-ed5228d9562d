"""Application factory, schema bootstrap, error envelope."""
from __future__ import annotations

import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text

from . import config
from .db import engine
from .errors import ApiError
from .routers import audit, erasures, policies, queries, records, seals


def ensure_schema() -> None:
    """Apply sql/001_schema.sql (idempotent) once the database is reachable."""
    schema = Path(config.SCHEMA_PATH).read_text(encoding="utf-8")
    last_error: Exception | None = None
    for _ in range(config.DB_CONNECT_RETRIES):
        try:
            raw = engine.raw_connection()
            try:
                with raw.cursor() as cursor:
                    cursor.execute(schema)
                raw.commit()
            finally:
                raw.close()
            return
        except Exception as exc:  # database not ready yet
            last_error = exc
            time.sleep(config.DB_CONNECT_DELAY)
    raise RuntimeError(f"database not reachable: {last_error}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_schema()
    yield


app = FastAPI(
    title="Differential-Privacy Query Budget Orchestration API",
    version="1.0.0",
    lifespan=lifespan,
)


@app.exception_handler(ApiError)
def api_error_handler(_request: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message, "details": exc.details}},
    )


@app.exception_handler(RequestValidationError)
def validation_error_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={"error": {"code": "VALIDATION_ERROR",
                           "message": "request validation failed",
                           "details": {"errors": exc.errors()}}},
    )


@app.get("/health", tags=["meta"])
def health():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"status": "ok"}


@app.get("/", tags=["meta"])
def index():
    return {
        "service": "dp-budget-orchestration",
        "docs": "/docs",
        "endpoints": {
            "policies": "/policies",
            "policy_versions": "/policies/{policy_id}/versions",
            "policy_drafts": "/policies/{policy_id}/versions/drafts",
            "draft_publish": "/policies/versions/drafts/{draft_id}/publish",
            "draft_withdraw": "/policies/versions/drafts/{draft_id}/withdraw",
            "records": "/records",
            "seals": "/seals",
            "seal_compare": "/seals/compare",
            "seal_comparisons": "/seals/comparisons/{comparison_id}",
            "queries": "/queries",
            "erasures": "/erasures",
            "audit": "/audit/policies/{policy_id}/replay",
            "audit_erasures": "/audit/erasures",
        },
    }


app.include_router(policies.router)
app.include_router(records.router)
app.include_router(seals.router)
app.include_router(queries.router)
app.include_router(erasures.router)
app.include_router(audit.router)
