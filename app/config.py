"""Runtime configuration (environment driven)."""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg2://dp:dp@localhost:5432/dpdb",
)

SCHEMA_PATH = os.environ.get(
    "SCHEMA_PATH",
    str(BASE_DIR / "sql" / "001_schema.sql"),
)

# How long to wait for the database to come up at startup (compose healthcheck
# normally covers this; the retry loop makes bare `uvicorn` runs robust too).
DB_CONNECT_RETRIES = int(os.environ.get("DB_CONNECT_RETRIES", "30"))
DB_CONNECT_DELAY = float(os.environ.get("DB_CONNECT_DELAY", "1.0"))
