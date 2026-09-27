"""Versioned record upload endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import services
from ..db import get_db
from ..schemas import RecordsUpload

router = APIRouter(prefix="/records", tags=["records"])


@router.post("", status_code=201)
def upload_records(req: RecordsUpload, db: Session = Depends(get_db)):
    """Idempotent bulk upload: (dataset_version, record_key) is unique, so
    re-posting the same batch is a safe no-op for the duplicates."""
    return services.upload_records(db, req)
