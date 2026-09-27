"""Data-subject erasure endpoint: idempotent tombstone registration."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from .. import presenters, services
from ..db import get_db
from ..schemas import ErasureRequest

router = APIRouter(prefix="/erasures", tags=["erasures"])


@router.post("", status_code=201)
def erase_subject(req: ErasureRequest, response: Response, db: Session = Depends(get_db)):
    """Erase a data subject up to `until_dataset_version` (inclusive).

    * 201 — tombstone registered: the affected dataset-version set (versions
      actually holding the subject's records or referenced by stored
      snapshots) is determined under the erasure lock barrier, then raw
      records are deleted, query snapshots scrubbed, and still-RESERVED
      queries on affected versions invalidated and refunded exactly once
      (INVALIDATE ledger entries), all in one transaction. Queries, budgets
      and ledger entries on subject-free versions inside the cut-off range
      are untouched, as are disclosed results and existing ledger entries.
    * 200 — idempotent replay of an already-registered erasure (same key +
      same request); nothing is refunded or deleted twice.
    * 409 — key reused with a different request.
    """
    tombstone, created = services.erase_subject(db, req)
    if not created:
        response.status_code = 200
    return presenters.erasure_out(tombstone)
