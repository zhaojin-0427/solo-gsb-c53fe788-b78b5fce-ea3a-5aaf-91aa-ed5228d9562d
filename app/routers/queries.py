"""Query lifecycle endpoints: submit (reserve), disclose, cancel."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Body, Depends, Response
from sqlalchemy.orm import Session

from .. import presenters, services
from ..db import get_db
from ..schemas import QuerySubmit, VersionExpect

router = APIRouter(prefix="/queries", tags=["queries"])


@router.post("", status_code=201)
def submit_query(req: QuerySubmit, response: Response, db: Session = Depends(get_db)):
    """Reserve budget for a count/sum query.

    * 201 — reservation created (status RESERVED).
    * 200 — idempotent replay of an existing reservation (same key + digest).
    * 409 — key reused with a different digest, budget exceeded, or CAS
      version conflict.
    """
    query, created = services.submit_query(db, req)
    if not created:
        response.status_code = 200
    return presenters.query_out(query)


@router.get("/{query_id}")
def get_query(query_id: uuid.UUID, db: Session = Depends(get_db)):
    return presenters.query_out(services.get_query(db, query_id), disclose=True)


@router.post("/{query_id}/disclose")
def disclose_query(query_id: uuid.UUID,
                   payload: VersionExpect | None = Body(default=None),
                   db: Session = Depends(get_db)):
    """Disclose the noisy result; converts the reservation into spent budget."""
    expected = payload.expected_policy_version if payload else None
    query = services.disclose_query(db, query_id, expected)
    return presenters.query_out(query, disclose=True)


@router.post("/{query_id}/cancel")
def cancel_query(query_id: uuid.UUID,
                 payload: VersionExpect | None = Body(default=None),
                 db: Session = Depends(get_db)):
    """Cancel a reservation (only before disclosure; refunded exactly once)."""
    expected = payload.expected_policy_version if payload else None
    query = services.cancel_query(db, query_id, expected)
    out = presenters.query_out(query)
    out["refunded"] = {"epsilon": float(query.epsilon), "delta": float(query.delta)}
    return out
