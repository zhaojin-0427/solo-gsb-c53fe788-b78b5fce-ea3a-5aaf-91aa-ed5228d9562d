"""Policy management and policy parameter version endpoints."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from .. import presenters, services
from ..db import get_db
from ..schemas import PolicyCreate, PolicyDraftSubmit, PolicyVersionPublish

router = APIRouter(prefix="/policies", tags=["policies"])


@router.post("", status_code=201)
def create_policy(req: PolicyCreate, db: Session = Depends(get_db)):
    policy = services.create_policy(db, req)
    return services.policy_view(db, policy)


@router.get("")
def list_policies(db: Session = Depends(get_db)):
    return {"policies": services.list_policy_views(db)}


@router.get("/{policy_id}")
def get_policy(policy_id: uuid.UUID, db: Session = Depends(get_db)):
    return services.policy_view(db, services.get_policy(db, policy_id))


# --- policy parameter versions (drafts / publish / withdraw) ----------------

@router.post("/{policy_id}/versions/drafts", status_code=201)
def submit_draft(policy_id: uuid.UUID, req: PolicyDraftSubmit,
                 response: Response, db: Session = Depends(get_db)):
    """Submit an immutable policy draft (epsilon / delta / per-subject cap /
    dimensions).

    * 201 — draft created (stays DRAFT until published or withdrawn).
    * 200 — idempotent replay: same idempotency key, or identical parameters
      already held by a non-withdrawn draft/published version.
    * 404 — unknown policy (POLICY_NOT_FOUND).
    * 409 — IDEMPOTENCY_CONFLICT (same key, different body) or
      DRAFT_WITHDRAWN (identical content previously withdrawn; resubmit a
      fresh draft).
    """
    draft, created = services.submit_policy_draft(db, policy_id, req)
    if not created:
        response.status_code = 200
    return presenters.policy_version_out(draft)


@router.post("/versions/drafts/{draft_id}/publish", status_code=201)
def publish_draft(draft_id: uuid.UUID, req: PolicyVersionPublish | None = None,
                  response: Response = None, db: Session = Depends(get_db)):
    """Atomically publish a draft: it receives the next gapless version
    number, the policy's effective pointer switches to it, the global CAS
    token bumps, and a fresh independent budget pool is created — in one
    transaction.

    * 201 — draft published and now effective.
    * 200 — idempotent replay of an already-published draft.
    * 409 — VERSION_CONFLICT (stale expected_policy_version),
      EFFECTIVE_VERSION_CONFLICT (another version became effective),
      DRAFT_WITHDRAWN or DRAFT_NOT_FOUND on races.
    """
    body = req or PolicyVersionPublish()
    version, created = services.publish_policy_draft(db, draft_id, body)
    if not created:
        response.status_code = 200
    pv, budget = services.get_published_version_with_budget(db, version)
    return presenters.policy_version_out(pv, budget)


@router.post("/versions/drafts/{draft_id}/withdraw", status_code=200)
def withdraw_draft(draft_id: uuid.UUID, response: Response,
                   db: Session = Depends(get_db)):
    """Withdraw a draft that never became effective. Idempotent: a repeated
    withdraw replays the stored withdrawn draft (200). A published version
    cannot be withdrawn (409 DRAFT_ALREADY_PUBLISHED)."""
    draft, created = services.withdraw_policy_draft(db, draft_id)
    if not created:
        response.status_code = 200
    return presenters.policy_version_out(draft)


@router.get("/{policy_id}/versions")
def list_versions(policy_id: uuid.UUID, db: Session = Depends(get_db)):
    """Published versions (with per-version budget) plus open drafts and the
    current effective pointer."""
    return services.list_policy_versions(db, policy_id)


@router.get("/{policy_id}/versions/{version_seq}")
def get_version(policy_id: uuid.UUID, version_seq: int,
                db: Session = Depends(get_db)):
    return services.get_policy_version_view(db, policy_id, version_seq)
