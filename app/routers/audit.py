"""Audit endpoints: replay the immutable ledger up to a policy version."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from .. import services
from ..db import get_db

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/policies/{policy_id}/replay")
def replay(policy_id: uuid.UUID,
           to_version: int | None = Query(default=None, ge=1),
           version_seq: int | None = Query(
               default=None, ge=1,
               description="Policy parameter version whose independent budget "
                           "pool and bound queries are replayed (default: the "
                           "currently effective version)"),
           db: Session = Depends(get_db)):
    """Replay the budget ledger as of `to_version` (default: latest), scoped
    to one policy parameter version (`version_seq`, default: effective).

    The global hash chain over every parameter version is verified, while
    balances are reconstructed solely from the scoped version's own entries
    (each version's pool is independent). Returns stably-sorted ledger entries
    with hash-chain verification, the reconstructed per-version balances, and
    per-query clipping / noise / budget details. Queries whose final state
    cannot be determined at the replay horizon are marked INDETERMINATE (with
    a `reason`); entries failing verification are marked UNVERIFIABLE.
    Queries invalidated by an erasure link to their tombstone and proof.
    """
    return services.replay_audit(db, policy_id, to_version, version_seq)


@router.get("/erasures")
def erasures(db: Session = Depends(get_db)):
    """List all erasure tombstones with their proofs and affected queries.

    Each entry re-verifies its erasure proof (`VERIFIED` / `UNVERIFIABLE`).
    Only the pseudonymous subject hash is returned — the erased subject
    identifier is never exposed.
    """
    return {"erasures": services.list_erasures(db)}
