"""Version-seal endpoints: idempotent sealing, manifests, record proofs,
immutable revision comparisons."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from .. import presenters, services
from ..db import get_db
from ..schemas import SealCompareRequest, SealRequest

router = APIRouter(prefix="/seals", tags=["seals"])


@router.post("", status_code=201)
def seal_version(req: SealRequest, response: Response, db: Session = Depends(get_db)):
    """Seal a dataset version: freeze uploads and commit an immutable
    manifest + Merkle root (revision #0).

    * 201 — seal created; the version is now frozen for uploads.
    * 200 — idempotent replay of an existing seal (same key + same request).
    * 409 — empty version (VERSION_EMPTY), version already sealed under
      another key (VERSION_SEALED), or key reused with a different request.
    """
    seal, revision0, created = services.seal_version(db, req)
    if not created:
        response.status_code = 200
    return presenters.seal_out(seal, revision0)


@router.post("/compare", status_code=201)
def compare_revisions(req: SealCompareRequest, response: Response,
                      db: Session = Depends(get_db)):
    """Compare two verified seal revisions and commit an immutable diff proof.

    Both revisions must re-verify (root, revision hash, chain link); the
    manifests are aligned by record_key into a stably sorted added / removed
    / changed diff (subject hashes only — never raw identifiers), hashed
    together with both ends' seal/revision hashes and roots into `diff_hash`.

    * 201 — comparison created; the response is self-contained
      offline-verification material (see scripts/verify_diff.py).
    * 200 — idempotent replay (same key + same request).
    * 404 — unknown seal (SEAL_NOT_FOUND) or revision
      (SEAL_REVISION_NOT_FOUND).
    * 409 — key reused with a different request (IDEMPOTENCY_CONFLICT) or a
      revision that does not verify (SEAL_REVISION_UNVERIFIED).
    """
    comparison, created = services.compare_seals(db, req)
    if not created:
        response.status_code = 200
    return services.comparison_view(db, comparison)


@router.get("/comparisons/{comparison_id}")
def get_comparison(comparison_id: uuid.UUID, db: Session = Depends(get_db)):
    """The same immutable comparison material as the POST response, fetched
    by comparison id (404 COMPARISON_NOT_FOUND)."""
    comparison = services.get_comparison(db, comparison_id)
    return services.comparison_view(db, comparison)


@router.get("")
def list_seals(db: Session = Depends(get_db)):
    """List all seals with their latest revision and verification status."""
    return {"seals": services.list_seals(db)}


@router.get("/{seal_id}")
def get_seal(seal_id: uuid.UUID, db: Session = Depends(get_db)):
    """Seal detail: the full revision chain with per-revision verification
    (root recomputed from the stored manifest, revision hash and chain links
    re-checked)."""
    return services.get_seal_view(db, seal_id)


@router.get("/{seal_id}/manifest")
def get_manifest(seal_id: uuid.UUID,
                 revision: int | None = Query(default=None, ge=0),
                 db: Session = Depends(get_db)):
    """Offline-verifiable manifest material for one revision (default:
    latest): canonical leaves sorted by record_key (subject hashes only,
    never raw identifiers) plus the committed root and revision hash."""
    return services.get_manifest_view(db, seal_id, revision)


@router.get("/{seal_id}/records/{record_key}/proof")
def get_record_proof(seal_id: uuid.UUID, record_key: str,
                     revision: int | None = Query(default=None, ge=0),
                     db: Session = Depends(get_db)):
    """Inclusion / non-inclusion proof for one record_key (default revision:
    latest). The response is self-contained offline verification material —
    see scripts/verify_proof.py."""
    return services.get_record_proof(db, seal_id, record_key, revision)
