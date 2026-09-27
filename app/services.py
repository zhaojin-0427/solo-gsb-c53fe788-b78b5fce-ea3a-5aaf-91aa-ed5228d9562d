"""Transactional core: policies, records, seals, query lifecycle, erasure, audit replay.

Concurrency model
-----------------
* Every budget mutation runs in a single transaction together with its
  immutable ledger append.
* The policy row is the serialisation point: budget operations take
  ``SELECT ... FOR UPDATE`` on it and then apply a compare-and-swap
  ``UPDATE ... WHERE id = ? AND version = ?``. A client may additionally pass
  ``expected_policy_version``; a stale token yields 409 VERSION_CONFLICT.
* Idempotency keys are unique; resubmitting the same key with a different
  request digest yields 409 IDEMPOTENCY_CONFLICT, resubmitting with the same
  digest is a retry: it appends a RETRY ledger entry and returns the original
  query without touching the budget.
* Erasure, uploads, seals and query submissions are serialised per dataset
  version with transaction-scoped advisory locks: uploads / seals /
  submissions take a shared erasure lock plus an exclusive per-version lock,
  an erasure takes the erasure lock exclusively. An erasure therefore never
  overlaps an in-flight upload, seal or submission, so its invalidation scan
  cannot miss a query, its record deletion cannot miss an uploaded row and
  its seal-revision appends cannot miss a fresh manifest; concurrent erasures
  serialise and never refund twice (the RESERVED -> INVALIDATED transition is
  one-way). Under that barrier the erasure first pins the affected
  dataset-version set (versions actually holding the subject's records or
  referenced by stored snapshots) and scopes record deletion, snapshot
  scrubbing, invalidation, refunds, seal-revision appends and the proof hash
  to exactly that set.
* Sealing freezes a dataset version (later uploads are rejected) and commits
  an immutable manifest plus Merkle root; an erasure never rewrites a sealed
  manifest — it appends a new revision linking the previous revision hash,
  the scrubbed manifest and its recomputed root. A seal-bound query pins the
  revision current at submission time, so concurrent uploads / seals /
  erasures / queries can never produce a snapshot spanning two roots; unbound
  queries keep the original live-table semantics.
* Policy parameter versions are immutable drafts (epsilon / delta /
  per-subject cap / dimensions) that are published atomically: under the
  policy row lock the draft receives the next gapless ``version_seq``, the
  ``policies.effective_version_seq`` pointer switches to it and the global
  CAS token ``version`` bumps. Each published version owns an independent
  budget pool (``policy_version_budgets``); a query binds the effective
  version at submission time and books disclose / cancel / invalidate against
  that exact pool forever, while new submissions may only bind the currently
  effective version. The global hash chain still spans every version (one
  chain per policy, entries tagged with ``policy_version_seq``), and the
  policies-row balance columns stay as a frozen mirror of version #1. A
  single global lock order — policy row(s) -> erasure barrier -> dataset
  version lock -> query rows — keeps publishes, cross-version bookings and
  erasures deadlock-free with no in-place version modification.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

import sqlalchemy as sa
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import presenters, privacy
from .errors import ApiError, conflict
from .models import (
    ErasureTombstone,
    LedgerEntry,
    Policy,
    PolicyVersion,
    PolicyVersionBudget,
    Query,
    Record,
    SealComparison,
    SealRevision,
    VersionSeal,
)

GENESIS_HASH = "0" * 64

# Marker substituted for an erased subject identifier inside stored query
# snapshots. The raw identifier is never kept after erasure.
ERASED_SUBJECT_MARKER = "[erased]"

# Advisory-lock namespaces (transaction-scoped): one key serialises erasures
# against all uploads / submissions, the other serialises uploads and
# submissions per dataset version.
_LOCK_NS_ERASURE = 841_001
_LOCK_NS_DATASET = 841_002


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# NUMERIC(30, 12) stores exactly 12 fractional digits (ties round away from
# zero, like Postgres). Hashing must use the identical canonical form at
# insert time and at audit-verification time, so quantize accordingly.
_QUANTUM = Decimal("0.000000000001")


def _dec(value) -> str:
    """Deterministic plain-decimal rendering used inside ledger hashes."""
    return format(Decimal(value).quantize(_QUANTUM, rounding="ROUND_HALF_UP"), "f")


# ---------------------------------------------------------------------------
# Policies + policy parameter versions
# ---------------------------------------------------------------------------
def _policy_version_spec(version: PolicyVersion) -> dict[str, Any]:
    return privacy.policy_version_spec(
        version.epsilon_total, version.delta_total,
        version.per_subject_cap, list(version.dimensions or []))


def create_policy(db: Session, req) -> Policy:
    """Create a policy together with its immutable, already-published
    parameter version #1 and that version's independent budget pool."""
    now = _utcnow()
    policy = Policy(
        id=uuid.uuid4(),
        name=req.name,
        version=1,
        status="ACTIVE",
        effective_version_seq=1,
        epsilon_total=req.epsilon_total,
        delta_total=req.delta_total,
        per_subject_cap=req.per_subject_cap,
        dimensions=list(req.dimensions),
        created_at=now,
        updated_at=now,
    )
    spec = privacy.policy_version_spec(
        req.epsilon_total, req.delta_total, req.per_subject_cap,
        list(req.dimensions))
    draft_hash = privacy.policy_draft_hash(spec)
    version = PolicyVersion(
        id=uuid.uuid4(),
        policy_id=policy.id,
        version_seq=1,
        status="PUBLISHED",
        # Synthetic key/digest for the implicit v1; no draft endpoint can race it.
        idempotency_key=f"policy-v1-bootstrap-{policy.id}",
        request_digest="bootstrap:v1",
        epsilon_total=req.epsilon_total,
        delta_total=req.delta_total,
        per_subject_cap=req.per_subject_cap,
        dimensions=list(req.dimensions),
        draft_hash=draft_hash,
        published_at=now,
        created_at=now,
    )
    version.summary_hash = privacy.policy_version_summary_hash(
        policy.id, 1, spec, draft_hash)
    budget = PolicyVersionBudget(
        policy_id=policy.id,
        version_seq=1,
        epsilon_total=req.epsilon_total,
        delta_total=req.delta_total,
        created_at=now,
        updated_at=now,
    )
    db.add(policy)
    db.add(version)
    db.add(budget)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise conflict("POLICY_EXISTS", f"policy named '{req.name}' already exists")
    db.refresh(policy)
    return policy


def list_policies(db: Session) -> list[Policy]:
    return list(db.execute(select(Policy).order_by(Policy.name)).scalars())


def _effective_version_rows(db: Session, policy: Policy) -> tuple[PolicyVersion, PolicyVersionBudget]:
    """The effective parameter version row and its independent budget pool."""
    pv = _get_policy_version(db, policy.id, policy.effective_version_seq)
    budget = db.get(PolicyVersionBudget, (policy.id, policy.effective_version_seq))
    if budget is None:
        raise ApiError(500, "POLICY_VERSION_BUDGET_MISSING",
                       "effective policy version has no budget pool",
                       {"policy_id": str(policy.id),
                        "version_seq": policy.effective_version_seq})
    return pv, budget


def policy_view(db: Session, policy: Policy) -> dict[str, Any]:
    pv, budget = _effective_version_rows(db, policy)
    return presenters.policy_out(policy, pv, budget)


def list_policy_views(db: Session) -> list[dict[str, Any]]:
    return [policy_view(db, p) for p in list_policies(db)]


def get_policy(db: Session, policy_id: uuid.UUID) -> Policy:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise ApiError(404, "POLICY_NOT_FOUND", f"policy {policy_id} not found")
    return policy


def _lock_policy(db: Session, policy_id: uuid.UUID) -> Policy:
    policy = db.execute(
        select(Policy)
        .where(Policy.id == policy_id)
        .with_for_update()
        .execution_options(populate_existing=True)  # refresh identity-map copy under the lock
    ).scalar_one_or_none()
    if policy is None:
        raise ApiError(404, "POLICY_NOT_FOUND", f"policy {policy_id} not found")
    return policy


def _check_expected_version(policy: Policy, expected: int | None) -> None:
    if expected is not None and expected != policy.version:
        raise conflict(
            "VERSION_CONFLICT",
            f"policy version is {policy.version}, expected {expected}",
            {"current_version": policy.version, "expected_version": expected},
        )


def _get_policy_version(db: Session, policy_id: uuid.UUID,
                        version_seq: int) -> PolicyVersion:
    pv = db.execute(
        select(PolicyVersion).where(
            PolicyVersion.policy_id == policy_id,
            PolicyVersion.version_seq == version_seq,
        )
    ).scalar_one_or_none()
    if pv is None:
        raise ApiError(404, "POLICY_VERSION_NOT_FOUND",
                       f"policy {policy_id} has no version {version_seq}",
                       {"policy_id": str(policy_id), "version_seq": version_seq})
    return pv


def _get_draft(db: Session, draft_id: uuid.UUID) -> PolicyVersion:
    pv = db.get(PolicyVersion, draft_id)
    if pv is None:
        raise ApiError(404, "DRAFT_NOT_FOUND", f"policy draft {draft_id} not found")
    return pv


def _lock_budget(db: Session, policy_id: uuid.UUID,
                 version_seq: int) -> PolicyVersionBudget:
    """Lock the per-version budget pool. The caller must already hold the
    parent policy row lock (the policy-wide serialisation point)."""
    budget = db.execute(
        select(PolicyVersionBudget)
        .where(PolicyVersionBudget.policy_id == policy_id,
               PolicyVersionBudget.version_seq == version_seq)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if budget is None:  # unreachable in practice: a published version has a pool
        raise ApiError(500, "POLICY_VERSION_BUDGET_MISSING",
                       "published policy version has no budget pool",
                       {"policy_id": str(policy_id), "version_seq": version_seq})
    return budget


def _version_balances(budget: PolicyVersionBudget) -> dict[str, Decimal]:
    return {
        "epsilon_reserved": budget.epsilon_reserved,
        "delta_reserved": budget.delta_reserved,
        "epsilon_spent": budget.epsilon_spent,
        "delta_spent": budget.delta_spent,
    }


# --- draft submission -------------------------------------------------------
def submit_policy_draft(db: Session, policy_id: uuid.UUID, req) -> tuple[PolicyVersion, bool]:
    """Submit an immutable parameter draft for a policy.

    Idempotent in two ways:
      * same idempotency key replays the stored draft (different body under
        the same key -> 409 IDEMPOTENCY_CONFLICT),
      * same content (epsilon/delta/cap/dimensions) replays the stored draft
        or the published version even under a different key; a withdrawn
        draft with the same content is dead (409 DRAFT_WITHDRAWN) and the
        content may be resubmitted as a fresh draft.
    Returns (policy_version_row, created).
    """
    # The policy row lock serialises drafts against publishes / withdrawals
    # / submissions for the whole policy.
    policy = _lock_policy(db, policy_id)
    spec = privacy.policy_version_spec(
        req.epsilon_total, req.delta_total, req.per_subject_cap,
        list(req.dimensions))
    digest = privacy.policy_draft_request_digest(spec)
    draft_hash = privacy.policy_draft_hash(spec)

    def _by_key() -> PolicyVersion | None:
        pv = db.execute(
            select(PolicyVersion).where(PolicyVersion.idempotency_key == req.idempotency_key)
        ).scalar_one_or_none()
        if pv is not None:
            if pv.policy_id != policy.id:
                raise conflict(
                    "IDEMPOTENCY_CONFLICT",
                    "idempotency key was already used for another policy",
                    {"draft_id": str(pv.id), "policy_id": str(pv.policy_id)})
            if pv.request_digest != digest:
                raise conflict(
                    "IDEMPOTENCY_CONFLICT",
                    "idempotency key was already used with a different draft body",
                    {"draft_id": str(pv.id), "status": pv.status})
        return pv

    existing = _by_key()
    if existing is not None:
        return existing, False

    # Content-addressed dedup: identical parameters resolve to the same row
    # regardless of the idempotency key. A withdrawn draft is a dead row and
    # is deliberately excluded here — its content may be resubmitted as a
    # fresh draft (the partial unique index only covers active rows).
    same_content = db.execute(
        select(PolicyVersion).where(
            PolicyVersion.policy_id == policy.id,
            PolicyVersion.draft_hash == draft_hash,
            PolicyVersion.status != "WITHDRAWN",
        )
    ).scalar_one_or_none()
    if same_content is not None:
        return same_content, False

    draft = PolicyVersion(
        id=uuid.uuid4(),
        policy_id=policy.id,
        version_seq=None,
        status="DRAFT",
        idempotency_key=req.idempotency_key,
        request_digest=digest,
        epsilon_total=req.epsilon_total,
        delta_total=req.delta_total,
        per_subject_cap=req.per_subject_cap,
        dimensions=list(req.dimensions),
        draft_hash=draft_hash,
        created_at=_utcnow(),
    )
    db.add(draft)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Lost a race: either the key or the content partial-unique index.
        winner_key = _by_key()
        if winner_key is not None:
            return winner_key, False
        winner_content = db.execute(
            select(PolicyVersion).where(
                PolicyVersion.policy_id == policy.id,
                PolicyVersion.draft_hash == draft_hash,
                PolicyVersion.status != "WITHDRAWN",
            )
        ).scalar_one_or_none()
        if winner_content is not None:
            return winner_content, False
        raise conflict("IDEMPOTENCY_CONFLICT",
                       "draft was concurrently registered; retry the request")
    return draft, True


# --- publish / withdraw -----------------------------------------------------
def publish_policy_draft(db: Session, draft_id: uuid.UUID,
                         req) -> tuple[PolicyVersion, bool]:
    """Atomically publish a draft: assign the next gapless version_seq, switch
    the policy's effective pointer to it, bump the global CAS token and create
    the new version's independent budget pool — all in one transaction.

    Idempotent: publishing an already-published draft (or the key it was
    published under) replays it. A withdrawn draft can never be published.
    Returns (policy_version_row, created).
    """
    draft = _get_draft(db, draft_id)
    if draft.status == "WITHDRAWN":
        raise conflict("DRAFT_WITHDRAWN",
                       "draft was withdrawn before becoming effective and cannot "
                       "be published; submit a fresh draft",
                       {"draft_id": str(draft.id)})
    if draft.status == "PUBLISHED":
        return draft, False

    policy = _lock_policy(db, draft.policy_id)
    # Re-read the draft state under the policy lock barrier.
    draft = db.execute(
        select(PolicyVersion).where(PolicyVersion.id == draft.id).with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    if draft.status == "PUBLISHED":
        return draft, False
    if draft.status == "WITHDRAWN":
        raise conflict("DRAFT_WITHDRAWN",
                       "draft was withdrawn concurrently and cannot be published",
                       {"draft_id": str(draft.id)})

    _check_expected_version(policy, req.expected_policy_version)
    if req.expected_effective_version is not None \
            and req.expected_effective_version != policy.effective_version_seq:
        raise conflict(
            "EFFECTIVE_VERSION_CONFLICT",
            f"effective policy version is {policy.effective_version_seq}, "
            f"expected {req.expected_effective_version}",
            {"current_effective_version": policy.effective_version_seq,
             "expected_effective_version": req.expected_effective_version})

    now = _utcnow()
    next_seq = db.execute(
        select(sa.func.coalesce(sa.func.max(PolicyVersion.version_seq), 0) + 1)
        .where(PolicyVersion.policy_id == policy.id)
    ).scalar_one()
    # A concurrent publish serialised ahead on this same row lock would have
    # moved the pointer; next_seq is therefore exactly pointer + 1.
    if next_seq != policy.effective_version_seq + 1:
        raise conflict(
            "EFFECTIVE_VERSION_CONFLICT",
            "effective policy version changed concurrently; retry the publish",
            {"current_effective_version": policy.effective_version_seq})

    spec = _policy_version_spec(draft)
    draft.version_seq = next_seq
    draft.status = "PUBLISHED"
    draft.published_at = now
    draft.summary_hash = privacy.policy_version_summary_hash(
        policy.id, next_seq, spec, draft.draft_hash)

    budget = PolicyVersionBudget(
        policy_id=policy.id,
        version_seq=next_seq,
        epsilon_total=draft.epsilon_total,
        delta_total=draft.delta_total,
        created_at=now,
        updated_at=now,
    )
    db.add(budget)

    policy.effective_version_seq = next_seq
    policy.version += 1
    policy.updated_at = now
    # The policies-table parameter / balance columns stay frozen as the
    # version-#1 mirror; the new effective version's authoritative balances
    # live in policy_version_budgets. The publish itself is recorded
    # immutably in policy_versions (the ledger only carries budget events).

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        recheck = db.get(PolicyVersion, draft_id)
        if recheck is not None and recheck.status == "PUBLISHED":
            return recheck, False
        raise conflict("VERSION_CONFLICT",
                       "draft publish raced a concurrent change; retry the request")
    return draft, True


def withdraw_policy_draft(db: Session, draft_id: uuid.UUID) -> tuple[PolicyVersion, bool]:
    """Withdraw a draft that has never become effective. Idempotent: a second
    withdraw of the same withdrawn draft replays it. Published drafts cannot
    be withdrawn (a published version is immutable and stays effective history)."""
    draft = _get_draft(db, draft_id)
    if draft.status == "WITHDRAWN":
        return draft, False
    if draft.status == "PUBLISHED":
        raise conflict("DRAFT_ALREADY_PUBLISHED",
                       "draft is already a published effective version and cannot "
                       "be withdrawn; publish a new version instead",
                       {"draft_id": str(draft.id),
                        "version_seq": draft.version_seq})

    # Serialise against publishes / submissions on this policy, then re-read
    # and lock the draft under that barrier.
    _lock_policy(db, draft.policy_id)
    draft = db.execute(
        select(PolicyVersion).where(PolicyVersion.id == draft.id).with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    if draft.status == "WITHDRAWN":
        return draft, False
    if draft.status == "PUBLISHED":
        raise conflict("DRAFT_ALREADY_PUBLISHED",
                       "draft was published concurrently and cannot be withdrawn",
                       {"draft_id": str(draft.id),
                        "version_seq": draft.version_seq})
    draft.status = "WITHDRAWN"
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        recheck = db.get(PolicyVersion, draft_id)
        if recheck is not None and recheck.status == "WITHDRAWN":
            return recheck, False
        raise
    return draft, True


def list_policy_versions(db: Session, policy_id: uuid.UUID) -> dict[str, Any]:
    policy = get_policy(db, policy_id)
    rows = list(db.execute(
        select(PolicyVersion, PolicyVersionBudget)
        .outerjoin(PolicyVersionBudget,
                   (PolicyVersionBudget.policy_id == PolicyVersion.policy_id)
                   & (PolicyVersionBudget.version_seq == PolicyVersion.version_seq))
        .where(PolicyVersion.policy_id == policy.id)
        .order_by(PolicyVersion.created_at, PolicyVersion.id)
    ).all())
    drafts, published, withdrawn = [], [], []
    for pv, budget in rows:
        view = presenters.policy_version_out(pv, budget)
        if pv.status == "DRAFT":
            drafts.append(view)
        elif pv.status == "WITHDRAWN":
            withdrawn.append(view)
        else:
            published.append(view)
    return {
        "policy_id": str(policy.id),
        "policy_name": policy.name,
        "effective_version_seq": policy.effective_version_seq,
        "global_policy_version": policy.version,
        "versions": sorted(published, key=lambda v: v["version_seq"]),
        "drafts": drafts,
        "withdrawn": withdrawn,
    }


def get_published_version_with_budget(
        db: Session, pv: PolicyVersion) -> tuple[PolicyVersion, PolicyVersionBudget]:
    if pv.version_seq is None:
        raise ApiError(500, "DRAFT_NOT_PUBLISHED", "draft has no version sequence",
                       {"draft_id": str(pv.id)})
    budget = db.get(PolicyVersionBudget, (pv.policy_id, pv.version_seq))
    if budget is None:
        raise ApiError(500, "POLICY_VERSION_BUDGET_MISSING",
                       "published policy version has no budget pool",
                       {"policy_id": str(pv.policy_id),
                        "version_seq": pv.version_seq})
    return pv, budget


def get_policy_version_view(db: Session, policy_id: uuid.UUID,
                            version_seq: int) -> dict[str, Any]:
    policy = get_policy(db, policy_id)
    pv = _get_policy_version(db, policy.id, version_seq)
    budget = db.get(PolicyVersionBudget, (policy.id, version_seq))
    view = presenters.policy_version_out(pv, budget)
    view["effective"] = policy.effective_version_seq == version_seq
    return view


# ---------------------------------------------------------------------------
# Dataset-version serialisation (advisory locks)
# ---------------------------------------------------------------------------
def _lock_erasure_exclusive(db: Session) -> None:
    """Exclusive erasure lock: blocks until every in-flight upload / query
    submission has finished, and blocks new ones until this transaction ends."""
    db.execute(text("SELECT pg_advisory_xact_lock(:ns, 0)"), {"ns": _LOCK_NS_ERASURE})


def _lock_dataset_version(db: Session, dataset_version: int) -> None:
    """Uploads and query submissions serialise per dataset version and, as a
    group, against erasures (shared erasure lock + exclusive version lock)."""
    db.execute(text("SELECT pg_advisory_xact_lock_shared(:ns, 0)"), {"ns": _LOCK_NS_ERASURE})
    db.execute(
        text("SELECT pg_advisory_xact_lock(:ns, :ver)"),
        {"ns": _LOCK_NS_DATASET, "ver": dataset_version},
    )


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------
def _enforce_tombstones(db: Session, req) -> None:
    """Reject uploads covered by an erasure tombstone: a subject whose
    erasure is registered up to version C may not be re-uploaded at any
    dataset_version <= C."""
    hashes = {privacy.erasure_subject_hash(item.subject_id) for item in req.records}
    tombstones = list(db.execute(
        select(ErasureTombstone).where(
            ErasureTombstone.subject_hash.in_(hashes),
            ErasureTombstone.until_dataset_version >= req.dataset_version,
        )
    ).scalars())
    if not tombstones:
        return
    by_hash = {t.subject_hash: t for t in tombstones}
    blocked = [
        {
            "record_key": item.record_key,
            "subject_id": item.subject_id,
            "tombstone_id": by_hash[privacy.erasure_subject_hash(item.subject_id)].id,
        }
        for item in req.records
        if privacy.erasure_subject_hash(item.subject_id) in by_hash
    ]
    raise conflict(
        "SUBJECT_ERASED",
        "subject was erased and a tombstone covers this dataset version; "
        "re-upload within the tombstone range is forbidden",
        {"dataset_version": req.dataset_version, "blocked": blocked},
    )


def upload_records(db: Session, req) -> dict[str, Any]:
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    _lock_dataset_version(db, req.dataset_version)
    _enforce_tombstones(db, req)
    _enforce_not_sealed(db, req.dataset_version)

    now = _utcnow()
    rows = [
        {
            "dataset_version": req.dataset_version,
            "record_key": item.record_key,
            "subject_id": item.subject_id,
            "attributes": item.attributes,
            "created_at": now,
        }
        for item in req.records
    ]
    stmt = pg_insert(Record).values(rows).on_conflict_do_nothing(
        index_elements=["dataset_version", "record_key"]
    )
    result = db.execute(stmt)
    db.commit()
    inserted = result.rowcount if result.rowcount is not None else 0
    return {
        "dataset_version": req.dataset_version,
        "received": len(rows),
        "inserted": inserted,
        "duplicates": len(rows) - inserted,
    }


# ---------------------------------------------------------------------------
# Version seals: immutable manifests, Merkle roots, revision chain
# ---------------------------------------------------------------------------
def _get_seal(db: Session, seal_id: uuid.UUID) -> VersionSeal:
    seal = db.get(VersionSeal, seal_id)
    if seal is None:
        raise ApiError(404, "SEAL_NOT_FOUND", f"seal {seal_id} not found")
    return seal


def _latest_revision(db: Session, seal_id: uuid.UUID) -> SealRevision:
    return db.execute(
        select(SealRevision)
        .where(SealRevision.seal_id == seal_id)
        .order_by(SealRevision.revision_seq.desc())
        .limit(1)
    ).scalar_one()


def _enforce_not_sealed(db: Session, dataset_version: int) -> None:
    """A sealed version is frozen: uploads to it are rejected."""
    seal = db.execute(
        select(VersionSeal).where(VersionSeal.dataset_version == dataset_version)
    ).scalar_one_or_none()
    if seal is not None:
        raise conflict(
            "VERSION_SEALED",
            f"dataset version {dataset_version} is sealed; uploads are frozen",
            {"dataset_version": dataset_version, "seal_id": str(seal.id)},
        )


def _build_manifest(records: list[Record]) -> list[dict]:
    """Canonical manifest leaves, stably sorted by record_key. Leaves commit
    only the pseudonymous subject hash — never the raw identifier."""
    leaves = [
        privacy.canonical_leaf(
            r.record_key, privacy.erasure_subject_hash(r.subject_id), r.attributes or {})
        for r in records
    ]
    leaves.sort(key=lambda leaf: leaf["record_key"])
    return leaves


def _revision_payload(rev: SealRevision) -> dict[str, Any]:
    """Canonical payload bound into a seal revision hash. Recomputed from the
    stored revision at verification time, so it must stay deterministic."""
    return {
        "seal_id": str(rev.seal_id),
        "revision_seq": rev.revision_seq,
        "kind": rev.kind,
        "prev_revision_hash": rev.prev_revision_hash,
        "root": rev.root,
        "record_count": rev.record_count,
        "subject_hash": rev.subject_hash,
        "tombstone_id": rev.tombstone_id,
        "created_at": rev.created_at.isoformat() if rev.created_at else None,
    }


def _insert_revision(db: Session, *, seal_id: uuid.UUID, revision_seq: int, kind: str,
                     prev_revision_hash: str, manifest: list[dict],
                     subject_hash: str | None = None,
                     tombstone_id: int | None = None,
                     created_at: datetime | None = None) -> SealRevision:
    leaf_hashes = [privacy.leaf_hash(leaf) for leaf in manifest]
    rev = SealRevision(
        seal_id=seal_id,
        revision_seq=revision_seq,
        kind=kind,
        prev_revision_hash=prev_revision_hash,
        root=privacy.merkle_root(leaf_hashes),
        record_count=len(manifest),
        manifest={"hash_version": privacy.SEAL_HASH_VERSION, "leaves": manifest},
        subject_hash=subject_hash,
        tombstone_id=tombstone_id,
        created_at=created_at or _utcnow(),
    )
    rev.revision_hash = privacy.seal_revision_hash(_revision_payload(rev))
    db.add(rev)
    return rev


def seal_version(db: Session, req) -> tuple[VersionSeal, SealRevision, bool]:
    """Seal one dataset version: freeze uploads and commit the immutable
    manifest + Merkle root (revision #0).

    One transaction under the per-version lock (serialised with uploads,
    submissions and erasures): reject an empty version, snapshot every record
    into canonical leaves sorted by record_key, and append revision #0.
    Idempotent per idempotency key. Returns (seal, revision0, created).
    """
    digest = privacy.seal_request_digest({"dataset_version": req.dataset_version})

    def _lookup() -> VersionSeal | None:
        seal = db.execute(
            select(VersionSeal).where(VersionSeal.idempotency_key == req.idempotency_key)
        ).scalar_one_or_none()
        if seal is not None and seal.request_digest != digest:
            raise conflict(
                "IDEMPOTENCY_CONFLICT",
                "idempotency key was already used with a different seal request",
                {"seal_id": str(seal.id)},
            )
        return seal

    existing = _lookup()
    if existing is not None:
        return existing, _revision0(db, existing.id), False

    # Serialise with concurrent uploads / submissions / erasures on this
    # version, then re-check under the lock barrier.
    _lock_dataset_version(db, req.dataset_version)
    existing = _lookup()
    if existing is not None:
        return existing, _revision0(db, existing.id), False
    by_version = db.execute(
        select(VersionSeal).where(VersionSeal.dataset_version == req.dataset_version)
    ).scalar_one_or_none()
    if by_version is not None:
        raise conflict(
            "VERSION_SEALED",
            f"dataset version {req.dataset_version} is already sealed",
            {"dataset_version": req.dataset_version, "seal_id": str(by_version.id)},
        )

    records = list(db.execute(
        select(Record).where(Record.dataset_version == req.dataset_version).order_by(Record.id)
    ).scalars())
    if not records:
        raise conflict(
            "VERSION_EMPTY",
            f"dataset version {req.dataset_version} has no records; refusing to seal an empty version",
            {"dataset_version": req.dataset_version},
        )

    now = _utcnow()
    seal = VersionSeal(
        id=uuid.uuid4(),
        dataset_version=req.dataset_version,
        idempotency_key=req.idempotency_key,
        request_digest=digest,
        created_at=now,
    )
    db.add(seal)
    db.flush()
    revision0 = _insert_revision(
        db, seal_id=seal.id, revision_seq=0, kind="seal",
        prev_revision_hash=GENESIS_HASH, manifest=_build_manifest(records),
        created_at=now,
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Lost a race on the idempotency key (or version) unique constraint.
        winner = _lookup()
        if winner is not None:
            return winner, _revision0(db, winner.id), False
        by_version = db.execute(
            select(VersionSeal).where(VersionSeal.dataset_version == req.dataset_version)
        ).scalar_one_or_none()
        if by_version is not None:
            raise conflict(
                "VERSION_SEALED",
                f"dataset version {req.dataset_version} is already sealed",
                {"dataset_version": req.dataset_version, "seal_id": str(by_version.id)},
            )
        raise conflict("IDEMPOTENCY_CONFLICT",
                       "idempotency key was concurrently registered; retry the request")
    return seal, revision0, True


def _revision0(db: Session, seal_id: uuid.UUID) -> SealRevision:
    return db.execute(
        select(SealRevision)
        .where(SealRevision.seal_id == seal_id, SealRevision.revision_seq == 0)
    ).scalar_one()


def _manifest_leaves(rev: SealRevision) -> list[dict]:
    return list((rev.manifest or {}).get("leaves") or [])


def _revision_view(db: Session, seal: VersionSeal, rev: SealRevision) -> dict[str, Any]:
    """Verification view of one revision: root recomputed from the stored
    manifest, revision hash recomputed, and the chain link to the previous
    revision checked."""
    leaves = _manifest_leaves(rev)
    recomputed_root = privacy.merkle_root([privacy.leaf_hash(leaf) for leaf in leaves])
    hash_ok = privacy.seal_revision_hash(_revision_payload(rev)) == rev.revision_hash
    chain_ok = True
    if rev.revision_seq > 0:
        prev = db.execute(
            select(SealRevision).where(
                SealRevision.seal_id == seal.id,
                SealRevision.revision_seq == rev.revision_seq - 1,
            )
        ).scalar_one_or_none()
        chain_ok = prev is not None and prev.revision_hash == rev.prev_revision_hash
    else:
        chain_ok = rev.prev_revision_hash == GENESIS_HASH
    verified = recomputed_root == rev.root and hash_ok and chain_ok
    return {
        "revision_seq": rev.revision_seq,
        "kind": rev.kind,
        "root": rev.root,
        "record_count": rev.record_count,
        "subject_hash": rev.subject_hash,
        "tombstone_id": rev.tombstone_id,
        "prev_revision_hash": rev.prev_revision_hash,
        "revision_hash": rev.revision_hash,
        "root_verified": recomputed_root == rev.root,
        "hash_verified": hash_ok,
        "chain_verified": chain_ok,
        "verification": "VERIFIED" if verified else "UNVERIFIABLE",
        "created_at": rev.created_at.isoformat() if rev.created_at else None,
    }


def get_seal_view(db: Session, seal_id: uuid.UUID) -> dict[str, Any]:
    seal = _get_seal(db, seal_id)
    revisions = list(db.execute(
        select(SealRevision)
        .where(SealRevision.seal_id == seal.id)
        .order_by(SealRevision.revision_seq)
    ).scalars())
    views = [_revision_view(db, seal, rev) for rev in revisions]
    return {
        "seal_id": str(seal.id),
        "dataset_version": seal.dataset_version,
        "idempotency_key": seal.idempotency_key,
        "request_digest": seal.request_digest,
        "hash_version": privacy.SEAL_HASH_VERSION,
        "created_at": seal.created_at.isoformat() if seal.created_at else None,
        "latest_revision": views[-1] if views else None,
        "revisions": views,
    }


def list_seals(db: Session) -> list[dict[str, Any]]:
    seals = list(db.execute(
        select(VersionSeal).order_by(VersionSeal.dataset_version)
    ).scalars())
    out = []
    for seal in seals:
        latest = _latest_revision(db, seal.id)
        out.append({
            "seal_id": str(seal.id),
            "dataset_version": seal.dataset_version,
            "idempotency_key": seal.idempotency_key,
            "hash_version": privacy.SEAL_HASH_VERSION,
            "created_at": seal.created_at.isoformat() if seal.created_at else None,
            "latest_revision": _revision_view(db, seal, latest),
        })
    return out


def get_manifest_view(db: Session, seal_id: uuid.UUID, revision_seq: int | None) -> dict[str, Any]:
    """Offline-verifiable manifest material for one revision: the canonical
    leaves (subject hashes only) plus everything needed to recompute the
    Merkle root and the revision hash without the service."""
    seal = _get_seal(db, seal_id)
    if revision_seq is None:
        rev = _latest_revision(db, seal.id)
    else:
        rev = db.execute(
            select(SealRevision).where(
                SealRevision.seal_id == seal.id,
                SealRevision.revision_seq == revision_seq,
            )
        ).scalar_one_or_none()
        if rev is None:
            raise ApiError(404, "SEAL_REVISION_NOT_FOUND",
                           f"seal {seal_id} has no revision {revision_seq}",
                           {"seal_id": str(seal_id), "revision_seq": revision_seq})
    leaves = _manifest_leaves(rev)
    return {
        "seal_id": str(seal.id),
        "dataset_version": seal.dataset_version,
        "revision_seq": rev.revision_seq,
        "kind": rev.kind,
        "hash_version": privacy.SEAL_HASH_VERSION,
        "root": rev.root,
        "record_count": rev.record_count,
        "prev_revision_hash": rev.prev_revision_hash,
        "revision_hash": rev.revision_hash,
        "subject_hash": rev.subject_hash,
        "tombstone_id": rev.tombstone_id,
        "created_at": rev.created_at.isoformat() if rev.created_at else None,
        "manifest": {"leaves": leaves},
        "verification": _revision_view(db, seal, rev),
    }


def get_record_proof(db: Session, seal_id: uuid.UUID, record_key: str,
                       revision_seq: int | None) -> dict[str, Any]:
    """Inclusion / non-inclusion proof for one record_key against a seal
    revision (default: latest). The response is self-contained offline
    verification material.

    The canonical ``leaves`` bind each record_key to a committed leaf (the
    leaf hash commits the key name) — a verifier derives every leaf hash and
    the root solely from them, so an independent key list can never assert
    absence under an authentic root. Inclusion additionally carries the leaf,
    its index and its Merkle sibling path.
    """
    seal = _get_seal(db, seal_id)
    if revision_seq is None:
        rev = _latest_revision(db, seal.id)
    else:
        rev = db.execute(
            select(SealRevision).where(
                SealRevision.seal_id == seal.id,
                SealRevision.revision_seq == revision_seq,
            )
        ).scalar_one_or_none()
        if rev is None:
            raise ApiError(404, "SEAL_REVISION_NOT_FOUND",
                           f"seal {seal_id} has no revision {revision_seq}",
                           {"seal_id": str(seal_id), "revision_seq": revision_seq})
    leaves = _manifest_leaves(rev)
    leaf_hashes = [privacy.leaf_hash(leaf) for leaf in leaves]
    keys = [leaf["record_key"] for leaf in leaves]
    base = {
        "seal_id": str(seal.id),
        "dataset_version": seal.dataset_version,
        "revision_seq": rev.revision_seq,
        "kind": rev.kind,
        "hash_version": privacy.SEAL_HASH_VERSION,
        "root": rev.root,
        "record_count": rev.record_count,
        "prev_revision_hash": rev.prev_revision_hash,
        "revision_hash": rev.revision_hash,
        "subject_hash": rev.subject_hash,
        "tombstone_id": rev.tombstone_id,
        "created_at": rev.created_at.isoformat() if rev.created_at else None,
        "record_key": record_key,
        # The leaves are the binding: keys and leaf hashes are both derived
        # from them by the verifier, and the revision hash anchors this proof
        # to the immutable revision chain.
        "leaves": leaves,
        "record_keys": keys,
        "leaf_hashes": leaf_hashes,
    }
    if record_key in keys:
        index = keys.index(record_key)
        return {
            **base,
            "type": "inclusion",
            "leaf": leaves[index],
            "leaf_index": index,
            "leaf_hash": leaf_hashes[index],
            "path": privacy.merkle_proof_path(leaf_hashes, index),
        }
    return {**base, "type": "non_inclusion"}


# ---------------------------------------------------------------------------
# Seal comparisons: immutable diffs between two verified revisions
# ---------------------------------------------------------------------------
def _revision_by_seq(db: Session, seal_id: uuid.UUID, revision_seq: int) -> SealRevision | None:
    return db.execute(
        select(SealRevision).where(
            SealRevision.seal_id == seal_id,
            SealRevision.revision_seq == revision_seq,
        )
    ).scalar_one_or_none()


def _revision_verified(db: Session, seal: VersionSeal, rev: SealRevision) -> bool:
    """A revision is only eligible for comparison when its stored material
    re-verifies: root recomputed from the manifest, revision hash recomputed
    and the chain link to the previous revision intact."""
    return _revision_view(db, seal, rev)["verification"] == "VERIFIED"


def _verified_revision_for_compare(db: Session, side: str, ref) -> tuple[VersionSeal, SealRevision]:
    """Resolve one side of a compare request to its (seal, revision) pair,
    refusing anything but a fully verified revision."""
    seal = _get_seal(db, ref.seal_id)
    rev = _revision_by_seq(db, seal.id, ref.revision_seq)
    if rev is None:
        raise ApiError(404, "SEAL_REVISION_NOT_FOUND",
                       f"seal {ref.seal_id} has no revision {ref.revision_seq}",
                       {"seal_id": str(ref.seal_id), "revision_seq": ref.revision_seq})
    if not _revision_verified(db, seal, rev):
        raise conflict(
            "SEAL_REVISION_UNVERIFIED",
            f"{side} revision {ref.revision_seq} of seal {ref.seal_id} does not "
            f"verify; refusing to compare unverified material",
            {"side": side, "seal_id": str(seal.id), "revision_seq": ref.revision_seq},
        )
    return seal, rev


def _comparison_side_view(seal: VersionSeal, rev: SealRevision) -> dict[str, Any]:
    """Offline-verifiable material for one side of a comparison: the revision
    fields needed to recompute its revision hash plus the full committed
    leaves (subject hashes only — never raw identifiers)."""
    return {
        "seal_id": str(seal.id),
        "dataset_version": seal.dataset_version,
        "revision_seq": rev.revision_seq,
        "kind": rev.kind,
        "root": rev.root,
        "record_count": rev.record_count,
        "prev_revision_hash": rev.prev_revision_hash,
        "revision_hash": rev.revision_hash,
        "subject_hash": rev.subject_hash,
        "tombstone_id": rev.tombstone_id,
        "created_at": rev.created_at.isoformat() if rev.created_at else None,
        "leaves": _manifest_leaves(rev),
    }


def _compare_request_spec(req) -> dict[str, Any]:
    return {
        "left": {"seal_id": str(req.left.seal_id),
                 "revision_seq": req.left.revision_seq},
        "right": {"seal_id": str(req.right.seal_id),
                  "revision_seq": req.right.revision_seq},
    }


def compare_seals(db: Session, req) -> tuple[SealComparison, bool]:
    """Compare two verified seal revisions and commit the immutable diff proof.

    Both revisions must re-verify (root, revision hash, chain link) before
    anything is computed. The manifests are aligned by record_key into a
    canonical added / removed / changed diff, which is hashed together with
    both ends' seal/revision hashes and roots into ``diff_hash``. Revisions
    are immutable, so the unique idempotency key is the only serialisation
    point; a concurrent duplicate replays the stored comparison. Returns
    (comparison, created).
    """
    digest = privacy.compare_request_digest(_compare_request_spec(req))

    def _lookup() -> SealComparison | None:
        comp = db.execute(
            select(SealComparison)
            .where(SealComparison.idempotency_key == req.idempotency_key)
        ).scalar_one_or_none()
        if comp is not None and comp.request_digest != digest:
            raise conflict(
                "IDEMPOTENCY_CONFLICT",
                "idempotency key was already used with a different compare request",
                {"comparison_id": str(comp.id)},
            )
        return comp

    existing = _lookup()
    if existing is not None:
        return existing, False

    left_seal, left_rev = _verified_revision_for_compare(db, "left", req.left)
    right_seal, right_rev = _verified_revision_for_compare(db, "right", req.right)

    left_view = _comparison_side_view(left_seal, left_rev)
    right_view = _comparison_side_view(right_seal, right_rev)
    diff = privacy.canonical_diff(left_view["leaves"], right_view["leaves"])
    diff_hash = privacy.seal_diff_hash({
        "left": privacy.diff_side_ref(left_view),
        "right": privacy.diff_side_ref(right_view),
        "diff": diff,
    })
    comparison = SealComparison(
        id=uuid.uuid4(),
        idempotency_key=req.idempotency_key,
        request_digest=digest,
        left_seal_id=left_seal.id,
        left_revision_seq=left_rev.revision_seq,
        right_seal_id=right_seal.id,
        right_revision_seq=right_rev.revision_seq,
        left_root=left_rev.root,
        right_root=right_rev.root,
        left_revision_hash=left_rev.revision_hash,
        right_revision_hash=right_rev.revision_hash,
        diff=diff,
        diff_hash=diff_hash,
        created_at=_utcnow(),
    )
    db.add(comparison)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Lost a race on the idempotency key unique constraint.
        winner = _lookup()
        if winner is not None:
            return winner, False
        raise conflict("IDEMPOTENCY_CONFLICT",
                       "idempotency key was concurrently registered; retry the request")
    return comparison, True


def get_comparison(db: Session, comparison_id: uuid.UUID) -> SealComparison:
    comparison = db.get(SealComparison, comparison_id)
    if comparison is None:
        raise ApiError(404, "COMPARISON_NOT_FOUND",
                       f"comparison {comparison_id} not found")
    return comparison


def comparison_view(db: Session, comparison: SealComparison) -> dict[str, Any]:
    """Full offline-verifiable comparison material: both sides' revisions and
    committed leaves, the canonical diff and the diff hash — re-verified
    against the immutable revisions on every read."""
    sides: dict[str, dict[str, Any]] = {}
    verified = True
    for side, seal_id, seq in (
        ("left", comparison.left_seal_id, comparison.left_revision_seq),
        ("right", comparison.right_seal_id, comparison.right_revision_seq),
    ):
        seal = db.get(VersionSeal, seal_id)
        rev = _revision_by_seq(db, seal_id, seq) if seal is not None else None
        if seal is None or rev is None:
            verified = False  # FKs make this unreachable in practice
            continue
        sides[side] = _comparison_side_view(seal, rev)
        verified = verified and _revision_verified(db, seal, rev)
    if set(sides) == {"left", "right"}:
        recomputed = privacy.canonical_diff(sides["left"]["leaves"], sides["right"]["leaves"])
        recomputed_hash = privacy.seal_diff_hash({
            "left": privacy.diff_side_ref(sides["left"]),
            "right": privacy.diff_side_ref(sides["right"]),
            "diff": comparison.diff,
        })
        verified = (verified
                    and recomputed == comparison.diff
                    and recomputed_hash == comparison.diff_hash
                    and comparison.left_root == sides["left"]["root"]
                    and comparison.right_root == sides["right"]["root"]
                    and comparison.left_revision_hash == sides["left"]["revision_hash"]
                    and comparison.right_revision_hash == sides["right"]["revision_hash"])
    else:
        verified = False
    return {
        "comparison_id": str(comparison.id),
        "idempotency_key": comparison.idempotency_key,
        "request_digest": comparison.request_digest,
        "hash_version": privacy.SEAL_HASH_VERSION,
        "left": sides.get("left"),
        "right": sides.get("right"),
        "diff": comparison.diff,
        "diff_hash": comparison.diff_hash,
        "verification": "VERIFIED" if verified else "UNVERIFIABLE",
        "created_at": comparison.created_at.isoformat() if comparison.created_at else None,
    }


# ---------------------------------------------------------------------------
# Immutable ledger
# ---------------------------------------------------------------------------
def _ledger_payload(entry: LedgerEntry) -> dict[str, Any]:
    return {
        "policy_id": str(entry.policy_id),
        "policy_version": entry.policy_version,
        "query_id": str(entry.query_id) if entry.query_id else None,
        "entry_type": entry.entry_type,
        "epsilon_delta": _dec(entry.epsilon_delta),
        "delta_delta": _dec(entry.delta_delta),
        "epsilon_reserved_after": _dec(entry.epsilon_reserved_after),
        "delta_reserved_after": _dec(entry.delta_reserved_after),
        "epsilon_spent_after": _dec(entry.epsilon_spent_after),
        "delta_spent_after": _dec(entry.delta_spent_after),
        "note": entry.note,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }


def _entry_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    return privacy.sha256_hex(prev_hash + "|" + privacy.canonical_json(payload))


def append_ledger(
    db: Session,
    *,
    policy_id: uuid.UUID,
    policy_version: int,
    policy_version_seq: int,
    query_id: uuid.UUID | None,
    entry_type: str,
    epsilon_delta,
    delta_delta,
    balances: dict[str, Decimal],
    note: str | None = None,
) -> LedgerEntry:
    """Append one hash-chained entry. There is one chain per policy: callers
    across all parameter versions hold the parent policy row lock, so the
    chain cannot fork even when different versions are booked concurrently.
    Each entry additionally records the parameter version it belongs to."""
    last = db.execute(
        select(LedgerEntry)
        .where(LedgerEntry.policy_id == policy_id)
        .order_by(LedgerEntry.id.desc())
        .limit(1)
    ).scalar_one_or_none()
    prev_hash = last.entry_hash if last else GENESIS_HASH
    entry = LedgerEntry(
        policy_id=policy_id,
        policy_version=policy_version,
        policy_version_seq=policy_version_seq,
        query_id=query_id,
        entry_type=entry_type,
        epsilon_delta=Decimal(epsilon_delta),
        delta_delta=Decimal(delta_delta),
        epsilon_reserved_after=balances["epsilon_reserved"],
        delta_reserved_after=balances["delta_reserved"],
        epsilon_spent_after=balances["epsilon_spent"],
        delta_spent_after=balances["delta_spent"],
        note=note,
        prev_hash=prev_hash,
        created_at=_utcnow(),
    )
    entry.entry_hash = _entry_hash(prev_hash, _ledger_payload(entry))
    db.add(entry)
    return entry


# ---------------------------------------------------------------------------
# Query submission (budget reservation)
# ---------------------------------------------------------------------------
# Every budget operation runs while the caller holds the parent policy row
# lock (policy-wide serialisation point, same as a publish). Two statements
# per mutation:
#   1. bump the global CAS token policies.version (shared by every version),
#   2. mutate the *bound version's* independent pool guarded by its limits.
# The returned pool row carries the authoritative post-mutation balances.
_BUMP_POLICY_SQL = text(
    """
    UPDATE policies
    SET version = version + 1,
        updated_at = :now
    WHERE id = :pid AND version = :ver
    RETURNING version
    """
)

_RESERVE_SQL = text(
    """
    WITH upd AS (
        UPDATE policy_version_budgets
        SET epsilon_reserved = epsilon_reserved + :eps,
            delta_reserved   = delta_reserved + :del,
            updated_at       = :now
        WHERE policy_id = :pid AND version_seq = :vseq
          AND epsilon_reserved + epsilon_spent + :eps <= epsilon_total
          AND delta_reserved   + delta_spent   + :del <= delta_total
        RETURNING epsilon_reserved, delta_reserved, epsilon_spent, delta_spent
    ), mirror AS (
        UPDATE policies p
        SET epsilon_reserved = p.epsilon_reserved + :eps,
            delta_reserved   = p.delta_reserved   + :del
        FROM upd
        WHERE p.id = :pid AND :vseq = 1
    )
    SELECT * FROM upd
    """
)

_DISCLOSE_SQL = text(
    """
    WITH upd AS (
        UPDATE policy_version_budgets
        SET epsilon_reserved = epsilon_reserved - :eps,
            delta_reserved   = delta_reserved   - :del,
            epsilon_spent    = epsilon_spent    + :eps,
            delta_spent      = delta_spent      + :del,
            updated_at       = :now
        WHERE policy_id = :pid AND version_seq = :vseq
          AND epsilon_reserved >= :eps
          AND delta_reserved   >= :del
        RETURNING epsilon_reserved, delta_reserved, epsilon_spent, delta_spent
    ), mirror AS (
        UPDATE policies p
        SET epsilon_reserved = p.epsilon_reserved - :eps,
            delta_reserved   = p.delta_reserved   - :del,
            epsilon_spent    = p.epsilon_spent    + :eps,
            delta_spent      = p.delta_spent      + :del
        FROM upd
        WHERE p.id = :pid AND :vseq = 1
    )
    SELECT * FROM upd
    """
)

_CANCEL_SQL = text(
    """
    WITH upd AS (
        UPDATE policy_version_budgets
        SET epsilon_reserved = epsilon_reserved - :eps,
            delta_reserved   = delta_reserved   - :del,
            updated_at       = :now
        WHERE policy_id = :pid AND version_seq = :vseq
          AND epsilon_reserved >= :eps
          AND delta_reserved   >= :del
        RETURNING epsilon_reserved, delta_reserved, epsilon_spent, delta_spent
    ), mirror AS (
        UPDATE policies p
        SET epsilon_reserved = p.epsilon_reserved - :eps,
            delta_reserved   = p.delta_reserved   - :del
        FROM upd
        WHERE p.id = :pid AND :vseq = 1
    )
    SELECT * FROM upd
    """
)

# Erasure invalidation refunds a reservation exactly like a cancel does.
_INVALIDATE_SQL = _CANCEL_SQL


def _cas_balances(row) -> dict[str, Decimal]:
    return {
        "epsilon_reserved": row[0],
        "delta_reserved": row[1],
        "epsilon_spent": row[2],
        "delta_spent": row[3],
    }


def _bump_policy(db: Session, policy: Policy, now) -> int:
    """Bump the global CAS token; caller holds the policy row lock."""
    row = db.execute(_BUMP_POLICY_SQL, {
        "pid": policy.id, "ver": policy.version, "now": now,
    }).first()
    if row is None:
        raise conflict("VERSION_CONFLICT",
                       "policy version changed concurrently; retry the operation",
                       {"current_version": policy.version})
    new_version = row[0]
    policy.version = new_version  # keep the locked ORM instance authoritative
    return new_version


def _matches(attributes: dict, filters: dict) -> bool:
    for key, wanted in (filters or {}).items():
        actual = attributes.get(key)
        if isinstance(wanted, list):
            if actual not in wanted:
                return False
        elif actual != wanted:
            return False
    return True


def _validate_query(req, params: PolicyVersion) -> None:
    """Validate a submission against the *bound* policy parameter version."""
    dimensions = params.dimensions or []
    unknown_group = [d for d in req.group_by if d not in dimensions]
    if unknown_group:
        raise ApiError(422, "DIMENSION_NOT_ALLOWED",
                       "group_by dimensions not allowed by the bound policy version",
                       {"unknown": unknown_group, "allowed": dimensions,
                        "policy_version_seq": params.version_seq})
    unknown_filters = [k for k in (req.filters or {}) if k not in dimensions]
    if unknown_filters:
        raise ApiError(422, "DIMENSION_NOT_ALLOWED",
                       "filter dimensions not allowed by the bound policy version",
                       {"unknown": unknown_filters, "allowed": dimensions,
                        "policy_version_seq": params.version_seq})
    if req.query_type == "sum":
        if not req.measure:
            raise ApiError(422, "MEASURE_REQUIRED", "sum queries require 'measure'")
        if req.value_min is None or req.value_max is None:
            raise ApiError(422, "VALUE_BOUNDS_REQUIRED",
                           "sum queries require value_min and value_max for clipping")
        if req.value_min > req.value_max:
            raise ApiError(422, "INVALID_VALUE_BOUNDS", "value_min must be <= value_max")
        if max(abs(req.value_min), abs(req.value_max)) == 0:
            raise ApiError(422, "ZERO_SENSITIVITY",
                           "value bounds [0, 0] give zero sensitivity; nothing to query")
    if req.delta > 0 and params.delta_total == 0:
        raise ApiError(422, "DELTA_NOT_ALLOWED",
                       f"the bound policy version {params.version_seq} has delta_total = 0 "
                       "(pure DP); submit queries with delta = 0")


def _request_spec(req, policy: Policy, version_seq: int) -> dict[str, Any]:
    spec = {
        "policy_id": str(policy.id),
        "policy_version_seq": version_seq,
        "dataset_version": req.dataset_version,
        "query_type": req.query_type,
        "measure": req.measure,
        "value_min": str(req.value_min) if req.value_min is not None else None,
        "value_max": str(req.value_max) if req.value_max is not None else None,
        "group_by": list(req.group_by),
        "filters": req.filters,
        "epsilon": str(req.epsilon),
        "delta": str(req.delta),
    }
    # Only present for seal-bound queries, so unbound digests (and their
    # idempotency semantics) remain stable otherwise.
    if getattr(req, "seal_id", None) is not None:
        spec["seal_id"] = str(req.seal_id)
    return spec


def submit_query(db: Session, req) -> tuple[Query, bool]:
    """Reserve budget and compute the (still undisclosed) noisy result.

    The submission binds to the currently effective policy parameter version
    (``policy_version_seq`` defaults to the effective pointer; an explicit
    stale seq fails with POLICY_VERSION_NOT_EFFECTIVE). All clipping
    parameters and the budget reservation come from that exact version pool,
    and the query keeps booking against it for its whole lifecycle. Returns
    (query, created). Idempotent: same key + same digest replays the original
    reservation; same key + different digest -> 409.
    """
    policy = db.execute(
        select(Policy).where(Policy.name == req.policy_name)
    ).scalar_one_or_none()
    if policy is None:
        raise ApiError(404, "POLICY_NOT_FOUND", f"policy '{req.policy_name}' not found")
    if policy.status != "ACTIVE":
        raise conflict("POLICY_NOT_ACTIVE", f"policy '{req.policy_name}' is {policy.status}")

    # Global lock order: policy row first (every budget mutation, publish and
    # erasure starts here), so a submission can never deadlock against an
    # erasure that locks policies before its barrier or a disclose/cancel that
    # locks the policy before the query row.
    locked = _lock_policy(db, policy.id)

    requested_seq = req.policy_version_seq or locked.effective_version_seq
    digest = privacy.request_digest(_request_spec(req, locked, requested_seq))

    existing = db.execute(
        select(Query).where(Query.idempotency_key == req.idempotency_key)
    ).scalar_one_or_none()
    if existing is not None:
        # An existing key always stays on its originally bound version: replay
        # its request digest with the query's stored version_seq so a version
        # switch in between cannot turn a legitimate retry into a digest
        # conflict. A genuinely different request body still conflicts.
        retry_digest = privacy.request_digest(
            _request_spec(req, locked, existing.policy_version_seq))
        if existing.request_digest != retry_digest:
            raise conflict(
                "IDEMPOTENCY_CONFLICT",
                "idempotency key was already used with a different request",
                {"query_id": str(existing.id), "status": existing.status},
            )
        # Retry: the policy is already locked; lock the query next (policy ->
        # query order), record the retry in the ledger, and return the
        # original reservation untouched.
        existing = db.execute(
            select(Query).where(Query.id == existing.id).with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one()
        budget = _lock_budget(db, locked.id, existing.policy_version_seq)
        existing.retry_count += 1
        existing.updated_at = _utcnow()
        append_ledger(
            db,
            policy_id=locked.id,
            policy_version=locked.version,
            policy_version_seq=existing.policy_version_seq,
            query_id=existing.id,
            entry_type="RETRY",
            epsilon_delta=0,
            delta_delta=0,
            balances=_version_balances(budget),
            note=f"retry #{existing.retry_count} of idempotent submit",
        )
        db.commit()
        return existing, False

    # New submissions may only bind the currently effective parameter version;
    # older versions stay available for disclosure / cancellation / audit of
    # queries already bound to them.
    _check_expected_version(locked, req.expected_policy_version)
    if requested_seq != locked.effective_version_seq:
        raise conflict(
            "POLICY_VERSION_NOT_EFFECTIVE",
            f"policy parameter version {requested_seq} is not effective; the "
            f"current effective version is {locked.effective_version_seq}",
            {"requested_version_seq": requested_seq,
             "effective_version_seq": locked.effective_version_seq})
    version_seq = locked.effective_version_seq
    params = _get_policy_version(db, locked.id, version_seq)

    _validate_query(req, params)

    # Next in the global lock order: erasure barrier + per-dataset-version
    # lock (taken before reading any query rows / snapshotting records).
    _lock_dataset_version(db, req.dataset_version)

    seal: VersionSeal | None = None
    revision: SealRevision | None = None
    if req.seal_id is not None:
        seal = _get_seal(db, req.seal_id)
        if seal.dataset_version != req.dataset_version:
            raise ApiError(
                422, "SEAL_VERSION_MISMATCH",
                f"seal {req.seal_id} covers dataset version {seal.dataset_version}, "
                f"not {req.dataset_version}",
                {"seal_id": str(seal.id), "seal_dataset_version": seal.dataset_version,
                 "dataset_version": req.dataset_version})
        # Pin the revision current at submission time; it is immutable, so
        # the snapshot below can never span two roots.
        revision = _latest_revision(db, seal.id)

    # ---- deterministic clipping & aggregation over the dataset version ----
    rows: list[tuple[int, str, Any]] = []
    invalid_measure = 0
    if revision is not None:
        # Seal-bound: compute over the pinned manifest revision. Subjects are
        # pseudonymous hashes here — the raw identifier never enters a bound
        # snapshot. Rows are ordered by the manifest's record_key order.
        leaves = _manifest_leaves(revision)
        matched_count = 0
        for index, leaf in enumerate(leaves):
            attrs = leaf.get("attributes") or {}
            if not _matches(attrs, req.filters):
                continue
            matched_count += 1
            if req.query_type == "sum":
                raw = attrs.get(req.measure)
                if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                    invalid_measure += 1
                    continue
                rows.append((index, leaf["subject_hash"], (attrs, float(raw))))
            else:
                rows.append((index, leaf["subject_hash"], (attrs, 1.0)))
        records_in_dataset = len(leaves)
        seed = privacy.derive_noise_seed_bound(req.idempotency_key, digest, revision.root)
    else:
        # Unbound: original semantics over the live records table.
        records = list(db.execute(
            select(Record).where(Record.dataset_version == req.dataset_version).order_by(Record.id)
        ).scalars())
        matched_records = [r for r in records if _matches(r.attributes or {}, req.filters)]
        matched_count = len(matched_records)
        for record in matched_records:
            if req.query_type == "sum":
                raw = (record.attributes or {}).get(req.measure)
                if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                    invalid_measure += 1
                    continue
                rows.append((record.id, record.subject_id, (record.attributes, float(raw))))
            else:
                rows.append((record.id, record.subject_id, (record.attributes, 1.0)))
        records_in_dataset = len(records)
        seed = privacy.derive_noise_seed(req.idempotency_key, digest)

    kept, clip_detail = privacy.clip_contributions(rows, params.per_subject_cap)
    groups = privacy.aggregate(kept, req.group_by, req.query_type, req.value_min, req.value_max)

    sens = privacy.sensitivity(req.query_type, params.per_subject_cap, req.value_min, req.value_max)
    mechanism = privacy.mechanism_for(req.delta)
    scale = privacy.noise_scale(mechanism, sens, float(req.epsilon), float(req.delta))
    noisy_groups = privacy.apply_noise(groups, mechanism, scale, seed)

    clipping_snapshot = {
        "policy_version_seq": version_seq,
        "per_subject_cap": params.per_subject_cap,
        "dimensions": list(params.dimensions or []),
        "epsilon_total": float(params.epsilon_total),
        "delta_total": float(params.delta_total),
        "version_summary_hash": params.summary_hash,
        "dataset_version": req.dataset_version,
        "records_in_dataset": records_in_dataset,
        "records_matched": matched_count,
        "records_excluded_invalid_measure": invalid_measure,
        "kept_contributions": len(kept),
        "subjects": clip_detail,  # sorted by subject_id (pseudonymous hash when seal-bound)
    }
    if revision is not None:
        clipping_snapshot["seal"] = {
            "seal_id": str(seal.id),
            "revision_seq": revision.revision_seq,
            "root": revision.root,
            "revision_hash": revision.revision_hash,
        }

    # ---- budget reservation against the bound version pool, one txn -------
    now = _utcnow()
    new_version = _bump_policy(db, locked, now)
    budget = _lock_budget(db, locked.id, version_seq)
    row = db.execute(_RESERVE_SQL, {
        "eps": req.epsilon, "del": req.delta,
        "pid": locked.id, "vseq": version_seq, "now": now,
    }).first()
    if row is None:
        # We hold both locks; the version guards are the only thing that can fail.
        raise conflict("BUDGET_EXCEEDED", "insufficient privacy budget on the "
                       f"effective policy version {version_seq}", {
            "policy_version_seq": version_seq,
            "epsilon_available": _dec(budget.epsilon_total - budget.epsilon_reserved - budget.epsilon_spent),
            "delta_available": _dec(budget.delta_total - budget.delta_reserved - budget.delta_spent),
            "epsilon_requested": _dec(req.epsilon),
            "delta_requested": _dec(req.delta),
        })

    query = Query(
        id=uuid.uuid4(),
        idempotency_key=req.idempotency_key,
        request_digest=digest,
        policy_id=locked.id,
        policy_name=locked.name,
        policy_version=new_version,
        policy_version_seq=version_seq,
        dataset_version=req.dataset_version,
        query_type=req.query_type,
        measure=req.measure,
        value_min=req.value_min,
        value_max=req.value_max,
        group_by=list(req.group_by),
        filters=dict(req.filters or {}),
        epsilon=req.epsilon,
        delta=req.delta,
        mechanism=mechanism,
        sensitivity=Decimal(str(sens)),
        noise_scale=Decimal(str(scale)),
        noise_seed=seed,
        status="RESERVED",
        clipping=clipping_snapshot,
        seal_id=seal.id if seal is not None else None,
        seal_root=revision.root if revision is not None else None,
        seal_revision_seq=revision.revision_seq if revision is not None else None,
        result={
            "mechanism": mechanism,
            "sensitivity": sens,
            "scale": scale,
            "seed": seed,
            "groups": noisy_groups,
        },
        created_at=now,
        updated_at=now,
    )
    db.add(query)
    db.flush()  # persist the query before its first ledger entry (FK order)
    append_ledger(
        db,
        policy_id=locked.id,
        policy_version=new_version,
        policy_version_seq=version_seq,
        query_id=query.id,
        entry_type="RESERVE",
        epsilon_delta=req.epsilon,
        delta_delta=req.delta,
        balances=_cas_balances(row),
        note=f"budget reserved on policy version {version_seq}",
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Lost a race on the idempotency key unique constraint.
        raise conflict("IDEMPOTENCY_CONFLICT",
                       "idempotency key was concurrently registered; retry the request")
    return query, True


# ---------------------------------------------------------------------------
# Disclosure & cancellation
# ---------------------------------------------------------------------------
def _lock_query(db: Session, query_id: uuid.UUID) -> Query:
    query = db.execute(
        select(Query)
        .where(Query.id == query_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if query is None:
        raise ApiError(404, "QUERY_NOT_FOUND", f"query {query_id} not found")
    return query


def disclose_query(db: Session, query_id: uuid.UUID, expected_policy_version: int | None) -> Query:
    # Global lock order: policy row -> query row. Read the query without
    # locking just to learn its policy, lock the policy first (the same order
    # erasures and submissions use), then re-read and lock the query under it.
    target = db.get(Query, query_id)
    if target is None:
        raise ApiError(404, "QUERY_NOT_FOUND", f"query {query_id} not found")
    policy = _lock_policy(db, target.policy_id)
    query = _lock_query(db, query_id)
    if query.status == "CANCELLED":
        raise conflict("QUERY_CANCELLED", "a cancelled query cannot be disclosed")
    if query.status == "INVALIDATED":
        raise conflict("QUERY_INVALIDATED",
                       "query was invalidated by a data-subject erasure; "
                       "its reservation was already refunded")

    budget = _lock_budget(db, policy.id, query.policy_version_seq)

    if query.status == "DISCLOSED":
        # Idempotent repeat disclosure: same stored result, ledger-audited.
        query.retry_count += 1
        query.updated_at = _utcnow()
        append_ledger(
            db,
            policy_id=policy.id,
            policy_version=policy.version,
            policy_version_seq=query.policy_version_seq,
            query_id=query.id,
            entry_type="RETRY",
            epsilon_delta=0,
            delta_delta=0,
            balances=_version_balances(budget),
            note=f"repeat disclosure #{query.retry_count} (idempotent)",
        )
        db.commit()
        return query

    _check_expected_version(policy, expected_policy_version)
    now = _utcnow()
    new_version = _bump_policy(db, policy, now)
    row = db.execute(_DISCLOSE_SQL, {
        "eps": query.epsilon, "del": query.delta,
        "pid": policy.id, "vseq": query.policy_version_seq, "now": now,
    }).first()
    if row is None:
        raise ApiError(500, "BUDGET_STATE_INVALID",
                       "disclosure could not convert the reservation atomically",
                       {"query_id": str(query.id),
                        "policy_version_seq": query.policy_version_seq})

    query.status = "DISCLOSED"
    query.disclosed_at = now
    query.updated_at = now
    query.policy_version = new_version
    append_ledger(
        db,
        policy_id=policy.id,
        policy_version=new_version,
        policy_version_seq=query.policy_version_seq,
        query_id=query.id,
        entry_type="DISCLOSE",
        epsilon_delta=0,   # reservation converts to spend; total unchanged
        delta_delta=0,
        balances=_cas_balances(row),
        note=f"result disclosed; reservation consumed on policy version {query.policy_version_seq}",
    )
    db.commit()
    return query


def cancel_query(db: Session, query_id: uuid.UUID, expected_policy_version: int | None) -> Query:
    # Global lock order: policy row -> query row (see disclose_query).
    target = db.get(Query, query_id)
    if target is None:
        raise ApiError(404, "QUERY_NOT_FOUND", f"query {query_id} not found")
    policy = _lock_policy(db, target.policy_id)
    query = _lock_query(db, query_id)
    if query.status == "DISCLOSED":
        raise conflict("CANCEL_WINDOW_CLOSED",
                       "query already disclosed; budget cannot be refunded")
    if query.status == "CANCELLED":
        raise conflict("REFUND_ALREADY_ISSUED",
                       "reservation was already refunded once; a second refund is not allowed")
    if query.status == "INVALIDATED":
        raise conflict("REFUND_ALREADY_ISSUED",
                       "reservation was already refunded by erasure invalidation; "
                       "a second refund is not allowed")

    # Lock the bound version pool to serialise the refund (its balances are
    # read back from the RETURNING row below).
    _lock_budget(db, policy.id, query.policy_version_seq)
    _check_expected_version(policy, expected_policy_version)
    now = _utcnow()
    new_version = _bump_policy(db, policy, now)
    row = db.execute(_CANCEL_SQL, {
        "eps": query.epsilon, "del": query.delta,
        "pid": policy.id, "vseq": query.policy_version_seq, "now": now,
    }).first()
    if row is None:
        raise ApiError(500, "BUDGET_STATE_INVALID",
                       "cancellation could not refund the reservation atomically",
                       {"query_id": str(query.id),
                        "policy_version_seq": query.policy_version_seq})

    query.status = "CANCELLED"
    query.cancelled_at = now
    query.updated_at = now
    query.policy_version = new_version
    append_ledger(
        db,
        policy_id=policy.id,
        policy_version=new_version,
        policy_version_seq=query.policy_version_seq,
        query_id=query.id,
        entry_type="CANCEL",
        epsilon_delta=-query.epsilon,   # refund the reservation, exactly once
        delta_delta=-query.delta,
        balances=_cas_balances(row),
        note=f"reservation cancelled and refunded on policy version {query.policy_version_seq}",
    )
    db.commit()
    return query


def get_query(db: Session, query_id: uuid.UUID) -> Query:
    query = db.get(Query, query_id)
    if query is None:
        raise ApiError(404, "QUERY_NOT_FOUND", f"query {query_id} not found")
    return query


# ---------------------------------------------------------------------------
# Data-subject erasure
# ---------------------------------------------------------------------------
def _erasure_proof_payload(tomb: ErasureTombstone) -> dict[str, Any]:
    """Canonical payload bound into the erasure proof hash. Recomputed from
    the stored tombstone at audit time, so it must stay deterministic."""
    return {
        "tombstone_id": tomb.id,
        "subject_hash": tomb.subject_hash,
        "until_dataset_version": tomb.until_dataset_version,
        "affected_dataset_versions": list(tomb.affected_dataset_versions or []),
        "records_deleted": tomb.records_deleted,
        "queries_invalidated": tomb.queries_invalidated,
        "snapshots_scrubbed": tomb.snapshots_scrubbed,
        "invalidated_queries": tomb.invalidated_queries,
        "seal_revisions": list(tomb.seal_revisions or []),
        "created_at": tomb.created_at.isoformat() if tomb.created_at else None,
    }


def erase_subject(db: Session, req) -> tuple[ErasureTombstone, bool]:
    """Register an erasure tombstone and apply all its effects atomically.

    One transaction: under the erasure lock barrier (which serialises against
    every in-flight upload / query submission), first determine the affected
    dataset-version set — versions within the cut-off range where the subject
    actually has records, plus versions whose stored query snapshots actually
    reference the subject. Every effect is then scoped to exactly that set:
    delete the subject's raw records, scrub the subject identifier from every
    affected snapshot, invalidate every still-RESERVED query on an affected
    version (refunding its reservation exactly once and appending the
    INVALIDATE ledger entries), and append the immutable tombstone with its
    erasure proof. Queries, budgets and ledger entries on cut-off-range
    versions that never contained the subject are left completely untouched;
    disclosed results and existing ledger entries are never touched either.
    Returns (tombstone, created); an idempotent replay returns the stored
    tombstone without redoing any work.
    """
    subject_hash = privacy.erasure_subject_hash(req.subject_id)
    digest = privacy.erasure_request_digest({
        "subject_hash": subject_hash,
        "until_dataset_version": req.until_dataset_version,
    })

    def _lookup() -> ErasureTombstone | None:
        tomb = db.execute(
            select(ErasureTombstone)
            .where(ErasureTombstone.idempotency_key == req.idempotency_key)
        ).scalar_one_or_none()
        if tomb is not None and tomb.request_digest != digest:
            raise conflict(
                "IDEMPOTENCY_CONFLICT",
                "idempotency key was already used with a different erasure request",
                {"tombstone_id": tomb.id},
            )
        return tomb

    existing = _lookup()
    if existing is not None:
        return existing, False

    # Global lock order across the whole service is:
    #   policy row lock(s) -> erasure barrier -> per-dataset-version lock
    #   -> individual query rows.
    # An erasure may touch reservations of *any* policy, so before taking the
    # exclusive erasure barrier it locks every ACTIVE policy row (stably by
    # id). A concurrent submission / disclose / cancel therefore can never
    # hold a policy row while waiting for the barrier the erasure needs: it
    # either gets the barrier first (shared) or queues behind the erasure on
    # the policy row — no lock-order cycle is possible.
    active_policies = list(db.execute(
        select(Policy).order_by(Policy.id).with_for_update()
    ).scalars())

    # Serialise against every in-flight upload / query submission so no new
    # record or RESERVED query on an affected version can slip past the scans.
    _lock_erasure_exclusive(db)
    existing = _lookup()  # another erasure may have committed while we waited
    if existing is not None:
        return existing, False

    now = _utcnow()
    cutoff = req.until_dataset_version

    # 1. determine the affected dataset-version set, still under the erasure
    #    lock barrier so no concurrent upload / submission can change it:
    #    versions where the subject actually has stored records within the
    #    cut-off range, plus versions whose stored query snapshots actually
    #    reference the subject. Record deletion, snapshot scrubbing, query
    #    invalidation, refunds and the proof hash below are all scoped to
    #    exactly this set — subject-free versions inside the cut-off range
    #    keep their queries, budget and ledger untouched.
    record_versions = set(db.execute(
        select(Record.dataset_version)
        .where(Record.subject_id == req.subject_id, Record.dataset_version <= cutoff)
        .distinct()
    ).scalars())
    # NOTE: this scan deliberately takes NO row locks. The exclusive erasure
    # barrier (acquired above) already excludes every concurrent upload and
    # query submission, so the affected set cannot change underneath us;
    # locking this broad set in a plan-dependent order used to deadlock two
    # concurrent erasures against each other. The only rows actually mutated
    # below — the still-RESERVED queries — are locked explicitly, in a stable
    # id order, in step 4.
    snapshot_candidates = list(db.execute(
        select(Query)
        .where(Query.dataset_version <= cutoff, Query.clipping.isnot(None))
    ).scalars())
    # Snapshots reference the subject either by raw identifier (unbound
    # queries) or by its pseudonymous hash (seal-bound queries).
    referencing = [
        query for query in snapshot_candidates
        if any(s.get("subject_id") in (req.subject_id, subject_hash)
               for s in (query.clipping or {}).get("subjects") or [])
    ]
    snapshot_versions = {query.dataset_version for query in referencing}
    affected_versions = sorted(record_versions | snapshot_versions)

    # 2. erase the subject's raw records: exactly the record_versions subset
    #    of the affected set loses rows
    records_deleted = db.execute(
        delete(Record).where(
            Record.subject_id == req.subject_id,
            Record.dataset_version <= cutoff,
        )
    ).rowcount or 0

    # 3. scrub the subject identifier from every affected snapshot that
    #    references it (noisy results stay untouched)
    snapshots_scrubbed = 0
    for query in referencing:
        subjects = (query.clipping or {}).get("subjects") or []
        query.clipping = {
            **query.clipping,
            "subjects": [
                {**s, "subject_id": ERASED_SUBJECT_MARKER}
                if s.get("subject_id") in (req.subject_id, subject_hash) else s
                for s in subjects
            ],
        }
        query.updated_at = now
        snapshots_scrubbed += 1

    # 3b. for every affected SEALED version, append an erasure revision to
    #     the seal's revision chain instead of rewriting the old manifest:
    #     the new revision links the previous revision hash, drops the erased
    #     subject's leaves (manifests only ever carry the pseudonymous hash)
    #     and commits the recomputed Merkle root. Bound queries submitted
    #     afterwards pin this latest revision; queries pinned to older
    #     revisions still verify against their original root.
    tombstone_id = db.execute(
        text("SELECT nextval('erasure_tombstones_id_seq')")
    ).scalar_one()
    affected_seals = []
    if affected_versions:
        affected_seals = list(db.execute(
            select(VersionSeal).where(VersionSeal.dataset_version.in_(affected_versions))
        ).scalars())
    pending_revisions: list[SealRevision] = []
    seal_rev_links: list[dict[str, Any]] = []
    for seal in sorted(affected_seals, key=lambda s: s.dataset_version):
        latest = _latest_revision(db, seal.id)
        leaves = _manifest_leaves(latest)
        if not any(leaf["subject_hash"] == subject_hash for leaf in leaves):
            continue  # already scrubbed by an earlier erasure — no-op
        new_leaves = [leaf for leaf in leaves if leaf["subject_hash"] != subject_hash]
        rev = SealRevision(
            seal_id=seal.id,
            revision_seq=latest.revision_seq + 1,
            kind="erasure",
            prev_revision_hash=latest.revision_hash,
            root=privacy.merkle_root([privacy.leaf_hash(leaf) for leaf in new_leaves]),
            record_count=len(new_leaves),
            manifest={"hash_version": privacy.SEAL_HASH_VERSION, "leaves": new_leaves},
            subject_hash=subject_hash,
            tombstone_id=tombstone_id,
            created_at=now,
        )
        rev.revision_hash = privacy.seal_revision_hash(_revision_payload(rev))
        pending_revisions.append(rev)
        seal_rev_links.append({
            "seal_id": str(seal.id),
            "dataset_version": seal.dataset_version,
            "revision_seq": rev.revision_seq,
            "prev_revision_hash": rev.prev_revision_hash,
            "root": rev.root,
            "record_count": rev.record_count,
            "revision_hash": rev.revision_hash,
        })

    # 4. invalidate every still-RESERVED query on an affected version: refund
    #    the reservation exactly once, in the same transaction as the ledger
    #    append. Queries may be bound to different policy parameter versions;
    #    each refund goes to its query's own independent pool. Lock order
    #    query -> policy matches disclose / cancel; group by policy and take
    #    policy locks in a stable order so a multi-policy erasure can never
    #    deadlock against concurrent budget operations.
    reserved = []
    if affected_versions:
        reserved = list(db.execute(
            select(Query)
            .where(Query.dataset_version.in_(affected_versions), Query.status == "RESERVED")
            .order_by(Query.id)
            .with_for_update()
        ).scalars())
    invalidated: list[dict[str, Any]] = []
    # All ACTIVE policy rows are already locked (in id order) above; the
    # barrier guarantees the set cannot have changed. Lock each reservation's
    # own independent version pool as we refund it.
    locked_policies = {p.id: p for p in active_policies}
    for query in reserved:
        policy = locked_policies[query.policy_id]
        _lock_budget(db, policy.id, query.policy_version_seq)
        new_version = _bump_policy(db, policy, now)
        row = db.execute(_INVALIDATE_SQL, {
            "eps": query.epsilon, "del": query.delta,
            "pid": policy.id, "vseq": query.policy_version_seq, "now": now,
        }).first()
        if row is None:  # we hold both locks; only the guards can fail
            raise ApiError(500, "INVALIDATION_FAILED",
                           "could not refund the reservation atomically",
                           {"query_id": str(query.id)})
        query.status = "INVALIDATED"
        query.invalidated_at = now
        query.invalidated_by = tombstone_id
        query.updated_at = now
        query.policy_version = new_version
        entry = append_ledger(
            db,
            policy_id=policy.id,
            policy_version=new_version,
            policy_version_seq=query.policy_version_seq,
            query_id=query.id,
            entry_type="INVALIDATE",
            epsilon_delta=-query.epsilon,   # refund the reservation, exactly once
            delta_delta=-query.delta,
            balances=_cas_balances(row),
            note=f"reservation invalidated by erasure tombstone #{tombstone_id} "
                 f"and refunded on policy version {query.policy_version_seq}",
        )
        db.flush()  # assign the ledger seq and make the entry visible to the
                    # next append_ledger chain lookup inside this transaction
        invalidated.append({
            "query_id": str(query.id),
            "policy_id": str(policy.id),
            "policy_name": policy.name,
            "policy_version_seq": query.policy_version_seq,
            "dataset_version": query.dataset_version,
            "ledger_seq": entry.id,
            "refunded": {"epsilon": float(query.epsilon), "delta": float(query.delta)},
        })
    invalidated.sort(key=lambda item: item["query_id"])

    # 5. append the immutable tombstone with its erasure proof (binding the
    #    seal-revision links), then the pending seal revisions — the ORM
    #    orders the tombstone insert first thanks to the FK dependency.
    tombstone = ErasureTombstone(
        id=tombstone_id,
        idempotency_key=req.idempotency_key,
        request_digest=digest,
        subject_hash=subject_hash,
        until_dataset_version=cutoff,
        affected_dataset_versions=affected_versions,
        records_deleted=records_deleted,
        queries_invalidated=len(invalidated),
        snapshots_scrubbed=snapshots_scrubbed,
        invalidated_queries=invalidated,
        seal_revisions=seal_rev_links,
        created_at=now,
    )
    tombstone.proof_hash = privacy.erasure_proof_hash(_erasure_proof_payload(tombstone))
    db.add(tombstone)
    for rev in pending_revisions:
        db.add(rev)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Lost a race on the idempotency key unique constraint.
        tomb = db.execute(
            select(ErasureTombstone)
            .where(ErasureTombstone.idempotency_key == req.idempotency_key)
        ).scalar_one_or_none()
        if tomb is not None and tomb.request_digest == digest:
            return tomb, False
        raise conflict("IDEMPOTENCY_CONFLICT",
                       "idempotency key was concurrently registered; retry the request")
    return tombstone, True


def _seal_revision_link_view(db: Session, tomb: ErasureTombstone, link: dict) -> dict[str, Any]:
    """Audit view of one erasure-appended seal revision: re-verify the stored
    revision against the tombstone's link (root recomputed from the stored
    manifest, revision hash recomputed, chain link and tombstone reference
    checked)."""
    rev = db.execute(
        select(SealRevision).where(SealRevision.revision_hash == link.get("revision_hash"))
    ).scalar_one_or_none()
    checks = {"exists": rev is not None}
    if rev is not None:
        leaves = _manifest_leaves(rev)
        checks.update({
            "tombstone_link": rev.tombstone_id == tomb.id,
            "root": privacy.merkle_root([privacy.leaf_hash(leaf) for leaf in leaves]) == rev.root == link.get("root"),
            "revision_hash": privacy.seal_revision_hash(_revision_payload(rev)) == rev.revision_hash,
            "chain": rev.prev_revision_hash == link.get("prev_revision_hash"),
            "subject": rev.subject_hash == tomb.subject_hash,
            "record_count": rev.record_count == len(leaves) == link.get("record_count"),
        })
    verified = all(checks.values())
    return {
        **link,
        "subject_hash": tomb.subject_hash,
        "checks": checks,
        "verification": "VERIFIED" if verified else "UNVERIFIABLE",
    }


def list_erasures(db: Session) -> list[dict[str, Any]]:
    """Audit view of all tombstones: proof, affected queries, verification.

    Never exposes the erased subject identifier — only its pseudonymous hash.
    """
    tombstones = list(db.execute(
        select(ErasureTombstone).order_by(ErasureTombstone.id)
    ).scalars())
    views = []
    for tomb in tombstones:
        verified = privacy.erasure_proof_hash(_erasure_proof_payload(tomb)) == tomb.proof_hash
        seal_links = [_seal_revision_link_view(db, tomb, link)
                      for link in (tomb.seal_revisions or [])]
        views.append({
            "tombstone_id": tomb.id,
            "subject_hash": tomb.subject_hash,
            "until_dataset_version": tomb.until_dataset_version,
            "affected_dataset_versions": list(tomb.affected_dataset_versions or []),
            "records_deleted": tomb.records_deleted,
            "queries_invalidated": tomb.queries_invalidated,
            "snapshots_scrubbed": tomb.snapshots_scrubbed,
            "affected_queries": list(tomb.invalidated_queries or []),
            "seal_revisions": seal_links,
            "proof_hash": tomb.proof_hash,
            "proof_verified": verified,
            "verification": "VERIFIED" if verified else "UNVERIFIABLE",
            "created_at": tomb.created_at.isoformat(),
        })
    return views



# ---------------------------------------------------------------------------
# Audit: replay the ledger up to a global CAS version, scoped to one policy
# parameter version (its independent budget pool and the queries bound to it)
# ---------------------------------------------------------------------------
def replay_audit(db: Session, policy_id: uuid.UUID, to_version: int | None,
                 version_seq: int | None = None) -> dict[str, Any]:
    policy = get_policy(db, policy_id)
    latest_version = policy.version
    if to_version is None:
        to_version = latest_version
    if to_version < 1 or to_version > latest_version:
        raise ApiError(422, "VERSION_OUT_OF_RANGE",
                       f"to_version must be within [1, {latest_version}]",
                       {"latest_version": latest_version})
    if version_seq is None:
        version_seq = policy.effective_version_seq
    params = _get_policy_version(db, policy.id, version_seq)
    budget = db.get(PolicyVersionBudget, (policy.id, version_seq))
    if budget is None:
        raise ApiError(404, "POLICY_VERSION_NOT_FOUND",
                       f"policy {policy_id} has no published version {version_seq}",
                       {"policy_id": str(policy_id), "version_seq": version_seq})

    all_entries = list(db.execute(
        select(LedgerEntry).where(LedgerEntry.policy_id == policy.id).order_by(LedgerEntry.id)
    ).scalars())

    # The global hash chain spans every parameter version (one chain per
    # policy). Verify the whole id-ordered prefix up to the CAS horizon first.
    prefix = [e for e in all_entries if e.policy_version <= to_version]
    chain_ok = True
    first_bad_seq: int | None = None
    hash_valid: dict[int, bool] = {}
    prev = GENESIS_HASH
    broken = False
    for entry in prefix:
        valid = (not broken
                 and entry.prev_hash == prev
                 and _entry_hash(entry.prev_hash, _ledger_payload(entry)) == entry.entry_hash)
        if not valid:
            broken = True
            chain_ok = False
            if first_bad_seq is None:
                first_bad_seq = entry.id
        hash_valid[entry.id] = valid
        prev = entry.entry_hash

    # Scope the accounting to the requested parameter version: bookings are
    # independent per version, so balances are reconstructed solely from this
    # version's own entries (interleaved entries of other versions are skipped,
    # but their hashes still anchor the global chain verification above).
    included = [e for e in prefix if e.policy_version_seq == version_seq]

    # The scoped subsequence is embedded in the global chain: its entries stay
    # in global id order (the append order), and each entry's prev_hash is the
    # hash of some earlier entry in the global prefix (or the genesis).
    scope_ok = True
    prefix_hash_ids = {e.entry_hash: e.id for e in prefix}
    prev_included_id = 0
    for entry in included:
        if entry.prev_hash != GENESIS_HASH:
            anchor = prefix_hash_ids.get(entry.prev_hash)
            if anchor is None or anchor >= entry.id:
                scope_ok = False
        if entry.id <= prev_included_id:
            scope_ok = False
        prev_included_id = entry.id

    # --- per-version balance reconstruction from this version's entries ----
    version_queries = {q.id: q for q in db.execute(
        select(Query).where(Query.policy_id == policy.id,
                            Query.policy_version_seq == version_seq)
    ).scalars()}
    exp = {"epsilon_reserved": Decimal(0), "delta_reserved": Decimal(0),
           "epsilon_spent": Decimal(0), "delta_spent": Decimal(0)}
    balance_ok = True
    entry_views: list[dict[str, Any]] = []
    for entry in included:
        q = version_queries.get(entry.query_id) if entry.query_id else None
        delta_ok = True
        if entry.entry_type == "RESERVE":
            exp["epsilon_reserved"] += entry.epsilon_delta
            exp["delta_reserved"] += entry.delta_delta
            delta_ok = q is not None and entry.epsilon_delta == q.epsilon and entry.delta_delta == q.delta
        elif entry.entry_type == "DISCLOSE" and q is not None:
            exp["epsilon_reserved"] -= q.epsilon
            exp["delta_reserved"] -= q.delta
            exp["epsilon_spent"] += q.epsilon
            exp["delta_spent"] += q.delta
            delta_ok = entry.epsilon_delta == 0 and entry.delta_delta == 0
        elif entry.entry_type == "CANCEL":
            exp["epsilon_reserved"] += entry.epsilon_delta  # negative: refund
            exp["delta_reserved"] += entry.delta_delta
            delta_ok = q is not None and entry.epsilon_delta == -q.epsilon and entry.delta_delta == -q.delta
        elif entry.entry_type == "INVALIDATE":
            exp["epsilon_reserved"] += entry.epsilon_delta  # negative: refund
            exp["delta_reserved"] += entry.delta_delta
            delta_ok = q is not None and entry.epsilon_delta == -q.epsilon and entry.delta_delta == -q.delta
        elif entry.entry_type == "RETRY":
            delta_ok = entry.epsilon_delta == 0 and entry.delta_delta == 0

        consistent = (
            delta_ok
            and exp["epsilon_reserved"] == entry.epsilon_reserved_after
            and exp["delta_reserved"] == entry.delta_reserved_after
            and exp["epsilon_spent"] == entry.epsilon_spent_after
            and exp["delta_spent"] == entry.delta_spent_after
        )
        if not consistent:
            balance_ok = False
        entry_views.append({
            "seq": entry.id,
            "entry_type": entry.entry_type,
            "query_id": str(entry.query_id) if entry.query_id else None,
            "policy_version": entry.policy_version,
            "policy_version_seq": entry.policy_version_seq,
            "epsilon_delta": float(entry.epsilon_delta),
            "delta_delta": float(entry.delta_delta),
            "epsilon_reserved_after": float(entry.epsilon_reserved_after),
            "delta_reserved_after": float(entry.delta_reserved_after),
            "epsilon_spent_after": float(entry.epsilon_spent_after),
            "delta_spent_after": float(entry.delta_spent_after),
            "hash_valid": hash_valid.get(entry.id, False),
            "balance_consistent": consistent,
            "verification": "VERIFIED" if (hash_valid.get(entry.id, False) and consistent)
                            else "UNVERIFIABLE",
            "note": entry.note,
            "prev_hash": entry.prev_hash,
            "entry_hash": entry.entry_hash,
            "created_at": entry.created_at.isoformat(),
        })

    # --- per-query outcomes as of the replay horizon (this version only) ----
    first_seq: dict[uuid.UUID, int] = {}
    for index, entry in enumerate(included):
        if entry.query_id is not None and entry.query_id not in first_seq:
            first_seq[entry.query_id] = index

    # tombstones referenced by invalidated queries (for erasure proofs)
    tombstone_ids = {q.invalidated_by for q in version_queries.values()
                     if q.invalidated_by is not None}
    tombstones = (
        {t.id: t for t in db.execute(
            select(ErasureTombstone).where(ErasureTombstone.id.in_(tombstone_ids))
        ).scalars()}
        if tombstone_ids else {}
    )

    # seal revisions pinned by seal-bound queries (for root / seed verification)
    seal_ids = {q.seal_id for q in version_queries.values() if q.seal_id is not None}
    pinned_revisions: dict[tuple[uuid.UUID, int], SealRevision] = {}
    if seal_ids:
        pinned_revisions = {
            (rev.seal_id, rev.revision_seq): rev
            for rev in db.execute(
                select(SealRevision).where(SealRevision.seal_id.in_(seal_ids))
            ).scalars()
        }

    query_views: list[dict[str, Any]] = []
    for query_id in sorted(first_seq, key=lambda qid: first_seq[qid]):
        q = version_queries.get(query_id)
        if q is None:
            continue
        q_entries = [e for e in included if e.query_id == query_id]
        kinds = {e.entry_type for e in q_entries}
        if "DISCLOSE" in kinds:
            outcome, determinate = "DISCLOSED", True
        elif "CANCEL" in kinds:
            outcome, determinate = "CANCELLED", True
        elif "INVALIDATE" in kinds:
            outcome, determinate = "INVALIDATED", True
        else:
            # Reserved but neither disclosed nor cancelled nor invalidated at
            # this CAS horizon: the final state cannot be determined yet.
            outcome, determinate = "INDETERMINATE", False
        later_events = any(
            e.policy_version > to_version
            for e in all_entries
            if e.query_id == query_id and e.policy_version_seq == version_seq)
        view: dict[str, Any] = {
            "query_id": str(q.id),
            "idempotency_key": q.idempotency_key,
            "request_digest": q.request_digest,
            "policy_version_seq": q.policy_version_seq,
            "version_summary_hash": params.summary_hash,
            "outcome": outcome,
            "determinate": determinate,
            "later_events_beyond_replay": later_events,
            "current_status": q.status,
            "budget": {"epsilon": float(q.epsilon), "delta": float(q.delta)},
            "noise": {
                "mechanism": q.mechanism,
                "sensitivity": float(q.sensitivity),
                "scale": float(q.noise_scale),
                "seed": q.noise_seed,
            },
            "clipping": q.clipping,
            "ledger_seqs": [e.id for e in q_entries],
        }
        if not determinate:
            view["reason"] = (
                f"no DISCLOSE, CANCEL or INVALIDATE event for this query up to "
                f"replay version {to_version} on policy parameter version "
                f"{version_seq}; its final state cannot be determined from this replay"
            )
        if outcome == "DISCLOSED" and q.result:
            view["groups"] = q.result.get("groups", [])
        if outcome == "INVALIDATED":
            view["invalidated_by"] = q.invalidated_by
            tomb = tombstones.get(q.invalidated_by)
            if tomb is not None:
                # erasure proof reference — the subject hash, never the identifier
                view["erasure"] = {
                    "tombstone_id": tomb.id,
                    "subject_hash": tomb.subject_hash,
                    "until_dataset_version": tomb.until_dataset_version,
                    "proof_hash": tomb.proof_hash,
                }
        if q.seal_id is not None:
            # Seal-bound query: verify that the stored snapshot / noise seed
            # and the audit output are all anchored to the same Merkle root.
            rev = pinned_revisions.get((q.seal_id, q.seal_revision_seq))
            seal_view: dict[str, Any] = {
                "seal_id": str(q.seal_id),
                "revision_seq": q.seal_revision_seq,
                "root": q.seal_root,
            }
            if rev is None:
                seal_view["checks"] = {"revision_exists": False}
                seal_view["verification"] = "UNVERIFIABLE"
            else:
                leaves = _manifest_leaves(rev)
                expected_seed = privacy.derive_noise_seed_bound(
                    q.idempotency_key, q.request_digest, rev.root)
                checks = {
                    "root_matches_query": rev.root == q.seal_root,
                    "root_recomputed": privacy.merkle_root(
                        [privacy.leaf_hash(leaf) for leaf in leaves]) == rev.root,
                    "revision_hash": privacy.seal_revision_hash(
                        _revision_payload(rev)) == rev.revision_hash,
                    "noise_seed": expected_seed == q.noise_seed,
                }
                seal_view.update({
                    "revision_hash": rev.revision_hash,
                    "prev_revision_hash": rev.prev_revision_hash,
                    "record_count": rev.record_count,
                    "checks": checks,
                    "verification": "VERIFIED" if all(checks.values()) else "UNVERIFIABLE",
                })
            view["seal"] = seal_view
        query_views.append(view)

    if included:
        last = included[-1]
        scoped_budget = {
            "epsilon_reserved": float(last.epsilon_reserved_after),
            "delta_reserved": float(last.delta_reserved_after),
            "epsilon_spent": float(last.epsilon_spent_after),
            "delta_spent": float(last.delta_spent_after),
        }
    else:
        scoped_budget = {"epsilon_reserved": 0.0, "delta_reserved": 0.0,
                         "epsilon_spent": 0.0, "delta_spent": 0.0}

    # Authoritative live balances of this version pool (for cross-checking).
    live_budget = {
        "epsilon_total": float(budget.epsilon_total),
        "delta_total": float(budget.delta_total),
        "epsilon_reserved": float(budget.epsilon_reserved),
        "delta_reserved": float(budget.delta_reserved),
        "epsilon_spent": float(budget.epsilon_spent),
        "delta_spent": float(budget.delta_spent),
        "epsilon_available": float(
            budget.epsilon_total - budget.epsilon_reserved - budget.epsilon_spent),
        "delta_available": float(
            budget.delta_total - budget.delta_reserved - budget.delta_spent),
    }

    return {
        "policy": {
            "id": str(policy.id),
            "name": policy.name,
            "status": policy.status,
            "global_policy_version": policy.version,
            "effective_version_seq": policy.effective_version_seq,
        },
        "policy_version": {
            "version_seq": params.version_seq,
            "status": params.status,
            "epsilon_total": float(params.epsilon_total),
            "delta_total": float(params.delta_total),
            "per_subject_cap": params.per_subject_cap,
            "dimensions": list(params.dimensions or []),
            "draft_hash": params.draft_hash,
            "summary_hash": params.summary_hash,
            "published_at": params.published_at.isoformat() if params.published_at else None,
            "effective": policy.effective_version_seq == version_seq,
        },
        "replay": {
            "to_version": to_version,
            "latest_version": latest_version,
            "version_seq": version_seq,
            "entries_included": len(included),
            "entries_total_in_version":
                sum(1 for e in all_entries if e.policy_version_seq == version_seq),
            "prefix_entries_verified": len(prefix),
        },
        "chain": {
            "verified": chain_ok,
            "first_bad_seq": first_bad_seq,
            "genesis_hash": GENESIS_HASH,
            "scope_consistent": scope_ok,
        },
        "budget": {
            **scoped_budget,
            "reconstruction_consistent": balance_ok and scope_ok,
        },
        "live_budget": live_budget,
        "entries": entry_views,
        "queries": query_views,
    }
