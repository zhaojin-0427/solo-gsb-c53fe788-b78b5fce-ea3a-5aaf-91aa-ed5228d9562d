"""Response shaping helpers (ORM -> JSON-ready dicts)."""
from __future__ import annotations

from typing import Any

from . import privacy
from .models import (
    ErasureTombstone,
    Policy,
    PolicyVersion,
    PolicyVersionBudget,
    Query,
    SealRevision,
    VersionSeal,
)


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


def policy_out(p: Policy, effective: PolicyVersion | None = None,
               effective_budget: PolicyVersionBudget | None = None) -> dict[str, Any]:
    """Policy summary.

    Balance fields describe the *currently effective* parameter version's
    independent pool (``effective_budget``); the immutable parameters
    (``epsilon_total`` / ``delta_total`` / ``per_subject_cap`` / ``dimensions``)
    describe that same effective version (``effective``). ``version`` is the
    global CAS token and ``effective_version_seq`` is the active
    parameter-version pointer. When no version rows are supplied (e.g. raw
    ORM rows outside a request) the policies-table v1 mirror is used.
    """
    if effective is not None:
        eps_total, del_total = effective.epsilon_total, effective.delta_total
        cap = effective.per_subject_cap
        dimensions = list(effective.dimensions or [])
    else:
        eps_total, del_total = p.epsilon_total, p.delta_total
        cap, dimensions = p.per_subject_cap, list(p.dimensions or [])
    if effective_budget is not None:
        eps_res, del_res = effective_budget.epsilon_reserved, effective_budget.delta_reserved
        eps_spent, del_spent = effective_budget.epsilon_spent, effective_budget.delta_spent
    else:
        eps_res, del_res = p.epsilon_reserved, p.delta_reserved
        eps_spent, del_spent = p.epsilon_spent, p.delta_spent
    return {
        "id": str(p.id),
        "name": p.name,
        "version": p.version,
        "effective_version_seq": p.effective_version_seq,
        "status": p.status,
        "epsilon_total": float(eps_total),
        "delta_total": float(del_total),
        "epsilon_reserved": float(eps_res),
        "delta_reserved": float(del_res),
        "epsilon_spent": float(eps_spent),
        "delta_spent": float(del_spent),
        "epsilon_available": float(eps_total - eps_res - eps_spent),
        "delta_available": float(del_total - del_res - del_spent),
        "per_subject_cap": cap,
        "dimensions": dimensions,
        "summary_hash": effective.summary_hash if effective is not None else None,
        "created_at": _iso(p.created_at),
        "updated_at": _iso(p.updated_at),
    }


def policy_version_out(pv: PolicyVersion, budget: PolicyVersionBudget | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": str(pv.id),
        "policy_id": str(pv.policy_id),
        "version_seq": pv.version_seq,   # NULL while DRAFT, assigned at publish
        "status": pv.status,
        "idempotency_key": pv.idempotency_key,
        "request_digest": pv.request_digest,
        "epsilon_total": float(pv.epsilon_total),
        "delta_total": float(pv.delta_total),
        "per_subject_cap": pv.per_subject_cap,
        "dimensions": list(pv.dimensions or []),
        "draft_hash": pv.draft_hash,
        "summary_hash": pv.summary_hash,
        "created_at": _iso(pv.created_at),
        "published_at": _iso(pv.published_at),
    }
    if budget is not None:
        out["budget"] = {
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
    return out


def query_out(q: Query, disclose: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": str(q.id),
        "idempotency_key": q.idempotency_key,
        "request_digest": q.request_digest,
        "status": q.status,
        "policy_id": str(q.policy_id),
        "policy_name": q.policy_name,
        "policy_version": q.policy_version,
        "policy_version_seq": q.policy_version_seq,
        "dataset_version": q.dataset_version,
        "query_type": q.query_type,
        "measure": q.measure,
        "group_by": list(q.group_by or []),
        "filters": dict(q.filters or {}),
        "epsilon": float(q.epsilon),
        "delta": float(q.delta),
        "mechanism": q.mechanism,
        "sensitivity": float(q.sensitivity),
        "noise_scale": float(q.noise_scale),
        "retry_count": q.retry_count,
        "created_at": _iso(q.created_at),
        "updated_at": _iso(q.updated_at),
        "disclosed_at": _iso(q.disclosed_at),
        "cancelled_at": _iso(q.cancelled_at),
        "invalidated_at": _iso(q.invalidated_at),
        "invalidated_by": q.invalidated_by,
    }
    if q.seal_id is not None:
        # Seal-bound query: the snapshot, noise seed and audit view are all
        # anchored to this Merkle root / revision.
        out["seal"] = {
            "seal_id": str(q.seal_id),
            "revision_seq": q.seal_revision_seq,
            "root": q.seal_root,
        }
    if disclose and q.status == "DISCLOSED" and q.result:
        # Public disclosure view: noisy values only, never raw aggregates.
        out["result"] = {
            "mechanism": q.mechanism,
            "groups": [
                {"key": g["key"], "value": g["noisy_value"]}
                for g in q.result.get("groups", [])
            ],
        }
    return out


def erasure_out(t: ErasureTombstone) -> dict[str, Any]:
    """Public erasure receipt. Carries the pseudonymous subject hash and the
    erasure proof — never the erased subject identifier."""
    return {
        "tombstone_id": t.id,
        "idempotency_key": t.idempotency_key,
        "subject_hash": t.subject_hash,
        "until_dataset_version": t.until_dataset_version,
        "affected_dataset_versions": list(t.affected_dataset_versions or []),
        "records_deleted": t.records_deleted,
        "queries_invalidated": t.queries_invalidated,
        "snapshots_scrubbed": t.snapshots_scrubbed,
        "affected_queries": list(t.invalidated_queries or []),
        "seal_revisions": list(t.seal_revisions or []),
        "proof_hash": t.proof_hash,
        "created_at": _iso(t.created_at),
    }


def seal_out(seal: VersionSeal, revision: SealRevision) -> dict[str, Any]:
    """Public seal receipt: the committed Merkle root of revision #0."""
    return {
        "seal_id": str(seal.id),
        "dataset_version": seal.dataset_version,
        "idempotency_key": seal.idempotency_key,
        "request_digest": seal.request_digest,
        "revision_seq": revision.revision_seq,
        "root": revision.root,
        "record_count": revision.record_count,
        "revision_hash": revision.revision_hash,
        "hash_version": privacy.SEAL_HASH_VERSION,
        "created_at": _iso(seal.created_at),
    }
