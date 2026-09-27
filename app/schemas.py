"""Pydantic request models."""
from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PolicyCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=128)
    epsilon_total: Decimal = Field(gt=0, description="Total epsilon budget")
    delta_total: Decimal = Field(default=Decimal("0"), ge=0, lt=1,
                                 description="Total delta budget (0 => pure DP only)")
    per_subject_cap: int = Field(gt=0, le=1_000_000,
                                 description="Max contributions per subject per query")
    dimensions: list[str] = Field(default_factory=list,
                                  description="Group-by / filter dimensions allowed")

    @field_validator("dimensions")
    @classmethod
    def _check_dimensions(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("dimensions must be unique")
        for dim in value:
            if not dim or len(dim) > 64:
                raise ValueError("dimension names must be 1..64 chars")
        return value


class PolicyDraftSubmit(BaseModel):
    """An immutable policy draft: epsilon / delta / per-subject cap and the
    allowed dimensions. A draft never changes after submission; it is either
    published (becoming the next effective version) or withdrawn."""
    model_config = ConfigDict(str_strip_whitespace=True)

    idempotency_key: str = Field(min_length=1, max_length=256)
    epsilon_total: Decimal = Field(gt=0, description="Total epsilon budget of the new version")
    delta_total: Decimal = Field(default=Decimal("0"), ge=0, lt=1,
                                 description="Total delta budget (0 => pure DP only)")
    per_subject_cap: int = Field(gt=0, le=1_000_000,
                                 description="Max contributions per subject per query")
    dimensions: list[str] = Field(default_factory=list,
                                  description="Group-by / filter dimensions allowed")

    @field_validator("dimensions")
    @classmethod
    def _check_dimensions(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("dimensions must be unique")
        for dim in value:
            if not dim or len(dim) > 64:
                raise ValueError("dimension names must be 1..64 chars")
        return value


class PolicyVersionPublish(BaseModel):
    """Atomic draft publish: optional optimistic-concurrency tokens.

    * expected_policy_version: the global policy CAS token the client observed
      (``policies.version``) — a stale value fails with 409 VERSION_CONFLICT.
    * expected_effective_version: the version_seq the client expects to be
      effective right before the switch (the publish creates exactly its
      successor) — prevents a concurrent publish from silently switching
      underneath the client.
    """
    expected_policy_version: int | None = Field(default=None, ge=1)
    expected_effective_version: int | None = Field(default=None, ge=1)


class RecordItem(BaseModel):
    record_key: str = Field(min_length=1, max_length=256)
    subject_id: str = Field(min_length=1, max_length=256)
    attributes: dict[str, Any] = Field(default_factory=dict)


class RecordsUpload(BaseModel):
    dataset_version: int = Field(ge=0, le=2_147_483_647)
    records: list[RecordItem] = Field(min_length=1, max_length=10_000)


class QuerySubmit(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    idempotency_key: str = Field(min_length=1, max_length=256)
    policy_name: str = Field(min_length=1, max_length=128)
    expected_policy_version: int | None = Field(
        default=None, ge=1,
        description="Optional global CAS token: policies.version the client observed")
    policy_version_seq: int | None = Field(
        default=None, ge=1,
        description="Policy parameter version to bind the query to; must be "
                    "the currently effective version (default: effective). "
                    "The query keeps booking and replaying against this exact "
                    "version for its whole lifecycle.")
    dataset_version: int = Field(ge=0, le=2_147_483_647)
    query_type: Literal["count", "sum"]
    measure: str | None = Field(default=None, max_length=64,
                                description="Numeric attribute to sum (sum queries)")
    value_min: Decimal | None = Field(default=None, description="Clip lower bound (sum)")
    value_max: Decimal | None = Field(default=None, description="Clip upper bound (sum)")
    group_by: list[str] = Field(default_factory=list)
    filters: dict[str, Any] = Field(default_factory=dict)
    epsilon: Decimal = Field(gt=0, description="Epsilon to spend on this query")
    delta: Decimal = Field(default=Decimal("0"), ge=0, lt=1,
                           description="Delta to spend (0 => Laplace, >0 => Gaussian)")
    seal_id: uuid.UUID | None = Field(
        default=None,
        description="Optional seal binding: compute against the sealed manifest "
                    "revision current at submission time (must match dataset_version)")


class SealRequest(BaseModel):
    """Idempotent seal of one dataset version: freezes uploads and commits an
    immutable manifest + Merkle root."""
    model_config = ConfigDict(str_strip_whitespace=True)

    idempotency_key: str = Field(min_length=1, max_length=256)
    dataset_version: int = Field(ge=0, le=2_147_483_647)


class SealRevisionRef(BaseModel):
    """Reference to one immutable seal revision (one side of a comparison)."""
    seal_id: uuid.UUID
    revision_seq: int = Field(ge=0, le=2_147_483_647)


class SealCompareRequest(BaseModel):
    """Idempotent comparison of two seal revisions: aligns both manifests by
    record_key and commits an immutable, offline-verifiable diff proof."""
    model_config = ConfigDict(str_strip_whitespace=True)

    idempotency_key: str = Field(min_length=1, max_length=256)
    left: SealRevisionRef
    right: SealRevisionRef


class VersionExpect(BaseModel):
    """Optional body for disclose / cancel: client-side CAS token."""
    expected_policy_version: int | None = Field(default=None, ge=1)


class ErasureRequest(BaseModel):
    """Idempotent data-subject erasure: registers a tombstone covering all
    dataset versions up to `until_dataset_version` (inclusive)."""
    model_config = ConfigDict(str_strip_whitespace=True)

    idempotency_key: str = Field(min_length=1, max_length=256)
    subject_id: str = Field(min_length=1, max_length=256)
    until_dataset_version: int = Field(ge=0, le=2_147_483_647)
