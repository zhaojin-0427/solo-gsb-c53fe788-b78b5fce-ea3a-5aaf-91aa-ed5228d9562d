"""ORM models mirroring sql/001_schema.sql."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(sa.Text, unique=True)
    version: Mapped[int] = mapped_column(sa.Integer, default=1)
    status: Mapped[str] = mapped_column(sa.Text, default="ACTIVE")
    effective_version_seq: Mapped[int] = mapped_column(sa.Integer, default=1)
    epsilon_total: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12))
    delta_total: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12), default=Decimal("0"))
    per_subject_cap: Mapped[int] = mapped_column(sa.Integer)
    dimensions: Mapped[list] = mapped_column(JSONB, default=list)
    epsilon_reserved: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12), default=Decimal("0"))
    delta_reserved: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12), default=Decimal("0"))
    epsilon_spent: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12), default=Decimal("0"))
    delta_spent: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12), default=Decimal("0"))
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_utcnow)


class PolicyVersion(Base):
    """Immutable draft or published parameter version of a policy.

    status DRAFT -> PUBLISHED / WITHDRAWN, one-way and content-immutable
    (enforced by a database trigger). ``version_seq`` is NULL while a draft;
    it is assigned gaplessly at publish time under the policy row lock.
    """
    __tablename__ = "policy_versions"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    policy_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, sa.ForeignKey("policies.id"))
    version_seq: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    status: Mapped[str] = mapped_column(sa.Text, default="DRAFT")
    idempotency_key: Mapped[str] = mapped_column(sa.Text, unique=True)
    request_digest: Mapped[str] = mapped_column(sa.Text)
    epsilon_total: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12))
    delta_total: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12))
    per_subject_cap: Mapped[int] = mapped_column(sa.Integer)
    dimensions: Mapped[list] = mapped_column(JSONB, default=list)
    draft_hash: Mapped[str] = mapped_column(sa.Text)
    summary_hash: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_utcnow)


class PolicyVersionBudget(Base):
    """Independent privacy-budget pool of one published policy version."""
    __tablename__ = "policy_version_budgets"
    __table_args__ = (sa.PrimaryKeyConstraint("policy_id", "version_seq"),)

    policy_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("policies.id"))
    version_seq: Mapped[int] = mapped_column(sa.Integer)
    epsilon_total: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12))
    delta_total: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12))
    epsilon_reserved: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12), default=Decimal("0"))
    delta_reserved: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12), default=Decimal("0"))
    epsilon_spent: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12), default=Decimal("0"))
    delta_spent: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12), default=Decimal("0"))
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_utcnow)


class Record(Base):
    __tablename__ = "records"

    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=True)
    dataset_version: Mapped[int] = mapped_column(sa.Integer)
    record_key: Mapped[str] = mapped_column(sa.Text)
    subject_id: Mapped[str] = mapped_column(sa.Text)
    attributes: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_utcnow)


class Query(Base):
    __tablename__ = "queries"
    __table_args__ = (sa.ForeignKeyConstraint(
        ["policy_id", "policy_version_seq"],
        ["policy_versions.policy_id", "policy_versions.version_seq"],
        name="queries_policy_version_fk",
    ),)

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    idempotency_key: Mapped[str] = mapped_column(sa.Text, unique=True)
    request_digest: Mapped[str] = mapped_column(sa.Text)
    policy_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, sa.ForeignKey("policies.id"))
    policy_name: Mapped[str] = mapped_column(sa.Text)
    policy_version: Mapped[int] = mapped_column(sa.Integer)
    policy_version_seq: Mapped[int] = mapped_column(sa.Integer, default=1)
    dataset_version: Mapped[int] = mapped_column(sa.Integer)
    query_type: Mapped[str] = mapped_column(sa.Text)
    measure: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    value_min: Mapped[Decimal | None] = mapped_column(sa.Numeric(30, 12), nullable=True)
    value_max: Mapped[Decimal | None] = mapped_column(sa.Numeric(30, 12), nullable=True)
    group_by: Mapped[list] = mapped_column(JSONB, default=list)
    filters: Mapped[dict] = mapped_column(JSONB, default=dict)
    epsilon: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12))
    delta: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12), default=Decimal("0"))
    mechanism: Mapped[str] = mapped_column(sa.Text)
    sensitivity: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12))
    noise_scale: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12))
    noise_seed: Mapped[str] = mapped_column(sa.Text)
    status: Mapped[str] = mapped_column(sa.Text, default="RESERVED")
    clipping: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    retry_count: Mapped[int] = mapped_column(sa.Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_utcnow)
    disclosed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    invalidated_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    invalidated_by: Mapped[int | None] = mapped_column(sa.BigInteger, nullable=True)
    # Seal binding: NULL => unbound query over the live records table
    # (original semantics); otherwise pinned to one seal revision / root.
    seal_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid, sa.ForeignKey("version_seals.id"), nullable=True)
    seal_root: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    seal_revision_seq: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)


class ErasureTombstone(Base):
    __tablename__ = "erasure_tombstones"

    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True)  # id via explicit nextval
    idempotency_key: Mapped[str] = mapped_column(sa.Text, unique=True)
    request_digest: Mapped[str] = mapped_column(sa.Text)
    subject_hash: Mapped[str] = mapped_column(sa.Text)
    until_dataset_version: Mapped[int] = mapped_column(sa.Integer)
    affected_dataset_versions: Mapped[list] = mapped_column(JSONB, default=list)
    records_deleted: Mapped[int] = mapped_column(sa.Integer, default=0)
    queries_invalidated: Mapped[int] = mapped_column(sa.Integer, default=0)
    snapshots_scrubbed: Mapped[int] = mapped_column(sa.Integer, default=0)
    invalidated_queries: Mapped[list] = mapped_column(JSONB, default=list)
    seal_revisions: Mapped[list] = mapped_column(JSONB, default=list)
    proof_hash: Mapped[str] = mapped_column(sa.Text)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_utcnow)


class VersionSeal(Base):
    __tablename__ = "version_seals"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    dataset_version: Mapped[int] = mapped_column(sa.Integer, unique=True)
    idempotency_key: Mapped[str] = mapped_column(sa.Text, unique=True)
    request_digest: Mapped[str] = mapped_column(sa.Text)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_utcnow)


class SealRevision(Base):
    __tablename__ = "seal_revisions"

    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=True)
    seal_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, sa.ForeignKey("version_seals.id"))
    revision_seq: Mapped[int] = mapped_column(sa.Integer)
    kind: Mapped[str] = mapped_column(sa.Text)
    prev_revision_hash: Mapped[str] = mapped_column(sa.Text)
    root: Mapped[str] = mapped_column(sa.Text)
    record_count: Mapped[int] = mapped_column(sa.Integer)
    manifest: Mapped[dict] = mapped_column(JSONB)
    subject_hash: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    tombstone_id: Mapped[int | None] = mapped_column(
        sa.BigInteger, sa.ForeignKey("erasure_tombstones.id"), nullable=True)
    revision_hash: Mapped[str] = mapped_column(sa.Text, unique=True)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_utcnow)


class SealComparison(Base):
    __tablename__ = "seal_comparisons"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    idempotency_key: Mapped[str] = mapped_column(sa.Text, unique=True)
    request_digest: Mapped[str] = mapped_column(sa.Text)
    left_seal_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("version_seals.id"))
    left_revision_seq: Mapped[int] = mapped_column(sa.Integer)
    right_seal_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("version_seals.id"))
    right_revision_seq: Mapped[int] = mapped_column(sa.Integer)
    left_root: Mapped[str] = mapped_column(sa.Text)
    right_root: Mapped[str] = mapped_column(sa.Text)
    left_revision_hash: Mapped[str] = mapped_column(sa.Text)
    right_revision_hash: Mapped[str] = mapped_column(sa.Text)
    diff: Mapped[dict] = mapped_column(JSONB)
    diff_hash: Mapped[str] = mapped_column(sa.Text)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_utcnow)


class LedgerEntry(Base):
    __tablename__ = "budget_ledger"

    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=True)
    policy_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, sa.ForeignKey("policies.id"))
    policy_version: Mapped[int] = mapped_column(sa.Integer)
    policy_version_seq: Mapped[int] = mapped_column(sa.Integer, default=1)
    query_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid, sa.ForeignKey("queries.id"), nullable=True)
    entry_type: Mapped[str] = mapped_column(sa.Text)
    epsilon_delta: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12))
    delta_delta: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12))
    epsilon_reserved_after: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12))
    delta_reserved_after: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12))
    epsilon_spent_after: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12))
    delta_spent_after: Mapped[Decimal] = mapped_column(sa.Numeric(30, 12))
    note: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    prev_hash: Mapped[str] = mapped_column(sa.Text)
    entry_hash: Mapped[str] = mapped_column(sa.Text, unique=True)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_utcnow)
