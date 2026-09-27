-- ============================================================================
-- Differential-Privacy Query Budget Orchestration — database schema
-- Idempotent: safe to run on every API startup (also mounted as an initdb
-- script by docker-compose for first-boot provisioning).
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Policies: privacy budget pools. `version` is the CAS (compare-and-swap)
-- token: every budget mutation does
--   UPDATE ... SET version = version + 1 ... WHERE id = ? AND version = ?
-- so concurrent writers conflict deterministically.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policies (
    id                UUID PRIMARY KEY,
    name              TEXT NOT NULL UNIQUE,
    version           INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
    status            TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'ARCHIVED')),
    -- Pointer to the currently effective policy parameter version. Budget
    -- mutation and publish operations serialise on this row (SELECT ... FOR
    -- UPDATE) and bump `version` (the global CAS token); this pointer is the
    -- atomic switch target for a version publish.
    effective_version_seq INTEGER NOT NULL DEFAULT 1 CHECK (effective_version_seq >= 1),
    epsilon_total     NUMERIC(30, 12) NOT NULL CHECK (epsilon_total > 0),
    delta_total       NUMERIC(30, 12) NOT NULL DEFAULT 0 CHECK (delta_total >= 0 AND delta_total < 1),
    per_subject_cap   INTEGER NOT NULL CHECK (per_subject_cap > 0),
    dimensions        JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- NOTE: the balance columns below mirror version #1's pool (and stay
    -- frozen there once a later version becomes effective). The authoritative
    -- per-version balances live in policy_version_budgets; the CHECKs stay
    -- valid because the v1 mirror never changes after a switch.
    epsilon_reserved  NUMERIC(30, 12) NOT NULL DEFAULT 0 CHECK (epsilon_reserved >= 0),
    delta_reserved    NUMERIC(30, 12) NOT NULL DEFAULT 0 CHECK (delta_reserved >= 0),
    epsilon_spent     NUMERIC(30, 12) NOT NULL DEFAULT 0 CHECK (epsilon_spent >= 0),
    delta_spent       NUMERIC(30, 12) NOT NULL DEFAULT 0 CHECK (delta_spent >= 0),
    created_at        TIMESTAMPTZ NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL,
    CHECK (epsilon_reserved + epsilon_spent <= epsilon_total),
    CHECK (delta_reserved + delta_spent <= delta_total)
);

-- ---------------------------------------------------------------------------
-- Policy versions: immutable drafts + published parameter versions.
--
-- An administrator submits an *immutable draft* (epsilon_total / delta_total /
-- per_subject_cap / dimensions) for one policy; the draft never changes after
-- submission. A draft is either published atomically (it receives the next
-- gapless version_seq, the policy's effective_version_seq pointer switches to
-- it and the policies.version CAS token bumps) or withdrawn before it ever
-- becomes effective. Draft submission is idempotent in two ways: replaying
-- the same idempotency key (any body) returns the stored draft, and resubmitting
-- the same content (draft_hash) returns the stored draft even under a different
-- key. Publishing and withdrawing an un-effective draft are idempotent too.
--
-- Each published version carries an independent privacy-budget pool (see
-- policy_version_budgets below); queries are bound at submission time to the
-- then-effective version and keep booking against that exact version pool and
-- ledger chain for their whole lifecycle. `summary_hash` binds the version
-- identity and parameters into one verifiable digest; `draft_hash` binds the
-- submitted draft content.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_versions (
    id                UUID PRIMARY KEY,
    policy_id         UUID NOT NULL REFERENCES policies (id),
    -- NULL while the row is a DRAFT; assigned gaplessly at publish time
    -- (max(version_seq) + 1 under the policy-row lock).
    version_seq       INTEGER CHECK (version_seq IS NULL OR version_seq >= 1),
    status            TEXT NOT NULL DEFAULT 'DRAFT'
                      CHECK (status IN ('DRAFT', 'PUBLISHED', 'WITHDRAWN')),
    idempotency_key   TEXT NOT NULL UNIQUE,
    request_digest    TEXT NOT NULL,           -- binds the key to one draft body
    epsilon_total     NUMERIC(30, 12) NOT NULL CHECK (epsilon_total > 0),
    delta_total       NUMERIC(30, 12) NOT NULL CHECK (delta_total >= 0 AND delta_total < 1),
    per_subject_cap   INTEGER NOT NULL CHECK (per_subject_cap > 0),
    dimensions        JSONB NOT NULL DEFAULT '[]'::jsonb,
    draft_hash        TEXT NOT NULL,           -- sha256 over the draft content
    summary_hash      TEXT,                    -- sha256 over the published version
    published_at      TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL,
    -- one published number per policy, assigned in order under the row lock
    UNIQUE (policy_id, version_seq)
);
CREATE INDEX IF NOT EXISTS idx_policy_versions_policy
    ON policy_versions (policy_id, created_at);
-- Content-addressed draft dedup: at most one *non-withdrawn* draft/published
-- row per (policy, draft_hash). A withdrawn draft is a dead draft — its
-- content may be resubmitted (creating a fresh draft), but it can never be
-- published or withdrawn again.
CREATE UNIQUE INDEX IF NOT EXISTS uq_policy_draft_content_active
    ON policy_versions (policy_id, draft_hash)
    WHERE status <> 'WITHDRAWN';

-- ---------------------------------------------------------------------------
-- Per-version budget pools. A row is created together with its published
-- version (version #1 is provisioned when the policy is created). Every
-- budget mutation holds the parent policy row lock (the single policy-wide
-- serialisation point), so concurrent reservations against different versions
-- never overwrite each other and the ledger chain per policy cannot fork.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_version_budgets (
    policy_id         UUID NOT NULL REFERENCES policies (id),
    version_seq       INTEGER NOT NULL CHECK (version_seq >= 1),
    epsilon_total     NUMERIC(30, 12) NOT NULL CHECK (epsilon_total > 0),
    delta_total       NUMERIC(30, 12) NOT NULL CHECK (delta_total >= 0 AND delta_total < 1),
    epsilon_reserved  NUMERIC(30, 12) NOT NULL DEFAULT 0 CHECK (epsilon_reserved >= 0),
    delta_reserved    NUMERIC(30, 12) NOT NULL DEFAULT 0 CHECK (delta_reserved >= 0),
    epsilon_spent     NUMERIC(30, 12) NOT NULL DEFAULT 0 CHECK (epsilon_spent >= 0),
    delta_spent       NUMERIC(30, 12) NOT NULL DEFAULT 0 CHECK (delta_spent >= 0),
    created_at        TIMESTAMPTZ NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (policy_id, version_seq),
    CHECK (epsilon_reserved + epsilon_spent <= epsilon_total),
    CHECK (delta_reserved + delta_spent <= delta_total)
);

-- Immutability of policy versions: rows are append-only. The *only* legal
-- update is the one-way lifecycle transition
--   DRAFT -> PUBLISHED  (fills version_seq / status / summary_hash / published_at)
--   DRAFT -> WITHDRAWN  (fills status only)
-- Every other column — and every update after the transition — is rejected.
CREATE OR REPLACE FUNCTION enforce_policy_version_immutability() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'policy_versions is append-only: DELETE not allowed';
    END IF;
    -- Content columns are immutable in EVERY state, including during the
    -- DRAFT -> PUBLISHED / DRAFT -> WITHDRAWN transitions (checked first so a
    -- content rewrite is always rejected as an in-place modification).
    IF NEW.policy_id IS DISTINCT FROM OLD.policy_id
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
       OR NEW.epsilon_total IS DISTINCT FROM OLD.epsilon_total
       OR NEW.delta_total IS DISTINCT FROM OLD.delta_total
       OR NEW.per_subject_cap IS DISTINCT FROM OLD.per_subject_cap
       OR NEW.dimensions IS DISTINCT FROM OLD.dimensions
       OR NEW.draft_hash IS DISTINCT FROM OLD.draft_hash
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'policy version content is immutable: % not allowed', TG_OP;
    END IF;
    IF OLD.status = 'DRAFT' AND NEW.status = 'PUBLISHED' THEN
        IF NEW.version_seq IS NULL OR NEW.summary_hash IS NULL
           OR NEW.published_at IS NULL THEN
            RAISE EXCEPTION 'publishing a draft requires version_seq, summary_hash and published_at';
        END IF;
    ELSIF OLD.status = 'DRAFT' AND NEW.status = 'WITHDRAWN' THEN
        IF NEW.version_seq IS NOT NULL OR NEW.summary_hash IS NOT NULL
           OR NEW.published_at IS NOT NULL THEN
            RAISE EXCEPTION 'a withdrawn draft never receives a version_seq or summary';
        END IF;
    ELSE
        RAISE EXCEPTION 'illegal policy version lifecycle change: % -> %', OLD.status, NEW.status;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_policy_version_no_update ON policy_versions;
CREATE TRIGGER trg_policy_version_no_update
    BEFORE UPDATE ON policy_versions
    FOR EACH ROW EXECUTE FUNCTION enforce_policy_version_immutability();

DROP TRIGGER IF EXISTS trg_policy_version_no_delete ON policy_versions;
CREATE TRIGGER trg_policy_version_no_delete
    BEFORE DELETE ON policy_versions
    FOR EACH ROW EXECUTE FUNCTION enforce_policy_version_immutability();

-- Per-version budgets may never be deleted (a version pool lives as long as
-- the policy); they are only updated while holding the policy row lock.
CREATE OR REPLACE FUNCTION forbid_policy_version_budget_delete() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'policy_version_budgets is append-only: DELETE not allowed';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_policy_version_budget_no_delete ON policy_version_budgets;
CREATE TRIGGER trg_policy_version_budget_no_delete
    BEFORE DELETE ON policy_version_budgets
    FOR EACH ROW EXECUTE FUNCTION forbid_policy_version_budget_delete();

-- ---------------------------------------------------------------------------
-- Records: versioned client uploads. Idempotent per (dataset_version,
-- record_key) so re-uploads of the same batch are safe.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS records (
    id               BIGSERIAL PRIMARY KEY,
    dataset_version  INTEGER NOT NULL CHECK (dataset_version >= 0),
    record_key       TEXT NOT NULL,
    subject_id       TEXT NOT NULL,
    attributes       JSONB NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL,
    UNIQUE (dataset_version, record_key)
);
CREATE INDEX IF NOT EXISTS idx_records_dataset_subject
    ON records (dataset_version, subject_id);

-- ---------------------------------------------------------------------------
-- Queries: one row per idempotency key. Status machine:
--   RESERVED --disclose----> DISCLOSED
--   RESERVED --cancel------> CANCELLED    (only before disclosure, refund once)
--   RESERVED --invalidate--> INVALIDATED  (data-subject erasure, refund once)
-- `clipping` holds the deterministic clipping snapshot; erasure scrubs the
-- subject identifiers out of it (the noisy `result` is never touched).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS queries (
    id               UUID PRIMARY KEY,
    idempotency_key  TEXT NOT NULL UNIQUE,
    request_digest   TEXT NOT NULL,
    policy_id        UUID NOT NULL REFERENCES policies (id),
    policy_name      TEXT NOT NULL,
    policy_version   INTEGER NOT NULL,           -- global policy CAS token right after RESERVE
    -- The policy parameter version the query is bound to (the effective one
    -- at submission time). The query's clipping parameters, budget accounting
    -- and audit replay all stay scoped to this exact version forever.
    policy_version_seq INTEGER NOT NULL DEFAULT 1 CHECK (policy_version_seq >= 1),
    dataset_version  INTEGER NOT NULL CHECK (dataset_version >= 0),
    query_type       TEXT NOT NULL CHECK (query_type IN ('count', 'sum')),
    measure          TEXT,
    value_min        NUMERIC(30, 12),
    value_max        NUMERIC(30, 12),
    group_by         JSONB NOT NULL DEFAULT '[]'::jsonb,
    filters          JSONB NOT NULL DEFAULT '{}'::jsonb,
    epsilon          NUMERIC(30, 12) NOT NULL CHECK (epsilon > 0),
    delta            NUMERIC(30, 12) NOT NULL DEFAULT 0 CHECK (delta >= 0 AND delta < 1),
    mechanism        TEXT NOT NULL CHECK (mechanism IN ('laplace', 'gaussian')),
    sensitivity      NUMERIC(30, 12) NOT NULL CHECK (sensitivity >= 0),
    noise_scale      NUMERIC(30, 12) NOT NULL CHECK (noise_scale >= 0),
    noise_seed       TEXT NOT NULL,              -- sha256 derived from idempotency key
    status           TEXT NOT NULL DEFAULT 'RESERVED'
                     CHECK (status IN ('RESERVED', 'DISCLOSED', 'CANCELLED', 'INVALIDATED')),
    clipping         JSONB,                      -- deterministic clipping snapshot
    result           JSONB,                      -- noisy result (revealed at disclosure)
    retry_count      INTEGER NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL,
    disclosed_at     TIMESTAMPTZ,
    cancelled_at     TIMESTAMPTZ,
    invalidated_at   TIMESTAMPTZ,
    invalidated_by   BIGINT                      -- erasure_tombstones.id
);
CREATE INDEX IF NOT EXISTS idx_queries_policy ON queries (policy_id, created_at);
CREATE INDEX IF NOT EXISTS idx_queries_dataset_status
    ON queries (dataset_version, status);

-- idx_queries_policy_version is created in the migration block below (after
-- the policy_version_seq column exists on upgraded databases).

-- ---------------------------------------------------------------------------
-- Budget ledger: append-only, hash-chained, immutable. Every reserve /
-- disclose / cancel / retry / invalidate runs in the same transaction as its
-- balance mutation and appends exactly one entry here.
--   epsilon_delta / delta_delta = signed change of total consumption
--   (reserved + spent): RESERVE +x, DISCLOSE 0, CANCEL -x, RETRY 0,
--   INVALIDATE -x.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS budget_ledger (
    id                     BIGSERIAL PRIMARY KEY,
    policy_id              UUID NOT NULL REFERENCES policies (id),
    policy_version         INTEGER NOT NULL,       -- global policy CAS token after this entry
    -- Parameter version this booking belongs to: every entry stays scoped to
    -- the query's bound version, so each version pool is accounted separately.
    policy_version_seq     INTEGER NOT NULL DEFAULT 1 CHECK (policy_version_seq >= 1),
    query_id               UUID REFERENCES queries (id),
    entry_type             TEXT NOT NULL CHECK (entry_type IN ('RESERVE', 'DISCLOSE', 'CANCEL', 'RETRY', 'INVALIDATE')),
    epsilon_delta          NUMERIC(30, 12) NOT NULL,
    delta_delta            NUMERIC(30, 12) NOT NULL,
    epsilon_reserved_after NUMERIC(30, 12) NOT NULL,
    delta_reserved_after   NUMERIC(30, 12) NOT NULL,
    epsilon_spent_after    NUMERIC(30, 12) NOT NULL,
    delta_spent_after      NUMERIC(30, 12) NOT NULL,
    note                   TEXT,
    prev_hash              TEXT NOT NULL,
    entry_hash             TEXT NOT NULL UNIQUE,
    created_at             TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ledger_policy ON budget_ledger (policy_id, id);
-- idx_ledger_policy_version is created in the migration block below (after
-- the policy_version_seq column exists on upgraded databases).
CREATE INDEX IF NOT EXISTS idx_ledger_query  ON budget_ledger (query_id, id);

-- Immutability: the ledger may only be appended to, never rewritten.
CREATE OR REPLACE FUNCTION forbid_ledger_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'budget_ledger is immutable: % not allowed', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_ledger_no_update ON budget_ledger;
CREATE TRIGGER trg_ledger_no_update
    BEFORE UPDATE ON budget_ledger
    FOR EACH ROW EXECUTE FUNCTION forbid_ledger_mutation();

DROP TRIGGER IF EXISTS trg_ledger_no_delete ON budget_ledger;
CREATE TRIGGER trg_ledger_no_delete
    BEFORE DELETE ON budget_ledger
    FOR EACH ROW EXECUTE FUNCTION forbid_ledger_mutation();

-- Query status transitions are one-way; enforce at the storage layer too.
CREATE OR REPLACE FUNCTION enforce_query_transition() RETURNS trigger AS $$
BEGIN
    IF OLD.status = 'RESERVED' AND NEW.status IN ('DISCLOSED', 'CANCELLED', 'INVALIDATED') THEN
        RETURN NEW;
    ELSIF OLD.status = NEW.status THEN
        RETURN NEW;  -- touch of updated_at / retry_count / snapshot scrubbing only
    END IF;
    RAISE EXCEPTION 'illegal query status transition: % -> %', OLD.status, NEW.status;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_query_transition ON queries;
CREATE TRIGGER trg_query_transition
    BEFORE UPDATE ON queries
    FOR EACH ROW EXECUTE FUNCTION enforce_query_transition();

-- ---------------------------------------------------------------------------
-- Erasure tombstones: one row per erasure idempotency key. Registering a
-- tombstone for (subject, until_dataset_version) — in a single transaction —
--   * determines the affected dataset-version set under the erasure lock
--     barrier: versions within the cut-off range where the subject actually
--     has records, plus versions whose stored query snapshots actually
--     reference the subject,
--   * deletes the subject's raw records on those versions,
--   * scrubs the subject identifier from every affected query snapshot,
--   * invalidates every still-RESERVED query on an affected version and
--     refunds its reservation exactly once (INVALIDATE ledger entries).
-- Versions inside the cut-off range that never contained the subject keep
-- their query status, budget and ledger completely untouched. Only the
-- salted subject hash is stored, never the identifier itself, and re-uploads
-- within the tombstone range are rejected. Tombstones are append-only;
-- `proof_hash` binds all erasure effects (including the affected version
-- set) into one verifiable erasure proof.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS erasure_tombstones (
    id                     BIGSERIAL PRIMARY KEY,
    idempotency_key        TEXT NOT NULL UNIQUE,
    request_digest         TEXT NOT NULL,
    subject_hash           TEXT NOT NULL,        -- sha256, domain-separated
    until_dataset_version  INTEGER NOT NULL CHECK (until_dataset_version >= 0),
    affected_dataset_versions JSONB NOT NULL DEFAULT '[]'::jsonb,
    records_deleted        INTEGER NOT NULL DEFAULT 0,
    queries_invalidated    INTEGER NOT NULL DEFAULT 0,
    snapshots_scrubbed     INTEGER NOT NULL DEFAULT 0,
    invalidated_queries    JSONB NOT NULL DEFAULT '[]'::jsonb,
    proof_hash             TEXT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tombstones_subject_version
    ON erasure_tombstones (subject_hash, until_dataset_version);

-- Immutability: tombstones are append-only, like the ledger.
CREATE OR REPLACE FUNCTION forbid_tombstone_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'erasure_tombstones is immutable: % not allowed', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_tombstone_no_update ON erasure_tombstones;
CREATE TRIGGER trg_tombstone_no_update
    BEFORE UPDATE ON erasure_tombstones
    FOR EACH ROW EXECUTE FUNCTION forbid_tombstone_mutation();

DROP TRIGGER IF EXISTS trg_tombstone_no_delete ON erasure_tombstones;
CREATE TRIGGER trg_tombstone_no_delete
    BEFORE DELETE ON erasure_tombstones
    FOR EACH ROW EXECUTE FUNCTION forbid_tombstone_mutation();

-- ---------------------------------------------------------------------------
-- Version seals: an idempotent seal freezes one dataset version. Sealing (in
-- one transaction, under the per-version lock):
--   * rejects an empty version (VERSION_EMPTY),
--   * snapshots every record of the version into an immutable manifest whose
--     leaves are canonicalised and stably sorted by record_key,
--   * commits the manifest's Merkle root (revision #0, kind 'seal'),
--   * freezes the version: later uploads to it are rejected (VERSION_SEALED).
-- Queries may bind to a seal via seal_id; a bound query is computed from the
-- manifest revision current at submission time, and its noise seed / snapshot
-- / audit view are all bound to that same root. Seals are append-only.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS version_seals (
    id               UUID PRIMARY KEY,
    dataset_version  INTEGER NOT NULL UNIQUE,
    idempotency_key  TEXT NOT NULL UNIQUE,
    request_digest   TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL
);

-- ---------------------------------------------------------------------------
-- Seal revision chain: revision #0 is the original sealed manifest; every
-- later revision (kind 'erasure') is appended by a data-subject erasure. The
-- previous manifest is never rewritten: a new revision links the previous
-- revision hash, carries the scrubbed manifest (the erased subject's leaves
-- are removed — leaves only ever hold the pseudonymous subject hash, never
-- the raw identifier) and its recomputed Merkle root, and references the
-- erasure tombstone. Bound queries submitted afterwards pin the latest
-- revision; older queries stay pinned to their original revision and remain
-- verifiable against it. Revisions are append-only.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS seal_revisions (
    id                   BIGSERIAL PRIMARY KEY,
    seal_id              UUID NOT NULL REFERENCES version_seals (id),
    revision_seq         INTEGER NOT NULL CHECK (revision_seq >= 0),
    kind                 TEXT NOT NULL CHECK (kind IN ('seal', 'erasure')),
    prev_revision_hash   TEXT NOT NULL,
    root                 TEXT NOT NULL,           -- Merkle root of `manifest`
    record_count         INTEGER NOT NULL CHECK (record_count >= 0),
    manifest             JSONB NOT NULL,          -- canonical leaves sorted by record_key
    subject_hash         TEXT,                    -- erasure revisions only
    tombstone_id         BIGINT REFERENCES erasure_tombstones (id),
    revision_hash        TEXT NOT NULL UNIQUE,
    created_at           TIMESTAMPTZ NOT NULL,
    UNIQUE (seal_id, revision_seq)
);
CREATE INDEX IF NOT EXISTS idx_seal_revisions_seal ON seal_revisions (seal_id, revision_seq);
CREATE INDEX IF NOT EXISTS idx_seal_revisions_tomb ON seal_revisions (tombstone_id);

CREATE OR REPLACE FUNCTION forbid_seal_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% is immutable: % not allowed', TG_TABLE_NAME, TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_seal_no_update ON version_seals;
CREATE TRIGGER trg_seal_no_update
    BEFORE UPDATE ON version_seals
    FOR EACH ROW EXECUTE FUNCTION forbid_seal_mutation();

DROP TRIGGER IF EXISTS trg_seal_no_delete ON version_seals;
CREATE TRIGGER trg_seal_no_delete
    BEFORE DELETE ON version_seals
    FOR EACH ROW EXECUTE FUNCTION forbid_seal_mutation();

DROP TRIGGER IF EXISTS trg_seal_revision_no_update ON seal_revisions;
CREATE TRIGGER trg_seal_revision_no_update
    BEFORE UPDATE ON seal_revisions
    FOR EACH ROW EXECUTE FUNCTION forbid_seal_mutation();

DROP TRIGGER IF EXISTS trg_seal_revision_no_delete ON seal_revisions;
CREATE TRIGGER trg_seal_revision_no_delete
    BEFORE DELETE ON seal_revisions
    FOR EACH ROW EXECUTE FUNCTION forbid_seal_mutation();

-- ---------------------------------------------------------------------------
-- Seal comparisons: an idempotent compare of two verified revisions commits
-- an immutable diff proof. In one transaction both revisions must re-verify
-- (root recomputed from the stored manifest, revision hash recomputed, chain
-- link intact); the two manifests are then aligned by record_key into a
-- canonical added / removed / changed diff (leaves carry only the
-- pseudonymous subject hash — never the raw identifier), and the diff is
-- hashed together with both ends' seal / revision hashes and roots into
-- `diff_hash`. Comparisons are append-only, like the seals themselves.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS seal_comparisons (
    id                  UUID PRIMARY KEY,
    idempotency_key     TEXT NOT NULL UNIQUE,
    request_digest      TEXT NOT NULL,
    left_seal_id        UUID NOT NULL REFERENCES version_seals (id),
    left_revision_seq   INTEGER NOT NULL CHECK (left_revision_seq >= 0),
    right_seal_id       UUID NOT NULL REFERENCES version_seals (id),
    right_revision_seq  INTEGER NOT NULL CHECK (right_revision_seq >= 0),
    left_root           TEXT NOT NULL,
    right_root          TEXT NOT NULL,
    left_revision_hash  TEXT NOT NULL,
    right_revision_hash TEXT NOT NULL,
    diff                JSONB NOT NULL,           -- canonical added/removed/changed + counts
    diff_hash           TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_seal_comparisons_left
    ON seal_comparisons (left_seal_id, left_revision_seq);
CREATE INDEX IF NOT EXISTS idx_seal_comparisons_right
    ON seal_comparisons (right_seal_id, right_revision_seq);

DROP TRIGGER IF EXISTS trg_seal_comparison_no_update ON seal_comparisons;
CREATE TRIGGER trg_seal_comparison_no_update
    BEFORE UPDATE ON seal_comparisons
    FOR EACH ROW EXECUTE FUNCTION forbid_seal_mutation();

DROP TRIGGER IF EXISTS trg_seal_comparison_no_delete ON seal_comparisons;
CREATE TRIGGER trg_seal_comparison_no_delete
    BEFORE DELETE ON seal_comparisons
    FOR EACH ROW EXECUTE FUNCTION forbid_seal_mutation();

-- ---------------------------------------------------------------------------
-- Idempotent migrations for databases provisioned before erasure support
-- (fresh installs already have the final shape; these are no-ops there).
-- ---------------------------------------------------------------------------
ALTER TABLE policies ADD COLUMN IF NOT EXISTS effective_version_seq
    INTEGER NOT NULL DEFAULT 1;

-- Policy parameter versions + per-version budget pools (no-ops on fresh DBs).
-- Existing policies are backfilled with an immutable, already-published
-- version #1 summarising the parameters the policy was created with, plus a
-- version-#1 budget pool seeded with the policy's current balances.
INSERT INTO policy_versions (
        id, policy_id, version_seq, status, idempotency_key, request_digest,
        epsilon_total, delta_total, per_subject_cap, dimensions,
        draft_hash, summary_hash, published_at, created_at)
SELECT
        gen_random_uuid(), p.id, 1, 'PUBLISHED',
        'policy-v1-bootstrap-' || p.id::text,
        'bootstrap:v1',
        p.epsilon_total, p.delta_total, p.per_subject_cap, p.dimensions,
        'bootstrap-draft:' || p.id::text,
        'bootstrap-summary:' || p.id::text,
        p.created_at, p.created_at
FROM policies p
WHERE NOT EXISTS (
    SELECT 1 FROM policy_versions pv WHERE pv.policy_id = p.id AND pv.version_seq = 1
);

INSERT INTO policy_version_budgets (
        policy_id, version_seq, epsilon_total, delta_total,
        epsilon_reserved, delta_reserved, epsilon_spent, delta_spent,
        created_at, updated_at)
SELECT
        p.id, 1, p.epsilon_total, p.delta_total,
        p.epsilon_reserved, p.delta_reserved, p.epsilon_spent, p.delta_spent,
        p.created_at, p.updated_at
FROM policies p
WHERE NOT EXISTS (
    SELECT 1 FROM policy_version_budgets b
    WHERE b.policy_id = p.id AND b.version_seq = 1
);

ALTER TABLE queries ADD COLUMN IF NOT EXISTS policy_version_seq
    INTEGER NOT NULL DEFAULT 1;

CREATE INDEX IF NOT EXISTS idx_queries_policy_version
    ON queries (policy_id, policy_version_seq, created_at);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'queries_policy_version_fk'
    ) THEN
        ALTER TABLE queries
            ADD CONSTRAINT queries_policy_version_fk
            FOREIGN KEY (policy_id, policy_version_seq)
            REFERENCES policy_versions (policy_id, version_seq);
    END IF;
END $$;

ALTER TABLE budget_ledger ADD COLUMN IF NOT EXISTS policy_version_seq
    INTEGER NOT NULL DEFAULT 1;

CREATE INDEX IF NOT EXISTS idx_ledger_policy_version
    ON budget_ledger (policy_id, policy_version_seq, id);

ALTER TABLE queries ADD COLUMN IF NOT EXISTS invalidated_at TIMESTAMPTZ;
ALTER TABLE queries ADD COLUMN IF NOT EXISTS invalidated_by BIGINT;

-- Seal binding: a query is either unbound (NULL — original semantics, it was
-- computed over the live records table) or pinned to exactly one seal
-- revision / Merkle root.
ALTER TABLE queries ADD COLUMN IF NOT EXISTS seal_id UUID REFERENCES version_seals (id);
ALTER TABLE queries ADD COLUMN IF NOT EXISTS seal_root TEXT;
ALTER TABLE queries ADD COLUMN IF NOT EXISTS seal_revision_seq INTEGER;

ALTER TABLE erasure_tombstones
    ADD COLUMN IF NOT EXISTS affected_dataset_versions JSONB NOT NULL DEFAULT '[]'::jsonb;

-- Seal revision links appended by an erasure (one entry per affected seal).
ALTER TABLE erasure_tombstones
    ADD COLUMN IF NOT EXISTS seal_revisions JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE queries DROP CONSTRAINT IF EXISTS queries_status_check;
ALTER TABLE queries ADD CONSTRAINT queries_status_check
    CHECK (status IN ('RESERVED', 'DISCLOSED', 'CANCELLED', 'INVALIDATED'));

ALTER TABLE budget_ledger DROP CONSTRAINT IF EXISTS budget_ledger_entry_type_check;
ALTER TABLE budget_ledger ADD CONSTRAINT budget_ledger_entry_type_check
    CHECK (entry_type IN ('RESERVE', 'DISCLOSE', 'CANCEL', 'RETRY', 'INVALIDATE'));
