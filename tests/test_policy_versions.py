"""End-to-end tests of policy version drafts, atomic publish/switch,
idempotent withdrawal, per-version independent budgets and audit replay.
"""
from __future__ import annotations

import concurrent.futures
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.db import SessionLocal

from .conftest import seed_dataset, uniq


def make_policy(client, **overrides):
    payload = {
        "name": uniq("pol"),
        "epsilon_total": 5.0,
        "delta_total": 0.0,
        "per_subject_cap": 2,
        "dimensions": ["region", "age_band"],
    }
    payload.update(overrides)
    resp = client.post("/policies", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


def submit(client, policy, key, **overrides):
    payload = {
        "idempotency_key": key,
        "policy_name": policy["name"],
        "dataset_version": 1,
        "query_type": "count",
        "group_by": ["region"],
        "epsilon": 1.0,
        "delta": 0.0,
    }
    payload.update(overrides)
    return client.post("/queries", json=payload)


def draft(client, policy, key, **params):
    body = {"idempotency_key": key,
            "epsilon_total": params.pop("epsilon_total", 8.0),
            "delta_total": params.pop("delta_total", 0.0),
            "per_subject_cap": params.pop("per_subject_cap", 3),
            "dimensions": params.pop("dimensions", ["region", "age_band", "plan"])}
    return client.post(f"/policies/{policy['id']}/versions/drafts", json=body)


# ---------------------------------------------------------------------------
# version #1 bootstrap
# ---------------------------------------------------------------------------
def test_policy_is_created_with_published_version_one(client):
    policy = make_policy(client)
    assert policy["effective_version_seq"] == 1
    listing = client.get(f"/policies/{policy['id']}/versions").json()
    assert listing["effective_version_seq"] == 1
    (v1,) = listing["versions"]
    assert v1["version_seq"] == 1
    assert v1["status"] == "PUBLISHED"
    assert v1["epsilon_total"] == 5.0
    assert v1["per_subject_cap"] == 2
    assert v1["dimensions"] == ["region", "age_band"]
    assert len(v1["draft_hash"]) == 64
    assert len(v1["summary_hash"]) == 64
    assert v1["budget"]["epsilon_total"] == 5.0
    assert listing["drafts"] == []

    detail = client.get(f"/policies/{policy['id']}/versions/1")
    assert detail.status_code == 200
    assert detail.json()["effective"] is True


def test_version_summary_hashes_are_determinant(client):
    # Two policies with identical parameters get different summary hashes
    # (bound to policy id + version seq) but identical draft content hashes.
    p1 = make_policy(client)
    p2 = make_policy(client)
    l1 = client.get(f"/policies/{p1['id']}/versions").json()["versions"][0]
    l2 = client.get(f"/policies/{p2['id']}/versions").json()["versions"][0]
    assert l1["draft_hash"] == l2["draft_hash"]
    assert l1["summary_hash"] != l2["summary_hash"]


# ---------------------------------------------------------------------------
# draft submission: immutable + idempotent
# ---------------------------------------------------------------------------
def test_draft_submission_and_idempotent_replay(client):
    policy = make_policy(client)
    key = uniq("draft")
    r1 = draft(client, policy, key)
    assert r1.status_code == 201, r1.text
    d1 = r1.json()
    assert d1["status"] == "DRAFT"
    assert d1["version_seq"] is None
    assert d1["summary_hash"] is None

    # same key, same body -> 200 identical replay
    r2 = draft(client, policy, key)
    assert r2.status_code == 200
    assert r2.json() == d1

    # same key, different body -> 409
    bad = client.post(f"/policies/{policy['id']}/versions/drafts", json={
        "idempotency_key": key, "epsilon_total": 99.0, "delta_total": 0.0,
        "per_subject_cap": 1, "dimensions": ["region"]})
    assert bad.status_code == 409
    assert bad.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"


def test_duplicate_draft_content_is_idempotent_without_matching_key(client):
    policy = make_policy(client)
    r1 = draft(client, policy, uniq("draft"), epsilon_total=7.0)
    assert r1.status_code == 201
    # identical parameters, different idempotency key -> same stored draft
    r2 = draft(client, policy, uniq("draft-other"), epsilon_total=7.0)
    assert r2.status_code == 200
    assert r2.json()["id"] == r1.json()["id"]

    listing = client.get(f"/policies/{policy['id']}/versions").json()
    assert len(listing["drafts"]) == 1


def test_identical_to_published_version_resolves_to_published(client):
    policy = make_policy(client)
    # submitting v1's exact parameters as a draft resolves to published v1
    r = client.post(f"/policies/{policy['id']}/versions/drafts", json={
        "idempotency_key": uniq("draft"), "epsilon_total": 5.0, "delta_total": 0.0,
        "per_subject_cap": 2, "dimensions": ["region", "age_band"]})
    assert r.status_code == 200
    assert r.json()["status"] == "PUBLISHED"
    assert r.json()["version_seq"] == 1


def test_dimension_order_does_not_change_draft_hash(client):
    policy = make_policy(client)
    r1 = draft(client, policy, uniq("d"), dimensions=["region", "plan"])
    r2 = draft(client, policy, uniq("d2"), dimensions=["plan", "region"])
    assert r1.status_code == 201
    assert r2.status_code == 200
    assert r2.json()["id"] == r1.json()["id"]


# ---------------------------------------------------------------------------
# withdrawal
# ---------------------------------------------------------------------------
def test_withdraw_unpublished_draft_is_idempotent(client):
    policy = make_policy(client)
    d = draft(client, policy, uniq("draft")).json()
    w1 = client.post(f"/policies/versions/drafts/{d['id']}/withdraw")
    assert w1.status_code == 200
    assert w1.json()["status"] == "WITHDRAWN"
    # replay is idempotent
    w2 = client.post(f"/policies/versions/drafts/{d['id']}/withdraw")
    assert w2.status_code == 200
    assert w2.json() == w1.json()

    # a withdrawn draft can never be published
    pub = client.post(f"/policies/versions/drafts/{d['id']}/publish", json={})
    assert pub.status_code == 409
    assert pub.json()["error"]["code"] == "DRAFT_WITHDRAWN"

    # its content may be resubmitted as a FRESH draft (withdrawal isn't a veto)
    resubmitted = draft(client, policy, uniq("draft-fresh"))
    assert resubmitted.status_code == 201
    assert resubmitted.json()["id"] != d["id"]


def test_published_draft_cannot_be_withdrawn(client):
    policy = make_policy(client)
    d = draft(client, policy, uniq("draft")).json()
    client.post(f"/policies/versions/drafts/{d['id']}/publish", json={})
    w = client.post(f"/policies/versions/drafts/{d['id']}/withdraw")
    assert w.status_code == 409
    assert w.json()["error"]["code"] == "DRAFT_ALREADY_PUBLISHED"


def test_unknown_draft_is_404(client):
    make_policy(client)
    missing = uuid.uuid4()
    assert client.post(f"/policies/versions/drafts/{missing}/withdraw").status_code == 404
    assert client.post(f"/policies/versions/drafts/{missing}/publish",
                       json={}).status_code == 404


# ---------------------------------------------------------------------------
# publish: atomic switch + independent budget
# ---------------------------------------------------------------------------
def test_publish_is_atomic_and_switches_effective_version(client):
    policy = make_policy(client)
    ds = seed_dataset(client)
    # spend some of v1's budget with an old query
    old = submit(client, policy, uniq("q-old"), dataset_version=ds).json()
    assert old["policy_version_seq"] == 1

    d = draft(client, policy, uniq("draft")).json()
    before_publish = client.get(f"/policies/{policy['id']}").json()["version"]
    pub = client.post(f"/policies/versions/drafts/{d['id']}/publish", json={})
    assert pub.status_code == 201, pub.text
    body = pub.json()
    assert body["version_seq"] == 2
    assert body["status"] == "PUBLISHED"
    assert body["summary_hash"] != d["draft_hash"]
    assert body["budget"]["epsilon_total"] == 8.0
    assert body["budget"]["epsilon_reserved"] == 0.0   # fresh independent pool

    # policy now reports v2 parameters / pool and a bumped CAS token
    after = client.get(f"/policies/{policy['id']}").json()
    assert after["effective_version_seq"] == 2
    assert after["version"] == before_publish + 1
    assert after["epsilon_total"] == 8.0
    assert after["per_subject_cap"] == 3
    assert after["dimensions"] == ["region", "age_band", "plan"]
    assert after["epsilon_reserved"] == 0.0
    assert after["epsilon_available"] == 8.0

    # publishing the same draft again is idempotent
    again = client.post(f"/policies/versions/drafts/{d['id']}/publish", json={})
    assert again.status_code == 200
    assert again.json()["version_seq"] == 2

    # a new query binds v2 and books against the fresh pool
    new = submit(client, policy, uniq("q-new"), dataset_version=ds)
    assert new.status_code == 201
    qnew = new.json()
    assert qnew["policy_version_seq"] == 2
    after2 = client.get(f"/policies/{policy['id']}").json()
    assert after2["epsilon_reserved"] == 1.0


def test_old_query_keeps_booking_against_original_version(client):
    policy = make_policy(client)
    ds = seed_dataset(client)
    old = submit(client, policy, uniq("q-old"), dataset_version=ds).json()
    # publish v2
    d = draft(client, policy, uniq("draft")).json()
    client.post(f"/policies/versions/drafts/{d['id']}/publish", json={})

    # new v2 reservation
    submit(client, policy, uniq("q-new"), dataset_version=ds)

    # disclose the OLD query: spends against v1 pool, not v2
    disc = client.post(f"/queries/{old['id']}/disclose")
    assert disc.status_code == 200

    v1 = client.get(f"/policies/{policy['id']}/versions/1").json()
    v2 = client.get(f"/policies/{policy['id']}/versions/2").json()
    assert v1["budget"]["epsilon_spent"] == 1.0
    assert v1["budget"]["epsilon_reserved"] == 0.0
    assert v2["budget"]["epsilon_spent"] == 0.0
    assert v2["budget"]["epsilon_reserved"] == 1.0
    assert v2["budget"]["epsilon_total"] == 8.0


def test_budgets_are_independent_budget_exceeded_is_per_version(client):
    # v1 has only 1.0 total
    policy = make_policy(client, epsilon_total=1.0, delta_total=0.0,
                         per_subject_cap=1, dimensions=["region"])
    ds = seed_dataset(client)
    # fill v1
    full = submit(client, policy, uniq("q"), dataset_version=ds, epsilon=1.0)
    assert full.status_code == 201

    # publish a generous v2
    d = draft(client, policy, uniq("draft"), epsilon_total=10.0,
              per_subject_cap=1, dimensions=["region"]).json()
    client.post(f"/policies/versions/drafts/{d['id']}/publish", json={})

    # v1 cannot reserve more ...
    over_v1 = submit(client, policy, uniq("q"), dataset_version=ds, epsilon=0.1,
                     policy_version_seq=1)
    assert over_v1.status_code == 409
    assert over_v1.json()["error"]["code"] == "POLICY_VERSION_NOT_EFFECTIVE"

    # ... but an ordinary (v2) submission succeeds on the independent pool
    ok = submit(client, policy, uniq("q"), dataset_version=ds, epsilon=9.0)
    assert ok.status_code == 201
    assert ok.json()["policy_version_seq"] == 2

    # and v2's own limit is enforced independently
    over_v2 = submit(client, policy, uniq("q"), dataset_version=ds, epsilon=2.0)
    assert over_v2.status_code == 409
    assert over_v2.json()["error"]["code"] == "BUDGET_EXCEEDED"
    assert over_v2.json()["error"]["details"]["policy_version_seq"] == 2


def test_publish_respects_expected_policy_version_cas(client):
    policy = make_policy(client)
    d = draft(client, policy, uniq("draft")).json()
    stale = client.post(f"/policies/versions/drafts/{d['id']}/publish",
                        json={"expected_policy_version": policy["version"] + 5})
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "VERSION_CONFLICT"

    # draft is unchanged and still publishable with the correct token
    ok = client.post(f"/policies/versions/drafts/{d['id']}/publish",
                     json={"expected_policy_version": policy["version"]})
    assert ok.status_code == 201


def test_publish_respects_expected_effective_version(client):
    policy = make_policy(client)
    d1 = draft(client, policy, uniq("d1")).json()
    d2 = draft(client, policy, uniq("d2"), epsilon_total=9.0,
               per_subject_cap=1, dimensions=["region"]).json()
    client.post(f"/policies/versions/drafts/{d1['id']}/publish", json={})
    # d2 client expected v1 still effective, but v2 now is
    stale = client.post(f"/policies/versions/drafts/{d2['id']}/publish",
                        json={"expected_effective_version": 1})
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "EFFECTIVE_VERSION_CONFLICT"
    ok = client.post(f"/policies/versions/drafts/{d2['id']}/publish",
                     json={"expected_effective_version": 2})
    assert ok.status_code == 201
    assert ok.json()["version_seq"] == 3


def test_version_numbers_are_gapless_and_versions_are_immutable(client):
    policy = make_policy(client)
    seqs = []
    for i in range(3):
        d = draft(client, policy, uniq("draft"), epsilon_total=10.0 + i,
                  per_subject_cap=1, dimensions=["region"]).json()
        pub = client.post(f"/policies/versions/drafts/{d['id']}/publish", json={})
        seqs.append(pub.json()["version_seq"])
    assert seqs == [2, 3, 4]
    listing = client.get(f"/policies/{policy['id']}/versions").json()
    assert [v["version_seq"] for v in listing["versions"]] == [1, 2, 3, 4]
    assert listing["effective_version_seq"] == 4


def test_new_query_parameters_come_from_effective_version(client):
    # v1 allows only region; v2 adds plan
    policy = make_policy(client, epsilon_total=5.0, per_subject_cap=2,
                         dimensions=["region"])
    ds = seed_dataset(client)
    d = draft(client, policy, uniq("draft"), dimensions=["region", "plan"]).json()
    client.post(f"/policies/versions/drafts/{d['id']}/publish", json={})

    # group_by a dimension only v2 allows -> now valid
    ok = submit(client, policy, uniq("q"), dataset_version=ds, group_by=["plan"])
    assert ok.status_code == 201, ok.text
    assert ok.json()["policy_version_seq"] == 2


# ---------------------------------------------------------------------------
# no in-place modification / concurrency
# ---------------------------------------------------------------------------
def test_concurrent_publishes_assign_distinct_versions(client):
    policy = make_policy(client)
    drafts = [draft(client, policy, uniq("d"), epsilon_total=20.0 + i,
                    per_subject_cap=1, dimensions=["region"]).json()
              for i in range(4)]

    def do_publish(d):
        return client.post(f"/policies/versions/drafts/{d['id']}/publish", json={})

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(do_publish, drafts))

    # exactly one 201 per draft, and no two drafts got the same version_seq
    by_id = {}
    for d, resp in zip(drafts, results):
        assert resp.status_code in (200, 201), resp.text
        seq = resp.json()["version_seq"]
        assert seq not in by_id
        by_id[seq] = d["id"]
    assert set(by_id) == {2, 3, 4, 5}

    final = client.get(f"/policies/{policy['id']}").json()
    assert final["effective_version_seq"] == 5


def test_concurrent_reservations_on_different_versions_never_overwrite(client):
    # v1 pool is large; publish v2; concurrently reserve against the *same*
    # effective version from many threads — sums must be exact, and after a
    # switch the old pool stays frozen.
    policy = make_policy(client, epsilon_total=100.0, per_subject_cap=1,
                         dimensions=["region"])
    ds = seed_dataset(client)
    for _ in range(10):
        r = submit(client, policy, uniq("old"), dataset_version=ds, epsilon=1.0)
        assert r.status_code == 201
    d = draft(client, policy, uniq("d"), epsilon_total=200.0,
              per_subject_cap=1, dimensions=["region"]).json()
    client.post(f"/policies/versions/drafts/{d['id']}/publish", json={})

    def do_submit(_):
        return submit(client, policy, uniq("new"), dataset_version=ds, epsilon=1.0)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(do_submit, range(16)))
    assert sum(1 for r in results if r.status_code == 201) == 16

    v1 = client.get(f"/policies/{policy['id']}/versions/1").json()
    v2 = client.get(f"/policies/{policy['id']}/versions/2").json()
    assert v1["budget"]["epsilon_reserved"] == 10.0
    assert v2["budget"]["epsilon_reserved"] == 16.0
    assert v2["budget"]["epsilon_total"] == 200.0


# ---------------------------------------------------------------------------
# audit replay scoped per version
# ---------------------------------------------------------------------------
def test_audit_replay_is_scoped_per_version(client):
    policy = make_policy(client)
    ds = seed_dataset(client)
    q1 = submit(client, policy, uniq("q1"), dataset_version=ds).json()
    client.post(f"/queries/{q1['id']}/disclose")

    d = draft(client, policy, uniq("d")).json()
    client.post(f"/policies/versions/drafts/{d['id']}/publish", json={})
    q2 = submit(client, policy, uniq("q2"), dataset_version=ds).json()

    # default replay = effective version (v2): only q2, only v2 entries
    r2 = client.get(f"/audit/policies/{policy['id']}/replay").json()
    assert r2["policy_version"]["version_seq"] == 2
    assert r2["budget"]["epsilon_reserved"] == 1.0
    assert r2["budget"]["epsilon_spent"] == 0.0
    assert {q["query_id"] for q in r2["queries"]} == {q2["id"]}
    assert all(e["policy_version_seq"] == 2 for e in r2["entries"])
    assert r2["chain"]["verified"] is True
    assert r2["chain"]["scope_consistent"] is True
    assert r2["budget"]["reconstruction_consistent"] is True

    # explicit v1 replay: only q1, spent on v1
    r1 = client.get(f"/audit/policies/{policy['id']}/replay?version_seq=1").json()
    assert r1["policy_version"]["version_seq"] == 1
    assert r1["budget"]["epsilon_spent"] == 1.0
    assert r1["budget"]["epsilon_reserved"] == 0.0
    assert {q["query_id"] for q in r1["queries"]} == {q1["id"]}
    assert all(e["policy_version_seq"] == 1 for e in r1["entries"])
    assert r1["chain"]["verified"] is True

    # q1 replay after switch still reproduces its original outcome
    view = r1["queries"][0]
    assert view["outcome"] == "DISCLOSED"
    assert view["version_summary_hash"] == r1["policy_version"]["summary_hash"]


def test_audit_replay_to_version_pins_horizon_across_switches(client):
    policy = make_policy(client)
    ds = seed_dataset(client)
    q = submit(client, policy, uniq("q"), dataset_version=ds).json()
    reserve_version = q["policy_version"]
    d = draft(client, policy, uniq("d")).json()
    client.post(f"/policies/versions/drafts/{d['id']}/publish", json={})
    # the old v1 query is disclosed after the switch (still booked against v1)
    client.post(f"/queries/{q['id']}/disclose")

    # pinned at the global CAS version right after q's reservation: the v1
    # query is indeterminate at that horizon, and its later DISCLOSE (which
    # carries an even larger global CAS version) is reported as beyond replay
    pinned = client.get(
        f"/audit/policies/{policy['id']}/replay"
        f"?version_seq=1&to_version={reserve_version}").json()
    (view,) = pinned["queries"]
    assert view["query_id"] == q["id"]
    assert view["outcome"] == "INDETERMINATE"
    assert view["determinate"] is False
    assert view["later_events_beyond_replay"] is True


# ---------------------------------------------------------------------------
# storage-layer immutability (triggers): no in-place modification possible
# ---------------------------------------------------------------------------
def test_draft_and_published_versions_are_immutable_in_storage(client):
    policy = make_policy(client)
    d = draft(client, policy, uniq("d")).json()
    d_open = draft(client, policy, uniq("d-open"), epsilon_total=6.0,
                   per_subject_cap=1, dimensions=["region"]).json()
    pub = client.post(f"/policies/versions/drafts/{d['id']}/publish",
                      json={}).json()

    with SessionLocal() as db:
        open_id = uuid.UUID(d_open["id"])
        pub_id = uuid.UUID(pub["id"])

        # an open DRAFT cannot have its content rewritten in place ...
        with pytest.raises(DBAPIError) as ei:
            db.execute(text("UPDATE policy_versions SET epsilon_total = 999 "
                            "WHERE id = :id"), {"id": open_id})
        db.rollback()
        assert "immutable" in str(ei.value.orig)

        # ... nor be deleted ...
        with pytest.raises(DBAPIError) as ei:
            db.execute(text("DELETE FROM policy_versions WHERE id = :id"),
                       {"id": open_id})
        db.rollback()
        assert "append-only" in str(ei.value.orig)

        # a PUBLISHED version can neither change content nor move status back
        with pytest.raises(DBAPIError) as ei:
            db.execute(text("UPDATE policy_versions SET per_subject_cap = 42 "
                            "WHERE id = :id"), {"id": pub_id})
        db.rollback()
        assert "immutable" in str(ei.value.orig)

        with pytest.raises(DBAPIError) as ei:
            db.execute(text("UPDATE policy_versions SET status = 'WITHDRAWN' "
                            "WHERE id = :id"), {"id": pub_id})
        db.rollback()
        assert "illegal" in str(ei.value.orig)

        # and an already-published version row cannot be deleted
        with pytest.raises(DBAPIError) as ei:
            db.execute(text("DELETE FROM policy_versions WHERE id = :id"),
                       {"id": pub_id})
        db.rollback()
        assert "append-only" in str(ei.value.orig)

        # per-version budget pools cannot be deleted either
        with pytest.raises(DBAPIError) as ei:
            db.execute(text("DELETE FROM policy_version_budgets "
                            "WHERE policy_id = :p AND version_seq = 2"),
                       {"p": uuid.UUID(policy["id"])})
        db.rollback()
        assert "append-only" in str(ei.value.orig)

    # the published version is untouched afterwards
    again = client.get(f"/policies/{policy['id']}/versions/2").json()
    assert again["per_subject_cap"] == pub["per_subject_cap"]
    assert again["status"] == "PUBLISHED"


def test_cross_version_budget_pool_is_not_writable_through_policy_table(client):
    """The policies-table v1 mirror stays frozen after a switch: budget
    updates go through policy_version_budgets only."""
    policy = make_policy(client, epsilon_total=5.0)
    ds = seed_dataset(client)
    submit(client, policy, uniq("q"), dataset_version=ds)
    d = draft(client, policy, uniq("d"), epsilon_total=9.0,
              per_subject_cap=2, dimensions=["region", "age_band", "plan"]).json()
    client.post(f"/policies/versions/drafts/{d['id']}/publish", json={})

    with SessionLocal() as db:
        row = db.execute(text(
            "SELECT epsilon_reserved, epsilon_spent FROM policies WHERE id = :id"),
            {"id": uuid.UUID(policy["id"])}).one()
        # v1 mirror still carries the v1 reservation (1.0); it is untouched by
        # any v2 activity
        assert float(row.epsilon_reserved) == 1.0
        assert float(row.epsilon_spent) == 0.0
        pool2 = db.execute(text(
            "SELECT epsilon_reserved FROM policy_version_budgets "
            "WHERE policy_id = :p AND version_seq = 2"),
            {"p": uuid.UUID(policy["id"])}).one()
        assert float(pool2.epsilon_reserved) == 0.0


def test_ledger_entries_carry_version_seq_and_chain_stays_linear(client):
    policy = make_policy(client)
    ds = seed_dataset(client)
    q1 = submit(client, policy, uniq("q1"), dataset_version=ds).json()
    client.post(f"/queries/{q1['id']}/disclose")
    d = draft(client, policy, uniq("d")).json()
    client.post(f"/policies/versions/drafts/{d['id']}/publish", json={})
    q2 = submit(client, policy, uniq("q2"), dataset_version=ds).json()
    client.post(f"/queries/{q2['id']}/cancel")

    with SessionLocal() as db:
        rows = db.execute(text(
            "SELECT entry_type, policy_version_seq, prev_hash, entry_hash "
            "FROM budget_ledger WHERE policy_id = :p ORDER BY id"),
            {"p": uuid.UUID(policy["id"])}).all()
    types = [r[0] for r in rows]
    seqs = [r[1] for r in rows]
    assert types == ["RESERVE", "DISCLOSE", "RESERVE", "CANCEL"]
    assert seqs == [1, 1, 2, 2]
    # one linear chain across both versions: each prev matches the prior hash
    assert rows[0][2] == "0" * 64
    for prev, cur in zip(rows, rows[1:]):
        assert cur[2] == prev[3]


def test_idempotent_retry_after_switch_replays_original_version_query(client):
    """Replaying an existing idempotency key after a version switch must
    return the original (old-version) query — it keeps booking against its
    original version — rather than raising a digest conflict."""
    policy = make_policy(client)
    ds = seed_dataset(client)
    key = uniq("q")
    first = submit(client, policy, key, dataset_version=ds)
    assert first.status_code == 201
    q1 = first.json()
    assert q1["policy_version_seq"] == 1

    d = draft(client, policy, uniq("d")).json()
    client.post(f"/policies/versions/drafts/{d['id']}/publish", json={})

    # same key, same body -> 200, the exact old query (still bound to v1)
    replay = submit(client, policy, key, dataset_version=ds)
    assert replay.status_code == 200
    body = replay.json()
    assert body["id"] == q1["id"]
    assert body["policy_version_seq"] == 1
    assert body["retry_count"] == 1

    # no new reservation landed on either pool: v1 keeps its single reserve
    v1 = client.get(f"/policies/{policy['id']}/versions/1").json()
    v2 = client.get(f"/policies/{policy['id']}/versions/2").json()
    assert v1["budget"]["epsilon_reserved"] == 1.0
    assert v2["budget"]["epsilon_reserved"] == 0.0

    # the old query still discloses against v1
    assert client.post(f"/queries/{q1['id']}/disclose").status_code == 200
    v1b = client.get(f"/policies/{policy['id']}/versions/1").json()
    assert v1b["budget"]["epsilon_spent"] == 1.0
