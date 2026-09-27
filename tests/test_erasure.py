"""End-to-end tests of the data-subject erasure lifecycle."""
from __future__ import annotations

import concurrent.futures
import uuid

import pytest
from sqlalchemy import text

from app.db import SessionLocal

from .conftest import uniq, upload


@pytest.fixture(autouse=True)
def clean_db():
    """Erasure effects (invalidation, tombstones) are global by design — they
    span every policy and all dataset versions up to the cut-off. Give each
    erasure test a clean slate so counts and ledger contents are exact."""
    with SessionLocal() as db:
        db.execute(text(
            "TRUNCATE budget_ledger, queries, erasure_tombstones, records, policies "
            "RESTART IDENTITY CASCADE"
        ))
        db.commit()
    yield


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


def seed(client):
    """Seed the standard 3-subject dataset with per-test unique subject ids,
    so erasure tombstones never leak across tests (they are global by design).

    Returns (dataset_version, alice, bob, carol): alice has 3 records in "us"
    (one over the per-subject cap), bob 1 in "us", carol 1 in "eu".
    """
    dataset_version = uuid.uuid4().int % 1_000_000_000
    suffix = uuid.uuid4().hex[:10]
    alice, bob, carol = f"alice-{suffix}", f"bob-{suffix}", f"carol-{suffix}"
    upload(client, dataset_version, [
        {"record_key": "r1", "subject_id": alice, "attributes": {"region": "us", "value": 5}},
        {"record_key": "r2", "subject_id": alice, "attributes": {"region": "us", "value": 7}},
        {"record_key": "r3", "subject_id": alice, "attributes": {"region": "us", "value": 100}},
        {"record_key": "r4", "subject_id": bob, "attributes": {"region": "us", "value": 3}},
        {"record_key": "r5", "subject_id": carol, "attributes": {"region": "eu", "value": 11}},
    ])
    return dataset_version, alice, bob, carol


def submit(client, policy, key, dataset_version, **overrides):
    payload = {
        "idempotency_key": key,
        "policy_name": policy["name"],
        "dataset_version": dataset_version,
        "query_type": "count",
        "group_by": ["region"],
        "filters": {},
        "epsilon": 1.0,
        "delta": 0.0,
    }
    payload.update(overrides)
    return client.post("/queries", json=payload)


def erase(client, key, subject, cutoff):
    return client.post("/erasures", json={
        "idempotency_key": key,
        "subject_id": subject,
        "until_dataset_version": cutoff,
    })


def get_policy(client, policy):
    resp = client.get(f"/policies/{policy['id']}")
    assert resp.status_code == 200
    return resp.json()


def test_erasure_leaves_subject_free_versions_untouched(client):
    """Core scoping regression: a RESERVED query on a version that never
    contained the erased subject keeps its status, budget and ledger — only
    versions actually holding the subject are affected."""
    policy = make_policy(client)
    ds, alice, bob, carol = seed(client)
    free_ds = ds + 1
    # a second dataset version, inside the cut-off range, without alice
    upload(client, free_ds, [
        {"record_key": "s1", "subject_id": bob, "attributes": {"region": "us", "value": 1}},
        {"record_key": "s2", "subject_id": carol, "attributes": {"region": "eu", "value": 2}},
    ])
    q_affected = submit(client, policy, uniq("q"), ds).json()
    q_free = submit(client, policy, uniq("q"), free_ds).json()

    resp = erase(client, uniq("erase"), alice, free_ds)   # cut-off covers both
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["affected_dataset_versions"] == [ds]
    assert body["records_deleted"] == 3
    assert body["queries_invalidated"] == 1
    assert body["snapshots_scrubbed"] == 1
    assert [a["query_id"] for a in body["affected_queries"]] == [q_affected["id"]]

    # the query on the affected version is invalidated and refunded ...
    assert client.get(f"/queries/{q_affected['id']}").json()["status"] == "INVALIDATED"
    # ... the one on the subject-free version is completely untouched
    free = client.get(f"/queries/{q_free['id']}").json()
    assert free["status"] == "RESERVED"
    assert free["invalidated_by"] is None
    assert free["invalidated_at"] is None

    # budget: only the affected reservation was refunded
    after = get_policy(client, policy)
    assert after["epsilon_reserved"] == 1.0
    assert after["epsilon_spent"] == 0.0

    # ledger: exactly one INVALIDATE entry, bound to the affected query only
    audit = client.get(f"/audit/policies/{policy['id']}/replay").json()
    inv = [e for e in audit["entries"] if e["entry_type"] == "INVALIDATE"]
    assert [e["query_id"] for e in inv] == [q_affected["id"]]
    assert audit["budget"]["reconstruction_consistent"] is True
    assert audit["chain"]["verified"] is True
    # the subject-free query's snapshot was not scrubbed either
    view = next(v for v in audit["queries"] if v["query_id"] == q_free["id"])
    assert [s["subject_id"] for s in view["clipping"]["subjects"]] == [bob, carol]

    # and it can still be disclosed afterwards
    d = client.post(f"/queries/{q_free['id']}/disclose")
    assert d.status_code == 200
    final = get_policy(client, policy)
    assert final["epsilon_reserved"] == 0.0
    assert final["epsilon_spent"] == 1.0


def test_version_with_records_is_affected_even_if_snapshot_excludes_subject(client):
    """A version where the subject actually stored records is affected even
    when a query's own snapshot never referenced her (filters excluded her):
    the dataset changed under that query, so a still-RESERVED query on it is
    invalidated — while its snapshot needs no scrubbing."""
    policy = make_policy(client)
    ds, alice, _bob, _carol = seed(client)
    q = submit(client, policy, uniq("q"), ds, filters={"region": "eu"}).json()

    # sanity: alice (all her records are "us") is not in this snapshot
    audit0 = client.get(f"/audit/policies/{policy['id']}/replay").json()
    view0 = next(v for v in audit0["queries"] if v["query_id"] == q["id"])
    assert all(s["subject_id"] != alice for s in view0["clipping"]["subjects"])

    body = erase(client, uniq("erase"), alice, ds).json()
    assert body["affected_dataset_versions"] == [ds]
    assert body["snapshots_scrubbed"] == 0          # snapshot never referenced her
    assert body["queries_invalidated"] == 1         # but the dataset changed under it
    assert client.get(f"/queries/{q['id']}").json()["status"] == "INVALIDATED"
    after = get_policy(client, policy)
    assert after["epsilon_reserved"] == 0.0


def test_erasure_scopes_to_exact_affected_version_set(client):
    """Subject present in ds1 and ds3 but not ds2: the affected set is
    exactly [ds1, ds3]; the ds2 query keeps its status, budget and ledger."""
    policy = make_policy(client)
    suffix = uuid.uuid4().hex[:10]
    alice, bob = f"alice-{suffix}", f"bob-{suffix}"
    base = uuid.uuid4().int % 1_000_000_000
    ds1, ds2, ds3 = base, base + 1, base + 2
    upload(client, ds1, [{"record_key": "a1", "subject_id": alice,
                          "attributes": {"region": "us"}}])
    upload(client, ds2, [{"record_key": "b1", "subject_id": bob,
                          "attributes": {"region": "us"}}])
    upload(client, ds3, [{"record_key": "a2", "subject_id": alice,
                          "attributes": {"region": "eu"}}])
    q1 = submit(client, policy, uniq("q"), ds1).json()
    q2 = submit(client, policy, uniq("q"), ds2).json()
    q3 = submit(client, policy, uniq("q"), ds3).json()

    resp = erase(client, uniq("erase"), alice, ds3)   # cut-off covers all three
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["affected_dataset_versions"] == [ds1, ds3]
    assert body["records_deleted"] == 2
    assert body["queries_invalidated"] == 2
    assert body["snapshots_scrubbed"] == 2
    assert {a["query_id"] for a in body["affected_queries"]} == {q1["id"], q3["id"]}

    assert client.get(f"/queries/{q1['id']}").json()["status"] == "INVALIDATED"
    assert client.get(f"/queries/{q3['id']}").json()["status"] == "INVALIDATED"
    assert client.get(f"/queries/{q2['id']}").json()["status"] == "RESERVED"

    after = get_policy(client, policy)
    assert after["epsilon_reserved"] == 1.0           # only q2's reservation remains

    audit = client.get(f"/audit/policies/{policy['id']}/replay").json()
    inv = [e for e in audit["entries"] if e["entry_type"] == "INVALIDATE"]
    assert {e["query_id"] for e in inv} == {q1["id"], q3["id"]}
    assert audit["budget"]["reconstruction_consistent"] is True
    assert audit["chain"]["verified"] is True

    # the erasure audit view exposes the affected set and the proof verifies
    entry = next(e for e in client.get("/audit/erasures").json()["erasures"]
                 if e["tombstone_id"] == body["tombstone_id"])
    assert entry["affected_dataset_versions"] == [ds1, ds3]
    assert entry["proof_verified"] is True
    assert entry["verification"] == "VERIFIED"


def test_erasure_without_any_affected_version_touches_nothing(client):
    """A subject with no records and no snapshots inside the cut-off range:
    the tombstone is registered (and blocks future uploads), but no query,
    budget or ledger entry changes."""
    policy = make_policy(client)
    ds, _alice, _bob, _carol = seed(client)
    ghost = uniq("ghost")
    q = submit(client, policy, uniq("q"), ds).json()

    resp = erase(client, uniq("erase"), ghost, ds + 5)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["affected_dataset_versions"] == []
    assert body["records_deleted"] == 0
    assert body["queries_invalidated"] == 0
    assert body["snapshots_scrubbed"] == 0
    assert body["affected_queries"] == []

    # every query, balance and ledger entry is exactly as before
    assert client.get(f"/queries/{q['id']}").json()["status"] == "RESERVED"
    after = get_policy(client, policy)
    assert after["epsilon_reserved"] == 1.0
    audit = client.get(f"/audit/policies/{policy['id']}/replay").json()
    assert [e["entry_type"] for e in audit["entries"]] == ["RESERVE"]

    # the tombstone still blocks uploads of the ghost within its range
    blocked = client.post("/records", json={
        "dataset_version": ds,
        "records": [{"record_key": uniq("r"), "subject_id": ghost, "attributes": {}}],
    })
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "SUBJECT_ERASED"


def test_erasure_replay_keeps_affected_set_and_untouched_versions(client):
    """Idempotent replay returns the identical receipt (including the
    affected version set) and never re-touches subject-free versions."""
    policy = make_policy(client)
    ds, alice, bob, _carol = seed(client)
    free_ds = ds + 1
    upload(client, free_ds, [
        {"record_key": "s1", "subject_id": bob, "attributes": {"region": "us"}}])
    submit(client, policy, uniq("q"), ds)
    q_free = submit(client, policy, uniq("q"), free_ds).json()

    key = uniq("erase")
    first = erase(client, key, alice, free_ds)
    assert first.status_code == 201
    assert first.json()["affected_dataset_versions"] == [ds]

    replay = erase(client, key, alice, free_ds)
    assert replay.status_code == 200
    assert replay.json() == first.json()

    # the subject-free query is still reserved, still unrefunded
    assert client.get(f"/queries/{q_free['id']}").json()["status"] == "RESERVED"
    after = get_policy(client, policy)
    assert after["epsilon_reserved"] == 1.0
    audit = client.get(f"/audit/policies/{policy['id']}/replay").json()
    types = [e["entry_type"] for e in audit["entries"]]
    assert types.count("INVALIDATE") == 1
    assert audit["budget"]["reconstruction_consistent"] is True


def test_concurrent_erasure_and_subject_free_version_activity(client):
    """Concurrency regression: an erasure racing a disclose and a fresh
    submission on a subject-free version never disturbs that version — the
    disclose succeeds, the submission reserves, and only the affected
    version's query is invalidated."""
    policy = make_policy(client)
    ds, alice, bob, carol = seed(client)
    free_ds = ds + 1
    upload(client, free_ds, [
        {"record_key": "s1", "subject_id": bob, "attributes": {"region": "us"}},
        {"record_key": "s2", "subject_id": carol, "attributes": {"region": "eu"}},
    ])
    q_free = submit(client, policy, uniq("q"), free_ds).json()
    q_doomed = submit(client, policy, uniq("q"), ds).json()

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        f_disclose = pool.submit(client.post, f"/queries/{q_free['id']}/disclose")
        f_submit = pool.submit(submit, client, policy, uniq("q"), free_ds)
        f_erase = pool.submit(erase, client, uniq("erase"), alice, free_ds)
        d_resp = f_disclose.result()
        s_resp = f_submit.result()
        e_resp = f_erase.result()

    assert e_resp.status_code == 201
    assert e_resp.json()["affected_dataset_versions"] == [ds]
    assert d_resp.status_code == 200                 # unaffected by the erasure
    assert s_resp.status_code == 201
    assert s_resp.json()["status"] == "RESERVED"

    assert client.get(f"/queries/{q_doomed['id']}").json()["status"] == "INVALIDATED"
    assert client.get(f"/queries/{q_free['id']}").json()["status"] == "DISCLOSED"

    after = get_policy(client, policy)
    assert after["epsilon_reserved"] == 1.0          # only the new submission
    assert after["epsilon_spent"] == 1.0             # only the free-version query

    audit = client.get(f"/audit/policies/{policy['id']}/replay").json()
    inv = [e for e in audit["entries"] if e["entry_type"] == "INVALIDATE"]
    assert [e["query_id"] for e in inv] == [q_doomed["id"]]
    assert audit["budget"]["reconstruction_consistent"] is True
    assert audit["chain"]["verified"] is True


def test_erasure_invalidates_reserved_and_refunds_exactly_once(client):
    policy = make_policy(client)
    ds, alice, _bob, _carol = seed(client)
    q_reserved = submit(client, policy, uniq("q"), ds).json()
    q_disclosed = submit(client, policy, uniq("q"), ds).json()
    client.post(f"/queries/{q_disclosed['id']}/disclose")
    disclosed_before = client.get(f"/queries/{q_disclosed['id']}").json()

    resp = erase(client, uniq("erase"), alice, ds)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["records_deleted"] == 3          # alice's three records
    assert body["queries_invalidated"] == 1      # only the RESERVED one
    assert body["snapshots_scrubbed"] == 2       # both snapshots referenced alice
    assert body["subject_hash"] != alice
    assert len(body["subject_hash"]) == 64
    assert len(body["proof_hash"]) == 64
    assert [a["query_id"] for a in body["affected_queries"]] == [q_reserved["id"]]
    assert body["affected_queries"][0]["refunded"] == {"epsilon": 1.0, "delta": 0.0}
    assert body["affected_queries"][0]["ledger_seq"] > 0

    # the reservation was refunded exactly once; the disclosed spend is untouched
    after = get_policy(client, policy)
    assert after["epsilon_reserved"] == 0.0
    assert after["epsilon_spent"] == 1.0

    q1 = client.get(f"/queries/{q_reserved['id']}").json()
    assert q1["status"] == "INVALIDATED"
    assert q1["invalidated_by"] == body["tombstone_id"]
    assert q1["invalidated_at"] is not None

    # disclosed result is byte-identical after the erasure
    disclosed_after = client.get(f"/queries/{q_disclosed['id']}").json()
    assert disclosed_after["status"] == "DISCLOSED"
    assert disclosed_after["result"] == disclosed_before["result"]

    # the invalidated reservation can neither be disclosed nor refunded again
    d = client.post(f"/queries/{q_reserved['id']}/disclose")
    assert d.status_code == 409
    assert d.json()["error"]["code"] == "QUERY_INVALIDATED"
    c = client.post(f"/queries/{q_reserved['id']}/cancel")
    assert c.status_code == 409
    assert c.json()["error"]["code"] == "REFUND_ALREADY_ISSUED"


def test_erasure_is_idempotent_and_never_double_refunds(client):
    policy = make_policy(client)
    ds, _alice, bob, _carol = seed(client)
    submit(client, policy, uniq("q"), ds)

    key = uniq("erase")
    first = erase(client, key, bob, ds)
    assert first.status_code == 201
    replay = erase(client, key, bob, ds)
    assert replay.status_code == 200
    assert replay.json() == first.json()

    after = get_policy(client, policy)
    assert after["epsilon_reserved"] == 0.0      # refunded exactly once

    # same key, different request -> 409
    conflict = erase(client, key, bob, ds + 1)
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"

    # exactly one INVALIDATE entry; chain and balances still reconstruct
    audit = client.get(f"/audit/policies/{policy['id']}/replay").json()
    types = [e["entry_type"] for e in audit["entries"]]
    assert types == ["RESERVE", "INVALIDATE"]
    assert audit["budget"]["reconstruction_consistent"] is True
    assert audit["budget"]["epsilon_reserved"] == 0.0
    assert audit["chain"]["verified"] is True


def test_tombstone_blocks_reupload_within_range_only(client):
    ds, _alice, _bob, carol = seed(client)
    resp = erase(client, uniq("erase"), carol, ds)
    assert resp.status_code == 201

    # re-upload of the erased subject within the tombstone range is forbidden
    blocked = client.post("/records", json={
        "dataset_version": ds,
        "records": [{"record_key": uniq("r"), "subject_id": carol,
                     "attributes": {"region": "eu"}}],
    })
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "SUBJECT_ERASED"

    # ... but allowed beyond the cut-off version
    ok = client.post("/records", json={
        "dataset_version": ds + 1,
        "records": [{"record_key": uniq("r"), "subject_id": carol,
                     "attributes": {"region": "eu"}}],
    })
    assert ok.status_code == 201, ok.text
    assert ok.json()["inserted"] == 1

    # other subjects are unaffected within the range
    other = client.post("/records", json={
        "dataset_version": ds,
        "records": [{"record_key": uniq("r"), "subject_id": uniq("dave"),
                     "attributes": {"region": "eu"}}],
    })
    assert other.status_code == 201


def test_audit_reports_erasure_without_exposing_subject(client):
    policy = make_policy(client)
    ds, alice, _bob, _carol = seed(client)
    q = submit(client, policy, uniq("q"), ds).json()
    tomb = erase(client, uniq("erase"), alice, ds).json()

    audit = client.get(f"/audit/policies/{policy['id']}/replay")
    assert audit.status_code == 200
    assert alice not in audit.text               # subject identifier never leaks
    body = audit.json()
    view = next(qv for qv in body["queries"] if qv["query_id"] == q["id"])
    assert view["outcome"] == "INVALIDATED"
    assert view["determinate"] is True
    assert view["invalidated_by"] == tomb["tombstone_id"]
    assert view["erasure"]["tombstone_id"] == tomb["tombstone_id"]
    assert view["erasure"]["proof_hash"] == tomb["proof_hash"]
    subjects = view["clipping"]["subjects"]
    assert all(s["subject_id"] != alice for s in subjects)

    erasures = client.get("/audit/erasures")
    assert erasures.status_code == 200
    assert alice not in erasures.text
    entry = next(e for e in erasures.json()["erasures"]
                 if e["tombstone_id"] == tomb["tombstone_id"])
    assert entry["proof_verified"] is True
    assert entry["verification"] == "VERIFIED"
    assert entry["records_deleted"] == 3
    assert [a["query_id"] for a in entry["affected_queries"]] == [q["id"]]


def test_indeterminate_reason_and_pinned_replay(client):
    policy = make_policy(client)
    ds, alice, _bob, _carol = seed(client)
    q = submit(client, policy, uniq("q"), ds).json()

    # pinned at the reservation: the outcome cannot be determined yet
    pinned = client.get(f"/audit/policies/{policy['id']}/replay?to_version={q['policy_version']}")
    view = next(qv for qv in pinned.json()["queries"] if qv["query_id"] == q["id"])
    assert view["outcome"] == "INDETERMINATE"
    assert view["determinate"] is False
    assert "reason" in view

    erase(client, uniq("erase"), alice, ds)
    latest = client.get(f"/audit/policies/{policy['id']}/replay").json()
    view = next(qv for qv in latest["queries"] if qv["query_id"] == q["id"])
    assert view["outcome"] == "INVALIDATED"

    # the pinned replay still cannot see the invalidation
    pinned2 = client.get(f"/audit/policies/{policy['id']}/replay?to_version={q['policy_version']}")
    view2 = next(qv for qv in pinned2.json()["queries"] if qv["query_id"] == q["id"])
    assert view2["outcome"] == "INDETERMINATE"
    assert view2["later_events_beyond_replay"] is True


def test_query_after_erasure_computes_on_erased_data(client):
    policy = make_policy(client)
    ds, alice, bob, carol = seed(client)
    erase(client, uniq("erase"), alice, ds)

    resp = submit(client, policy, uniq("q"), ds)
    assert resp.status_code == 201, resp.text
    qid = resp.json()["id"]
    audit = client.get(f"/audit/policies/{policy['id']}/replay").json()
    view = next(qv for qv in audit["queries"] if qv["query_id"] == qid)
    subjects = [s["subject_id"] for s in view["clipping"]["subjects"]]
    assert subjects == [bob, carol]              # alice's records are gone
    assert view["clipping"]["records_in_dataset"] == 2


def test_submit_retry_of_invalidated_query_does_not_re_reserve(client):
    policy = make_policy(client)
    ds, alice, _bob, _carol = seed(client)
    key = uniq("q")
    created = submit(client, policy, key, ds)
    assert created.status_code == 201
    erase(client, uniq("erase"), alice, ds)

    replay = submit(client, policy, key, ds)
    assert replay.status_code == 200
    assert replay.json()["status"] == "INVALIDATED"
    after = get_policy(client, policy)
    assert after["epsilon_reserved"] == 0.0      # no new reservation


def test_concurrent_erasure_retries_refund_exactly_once(client):
    policy = make_policy(client)
    ds, alice, _bob, _carol = seed(client)
    for _ in range(3):
        submit(client, policy, uniq("q"), ds)

    key = uniq("erase")

    def do_erase(_):
        return erase(client, key, alice, ds)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(do_erase, range(4)))

    statuses = sorted(r.status_code for r in responses)
    assert statuses == [200, 200, 200, 201]
    assert len({r.json()["tombstone_id"] for r in responses}) == 1

    after = get_policy(client, policy)
    assert after["epsilon_reserved"] == 0.0      # 3 reservations refunded once each
    assert after["epsilon_spent"] == 0.0

    audit = client.get(f"/audit/policies/{policy['id']}/replay").json()
    types = [e["entry_type"] for e in audit["entries"]]
    assert types.count("INVALIDATE") == 3        # no duplicate refunds
    assert audit["budget"]["reconstruction_consistent"] is True
    assert audit["chain"]["verified"] is True


def test_concurrent_disclose_and_erasure_are_serialised(client):
    policy = make_policy(client)
    ds, alice, _bob, _carol = seed(client)
    q = submit(client, policy, uniq("q"), ds).json()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f_disclose = pool.submit(client.post, f"/queries/{q['id']}/disclose")
        f_erase = pool.submit(erase, client, uniq("erase"), alice, ds)
        d_resp, e_resp = f_disclose.result(), f_erase.result()

    assert e_resp.status_code == 201
    final = client.get(f"/queries/{q['id']}").json()
    after = get_policy(client, policy)
    if d_resp.status_code == 200:
        # disclosure won the race: nothing left to invalidate or refund
        assert final["status"] == "DISCLOSED"
        assert e_resp.json()["queries_invalidated"] == 0
        assert after["epsilon_reserved"] == 0.0
        assert after["epsilon_spent"] == 1.0
    else:
        # erasure won: the reservation was refunded before disclosure
        assert d_resp.status_code == 409
        assert d_resp.json()["error"]["code"] == "QUERY_INVALIDATED"
        assert final["status"] == "INVALIDATED"
        assert e_resp.json()["queries_invalidated"] == 1
        assert after["epsilon_reserved"] == 0.0
        assert after["epsilon_spent"] == 0.0

    audit = client.get(f"/audit/policies/{policy['id']}/replay").json()
    assert audit["budget"]["reconstruction_consistent"] is True
    assert audit["chain"]["verified"] is True


def test_concurrent_upload_and_erasure_are_serialised(client):
    ds, alice, _bob, _carol = seed(client)
    new_record = [{"record_key": uniq("r"), "subject_id": alice,
                   "attributes": {"region": "us"}}]

    def do_upload():
        return client.post("/records", json={"dataset_version": ds, "records": new_record})

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f_upload = pool.submit(do_upload)
        f_erase = pool.submit(erase, client, uniq("erase"), alice, ds)
        up_resp, er_resp = f_upload.result(), f_erase.result()

    assert er_resp.status_code == 201
    if up_resp.status_code == 201:
        # upload landed first: the erasure must have erased those rows too
        assert er_resp.json()["records_deleted"] == 4
    else:
        # erasure landed first: the tombstone rejects the upload
        assert up_resp.status_code == 409
        assert up_resp.json()["error"]["code"] == "SUBJECT_ERASED"
        assert er_resp.json()["records_deleted"] == 3

    # either way the tombstone now blocks alice on this version
    again = client.post("/records", json={"dataset_version": ds, "records": [
        {"record_key": uniq("r"), "subject_id": alice, "attributes": {}}]})
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "SUBJECT_ERASED"
