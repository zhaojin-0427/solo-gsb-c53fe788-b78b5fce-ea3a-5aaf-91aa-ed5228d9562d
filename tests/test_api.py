"""End-to-end tests of the budget orchestration lifecycle."""
from __future__ import annotations

import uuid

from .conftest import seed_dataset, uniq, upload


def submit_payload(policy, key, **overrides):
    payload = {
        "idempotency_key": key,
        "policy_name": policy["name"],
        "dataset_version": 1,
        "query_type": "count",
        "group_by": ["region"],
        "filters": {},
        "epsilon": 1.0,
        "delta": 0.0,
    }
    payload.update(overrides)
    return payload


def get_policy(client, policy):
    resp = client.get(f"/policies/{policy['id']}")
    assert resp.status_code == 200
    return resp.json()


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_create_policy_and_duplicate_name_conflicts(client, policy):
    assert policy["version"] == 1
    assert policy["epsilon_available"] == 5.0
    resp = client.post("/policies", json={
        "name": policy["name"],
        "epsilon_total": 1.0,
        "delta_total": 0.0,
        "per_subject_cap": 1,
        "dimensions": [],
    })
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "POLICY_EXISTS"


def test_record_upload_is_idempotent(client):
    version = 900_000 + uuid.uuid4().int % 1000
    batch = [{"record_key": "k1", "subject_id": "s1", "attributes": {"region": "us"}}]
    first = upload(client, version, batch)
    second = upload(client, version, batch)
    assert first["inserted"] == 1 and first["duplicates"] == 0
    assert second["inserted"] == 0 and second["duplicates"] == 1


def test_submit_reserves_budget_and_clips_contributions(client, policy):
    ds = seed_dataset(client)
    resp = client.post("/queries", json=submit_payload(policy, uniq("q"), dataset_version=ds))
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "RESERVED"
    assert body["mechanism"] == "laplace"          # delta = 0
    assert body["sensitivity"] == 2.0              # per_subject_cap
    assert body["noise_scale"] == 2.0              # sensitivity / epsilon

    after = get_policy(client, policy)
    assert after["epsilon_reserved"] == 1.0
    assert after["epsilon_spent"] == 0.0
    assert after["version"] == policy["version"] + 1


def test_idempotent_retry_same_digest_and_conflict_on_different(client, policy):
    ds = seed_dataset(client)
    key = uniq("q")
    first = client.post("/queries", json=submit_payload(policy, key, dataset_version=ds))
    assert first.status_code == 201

    replay = client.post("/queries", json=submit_payload(policy, key, dataset_version=ds))
    assert replay.status_code == 200
    assert replay.json()["id"] == first.json()["id"]
    assert replay.json()["retry_count"] == 1

    # retry does not reserve extra budget
    after = get_policy(client, policy)
    assert after["epsilon_reserved"] == 1.0

    # same key, different request -> 409
    conflict = client.post("/queries", json=submit_payload(policy, key, dataset_version=ds, epsilon=2.0))
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"


def test_disclose_spends_budget_and_is_reproducible(client, policy):
    ds = seed_dataset(client)
    key = uniq("q")
    created = client.post("/queries", json=submit_payload(policy, key, dataset_version=ds)).json()

    disclosed = client.post(f"/queries/{created['id']}/disclose")
    assert disclosed.status_code == 200, disclosed.text
    result = disclosed.json()["result"]
    groups = {tuple(sorted(g["key"].items())): g["value"] for g in result["groups"]}
    assert set(groups) == {(("region", "eu"),), (("region", "us"),)}
    # clipped true counts: us = min(3 alice -> 2) + 1 bob = 3, eu = 1
    assert abs(groups[(("region", "us"),)] - 3.0) < 10.0   # noisy but sane
    assert abs(groups[(("region", "eu"),)] - 1.0) < 10.0

    after = get_policy(client, policy)
    assert after["epsilon_reserved"] == 0.0
    assert after["epsilon_spent"] == 1.0

    # repeat disclosure is idempotent and reproduces identical noise
    again = client.post(f"/queries/{created['id']}/disclose")
    assert again.status_code == 200
    assert again.json()["result"] == result


def test_cancel_refunds_once_and_only_before_disclosure(client, policy):
    ds = seed_dataset(client)
    key = uniq("q")
    created = client.post("/queries", json=submit_payload(policy, key, dataset_version=ds)).json()

    cancelled = client.post(f"/queries/{created['id']}/cancel")
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "CANCELLED"
    assert cancelled.json()["refunded"] == {"epsilon": 1.0, "delta": 0.0}

    after = get_policy(client, policy)
    assert after["epsilon_reserved"] == 0.0
    assert after["epsilon_spent"] == 0.0

    second = client.post(f"/queries/{created['id']}/cancel")
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "REFUND_ALREADY_ISSUED"

    disclosed = client.post(f"/queries/{created['id']}/disclose")
    assert disclosed.status_code == 409
    assert disclosed.json()["error"]["code"] == "QUERY_CANCELLED"

    # and a disclosed query can no longer be cancelled
    key2 = uniq("q")
    created2 = client.post("/queries", json=submit_payload(policy, key2, dataset_version=ds)).json()
    assert client.post(f"/queries/{created2['id']}/disclose").status_code == 200
    late = client.post(f"/queries/{created2['id']}/cancel")
    assert late.status_code == 409
    assert late.json()["error"]["code"] == "CANCEL_WINDOW_CLOSED"


def test_budget_exceeded_conflict_and_recovery_via_cancel(client):
    resp = client.post("/policies", json={
        "name": uniq("tight"),
        "epsilon_total": 1.0,
        "delta_total": 0.0,
        "per_subject_cap": 1,
        "dimensions": ["region"],
    })
    policy = resp.json()
    ds = seed_dataset(client)

    first = client.post("/queries", json=submit_payload(policy, uniq("q"), dataset_version=ds, epsilon=0.8))
    assert first.status_code == 201

    over = client.post("/queries", json=submit_payload(policy, uniq("q"), dataset_version=ds, epsilon=0.5))
    assert over.status_code == 409
    assert over.json()["error"]["code"] == "BUDGET_EXCEEDED"

    # cancel the first reservation -> budget comes back -> retry succeeds
    assert client.post(f"/queries/{first.json()['id']}/cancel").status_code == 200
    retry = client.post("/queries", json=submit_payload(policy, uniq("q"), dataset_version=ds, epsilon=0.9))
    assert retry.status_code == 201


def test_expected_policy_version_cas(client, policy):
    ds = seed_dataset(client)
    stale = client.post("/queries", json=submit_payload(
        policy, uniq("q"), dataset_version=ds, expected_policy_version=policy["version"] + 5))
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "VERSION_CONFLICT"

    ok = client.post("/queries", json=submit_payload(
        policy, uniq("q"), dataset_version=ds, expected_policy_version=policy["version"]))
    assert ok.status_code == 201


def test_sum_query_with_gaussian_mechanism(client):
    resp = client.post("/policies", json={
        "name": uniq("approx"),
        "epsilon_total": 5.0,
        "delta_total": 0.001,
        "per_subject_cap": 2,
        "dimensions": ["region"],
    })
    policy = resp.json()
    ds = seed_dataset(client)

    payload = submit_payload(
        policy, uniq("q"), dataset_version=ds,
        query_type="sum", measure="value",
        value_min=0, value_max=10, delta=0.0001,
    )
    created = client.post("/queries", json=payload)
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["mechanism"] == "gaussian"         # delta > 0
    assert body["sensitivity"] == 20.0             # cap 2 * bound 10

    disclosed = client.post(f"/queries/{body['id']}/disclose").json()
    groups = {tuple(sorted(g["key"].items())): g["value"] for g in disclosed["result"]["groups"]}
    assert set(groups) == {(("region", "us"),), (("region", "eu"),)}

    # verify the deterministic parts exactly via the audit trail:
    # clipped sums: us = 5 + 7 (alice capped, 100 dropped) + 3 = 15 ; eu = 10 (11 clipped)
    audit = client.get(f"/audit/policies/{policy['id']}/replay").json()
    audited = next(q for q in audit["queries"] if q["query_id"] == body["id"])
    by_region = {g["key"]["region"]: g for g in audited["groups"]}
    assert by_region["us"]["clipped_value"] == 15.0
    assert by_region["eu"]["clipped_value"] == 10.0
    for g in by_region.values():
        assert g["noisy_value"] == g["clipped_value"] + g["noise"]
        # public disclosure shows exactly the audited noisy value
        assert groups[(("region", g["key"]["region"]),)] == g["noisy_value"]


def test_delta_rejected_when_policy_is_pure_dp(client, policy):
    resp = client.post("/queries", json=submit_payload(policy, uniq("q"), delta=0.001))
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "DELTA_NOT_ALLOWED"


def test_unknown_dimension_rejected(client, policy):
    resp = client.post("/queries", json=submit_payload(policy, uniq("q"), group_by=["country"]))
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "DIMENSION_NOT_ALLOWED"


def test_audit_replay_versions_and_indeterminate_states(client, policy):
    ds = seed_dataset(client)
    # q1: disclosed, q2: cancelled, q3: left reserved (indeterminate)
    q1 = client.post("/queries", json=submit_payload(policy, uniq("q1"), dataset_version=ds)).json()
    q2 = client.post("/queries", json=submit_payload(policy, uniq("q2"), dataset_version=ds)).json()
    q3 = client.post("/queries", json=submit_payload(policy, uniq("q3"), dataset_version=ds)).json()
    client.post(f"/queries/{q1['id']}/disclose")
    client.post(f"/queries/{q2['id']}/cancel")

    replay = client.get(f"/audit/policies/{policy['id']}/replay")
    assert replay.status_code == 200, replay.text
    body = replay.json()

    assert body["chain"]["verified"] is True
    assert body["budget"]["reconstruction_consistent"] is True
    assert body["budget"]["epsilon_spent"] == 1.0
    assert body["budget"]["epsilon_reserved"] == 1.0   # q3 still reserved

    seqs = [e["seq"] for e in body["entries"]]
    assert seqs == sorted(seqs)                        # stable ordering
    types = [e["entry_type"] for e in body["entries"]]
    assert types == ["RESERVE", "RESERVE", "RESERVE", "DISCLOSE", "CANCEL"]

    outcomes = {q["query_id"]: q for q in body["queries"]}
    assert outcomes[q1["id"]]["outcome"] == "DISCLOSED"
    assert outcomes[q1["id"]]["determinate"] is True
    assert outcomes[q2["id"]]["outcome"] == "CANCELLED"
    assert outcomes[q3["id"]]["outcome"] == "INDETERMINATE"
    assert outcomes[q3["id"]]["determinate"] is False

    # clipping detail is part of the audit record, sorted by subject
    subjects = outcomes[q1["id"]]["clipping"]["subjects"]
    assert [s["subject_id"] for s in subjects] == ["alice", "bob", "carol"]
    alice = subjects[0]
    assert alice["contributed"] == 3 and alice["kept"] == 2 and alice["dropped"] == 1

    # replay pinned at the version right after q1's reservation:
    # q1's disclosure is not visible yet -> outcome indeterminate at horizon
    v_after_q1_reserve = q1["policy_version"]
    pinned = client.get(
        f"/audit/policies/{policy['id']}/replay?to_version={v_after_q1_reserve}")
    assert pinned.status_code == 200
    pinned_outcomes = {q["query_id"]: q for q in pinned.json()["queries"]}
    assert pinned_outcomes[q1["id"]]["outcome"] == "INDETERMINATE"
    assert pinned_outcomes[q1["id"]]["later_events_beyond_replay"] is True
    assert q2["id"] not in pinned_outcomes
