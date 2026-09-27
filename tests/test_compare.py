"""End-to-end tests of immutable seal-revision comparisons (diff proofs)."""
from __future__ import annotations

import concurrent.futures
import json
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text

from app import privacy
from app.db import SessionLocal

from .conftest import uniq, upload

VERIFY_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify_diff.py"


@pytest.fixture(autouse=True)
def clean_db():
    """Seals, comparisons and tombstones are global by design; give each test
    a clean slate so diffs, counts and hashes are exact."""
    with SessionLocal() as db:
        db.execute(text(
            "TRUNCATE budget_ledger, queries, erasure_tombstones, records, "
            "policies, version_seals, seal_revisions, seal_comparisons "
            "RESTART IDENTITY CASCADE"
        ))
        db.commit()
    yield


def seed_version(client, records):
    """Upload records to a fresh dataset version and seal it. Returns
    (dataset_version, seal_body)."""
    dataset_version = uuid.uuid4().int % 1_000_000_000
    upload(client, dataset_version, records)
    resp = client.post("/seals", json={
        "idempotency_key": uniq("seal"),
        "dataset_version": dataset_version,
    })
    assert resp.status_code == 201, resp.text
    return dataset_version, resp.json()


def seed_two_seals(client):
    """Two sealed versions with a known diff between them.

    v1: r1 alice(us,5)  r2 alice(us,7)  r3 bob(eu,3)   r4 carol(eu,11)
    v2: r2 alice(us,7)  r3 bob(eu,9)    r4 dave(us,2)  r5 erin(eu,1)
    => added r5; removed r1; changed r3 (attributes), r4 (subject+attributes);
       unchanged r2.
    """
    suffix = uuid.uuid4().hex[:10]
    alice, bob, carol = f"alice-{suffix}", f"bob-{suffix}", f"carol-{suffix}"
    dave, erin = f"dave-{suffix}", f"erin-{suffix}"
    _, seal1 = seed_version(client, [
        {"record_key": "r1", "subject_id": alice, "attributes": {"region": "us", "value": 5}},
        {"record_key": "r2", "subject_id": alice, "attributes": {"region": "us", "value": 7}},
        {"record_key": "r3", "subject_id": bob, "attributes": {"region": "eu", "value": 3}},
        {"record_key": "r4", "subject_id": carol, "attributes": {"region": "eu", "value": 11}},
    ])
    _, seal2 = seed_version(client, [
        {"record_key": "r2", "subject_id": alice, "attributes": {"region": "us", "value": 7}},
        {"record_key": "r3", "subject_id": bob, "attributes": {"region": "eu", "value": 9}},
        {"record_key": "r4", "subject_id": dave, "attributes": {"region": "us", "value": 2}},
        {"record_key": "r5", "subject_id": erin, "attributes": {"region": "eu", "value": 1}},
    ])
    subjects = {"alice": alice, "bob": bob, "carol": carol, "dave": dave, "erin": erin}
    return seal1, seal2, subjects


def compare(client, key, left, right):
    return client.post("/seals/compare", json={
        "idempotency_key": key,
        "left": left,
        "right": right,
    })


def ref(seal_body, revision_seq=0):
    return {"seal_id": seal_body["seal_id"], "revision_seq": revision_seq}


def run_verifier(doc):
    return subprocess.run(
        [sys.executable, str(VERIFY_SCRIPT), "-"],
        input=json.dumps(doc), capture_output=True, text=True)


# ---------------------------------------------------------------------------
# The diff itself
# ---------------------------------------------------------------------------
def test_compare_two_seals_produces_canonical_sorted_diff(client):
    seal1, seal2, subjects = seed_two_seals(client)

    resp = compare(client, uniq("cmp"), ref(seal1), ref(seal2))
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["verification"] == "VERIFIED"
    assert body["hash_version"] == "v1"
    assert len(body["diff_hash"]) == 64

    diff = body["diff"]
    # added / removed / changed, each stably sorted by record_key
    assert [e["record_key"] for e in diff["added"]] == ["r5"]
    assert diff["added"][0]["leaf"]["subject_hash"] == \
        privacy.erasure_subject_hash(subjects["erin"])
    assert [e["record_key"] for e in diff["removed"]] == ["r1"]
    assert diff["removed"][0]["leaf"]["attributes"] == {"region": "us", "value": 5}
    assert [e["record_key"] for e in diff["changed"]] == ["r3", "r4"]
    r3, r4 = diff["changed"]
    assert r3["changes"] == ["attributes"]            # same subject, new value
    assert r3["from"]["attributes"]["value"] == 3
    assert r3["to"]["attributes"]["value"] == 9
    assert r3["from"]["subject_hash"] == r3["to"]["subject_hash"]
    assert r4["changes"] == ["subject_hash", "attributes"]
    assert r4["from"]["subject_hash"] == privacy.erasure_subject_hash(subjects["carol"])
    assert r4["to"]["subject_hash"] == privacy.erasure_subject_hash(subjects["dave"])
    assert diff["counts"] == {"added": 1, "removed": 1, "changed": 2, "unchanged": 1}

    # both ends carry the committed roots / revision hashes, and the material
    # re-verifies in-process and offline
    assert body["left"]["root"] == seal1["root"]
    assert body["right"]["root"] == seal2["root"]
    assert body["left"]["revision_hash"] == seal1["revision_hash"]
    assert body["right"]["revision_hash"] == seal2["revision_hash"]
    assert "OK comparison" in privacy.verify_comparison(body)
    proc = run_verifier(body)
    assert proc.returncode == 0, proc.stderr
    assert "+1/-1/~2" in proc.stdout

    # raw subject identifiers never appear anywhere in the comparison
    for raw in subjects.values():
        assert raw not in json.dumps(body)


def test_compare_is_idempotent_and_conflicts(client):
    seal1, seal2, _ = seed_two_seals(client)
    key = uniq("cmp")

    first = compare(client, key, ref(seal1), ref(seal2))
    assert first.status_code == 201
    replay = compare(client, key, ref(seal1), ref(seal2))
    assert replay.status_code == 200
    assert replay.json() == first.json()

    # same key, different request -> 409 (swapped sides are a different request)
    conflict = compare(client, key, ref(seal2), ref(seal1))
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"
    conflict = compare(client, key, ref(seal1), ref(seal1))
    assert conflict.status_code == 409

    # a different key for the same pair creates its own comparison row
    other = compare(client, uniq("cmp"), ref(seal1), ref(seal2))
    assert other.status_code == 201
    assert other.json()["comparison_id"] != first.json()["comparison_id"]
    assert other.json()["diff_hash"] == first.json()["diff_hash"]  # deterministic

    # GET returns exactly the same material
    fetched = client.get(f"/seals/comparisons/{first.json()['comparison_id']}")
    assert fetched.status_code == 200
    assert fetched.json() == first.json()
    assert run_verifier(fetched.json()).returncode == 0


def test_compare_unknown_resources_are_404(client):
    seal1, seal2, _ = seed_two_seals(client)
    missing = str(uuid.uuid4())

    resp = compare(client, uniq("cmp"), {"seal_id": missing, "revision_seq": 0}, ref(seal2))
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "SEAL_NOT_FOUND"

    resp = compare(client, uniq("cmp"), ref(seal1), {"seal_id": seal2["seal_id"], "revision_seq": 9})
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "SEAL_REVISION_NOT_FOUND"

    resp = client.get(f"/seals/comparisons/{missing}")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "COMPARISON_NOT_FOUND"


def test_compare_refuses_unverified_revisions(client):
    seal1, seal2, _ = seed_two_seals(client)

    # smuggle a corrupted revision into the chain (INSERT is allowed; the
    # immutability triggers only forbid UPDATE/DELETE): its stored root does
    # not match its manifest, so it can never verify
    with SessionLocal() as db:
        db.execute(text("""
            INSERT INTO seal_revisions
                (seal_id, revision_seq, kind, prev_revision_hash, root,
                 record_count, manifest, revision_hash, created_at)
            VALUES (:seal_id, 7, 'seal', :prev, :root, 1,
                    CAST(:manifest AS jsonb), :rhash, now())
        """), {
            "seal_id": seal2["seal_id"],
            "prev": "0" * 64,
            "root": "1" * 64,
            "manifest": json.dumps({"hash_version": "v1", "leaves": [
                {"record_key": "x", "subject_hash": "2" * 64, "attributes": {}}]}),
            "rhash": "3" * 64,
        })
        db.commit()

    resp = compare(client, uniq("cmp"), ref(seal1), ref(seal2, revision_seq=7))
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "SEAL_REVISION_UNVERIFIED"
    assert resp.json()["error"]["details"]["side"] == "right"

    resp = compare(client, uniq("cmp"), ref(seal2, revision_seq=7), ref(seal1))
    assert resp.status_code == 409
    assert resp.json()["error"]["details"]["side"] == "left"


def test_compare_across_erasure_revisions(client):
    """Comparing revision #0 with the post-erasure revision shows exactly the
    erased subject's leaves as removed — still without leaking identifiers."""
    ds = uuid.uuid4().int % 1_000_000_000
    suffix = uuid.uuid4().hex[:10]
    alice, bob = f"alice-{suffix}", f"bob-{suffix}"
    upload(client, ds, [
        {"record_key": "r1", "subject_id": alice, "attributes": {"region": "us"}},
        {"record_key": "r2", "subject_id": alice, "attributes": {"region": "us"}},
        {"record_key": "r3", "subject_id": bob, "attributes": {"region": "eu"}},
    ])
    seal_body = client.post("/seals", json={
        "idempotency_key": uniq("seal"), "dataset_version": ds}).json()
    tomb = client.post("/erasures", json={
        "idempotency_key": uniq("erase"), "subject_id": alice,
        "until_dataset_version": ds}).json()
    assert tomb["seal_revisions"][0]["revision_seq"] == 1

    resp = compare(client, uniq("cmp"), ref(seal_body, 0), ref(seal_body, 1))
    assert resp.status_code == 201, resp.text
    body = resp.json()
    diff = body["diff"]
    assert [e["record_key"] for e in diff["removed"]] == ["r1", "r2"]
    assert diff["added"] == [] and diff["changed"] == []
    assert diff["counts"] == {"added": 0, "removed": 2, "changed": 0, "unchanged": 1}
    assert body["left"]["kind"] == "seal"
    assert body["right"]["kind"] == "erasure"
    assert body["right"]["subject_hash"] == privacy.erasure_subject_hash(alice)
    assert alice not in json.dumps(body) and bob not in json.dumps(body)
    assert run_verifier(body).returncode == 0

    # identical revisions diff to empty
    same = compare(client, uniq("cmp"), ref(seal_body, 1), ref(seal_body, 1))
    assert same.status_code == 201
    assert same.json()["diff"]["counts"] == {
        "added": 0, "removed": 0, "changed": 0, "unchanged": 1}
    assert run_verifier(same.json()).returncode == 0


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------
def test_concurrent_duplicate_compares_are_idempotent(client):
    seal1, seal2, _ = seed_two_seals(client)
    key = uniq("cmp")

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(
            lambda _: compare(client, key, ref(seal1), ref(seal2)), range(4)))

    statuses = sorted(r.status_code for r in responses)
    assert statuses == [200, 200, 200, 201]
    ids = {r.json()["comparison_id"] for r in responses}
    assert len(ids) == 1
    hashes = {r.json()["diff_hash"] for r in responses}
    assert len(hashes) == 1
    with SessionLocal() as db:
        count = db.execute(text("SELECT count(*) FROM seal_comparisons")).scalar_one()
    assert count == 1


def test_concurrent_conflicting_compares_one_winner(client):
    seal1, seal2, _ = seed_two_seals(client)
    key = uniq("cmp")

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(compare, client, key, ref(seal1), ref(seal2))
        f2 = pool.submit(compare, client, key, ref(seal2), ref(seal1))
        statuses = sorted([f1.result().status_code, f2.result().status_code])

    assert statuses == [201, 409]
    with SessionLocal() as db:
        count = db.execute(text("SELECT count(*) FROM seal_comparisons")).scalar_one()
    assert count == 1


# ---------------------------------------------------------------------------
# Offline verification
# ---------------------------------------------------------------------------
def test_offline_verifier_detects_tampering(client):
    seal1, seal2, _ = seed_two_seals(client)
    body = compare(client, uniq("cmp"), ref(seal1), ref(seal2)).json()
    assert run_verifier(body).returncode == 0

    # 改键: rename a record_key inside the diff -> recomputed diff differs
    tampered = json.loads(json.dumps(body))
    tampered["diff"]["removed"][0]["record_key"] = "r9"
    assert run_verifier(tampered).returncode == 1

    # 改键: rename a key inside the committed leaves -> root no longer folds
    tampered = json.loads(json.dumps(body))
    tampered["left"]["leaves"][0]["record_key"] = "r9"
    assert run_verifier(tampered).returncode == 1

    # 改叶: alter a leaf inside the diff -> recomputed diff differs
    tampered = json.loads(json.dumps(body))
    tampered["diff"]["added"][0]["leaf"]["attributes"]["value"] = 999
    assert run_verifier(tampered).returncode == 1

    # 改叶: alter a committed leaf -> Merkle root mismatch
    tampered = json.loads(json.dumps(body))
    tampered["right"]["leaves"][0]["attributes"]["value"] = 999
    assert run_verifier(tampered).returncode == 1

    # 漏项: drop a diff entry (counts untouched) -> recomputed diff differs
    tampered = json.loads(json.dumps(body))
    tampered["diff"]["changed"] = tampered["diff"]["changed"][:1]
    assert run_verifier(tampered).returncode == 1

    # 漏项: drop a committed leaf -> record_count / root mismatch
    tampered = json.loads(json.dumps(body))
    tampered["left"]["leaves"] = tampered["left"]["leaves"][1:]
    assert run_verifier(tampered).returncode == 1

    # 跨根材料: swap the two sides' leaves while keeping roots -> fold fails
    tampered = json.loads(json.dumps(body))
    tampered["left"]["leaves"], tampered["right"]["leaves"] = \
        tampered["right"]["leaves"], tampered["left"]["leaves"]
    assert run_verifier(tampered).returncode == 1

    # 跨根材料: replace one side's leaves with another seal's manifest
    _, seal3 = seed_version(client, [
        {"record_key": "z1", "subject_id": uniq("zed"), "attributes": {}}])
    other = compare(client, uniq("cmp"), ref(seal3), ref(seal3)).json()
    tampered = json.loads(json.dumps(body))
    tampered["left"]["leaves"] = other["left"]["leaves"]
    tampered["left"]["record_count"] = len(other["left"]["leaves"])
    assert run_verifier(tampered).returncode == 1

    # the diff hash binds roots, revision hashes and the diff list
    tampered = json.loads(json.dumps(body))
    tampered["diff_hash"] = "0" * 64
    assert run_verifier(tampered).returncode == 1
    tampered = json.loads(json.dumps(body))
    tampered["left"]["revision_hash"] = "0" * 64
    assert run_verifier(tampered).returncode == 1
    tampered = json.loads(json.dumps(body))
    tampered["right"]["root"] = privacy.EMPTY_ROOT
    assert run_verifier(tampered).returncode == 1

    # malformed / missing sections are rejected, not crashed on
    assert run_verifier({"left": body["left"]}).returncode == 1
    assert run_verifier({}).returncode == 1


def test_comparison_material_is_append_only(client):
    """The comparison table is immutable at the storage layer, like seals."""
    seal1, seal2, _ = seed_two_seals(client)
    body = compare(client, uniq("cmp"), ref(seal1), ref(seal2)).json()

    with SessionLocal() as db:
        with pytest.raises(Exception):
            db.execute(text(
                "UPDATE seal_comparisons SET diff_hash = 'x' WHERE id = :id"),
                {"id": body["comparison_id"]})
            db.commit()
        db.rollback()
        with pytest.raises(Exception):
            db.execute(text(
                "DELETE FROM seal_comparisons WHERE id = :id"),
                {"id": body["comparison_id"]})
            db.commit()
        db.rollback()

    fetched = client.get(f"/seals/comparisons/{body['comparison_id']}")
    assert fetched.status_code == 200
    assert fetched.json() == body
