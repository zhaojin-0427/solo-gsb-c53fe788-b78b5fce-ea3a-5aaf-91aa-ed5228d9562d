"""End-to-end tests of version seals, record proofs and the erasure
revision chain."""
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

VERIFY_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify_proof.py"


@pytest.fixture(autouse=True)
def clean_db():
    """Seals and tombstones are global by design; give each test a clean
    slate so roots, counts and chain contents are exact."""
    with SessionLocal() as db:
        db.execute(text(
            "TRUNCATE budget_ledger, queries, erasure_tombstones, records, "
            "policies, version_seals, seal_revisions RESTART IDENTITY CASCADE"
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
    """Seed a 3-subject dataset with per-test unique subject ids and record
    keys uploaded out of order (manifests must re-sort them canonically).

    Returns (dataset_version, alice, bob, carol).
    """
    dataset_version = uuid.uuid4().int % 1_000_000_000
    suffix = uuid.uuid4().hex[:10]
    alice, bob, carol = f"alice-{suffix}", f"bob-{suffix}", f"carol-{suffix}"
    upload(client, dataset_version, [
        {"record_key": "r3", "subject_id": alice, "attributes": {"region": "us", "value": 100}},
        {"record_key": "r1", "subject_id": alice, "attributes": {"region": "us", "value": 5}},
        {"record_key": "r2", "subject_id": alice, "attributes": {"region": "us", "value": 7}},
        {"record_key": "r4", "subject_id": bob, "attributes": {"region": "us", "value": 3}},
        {"record_key": "r5", "subject_id": carol, "attributes": {"region": "eu", "value": 11}},
    ])
    return dataset_version, alice, bob, carol


def seal(client, key, dataset_version):
    return client.post("/seals", json={
        "idempotency_key": key,
        "dataset_version": dataset_version,
    })


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


def get_seal(client, seal_id):
    resp = client.get(f"/seals/{seal_id}")
    assert resp.status_code == 200, resp.text
    return resp.json()


def get_manifest(client, seal_id, revision=None):
    suffix = f"?revision={revision}" if revision is not None else ""
    resp = client.get(f"/seals/{seal_id}/manifest{suffix}")
    assert resp.status_code == 200, resp.text
    return resp.json()


def get_proof(client, seal_id, record_key, revision=None):
    suffix = f"?revision={revision}" if revision is not None else ""
    resp = client.get(f"/seals/{seal_id}/records/{record_key}/proof{suffix}")
    assert resp.status_code == 200, resp.text
    return resp.json()


def recompute_root(manifest_doc):
    leaves = manifest_doc["manifest"]["leaves"]
    return privacy.merkle_root([privacy.leaf_hash(leaf) for leaf in leaves])


# ---------------------------------------------------------------------------
# Sealing
# ---------------------------------------------------------------------------
def test_seal_freezes_uploads_and_manifest_is_canonical(client):
    ds, alice, bob, carol = seed(client)

    resp = seal(client, uniq("seal"), ds)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["dataset_version"] == ds
    assert body["revision_seq"] == 0
    assert body["record_count"] == 5
    assert len(body["root"]) == 64
    assert len(body["revision_hash"]) == 64

    # the version is frozen: later uploads are rejected
    frozen = client.post("/records", json={
        "dataset_version": ds,
        "records": [{"record_key": uniq("r"), "subject_id": uniq("dave"),
                     "attributes": {"region": "us"}}],
    })
    assert frozen.status_code == 409
    assert frozen.json()["error"]["code"] == "VERSION_SEALED"
    assert frozen.json()["error"]["details"]["seal_id"] == body["seal_id"]

    # other versions are unaffected
    ok = client.post("/records", json={
        "dataset_version": ds + 1,
        "records": [{"record_key": uniq("r"), "subject_id": uniq("dave"),
                     "attributes": {"region": "us"}}],
    })
    assert ok.status_code == 201

    # manifest: canonical leaves sorted by record_key, subject hashes only
    manifest = get_manifest(client, body["seal_id"])
    assert manifest["revision_seq"] == 0
    assert manifest["root"] == body["root"]
    assert manifest["hash_version"] == "v1"
    leaves = manifest["manifest"]["leaves"]
    assert [leaf["record_key"] for leaf in leaves] == ["r1", "r2", "r3", "r4", "r5"]
    assert leaves[0]["subject_hash"] == privacy.erasure_subject_hash(alice)
    assert leaves[3]["subject_hash"] == privacy.erasure_subject_hash(bob)
    assert leaves[3]["attributes"] == {"region": "us", "value": 3}
    assert recompute_root(manifest) == body["root"]
    assert manifest["verification"]["verification"] == "VERIFIED"

    # raw subject identifiers never appear in any seal material
    seal_doc = get_seal(client, body["seal_id"])
    for raw in (alice, bob, carol):
        assert raw not in json.dumps(manifest)
        assert raw not in json.dumps(seal_doc)
    assert [r["revision_seq"] for r in seal_doc["revisions"]] == [0]
    assert seal_doc["revisions"][0]["verification"] == "VERIFIED"
    assert seal_doc["latest_revision"]["root"] == body["root"]

    # the seal list view agrees
    listing = client.get("/seals").json()["seals"]
    entry = next(s for s in listing if s["seal_id"] == body["seal_id"])
    assert entry["latest_revision"]["root"] == body["root"]
    assert entry["latest_revision"]["verification"] == "VERIFIED"


def test_seal_empty_version_rejected(client):
    resp = seal(client, uniq("seal"), uuid.uuid4().int % 1_000_000_000)
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "VERSION_EMPTY"
    # nothing was sealed
    assert client.get("/seals").json()["seals"] == []


def test_seal_is_idempotent_and_conflicts(client):
    ds, _alice, _bob, _carol = seed(client)
    key = uniq("seal")
    first = seal(client, key, ds)
    assert first.status_code == 201

    replay = seal(client, key, ds)
    assert replay.status_code == 200
    assert replay.json() == first.json()

    # same key, different request -> 409
    conflict = seal(client, key, ds + 1)
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"

    # different key, same version -> already sealed
    again = seal(client, uniq("seal"), ds)
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "VERSION_SEALED"
    assert again.json()["error"]["details"]["seal_id"] == first.json()["seal_id"]


def test_seal_unknown_ids_are_404(client):
    missing = uuid.uuid4()
    assert client.get(f"/seals/{missing}").status_code == 404
    assert client.get(f"/seals/{missing}").json()["error"]["code"] == "SEAL_NOT_FOUND"
    assert client.get(f"/seals/{missing}/manifest").status_code == 404
    assert client.get(f"/seals/{missing}/records/r1/proof").status_code == 404


# ---------------------------------------------------------------------------
# Inclusion / non-inclusion proofs
# ---------------------------------------------------------------------------
def test_record_inclusion_and_non_inclusion_proofs(client):
    ds, alice, _bob, _carol = seed(client)
    seal_id = seal(client, uniq("seal"), ds).json()["seal_id"]

    proof = get_proof(client, seal_id, "r1")
    assert proof["type"] == "inclusion"
    assert proof["record_key"] == "r1"
    assert proof["record_keys"] == ["r1", "r2", "r3", "r4", "r5"]
    assert proof["leaf_index"] == 0
    assert proof["leaf"]["record_key"] == "r1"
    assert proof["leaf"]["subject_hash"] == privacy.erasure_subject_hash(alice)
    # the API material verifies with the canonical key-to-leaf binding check
    assert "inclusion" in privacy.verify_record_proof(proof)
    # the Merkle path folds to the committed root
    assert privacy.verify_merkle_proof(proof["leaf_hash"], proof["path"], proof["root"])
    # ... and the leaf hash is the one committed in the manifest
    assert proof["leaf_hash"] == privacy.leaf_hash(proof["leaf"])
    assert proof["leaf_hashes"][proof["leaf_index"]] == proof["leaf_hash"]
    assert privacy.merkle_root(proof["leaf_hashes"]) == proof["root"]
    # the bound leaves are the canonical manifest leaves
    assert [leaf["record_key"] for leaf in proof["leaves"]] == proof["record_keys"]
    assert [privacy.leaf_hash(leaf) for leaf in proof["leaves"]] == proof["leaf_hashes"]
    # a tampered path does not verify
    assert not privacy.verify_merkle_proof(proof["leaf_hash"], proof["path"][:-1], proof["root"])

    absent = get_proof(client, seal_id, "no-such-key")
    assert absent["type"] == "non_inclusion"
    assert "no-such-key" not in absent["record_keys"]
    assert absent["root"] == proof["root"]
    assert privacy.merkle_root(absent["leaf_hashes"]) == absent["root"]
    # every key is bound to its committed leaf, and the revision hash anchors it
    assert [leaf["record_key"] for leaf in absent["leaves"]] == absent["record_keys"]
    assert "non-inclusion" in privacy.verify_record_proof(absent)


def test_non_inclusion_cannot_be_forged_under_the_real_root(client):
    """The bug: a non-inclusion proof for a key the sealed revision actually
    contains used to verify, because record_keys and leaf_hashes were
    independent lists. Keeping the real root/hashes but hiding the key in the
    key list must now fail both the app check and the offline verifier — and
    every tamper variant must fail as well."""
    ds, _alice, _bob, _carol = seed(client)
    seal_id = seal(client, uniq("seal"), ds).json()["seal_id"]

    # honest material: r1 really is in revision 0
    honest = get_proof(client, seal_id, "r1", revision=0)
    assert honest["type"] == "inclusion"

    # the attack document: same root / leaf hashes, but presented as absence
    forged = json.loads(json.dumps(honest))
    forged["type"] = "non_inclusion"
    forged["record_key"] = "r1"
    forged["record_keys"] = [k for k in forged["record_keys"] if k != "r1"]
    with pytest.raises(privacy.InvalidProof):
        privacy.verify_record_proof(forged)
    assert run_verifier("proof", forged).returncode == 1

    # aligning record_count with the shortened list does not help either
    forged_count = json.loads(json.dumps(forged))
    forged_count["record_count"] = len(forged_count["record_keys"])
    with pytest.raises(privacy.InvalidProof):
        privacy.verify_record_proof(forged_count)
    assert run_verifier("proof", forged_count).returncode == 1

    # dropping the parallel key list (leaves still carry the bound keys)
    without_keys = json.loads(json.dumps(forged))
    without_keys.pop("record_keys")
    with pytest.raises(privacy.InvalidProof):
        privacy.verify_record_proof(without_keys)
    assert run_verifier("proof", without_keys).returncode == 1

    # renaming the key inside the bound leaves breaks the committed root
    renamed = json.loads(json.dumps(honest))
    renamed["type"] = "non_inclusion"
    renamed["leaves"][0] = {**renamed["leaves"][0], "record_key": "r9"}
    renamed["record_keys"][0] = "r9"
    with pytest.raises(privacy.InvalidProof):
        privacy.verify_record_proof(renamed)
    assert run_verifier("proof", renamed).returncode == 1

    # reordering the bound leaves changes the derived root
    reordered = json.loads(json.dumps(honest))
    reordered["type"] = "non_inclusion"
    reordered["leaves"] = list(reversed(reordered["leaves"]))
    with pytest.raises(privacy.InvalidProof):
        privacy.verify_record_proof(reordered)
    assert run_verifier("proof", reordered).returncode == 1

    # swapping a leaf hash independently of the leaves is detected too
    swapped = json.loads(json.dumps(honest))
    swapped["type"] = "non_inclusion"
    swapped["leaf_hashes"][0], swapped["leaf_hashes"][1] = \
        swapped["leaf_hashes"][1], swapped["leaf_hashes"][0]
    with pytest.raises(privacy.InvalidProof):
        privacy.verify_record_proof(swapped)
    assert run_verifier("proof", swapped).returncode == 1

    # old (pre-binding) non-inclusion material is rejected outright ...
    legacy = json.loads(json.dumps(get_proof(client, seal_id, "r1")))
    legacy["type"] = "non_inclusion"
    legacy.pop("leaves")
    assert run_verifier("proof", legacy).returncode == 1
    # ... while legacy inclusion material still verifies
    legacy_inc = json.loads(json.dumps(honest))
    legacy_inc.pop("leaves")
    assert run_verifier("proof", legacy_inc).returncode == 0


# ---------------------------------------------------------------------------
# Seal-bound queries
# ---------------------------------------------------------------------------
def test_bound_query_uses_manifest_root_and_seed(client):
    policy = make_policy(client)
    ds, alice, bob, carol = seed(client)
    seal_body = seal(client, uniq("seal"), ds).json()
    seal_id, root = seal_body["seal_id"], seal_body["root"]

    key = uniq("q")
    resp = submit(client, policy, key, ds, seal_id=seal_id)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["seal"] == {"seal_id": seal_id, "revision_seq": 0, "root": root}

    # the audit view verifies the query against its pinned root and seed
    audit = client.get(f"/audit/policies/{policy['id']}/replay").json()
    view = next(q for q in audit["queries"] if q["query_id"] == body["id"])
    assert view["seal"]["verification"] == "VERIFIED"
    assert view["seal"]["root"] == root
    assert view["seal"]["checks"]["noise_seed"] is True
    expected_seed = privacy.derive_noise_seed_bound(key, view["request_digest"], root)
    assert view["noise"]["seed"] == expected_seed
    # bound snapshots hold pseudonymous subject hashes, never raw identifiers
    subjects = view["clipping"]["subjects"]
    assert [s["subject_id"] for s in subjects] == sorted(
        privacy.erasure_subject_hash(s) for s in (alice, bob, carol))
    assert view["clipping"]["seal"]["root"] == root
    assert alice not in json.dumps(view)

    # disclosure works as usual and the noisy result stays reproducible
    disclosed = client.post(f"/queries/{body['id']}/disclose")
    assert disclosed.status_code == 200
    groups = {tuple(sorted(g["key"].items())): g["value"]
              for g in disclosed.json()["result"]["groups"]}
    assert set(groups) == {(("region", "us"),), (("region", "eu"),)}

    # an unbound query on the same version keeps the original semantics:
    # live-table snapshot with raw subject ids and the unbound seed domain
    plain = submit(client, policy, uniq("q"), ds)
    assert plain.status_code == 201
    assert "seal" not in plain.json()
    audit2 = client.get(f"/audit/policies/{policy['id']}/replay").json()
    plain_view = next(q for q in audit2["queries"] if q["query_id"] == plain.json()["id"])
    assert "seal" not in plain_view
    assert [s["subject_id"] for s in plain_view["clipping"]["subjects"]] == \
        sorted([alice, bob, carol])
    assert plain_view["noise"]["seed"] == privacy.derive_noise_seed(
        plain_view["idempotency_key"], plain_view["request_digest"])


def test_bound_query_validates_seal_and_version(client):
    policy = make_policy(client)
    ds, _alice, _bob, _carol = seed(client)
    other_ds, *_ = seed(client)
    seal_id = seal(client, uniq("seal"), ds).json()["seal_id"]

    # seal covers a different dataset version
    mismatch = submit(client, policy, uniq("q"), other_ds, seal_id=seal_id)
    assert mismatch.status_code == 422
    assert mismatch.json()["error"]["code"] == "SEAL_VERSION_MISMATCH"

    # unknown seal
    missing = submit(client, policy, uniq("q"), ds, seal_id=str(uuid.uuid4()))
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "SEAL_NOT_FOUND"

    # idempotency: bound and unbound requests under the same key conflict
    key = uniq("q")
    assert submit(client, policy, key, ds, seal_id=seal_id).status_code == 201
    replay = submit(client, policy, key, ds, seal_id=seal_id)
    assert replay.status_code == 200                      # same digest: retry
    conflict = submit(client, policy, key, ds)            # dropping the binding
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"


# ---------------------------------------------------------------------------
# Erasure: revision chain instead of rewriting manifests
# ---------------------------------------------------------------------------
def test_erasure_appends_revision_chain_and_keeps_old_root_verifiable(client):
    policy = make_policy(client)
    ds, alice, bob, carol = seed(client)
    seal_body = seal(client, uniq("seal"), ds).json()
    seal_id, root0 = seal_body["seal_id"], seal_body["root"]

    # one bound and one unbound query before the erasure
    q_bound = submit(client, policy, uniq("q"), ds, seal_id=seal_id).json()
    q_plain = submit(client, policy, uniq("q"), ds).json()

    resp = erase(client, uniq("erase"), alice, ds)
    assert resp.status_code == 201, resp.text
    tomb = resp.json()
    assert tomb["affected_dataset_versions"] == [ds]
    assert tomb["records_deleted"] == 3
    assert tomb["queries_invalidated"] == 2          # both RESERVED queries
    assert len(tomb["seal_revisions"]) == 1
    link = tomb["seal_revisions"][0]
    assert link["seal_id"] == seal_id
    assert link["revision_seq"] == 1
    assert link["record_count"] == 2                 # alice's 3 leaves removed
    assert link["root"] != root0
    assert link["prev_revision_hash"] == seal_body["revision_hash"]

    # the old manifest is NOT rewritten: revision 0 still commits alice's leaf
    rev0 = get_manifest(client, seal_id, revision=0)
    assert rev0["root"] == root0
    assert len(rev0["manifest"]["leaves"]) == 5
    assert rev0["verification"]["verification"] == "VERIFIED"

    # the latest revision is the scrubbed manifest, chained to revision 0
    seal_doc = get_seal(client, seal_id)
    assert [r["revision_seq"] for r in seal_doc["revisions"]] == [0, 1]
    assert all(r["verification"] == "VERIFIED" for r in seal_doc["revisions"])
    latest = seal_doc["latest_revision"]
    assert latest["root"] == link["root"]
    assert latest["kind"] == "erasure"
    assert latest["subject_hash"] == tomb["subject_hash"]
    assert latest["tombstone_id"] == tomb["tombstone_id"]
    leaves1 = get_manifest(client, seal_id)["manifest"]["leaves"]
    assert [leaf["record_key"] for leaf in leaves1] == ["r4", "r5"]
    assert {leaf["subject_hash"] for leaf in leaves1} == {
        privacy.erasure_subject_hash(bob), privacy.erasure_subject_hash(carol)}

    # proofs follow the bound revision: alice's record is provably present in
    # revision 0 and provably absent from the latest revision
    proof_old = get_proof(client, seal_id, "r1", revision=0)
    assert proof_old["type"] == "inclusion"
    assert privacy.verify_merkle_proof(proof_old["leaf_hash"], proof_old["path"], root0)
    proof_new = get_proof(client, seal_id, "r1")
    assert proof_new["type"] == "non_inclusion"
    assert proof_new["root"] == link["root"]

    # the old bound query still verifies against its original root ...
    audit = client.get(f"/audit/policies/{policy['id']}/replay").json()
    old_view = next(q for q in audit["queries"] if q["query_id"] == q_bound["id"])
    assert old_view["outcome"] == "INVALIDATED"
    assert old_view["seal"]["root"] == root0
    assert old_view["seal"]["verification"] == "VERIFIED"

    # ... while a new bound query pins the latest (scrubbed) revision and
    # computes on the erased data
    q_new = submit(client, policy, uniq("q"), ds, seal_id=seal_id)
    assert q_new.status_code == 201
    assert q_new.json()["seal"] == {"seal_id": seal_id, "revision_seq": 1,
                                    "root": link["root"]}
    audit2 = client.get(f"/audit/policies/{policy['id']}/replay").json()
    new_view = next(q for q in audit2["queries"] if q["query_id"] == q_new.json()["id"])
    assert new_view["seal"]["verification"] == "VERIFIED"
    assert new_view["clipping"]["records_in_dataset"] == 2
    assert [s["subject_id"] for s in new_view["clipping"]["subjects"]] == sorted(
        privacy.erasure_subject_hash(s) for s in (bob, carol))

    # the unbound query was invalidated exactly as before (original semantics)
    plain_view = next(q for q in audit2["queries"] if q["query_id"] == q_plain["id"])
    assert plain_view["outcome"] == "INVALIDATED"
    assert "seal" not in plain_view

    # the erasure audit view verifies the revision link and never leaks alice
    erasures = client.get("/audit/erasures")
    assert alice not in erasures.text
    entry = next(e for e in erasures.json()["erasures"]
                 if e["tombstone_id"] == tomb["tombstone_id"])
    assert entry["proof_verified"] is True
    assert len(entry["seal_revisions"]) == 1
    link_view = entry["seal_revisions"][0]
    assert link_view["verification"] == "VERIFIED"
    assert link_view["revision_hash"] == link["revision_hash"]
    assert link_view["subject_hash"] == tomb["subject_hash"]


def test_erasure_of_non_sealed_subject_appends_no_revision(client):
    ds, alice, _bob, _carol = seed(client)
    seal_body = seal(client, uniq("seal"), ds).json()
    ghost = uniq("ghost")

    tomb = erase(client, uniq("erase"), ghost, ds).json()
    assert tomb["affected_dataset_versions"] == []
    assert tomb["seal_revisions"] == []
    seal_doc = get_seal(client, seal_body["seal_id"])
    assert len(seal_doc["revisions"]) == 1            # untouched

    # erasing a subject whose records live only on OTHER versions leaves the
    # sealed manifest untouched as well (the seal's version is inside the
    # cut-off range but holds none of the subject's leaves)
    other_ds = ds + 1
    upload(client, other_ds, [
        {"record_key": "x1", "subject_id": alice,
         "attributes": {"region": "us"}}])
    tomb2 = erase(client, uniq("erase2"), alice, other_ds).json()
    assert tomb2["affected_dataset_versions"] == [ds, other_ds]
    # ds contributed a revision (alice's leaves were in the manifest) ...
    assert [link["dataset_version"] for link in tomb2["seal_revisions"]] == [ds]
    # ... and a further erasure limited to the other version touches no seal
    tomb3 = erase(client, uniq("erase3"), alice, other_ds).json()
    assert tomb3["seal_revisions"] == []              # idempotent subject-wise
    assert len(get_seal(client, seal_body["seal_id"])["revisions"]) == 2


def test_repeated_erasure_does_not_fork_the_chain(client):
    """A second erasure of the same subject (wider cut-off) finds no leaves
    to remove and appends nothing; a different subject's erasure appends one
    more revision on top of the latest."""
    ds, alice, bob, _carol = seed(client)
    seal_body = seal(client, uniq("seal"), ds).json()
    seal_id = seal_body["seal_id"]

    erase(client, uniq("erase"), alice, ds)
    again = erase(client, uniq("erase2"), alice, ds + 10).json()
    assert again["seal_revisions"] == []              # already scrubbed: no-op
    seal_doc = get_seal(client, seal_id)
    assert [r["revision_seq"] for r in seal_doc["revisions"]] == [0, 1]

    tomb_bob = erase(client, uniq("erase3"), bob, ds).json()
    assert len(tomb_bob["seal_revisions"]) == 1
    link = tomb_bob["seal_revisions"][0]
    assert link["revision_seq"] == 2
    assert link["record_count"] == 1                  # only carol's leaf remains
    seal_doc = get_seal(client, seal_id)
    assert [r["revision_seq"] for r in seal_doc["revisions"]] == [0, 1, 2]
    assert all(r["verification"] == "VERIFIED" for r in seal_doc["revisions"])
    assert seal_doc["revisions"][2]["prev_revision_hash"] == \
        seal_doc["revisions"][1]["revision_hash"]


# ---------------------------------------------------------------------------
# Concurrency: no cross-root snapshots
# ---------------------------------------------------------------------------
def test_concurrent_seal_and_upload_are_serialised(client):
    ds, alice, _bob, _carol = seed(client)
    new_record = [{"record_key": "r9", "subject_id": alice,
                   "attributes": {"region": "us"}}]

    def do_upload():
        return client.post("/records", json={"dataset_version": ds,
                                             "records": new_record})

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f_upload = pool.submit(do_upload)
        f_seal = pool.submit(seal, client, uniq("seal"), ds)
        up_resp, seal_resp = f_upload.result(), f_seal.result()

    assert seal_resp.status_code == 201
    count = seal_resp.json()["record_count"]
    if up_resp.status_code == 201:
        # upload landed first: the sealed manifest must contain the new record
        assert count == 6
        proof = get_proof(client, seal_resp.json()["seal_id"], "r9")
        assert proof["type"] == "inclusion"
    else:
        # seal landed first: the version was already frozen
        assert up_resp.status_code == 409
        assert up_resp.json()["error"]["code"] == "VERSION_SEALED"
        assert count == 5


def test_concurrent_bound_queries_and_erasure_never_span_roots(client):
    """Bound queries racing an erasure pin either the old or the new root —
    never a mixture — and every pinned root verifies afterwards."""
    policy = make_policy(client, epsilon_total=50.0)
    ds, alice, _bob, _carol = seed(client)
    seal_body = seal(client, uniq("seal"), ds).json()
    seal_id, root0 = seal_body["seal_id"], seal_body["root"]

    def do_submit(i):
        return submit(client, policy, uniq("q"), ds, seal_id=seal_id)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        f_queries = [pool.submit(do_submit, i) for i in range(4)]
        f_erase = pool.submit(erase, client, uniq("erase"), alice, ds)
        responses = [f.result() for f in f_queries]
        tomb = f_erase.result().json()

    root1 = tomb["seal_revisions"][0]["root"]
    assert root1 != root0
    roots = set()
    for resp in responses:
        assert resp.status_code == 201, resp.text
        roots.add(resp.json()["seal"]["root"])
    assert roots <= {root0, root1}                    # no cross-root snapshot

    audit = client.get(f"/audit/policies/{policy['id']}/replay").json()
    by_id = {q["query_id"]: q for q in audit["queries"]}
    for resp in responses:
        view = by_id[resp.json()["id"]]
        assert view["seal"]["verification"] == "VERIFIED"
        assert view["seal"]["root"] == resp.json()["seal"]["root"]
        # the stored snapshot is consistent with the pinned root alone
        assert view["clipping"]["seal"]["root"] == view["seal"]["root"]


def test_concurrent_seals_of_same_version_are_idempotent(client):
    ds, _alice, _bob, _carol = seed(client)
    key = uniq("seal")

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(lambda _: seal(client, key, ds), range(4)))

    statuses = sorted(r.status_code for r in responses)
    assert statuses == [200, 200, 200, 201]
    assert len({r.json()["seal_id"] for r in responses}) == 1
    assert len(client.get("/seals").json()["seals"]) == 1


# ---------------------------------------------------------------------------
# Offline verification material
# ---------------------------------------------------------------------------
def run_verifier(mode, doc):
    proc = subprocess.run(
        [sys.executable, str(VERIFY_SCRIPT), mode, "-"],
        input=json.dumps(doc), capture_output=True, text=True)
    return proc


def test_offline_verifier_accepts_api_material(client, tmp_path):
    ds, alice, _bob, _carol = seed(client)
    seal_id = seal(client, uniq("seal"), ds).json()["seal_id"]
    erase(client, uniq("erase"), alice, ds)

    # manifest mode: both revisions verify offline
    for revision in (0, 1):
        proc = run_verifier("manifest", get_manifest(client, seal_id, revision=revision))
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.startswith("OK")

    # proof mode: inclusion against revision 0, non-inclusion against latest
    proc = run_verifier("proof", get_proof(client, seal_id, "r1", revision=0))
    assert proc.returncode == 0 and "inclusion" in proc.stdout
    proc = run_verifier("proof", get_proof(client, seal_id, "r1"))
    assert proc.returncode == 0 and "non-inclusion" in proc.stdout

    # chain mode: the whole revision chain links from genesis
    proc = run_verifier("chain", get_seal(client, seal_id))
    assert proc.returncode == 0, proc.stderr
    assert "2 revision(s)" in proc.stdout


def test_offline_verifier_detects_tampering(client):
    ds, _alice, _bob, _carol = seed(client)
    seal_id = seal(client, uniq("seal"), ds).json()["seal_id"]

    manifest = get_manifest(client, seal_id)
    tampered = {**manifest, "record_count": manifest["record_count"] + 1}
    assert run_verifier("manifest", tampered).returncode == 1
    tampered = json.loads(json.dumps(manifest))
    tampered["manifest"]["leaves"][0]["attributes"]["value"] = 999
    assert run_verifier("manifest", tampered).returncode == 1

    proof = get_proof(client, seal_id, "r1")
    tampered = {**proof, "root": privacy.EMPTY_ROOT}
    assert run_verifier("proof", tampered).returncode == 1
    tampered = json.loads(json.dumps(proof))
    tampered["path"][0]["position"] = "left"
    assert run_verifier("proof", tampered).returncode == 1

    # non-inclusion material: every attack on the key/leaf binding fails
    absent = get_proof(client, seal_id, "no-such-key")
    # reorder the bound leaves -> the derived root no longer matches
    tampered = json.loads(json.dumps(absent))
    tampered["leaves"] = list(reversed(tampered["leaves"]))
    assert run_verifier("proof", tampered).returncode == 1
    # tamper with one committed leaf -> recomputed root differs
    tampered = json.loads(json.dumps(absent))
    tampered["leaves"][0]["attributes"]["value"] = 999
    assert run_verifier("proof", tampered).returncode == 1
    # forge an absence for a present key while keeping root/hashes authentic
    tampered = json.loads(json.dumps(proof))
    tampered["type"] = "non_inclusion"
    tampered["record_keys"] = [k for k in tampered["record_keys"] if k != "r1"]
    assert run_verifier("proof", tampered).returncode == 1
    # parallel key/hash lists must match the bound leaves
    tampered = json.loads(json.dumps(absent))
    tampered["leaf_hashes"][0], tampered["leaf_hashes"][1] = \
        tampered["leaf_hashes"][1], tampered["leaf_hashes"][0]
    assert run_verifier("proof", tampered).returncode == 1
    # the revision hash anchors the proof into the immutable chain
    tampered = {**absent, "revision_hash": "0" * 64}
    assert run_verifier("proof", tampered).returncode == 1

    seal_doc = get_seal(client, seal_id)
    tampered = json.loads(json.dumps(seal_doc))
    tampered["revisions"][0]["root"] = privacy.EMPTY_ROOT
    assert run_verifier("chain", tampered).returncode == 1
