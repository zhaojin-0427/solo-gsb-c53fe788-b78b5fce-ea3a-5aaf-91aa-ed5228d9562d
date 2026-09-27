"""Unit tests for the pure DP primitives (no database required)."""
from decimal import Decimal

import pytest

from app import privacy


def test_request_digest_is_stable_and_order_insensitive():
    spec_a = {"b": [2, 1], "a": {"x": 1, "y": 2}}
    spec_b = {"a": {"y": 2, "x": 1}, "b": [2, 1]}
    assert privacy.request_digest(spec_a) == privacy.request_digest(spec_b)
    assert privacy.request_digest(spec_a) != privacy.request_digest({"a": 1})


def test_noise_seed_reproducible_from_idempotency_key():
    s1 = privacy.derive_noise_seed("key-1", "digest-1")
    s2 = privacy.derive_noise_seed("key-1", "digest-1")
    s3 = privacy.derive_noise_seed("key-1", "digest-2")
    s4 = privacy.derive_noise_seed("key-2", "digest-1")
    assert s1 == s2
    assert s1 != s3 != s4


def test_erasure_hashes_are_deterministic_and_domain_separated():
    h1 = privacy.erasure_subject_hash("alice")
    assert h1 == privacy.erasure_subject_hash("alice")
    assert h1 != privacy.erasure_subject_hash("bob")
    assert h1 != privacy.sha256_hex("alice")          # domain-separated
    assert len(h1) == 64

    d1 = privacy.erasure_request_digest({"subject_hash": h1, "until_dataset_version": 3})
    assert d1 == privacy.erasure_request_digest({"until_dataset_version": 3, "subject_hash": h1})
    assert d1 != privacy.erasure_request_digest({"subject_hash": h1, "until_dataset_version": 4})

    p1 = privacy.erasure_proof_hash({"tombstone_id": 1, "subject_hash": h1})
    assert p1 == privacy.erasure_proof_hash({"subject_hash": h1, "tombstone_id": 1})
    assert p1 != privacy.erasure_proof_hash({"tombstone_id": 2, "subject_hash": h1})


# ---------------------------------------------------------------------------
# Policy parameter version hashes: immutable draft / published summary digests
# ---------------------------------------------------------------------------
def test_policy_version_spec_canonicalises_decimals_and_dimensions():
    a = privacy.policy_version_spec(Decimal("5"), Decimal("0"), 2, ["b", "a"])
    b = privacy.policy_version_spec(5.0, 0.0, 2, ["a", "b"])
    assert a == b == {
        "epsilon_total": "5.000000000000",
        "delta_total": "0.000000000000",
        "per_subject_cap": 2,
        "dimensions": ["a", "b"],
    }


def test_policy_draft_hash_is_content_addressed():
    spec = privacy.policy_version_spec(5.0, 0.0, 2, ["region"])
    h1 = privacy.policy_draft_hash(spec)
    # any one parameter changing changes the draft hash
    spec2 = privacy.policy_version_spec(5.0, 0.0, 3, ["region"])
    spec3 = privacy.policy_version_spec(5.0, 0.001, 2, ["region"])
    spec4 = privacy.policy_version_spec(6.0, 0.0, 2, ["region"])
    spec5 = privacy.policy_version_spec(5.0, 0.0, 2, ["region", "plan"])
    assert h1 == privacy.policy_draft_hash(spec)
    assert len({h1, privacy.policy_draft_hash(spec2), privacy.policy_draft_hash(spec3),
                privacy.policy_draft_hash(spec4), privacy.policy_draft_hash(spec5)}) == 5
    assert len(h1) == 64
    assert h1 != privacy.sha256_hex(privacy.canonical_json(spec))   # domain-separated


def test_policy_summary_hash_binds_identity_seq_and_draft():
    spec = privacy.policy_version_spec(5.0, 0.0, 2, ["region"])
    dh = privacy.policy_draft_hash(spec)
    s1 = privacy.policy_version_summary_hash("pol-1", 1, spec, dh)
    assert s1 == privacy.policy_version_summary_hash("pol-1", 1, spec, dh)
    # same parameters at a different policy / sequence -> different summary,
    # but the underlying draft content hash stays shared
    assert s1 != privacy.policy_version_summary_hash("pol-2", 1, spec, dh)
    assert s1 != privacy.policy_version_summary_hash("pol-1", 2, spec, dh)
    assert s1 != dh                                         # summary != draft hash
    assert len(s1) == 64


def test_policy_draft_request_digest_binds_body():
    spec = privacy.policy_version_spec(5.0, 0.0, 2, ["region"])
    d1 = privacy.policy_draft_request_digest(spec)
    spec2 = privacy.policy_version_spec(5.0, 0.0, 2, ["region", "plan"])
    assert d1 == privacy.policy_draft_request_digest(spec)
    assert d1 != privacy.policy_draft_request_digest(spec2)


def test_mechanism_selection():
    assert privacy.mechanism_for(Decimal("0")) == "laplace"
    assert privacy.mechanism_for(Decimal("0.0001")) == "gaussian"


def test_sensitivity_count_and_sum():
    assert privacy.sensitivity("count", 3, None, None) == 3.0
    assert privacy.sensitivity("sum", 2, Decimal("-5"), Decimal("10")) == 20.0


def test_noise_scales():
    assert privacy.noise_scale("laplace", 2.0, 0.5, 0.0) == 4.0
    sigma = privacy.noise_scale("gaussian", 2.0, 1.0, 1e-5)
    assert sigma > 4.0  # gaussian scale exceeds laplace scale for these params


def test_clipping_is_deterministic_and_caps_per_subject():
    rows = [
        (3, "alice", ("a3", 1.0)),
        (1, "alice", ("a1", 1.0)),
        (2, "alice", ("a2", 1.0)),
        (4, "bob", ("b1", 1.0)),
    ]
    kept, detail = privacy.clip_contributions(rows, 2)
    assert [sid for sid, _ in kept].count("alice") == 2
    assert [sid for sid, _ in kept].count("bob") == 1
    # deterministic: lowest record ids kept
    assert sorted(p[0] for _, p in kept) == ["a1", "a2", "b1"]
    alice = next(d for d in detail if d["subject_id"] == "alice")
    assert alice == {"subject_id": "alice", "contributed": 3, "kept": 2, "dropped": 1}
    # detail sorted by subject_id
    assert [d["subject_id"] for d in detail] == ["alice", "bob"]


def test_aggregate_sum_clips_values_to_bounds():
    kept = [
        ("s1", ({"region": "us"}, 50.0)),   # clipped to 10
        ("s1", ({"region": "us"}, -50.0)),  # clipped to 0
        ("s2", ({"region": "eu"}, 7.5)),
    ]
    groups = privacy.aggregate(kept, ["region"], "sum", Decimal("0"), Decimal("10"))
    assert groups == [({"region": "eu"}, 7.5), ({"region": "us"}, 10.0)]  # sorted by key


def test_apply_noise_reproducible_per_group():
    groups = [({"region": "eu"}, 5.0), ({"region": "us"}, 10.0)]
    a = privacy.apply_noise(groups, "laplace", 1.0, "seed-x")
    b = privacy.apply_noise(list(reversed(groups)), "laplace", 1.0, "seed-x")
    # same seed -> identical noise per group regardless of input order
    assert sorted(g["noisy_value"] for g in a) == sorted(g["noisy_value"] for g in b)
    c = privacy.apply_noise(groups, "laplace", 1.0, "seed-y")
    assert [g["noise"] for g in a] != [g["noise"] for g in c]
    # noisy = true + noise, groups keep stable key order
    for g in a:
        assert g["noisy_value"] == g["clipped_value"] + g["noise"]
    assert [g["key"] for g in a] == [{"region": "eu"}, {"region": "us"}]


# ---------------------------------------------------------------------------
# Seal Merkle tree (known-answer vectors — the offline verifier in
# scripts/verify_proof.py re-implements the same spec independently)
# ---------------------------------------------------------------------------
def _three_leaves():
    leaves = [
        privacy.canonical_leaf("r1", privacy.erasure_subject_hash("alice"),
                               {"region": "us", "value": 5}),
        privacy.canonical_leaf("r2", privacy.erasure_subject_hash("bob"),
                               {"region": "eu"}),
        privacy.canonical_leaf("r3", privacy.erasure_subject_hash("carol"),
                               {"region": "us"}),
    ]
    return leaves, [privacy.leaf_hash(leaf) for leaf in leaves]


def test_canonical_leaf_hashes_known_answer():
    leaves, hashes = _three_leaves()
    # leaves commit only the pseudonymous subject hash, never the identifier
    assert "alice" not in privacy.canonical_json(leaves[0])
    assert hashes == [
        "3c79d3d4e3b70786727bf98307fb97cf8f61e0b9632cf3683e663e93ca9e6ff3",
        "feb9aa8ed54a398d470d882c104492aba88eb092df23141d28c1a3a9b864c66e",
        "a7858eb0537de6ec096d49e50822089bbc8e0744d058fa26532be593221d6a80",
    ]
    # attribute key order does not change the leaf hash
    reordered = privacy.canonical_leaf("r1", privacy.erasure_subject_hash("alice"),
                                       {"value": 5, "region": "us"})
    assert privacy.leaf_hash(reordered) == hashes[0]


def test_merkle_root_known_answers():
    _leaves, hashes = _three_leaves()
    assert privacy.merkle_root([]) == privacy.EMPTY_ROOT
    assert privacy.merkle_root(hashes[:1]) == hashes[0]   # single leaf: root = leaf
    assert privacy.merkle_root(hashes[:2]) == \
        "35e8ed14ee9866b1166e722e6d18a3e7bf79b3ee6b3926ddd50d272b5cb84b7b"
    assert privacy.merkle_root(hashes) == \
        "2d81ca1bcf3034aefd727d1e7dcfad75f19403a1d6b0fffc524b4ac0e3883073"
    # order matters: a different leaf order commits to a different root
    assert privacy.merkle_root(list(reversed(hashes))) != privacy.merkle_root(hashes)


def test_merkle_proof_paths_verify_and_detect_tampering():
    _leaves, hashes = _three_leaves()
    root = privacy.merkle_root(hashes)
    for index in range(3):
        path = privacy.merkle_proof_path(hashes, index)
        assert privacy.verify_merkle_proof(hashes[index], path, root) is True
        # a tampered leaf or a tampered root must not verify
        assert privacy.verify_merkle_proof(hashes[(index + 1) % 3], path, root) is False
        assert privacy.verify_merkle_proof(hashes[index], path, privacy.EMPTY_ROOT) is False
    # known-answer path for the odd (duplicated-last) level
    assert privacy.merkle_proof_path(hashes, 2) == [
        {"position": "right",
         "hash": "a7858eb0537de6ec096d49e50822089bbc8e0744d058fa26532be593221d6a80"},
        {"position": "left",
         "hash": "35e8ed14ee9866b1166e722e6d18a3e7bf79b3ee6b3926ddd50d272b5cb84b7b"},
    ]


def test_seal_hashes_are_deterministic_and_domain_separated():
    d1 = privacy.seal_request_digest({"dataset_version": 7})
    assert d1 == privacy.seal_request_digest({"dataset_version": 7})
    assert d1 != privacy.seal_request_digest({"dataset_version": 8})

    r1 = privacy.seal_revision_hash({"seal_id": "s", "revision_seq": 0})
    assert r1 == privacy.seal_revision_hash({"revision_seq": 0, "seal_id": "s"})
    assert r1 != privacy.seal_revision_hash({"seal_id": "s", "revision_seq": 1})

    s1 = privacy.derive_noise_seed_bound("key", "digest", "root-a")
    assert s1 == privacy.derive_noise_seed_bound("key", "digest", "root-a")
    assert s1 != privacy.derive_noise_seed_bound("key", "digest", "root-b")
    # bound seeds live in a different domain than unbound seeds
    assert s1 != privacy.derive_noise_seed("key", "digest")


# ---------------------------------------------------------------------------
# Self-contained record proofs: the non-inclusion material must bind key
# names to the committed leaves, so under an unchanged root no tampering with
# the key list, ordering or leaf hashes can forge an absence assertion.
# ---------------------------------------------------------------------------
def _proof_doc(record_key="missing"):
    leaves, hashes = _three_leaves()
    root = privacy.merkle_root(hashes)
    revision = {
        "seal_id": "seal-1",
        "dataset_version": 1,
        "revision_seq": 0,
        "kind": "seal",
        "hash_version": privacy.SEAL_HASH_VERSION,
        "root": root,
        "record_count": len(leaves),
        "prev_revision_hash": "0" * 64,
        "revision_hash": None,
        "subject_hash": None,
        "tombstone_id": None,
        "created_at": "2026-09-26T00:00:00+00:00",
        "record_key": record_key,
        "leaves": leaves,
        "record_keys": [leaf["record_key"] for leaf in leaves],
        "leaf_hashes": hashes,
    }
    revision["revision_hash"] = privacy.seal_revision_hash({
        "seal_id": revision["seal_id"],
        "revision_seq": revision["revision_seq"],
        "kind": revision["kind"],
        "prev_revision_hash": revision["prev_revision_hash"],
        "root": root,
        "record_count": len(leaves),
        "subject_hash": None,
        "tombstone_id": None,
        "created_at": revision["created_at"],
    })
    return revision


def test_record_proof_verifies_honest_inclusion_and_non_inclusion():
    absent = _proof_doc("no-such-key")
    absent["type"] = "non_inclusion"
    assert "non-inclusion" in privacy.verify_record_proof(absent)

    inclusion = _proof_doc("r2")
    inclusion["type"] = "inclusion"
    index = 1
    inclusion.update({
        "leaf": inclusion["leaves"][index],
        "leaf_index": index,
        "leaf_hash": inclusion["leaf_hashes"][index],
        "path": privacy.merkle_proof_path(inclusion["leaf_hashes"], index),
    })
    assert "inclusion" in privacy.verify_record_proof(inclusion)

    # an empty (post-erasure) manifest proves absence honestly
    empty = _proof_doc("anything")
    empty.update({"leaves": [], "record_keys": [], "leaf_hashes": [],
                  "record_count": 0, "type": "non_inclusion",
                  "root": privacy.EMPTY_ROOT})
    empty["revision_hash"] = privacy.seal_revision_hash({
        "seal_id": empty["seal_id"], "revision_seq": 0, "kind": "seal",
        "prev_revision_hash": "0" * 64, "root": privacy.EMPTY_ROOT,
        "record_count": 0, "subject_hash": None, "tombstone_id": None,
        "created_at": empty["created_at"],
    })
    assert "non-inclusion" in privacy.verify_record_proof(empty)


def _forged_absence(record_key="r2"):
    """The attack: the sealed revision genuinely contains record_key, but the
    material keeps the real root and leaf hashes and only rewrites the
    independent key list to hide the key."""
    doc = _proof_doc(record_key)
    doc["type"] = "non_inclusion"
    doc["record_keys"] = [k for k in doc["record_keys"] if k != record_key]
    return doc


def test_record_proof_rejects_key_list_rewrite_under_real_root():
    with pytest.raises(privacy.InvalidProof):
        privacy.verify_record_proof(_forged_absence("r2"))


@pytest.mark.parametrize("mutate", [
    # record_count aligned with the shortened independent key list
    lambda d: d.update(record_count=len(d["record_keys"])),
    # drop the cross-checked parallel list entirely (leaves are still bound)
    lambda d: d.pop("record_keys"),
    # rename a committed key without touching the leaf hashes / root
    lambda d: d.update(record_keys=["r1", "r2-renamed", "r3"]),
])
def test_record_proof_rejects_every_absence_forgery_variant(mutate):
    doc = _forged_absence("r2")
    mutate(doc)
    with pytest.raises(privacy.InvalidProof):
        privacy.verify_record_proof(doc)


def test_record_proof_rejects_leaf_order_and_leaf_hash_tampering():
    # reordering leaves changes the root derived from them
    reordered = _proof_doc("r2")
    reordered["type"] = "non_inclusion"
    reordered["leaves"] = list(reversed(reordered["leaves"]))
    with pytest.raises(privacy.InvalidProof):
        privacy.verify_record_proof(reordered)

    # swapping one leaf hash while the leaves stay fixed
    swapped = _proof_doc("r2")
    swapped["type"] = "non_inclusion"
    hashes = list(swapped["leaf_hashes"])
    hashes[0], hashes[1] = hashes[1], hashes[0]
    swapped["leaf_hashes"] = hashes
    with pytest.raises(privacy.InvalidProof):
        privacy.verify_record_proof(swapped)

    # tampering with a leaf (its key name) recomputes to a different root
    renamed = _proof_doc("r2")
    renamed["type"] = "non_inclusion"
    renamed["leaves"][1] = {**renamed["leaves"][1], "record_key": "r2x"}
    renamed["record_keys"][1] = "r2x"
    with pytest.raises(privacy.InvalidProof):
        privacy.verify_record_proof(renamed)

    # an actual present key can never be asserted absent even with honest leaves
    present = _proof_doc("r2")
    present["type"] = "non_inclusion"
    with pytest.raises(privacy.InvalidProof, match="IS present"):
        privacy.verify_record_proof(present)


def test_record_proof_rejects_revision_hash_tampering():
    doc = _proof_doc("missing")
    doc["type"] = "non_inclusion"
    doc["revision_hash"] = "0" * 64
    with pytest.raises(privacy.InvalidProof):
        privacy.verify_record_proof(doc)


def test_record_proof_rejects_forgeable_legacy_non_inclusion_but_keeps_legacy_inclusion():
    leaves, hashes = _three_leaves()
    root = privacy.merkle_root(hashes)
    legacy = {
        "seal_id": "seal-1",
        "revision_seq": 0,
        "root": root,
        "record_count": 3,
        "revision_hash": "0" * 64,
        "record_key": "r2",
        "record_keys": [leaf["record_key"] for leaf in leaves],
        "leaf_hashes": hashes,
    }
    # legacy non-inclusion: no bound leaves — the known forgeable format
    legacy_nx = {**legacy, "type": "non_inclusion"}
    with pytest.raises(privacy.InvalidProof):
        privacy.verify_record_proof(legacy_nx)
    # legacy inclusion is self-contained (full leaf + sibling path) and stays valid
    legacy_inc = {
        **legacy,
        "type": "inclusion",
        "leaf": leaves[1],
        "leaf_index": 1,
        "leaf_hash": hashes[1],
        "path": privacy.merkle_proof_path(hashes, 1),
    }
    assert "inclusion" in privacy.verify_record_proof(legacy_inc)
