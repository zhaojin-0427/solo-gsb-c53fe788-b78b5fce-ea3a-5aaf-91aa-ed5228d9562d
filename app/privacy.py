"""Differential-privacy primitives.

Everything here is deterministic and pure so that:
  * the noise seed is reproducibly derived from the idempotency key,
  * retries / restarts reproduce bit-identical noise,
  * the audit API can re-derive and verify every reported number.
"""
from __future__ import annotations

import hashlib
import json
import math
import random
from decimal import Decimal
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# Canonicalisation & hashing
# ---------------------------------------------------------------------------
def canonical_json(obj: Any) -> str:
    """Stable JSON encoding (sorted keys, tight separators)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def request_digest(spec: dict) -> str:
    """Digest of the canonical query specification; binds an idempotency key
    to exactly one request shape."""
    return sha256_hex("dp-query|" + canonical_json(spec))


def derive_noise_seed(idempotency_key: str, digest: str) -> str:
    """Reproducible noise seed derived from the idempotency key (and the
    request digest, so a key can never be recycled for a different query)."""
    return sha256_hex(f"dp-noise-seed|{idempotency_key}|{digest}")


# ---------------------------------------------------------------------------
# Erasure proofs
# ---------------------------------------------------------------------------
def erasure_subject_hash(subject_id: str) -> str:
    """Pseudonymous handle for an erased subject. The raw identifier is never
    persisted after erasure; this domain-separated hash lets uploads check
    tombstones and lets auditors reference the erasure without exposing the
    subject identifier."""
    return sha256_hex("dp-erasure-subject|" + subject_id)


def erasure_request_digest(spec: dict) -> str:
    """Digest binding an erasure idempotency key to exactly one request shape
    (subject hash + cut-off dataset version)."""
    return sha256_hex("dp-erasure-request|" + canonical_json(spec))


def erasure_proof_hash(payload: dict) -> str:
    """Erasure proof: hash over every effect of the erasure (tombstone id,
    subject hash, cut-off version, counts and the invalidated queries with
    their ledger positions). Recomputable by the audit API."""
    return sha256_hex("dp-erasure-proof|" + canonical_json(payload))


# ---------------------------------------------------------------------------
# Policy parameter versions: immutable draft / published-version digests
# ---------------------------------------------------------------------------
# A draft is fully described by its four privacy parameters; the digest is
# content-addressed so resubmitting identical parameters (even under a new
# idempotency key) is an idempotent no-op. A published summary additionally
# binds the policy identity and the assigned, gapless version sequence.
def _canonical_decimal(value) -> str:
    return format(Decimal(value).quantize(Decimal("0.000000000001"),
                                          rounding="ROUND_HALF_UP"), "f")


def policy_version_spec(epsilon_total, delta_total, per_subject_cap,
                        dimensions) -> dict:
    """Canonical parameter description shared by draft and summary hashes."""
    return {
        "epsilon_total": _canonical_decimal(epsilon_total),
        "delta_total": _canonical_decimal(delta_total),
        "per_subject_cap": int(per_subject_cap),
        "dimensions": sorted(dimensions),
    }


def policy_draft_hash(spec: dict) -> str:
    """Digest of an immutable draft's content; content-addressed identity."""
    return sha256_hex("dp-policy-draft-v1|" + canonical_json(spec))


def policy_version_summary_hash(policy_id, version_seq: int,
                                spec: dict, draft_hash: str) -> str:
    """Digest of one published policy parameter version: binds the policy,
    the gapless version sequence, the immutable parameters and the draft."""
    payload = {
        "policy_id": str(policy_id),
        "version_seq": int(version_seq),
        "spec": spec,
        "draft_hash": draft_hash,
    }
    return sha256_hex("dp-policy-version-v1|" + canonical_json(payload))


def policy_draft_request_digest(spec: dict) -> str:
    """Digest binding a draft idempotency key to exactly one draft body."""
    return sha256_hex("dp-policy-draft-request|" + canonical_json(spec))


# ---------------------------------------------------------------------------
# Version seals: canonical manifest leaves, Merkle tree, revision hashes
# ---------------------------------------------------------------------------
# Hash algorithm / domain-separation version. Everything is reproducible from
# this spec alone (see scripts/verify_proof.py, which re-implements it with
# the standard library only):
#   leaf      = sha256("dp-seal-leaf-v1|"  + canonical_json(leaf_dict))
#   node      = sha256("dp-seal-node-v1|"  + left_hex + "|" + right_hex)
#   root      = fold(node) over the leaf-hash level, duplicating an odd last
#               element at every level; the empty manifest has EMPTY_ROOT
#   revision  = sha256("dp-seal-revision-v1|" + canonical_json(revision_dict))
SEAL_HASH_VERSION = "v1"
EMPTY_ROOT = sha256_hex("dp-seal-empty-root-v1")


def seal_request_digest(spec: dict) -> str:
    """Digest binding a seal idempotency key to exactly one request shape."""
    return sha256_hex("dp-seal-request|" + canonical_json(spec))


def canonical_leaf(record_key: str, subject_hash: str, attributes: dict) -> dict:
    """Canonical manifest leaf for one record. Only the pseudonymous subject
    hash is committed — never the raw subject identifier — so sealed manifests
    stay verifiable after an erasure without leaking the identifier."""
    return {
        "record_key": record_key,
        "subject_hash": subject_hash,
        "attributes": attributes or {},
    }


def leaf_hash(leaf: dict) -> str:
    return sha256_hex("dp-seal-leaf-v1|" + canonical_json(canonical_leaf(
        leaf["record_key"], leaf["subject_hash"], leaf.get("attributes"))))


def _node_hash(left: str, right: str) -> str:
    return sha256_hex(f"dp-seal-node-v1|{left}|{right}")


def merkle_root(leaf_hashes: list[str]) -> str:
    """Merkle root over the given leaf hashes (already in canonical order)."""
    level = list(leaf_hashes)
    if not level:
        return EMPTY_ROOT
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])          # duplicate the odd last element
        level = [_node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof_path(leaf_hashes: list[str], index: int) -> list[dict]:
    """Sibling path proving inclusion of leaf_hashes[index]. Each step is
    {"position": "left"|"right", "hash": sibling} — "left" means the sibling
    sits on the left of the running hash when folding upwards."""
    path: list[dict] = []
    level = list(leaf_hashes)
    idx = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        if idx % 2 == 0:
            path.append({"position": "right", "hash": level[idx + 1]})
        else:
            path.append({"position": "left", "hash": level[idx - 1]})
        level = [_node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        idx //= 2
    return path


def verify_merkle_proof(leaf_hash_hex: str, path: list[dict], root: str) -> bool:
    """Fold a leaf hash along its sibling path and compare with the root."""
    running = leaf_hash_hex
    for step in path:
        if step["position"] == "left":
            running = _node_hash(step["hash"], running)
        else:
            running = _node_hash(running, step["hash"])
    return running == root


class InvalidProof(Exception):
    """Self-contained seal proof material does not verify."""


def _revision_payload_from_doc(doc: dict) -> dict:
    return {
        "seal_id": doc["seal_id"],
        "revision_seq": doc["revision_seq"],
        "kind": doc["kind"],
        "prev_revision_hash": doc["prev_revision_hash"],
        "root": doc["root"],
        "record_count": doc["record_count"],
        "subject_hash": doc.get("subject_hash"),
        "tombstone_id": doc.get("tombstone_id"),
        "created_at": doc["created_at"],
    }


def verify_record_proof(doc: dict) -> str:
    """Verify self-contained inclusion / non-inclusion proof material for one
    record_key against one seal revision.

    Key names are bound to the committed leaves **per item**: the canonical
    ``leaves`` (every leaf hash commits its own ``record_key``) are the sole
    source from which leaf hashes and the Merkle root are derived; an
    independent ``record_keys`` / ``leaf_hashes`` list is never trusted on its
    own. Deleting a present key from ``record_keys``, reordering entries or
    swapping a leaf hash therefore cannot forge a non-inclusion assertion
    while the root stays unchanged. Returns a human-readable summary; raises
    ``InvalidProof`` on any mismatch. Independently re-implemented with the
    standard library only in scripts/verify_proof.py.
    """
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise InvalidProof(message)

    leaves = doc.get("leaves")
    if leaves is None:
        return _verify_legacy_record_proof(doc, require)

    require(isinstance(leaves, list), "proof is missing the bound leaf list")
    keys = [leaf["record_key"] for leaf in leaves]
    require(keys == sorted(keys), "leaves are not sorted by record_key")
    require(len(keys) == len(set(keys)), "duplicate record_key in committed leaves")
    require(len(leaves) == doc["record_count"], "record_count does not match the leaves")
    if "record_keys" in doc:
        require(doc["record_keys"] == keys,
                "record_keys do not match the keys of the committed leaves")
    derived_hashes = [leaf_hash(leaf) for leaf in leaves]
    if "leaf_hashes" in doc:
        require(doc["leaf_hashes"] == derived_hashes,
                "leaf_hashes do not match hashes recomputed from the committed leaves")
    root = merkle_root(derived_hashes)
    require(root == doc["root"],
            f"Merkle root mismatch: recomputed {root}, committed {doc['root']}")
    # Anchor the root into the immutable revision chain as well.
    require(seal_revision_hash(_revision_payload_from_doc(doc)) == doc["revision_hash"],
            "revision hash mismatch")

    target = doc["record_key"]
    if doc["type"] == "inclusion":
        require(target in keys, "record_key absent from the committed leaves")
        index = keys.index(target)
        require(doc["leaf_index"] == index, "leaf_index mismatch")
        require(doc["leaf"]["record_key"] == target, "leaf record_key mismatch")
        require(leaf_hash(doc["leaf"]) == derived_hashes[index],
                "recomputed leaf hash mismatch")
        require(doc["leaf_hash"] == derived_hashes[index],
                "leaf_hash does not match the committed leaf")
        require(verify_merkle_proof(derived_hashes[index], doc["path"], root),
                "Merkle path does not fold to the root")
        return (f"OK inclusion proof: '{target}' is leaf #{index} "
                f"under root {root[:16]}…")
    require(doc["type"] == "non_inclusion", f"unknown proof type {doc['type']!r}")
    require(target not in keys,
            f"'{target}' IS present in the committed leaves — non-inclusion fails")
    return (f"OK non-inclusion proof: '{target}' is absent from the "
            f"{len(keys)}-leaf manifest with root {root[:16]}…")


def _verify_legacy_record_proof(doc: dict, require) -> str:
    """Proof material emitted before the key-to-leaf binding existed.

    Legacy inclusion material is self-contained (the full leaf plus its
    sibling path) and remains trustworthy. Legacy non-inclusion material only
    carried an independent ``record_keys`` list beside the leaf hashes, so key
    names were not bound to the commitment and absence could be asserted under
    the genuine root by editing that list — reject it.
    """
    require(doc.get("type") == "inclusion",
            "legacy non-inclusion proofs carry no key-to-leaf binding; "
            "refetch the proof from the current API")
    keys = doc["record_keys"]
    require(keys == sorted(keys), "record_keys are not sorted")
    require(len(keys) == doc["record_count"], "record_count does not match record_keys")
    require(len(doc["leaf_hashes"]) == len(keys), "leaf_hashes / record_keys length mismatch")
    require(merkle_root(doc["leaf_hashes"]) == doc["root"], "Merkle root mismatch")
    leaf = doc["leaf"]
    require(leaf["record_key"] == doc["record_key"], "leaf record_key mismatch")
    require(doc["record_key"] in keys, "record_key absent from the key list")
    require(keys[doc["leaf_index"]] == doc["record_key"], "leaf_index mismatch")
    require(doc["leaf_hashes"][doc["leaf_index"]] == doc["leaf_hash"],
            "leaf_hash does not match the committed leaf hashes")
    require(leaf_hash(leaf) == doc["leaf_hash"], "recomputed leaf hash mismatch")
    require(verify_merkle_proof(doc["leaf_hash"], doc["path"], doc["root"]),
            "Merkle path does not fold to the root")
    return (f"OK inclusion proof (legacy format): '{doc['record_key']}' is leaf "
            f"#{doc['leaf_index']} under root {doc['root'][:16]}…")


def seal_revision_hash(payload: dict) -> str:
    """Hash of one seal revision; chains revisions of a seal together
    (prev_revision_hash links to the previous revision's hash)."""
    return sha256_hex("dp-seal-revision-v1|" + canonical_json(payload))


def derive_noise_seed_bound(idempotency_key: str, digest: str, root: str) -> str:
    """Noise seed for a seal-bound query: reproducible from the idempotency
    key, the request digest AND the Merkle root the query was computed
    against, so the seed can never be replayed against a different root."""
    return sha256_hex(f"dp-noise-seal-v1|{idempotency_key}|{digest}|{root}")


# ---------------------------------------------------------------------------
# Seal comparisons: canonical diffs between two verified revisions
# ---------------------------------------------------------------------------
#   diff = sha256("dp-seal-diff-v1|" + canonical_json({left, right, diff}))
# where left / right are the canonical side references (seal_id, revision_seq,
# revision_hash, root) and diff is the canonical added / removed / changed
# list. Reproducible from this spec alone (scripts/verify_diff.py re-implements
# it with the standard library only).
def compare_request_digest(spec: dict) -> str:
    """Digest binding a compare idempotency key to exactly one request shape
    (the two seal/revision references, roles included)."""
    return sha256_hex("dp-seal-compare-request|" + canonical_json(spec))


def canonical_diff(left_leaves: list[dict], right_leaves: list[dict]) -> dict:
    """Canonical, stably sorted diff between two manifests, aligned by
    record_key.

    Leaves carry only the pseudonymous subject hash, so the diff never
    exposes a raw subject identifier. Every list is sorted by record_key;
    ``changed`` entries record which committed fields (subject_hash and/or
    attributes) differ, carrying the full ``from`` / ``to`` leaves.
    """
    left_by_key = {
        leaf["record_key"]: canonical_leaf(
            leaf["record_key"], leaf["subject_hash"], leaf.get("attributes"))
        for leaf in left_leaves
    }
    right_by_key = {
        leaf["record_key"]: canonical_leaf(
            leaf["record_key"], leaf["subject_hash"], leaf.get("attributes"))
        for leaf in right_leaves
    }
    added = [{"record_key": key, "leaf": right_by_key[key]}
             for key in sorted(right_by_key.keys() - left_by_key.keys())]
    removed = [{"record_key": key, "leaf": left_by_key[key]}
               for key in sorted(left_by_key.keys() - right_by_key.keys())]
    changed: list[dict] = []
    unchanged = 0
    for key in sorted(left_by_key.keys() & right_by_key.keys()):
        old, new = left_by_key[key], right_by_key[key]
        changes = []
        if old["subject_hash"] != new["subject_hash"]:
            changes.append("subject_hash")
        if old["attributes"] != new["attributes"]:
            changes.append("attributes")
        if changes:
            changed.append({"record_key": key, "changes": changes,
                            "from": old, "to": new})
        else:
            unchanged += 1
    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": unchanged,
        },
    }


def diff_side_ref(side: dict) -> dict:
    """Canonical per-side reference bound into a diff hash: the seal /
    revision identity plus its committed Merkle root."""
    return {
        "seal_id": side["seal_id"],
        "revision_seq": side["revision_seq"],
        "revision_hash": side["revision_hash"],
        "root": side["root"],
    }


def seal_diff_hash(payload: dict) -> str:
    """Hash of one comparison: binds both ends' seal/revision hashes and
    roots plus the canonical diff list into one immutable diff proof."""
    return sha256_hex("dp-seal-diff-v1|" + canonical_json(payload))


def verify_comparison(doc: dict) -> str:
    """Verify self-contained comparison material for two seal revisions.

    Both sides' committed ``leaves`` are the sole source of truth: every leaf
    hash and both Merkle roots are re-derived from them (material smuggled in
    from another root fails here), each side is anchored to its revision
    hash, and the claimed ``diff`` must equal the diff re-derived from the
    leaves alone — renaming a key, altering a leaf or dropping an entry
    breaks that equality. Finally ``diff_hash`` is recomputed over both
    ends' seal/revision hashes, roots and the diff list. Returns a
    human-readable summary; raises ``InvalidProof`` on any mismatch.
    Independently re-implemented with the standard library only in
    scripts/verify_diff.py.
    """
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise InvalidProof(message)

    leaves_by_side: dict[str, list[dict]] = {}
    for side in ("left", "right"):
        sdoc = doc.get(side)
        require(isinstance(sdoc, dict), f"comparison is missing the {side} side")
        leaves = sdoc.get("leaves")
        require(isinstance(leaves, list), f"{side}: missing the committed leaves")
        keys = [leaf["record_key"] for leaf in leaves]
        require(keys == sorted(keys), f"{side}: leaves are not sorted by record_key")
        require(len(keys) == len(set(keys)), f"{side}: duplicate record_key in leaves")
        require(len(leaves) == sdoc["record_count"],
                f"{side}: record_count does not match the leaves")
        root = merkle_root([leaf_hash(leaf) for leaf in leaves])
        require(root == sdoc["root"],
                f"{side}: leaves do not fold to the committed Merkle root")
        require(seal_revision_hash(_revision_payload_from_doc(sdoc)) == sdoc["revision_hash"],
                f"{side}: revision hash mismatch")
        leaves_by_side[side] = leaves

    recomputed = canonical_diff(leaves_by_side["left"], leaves_by_side["right"])
    require(doc.get("diff") == recomputed,
            "diff does not match the diff recomputed from the committed leaves")
    payload = {
        "left": diff_side_ref(doc["left"]),
        "right": diff_side_ref(doc["right"]),
        "diff": doc["diff"],
    }
    require(seal_diff_hash(payload) == doc["diff_hash"], "diff_hash mismatch")
    counts = recomputed["counts"]
    return (f"OK comparison: +{counts['added']}/-{counts['removed']}/"
            f"~{counts['changed']} (unchanged {counts['unchanged']}), "
            f"diff_hash {doc['diff_hash'][:16]}… verified")


def _group_rng(base_seed: str, group_key: dict) -> random.Random:
    """Per-group PRNG: noise for a group depends only on the seed and the
    group key — never on row order or other groups."""
    h = sha256_hex(base_seed + "|" + canonical_json(group_key))
    return random.Random(int(h, 16))


# ---------------------------------------------------------------------------
# Mechanisms
# ---------------------------------------------------------------------------
def mechanism_for(delta: Decimal) -> str:
    """delta = 0 -> pure DP (Laplace); delta > 0 -> approximate DP (Gaussian)."""
    return "gaussian" if delta > 0 else "laplace"


def sensitivity(query_type: str, per_subject_cap: int,
                value_min: Decimal | None, value_max: Decimal | None) -> float:
    """L1/L2 global sensitivity after contribution capping.

    count: each subject contributes at most `cap` rows          -> cap
    sum:   each subject contributes at most `cap` clipped values
           in [value_min, value_max]                            -> cap * max(|min|, |max|)
    """
    if query_type == "count":
        return float(per_subject_cap)
    bound = max(abs(float(value_min)), abs(float(value_max)))
    return float(per_subject_cap) * bound


def noise_scale(mechanism: str, sens: float, epsilon: float, delta: float) -> float:
    if mechanism == "laplace":
        return sens / epsilon
    # Gaussian mechanism for (epsilon, delta)-DP: sigma = sens * sqrt(2 ln(1.25/delta)) / eps
    return sens * math.sqrt(2.0 * math.log(1.25 / delta)) / epsilon


def laplace_sample(scale: float, rng: random.Random) -> float:
    """Inverse-CDF Laplace draw, deterministic for a seeded rng."""
    u = rng.random() - 0.5
    return -scale * math.copysign(math.log1p(-2.0 * abs(u)), u)


def gaussian_sample(sigma: float, rng: random.Random) -> float:
    """Box-Muller normal draw, deterministic for a seeded rng."""
    u1 = max(rng.random(), 1e-300)
    u2 = rng.random()
    return sigma * math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)


# ---------------------------------------------------------------------------
# Contribution clipping & aggregation
# ---------------------------------------------------------------------------
def clip_contributions(rows: Iterable[tuple[int, str, Any]],
                       per_subject_cap: int) -> tuple[list[tuple[str, Any]], list[dict]]:
    """Cap per-subject contributions deterministically.

    rows: iterable of (record_id, subject_id, payload). Records are ordered by
    record_id and the first `per_subject_cap` rows of each subject are kept, so
    the clipping is stable across replays. Returns (kept, per_subject_detail)
    with the detail sorted by subject_id.
    """
    per_subject: dict[str, list[tuple[int, Any]]] = {}
    for record_id, subject_id, payload in sorted(rows, key=lambda r: r[0]):
        per_subject.setdefault(subject_id, []).append((record_id, payload))

    kept: list[tuple[str, Any]] = []
    detail: list[dict] = []
    for subject_id in sorted(per_subject):
        items = per_subject[subject_id]
        kept_items = items[:per_subject_cap]
        kept.extend((subject_id, payload) for _, payload in kept_items)
        detail.append({
            "subject_id": subject_id,
            "contributed": len(items),
            "kept": len(kept_items),
            "dropped": len(items) - len(kept_items),
        })
    return kept, detail


def aggregate(kept: Iterable[tuple[str, tuple[dict, float]]],
              group_by: list[str],
              query_type: str,
              value_min: Decimal | None,
              value_max: Decimal | None) -> list[tuple[dict, float]]:
    """Aggregate clipped contributions into groups.

    kept payloads are (attributes, raw_value). Sum values are clipped to
    [value_min, value_max]. Returns a list of (group_key_dict, value) sorted by
    the canonical key encoding — a stable order for noise application and
    audit output.
    """
    groups: dict[str, tuple[dict, float]] = {}
    for _subject_id, (attributes, raw_value) in kept:
        key = {dim: (None if attributes.get(dim) is None else str(attributes.get(dim)))
               for dim in group_by}
        encoded = canonical_json(key)
        if query_type == "count":
            contribution = 1.0
        else:
            contribution = min(max(float(raw_value), float(value_min)), float(value_max))
        if encoded in groups:
            groups[encoded] = (key, groups[encoded][1] + contribution)
        else:
            groups[encoded] = (key, contribution)
    return [groups[encoded] for encoded in sorted(groups)]


def apply_noise(groups: list[tuple[dict, float]],
                mechanism: str,
                scale: float,
                base_seed: str) -> list[dict]:
    """Add calibrated noise to each group; fully reproducible from base_seed."""
    sampler = laplace_sample if mechanism == "laplace" else gaussian_sample
    out = []
    for key, true_value in groups:
        rng = _group_rng(base_seed, key)
        noise = sampler(scale, rng)
        out.append({
            "key": key,
            "clipped_value": true_value,
            "noise": noise,
            "noisy_value": true_value + noise,
        })
    return out
