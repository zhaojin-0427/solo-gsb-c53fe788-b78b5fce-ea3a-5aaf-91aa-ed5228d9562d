#!/usr/bin/env python3
"""Offline verification of seal proofs and manifests.

Pure standard library — verifies the material returned by the API without
needing the service (or any dependency) at verification time:

  * manifest  — input: GET /seals/{seal_id}/manifest[?revision=N]
                Recomputes every leaf hash, the Merkle root and the revision
                hash from the canonical leaves and compares them with the
                committed values.
  * proof     — input: GET /seals/{seal_id}/records/{record_key}/proof[?revision=N]
                The canonical leaves bind each record_key to a committed leaf
                (a leaf hash commits its key name): the verifier derives every
                leaf hash and the Merkle root solely from "leaves", cross-checks
                the parallel key/hash lists, anchors the root to the revision
                hash, and then checks inclusion (full leaf + sibling path
                folded to the root) or non-inclusion (the key is absent from
                those same bound leaves). An independent record_keys list that
                merely omits a present key therefore cannot forge absence
                under the genuine root.
  * chain     — input: GET /seals/{seal_id}
                Recomputes every revision hash and checks the
                prev_revision_hash linkage of the whole revision chain.

Hash spec (hash_version "v1"), domain-separated SHA-256:
  leaf     = sha256("dp-seal-leaf-v1|"     + canonical_json(leaf))
  node     = sha256("dp-seal-node-v1|"     + left_hex + "|" + right_hex)
  root     = fold(node) over leaf hashes, duplicating an odd last element at
             every level; the empty manifest hashes to EMPTY_ROOT
  revision = sha256("dp-seal-revision-v1|" + canonical_json(revision))
  canonical_json = JSON, sorted keys, separators (",", ":"), UTF-8

Usage:
  python3 scripts/verify_proof.py manifest manifest.json
  python3 scripts/verify_proof.py proof inclusion.json
  python3 scripts/verify_proof.py chain seal.json
  curl -s .../proof | python3 scripts/verify_proof.py proof -

Exit code 0 = verified, 1 = verification failed, 2 = usage error.
"""
from __future__ import annotations

import hashlib
import json
import sys

EMPTY_ROOT = hashlib.sha256(b"dp-seal-empty-root-v1").hexdigest()
GENESIS_HASH = "0" * 64


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_leaf(leaf: dict) -> dict:
    return {
        "record_key": leaf["record_key"],
        "subject_hash": leaf["subject_hash"],
        "attributes": leaf.get("attributes") or {},
    }


def leaf_hash(leaf: dict) -> str:
    return sha256_hex("dp-seal-leaf-v1|" + canonical_json(canonical_leaf(leaf)))


def node_hash(left: str, right: str) -> str:
    return sha256_hex(f"dp-seal-node-v1|{left}|{right}")


def merkle_root(leaf_hashes: list[str]) -> str:
    level = list(leaf_hashes)
    if not level:
        return EMPTY_ROOT
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def fold_path(leaf_hash_hex: str, path: list[dict]) -> str:
    running = leaf_hash_hex
    for step in path:
        if step["position"] == "left":
            running = node_hash(step["hash"], running)
        else:
            running = node_hash(running, step["hash"])
    return running


def revision_hash(rev: dict) -> str:
    payload = {
        "seal_id": rev["seal_id"],
        "revision_seq": rev["revision_seq"],
        "kind": rev["kind"],
        "prev_revision_hash": rev["prev_revision_hash"],
        "root": rev["root"],
        "record_count": rev["record_count"],
        "subject_hash": rev.get("subject_hash"),
        "tombstone_id": rev.get("tombstone_id"),
        "created_at": rev["created_at"],
    }
    return sha256_hex("dp-seal-revision-v1|" + canonical_json(payload))


class Failure(Exception):
    pass


def check(condition: bool, message: str) -> None:
    if not condition:
        raise Failure(message)


def verify_manifest(doc: dict) -> str:
    leaves = doc["manifest"]["leaves"]
    keys = [leaf["record_key"] for leaf in leaves]
    check(keys == sorted(keys), "manifest leaves are not sorted by record_key")
    check(len(leaves) == doc["record_count"], "record_count does not match the leaf count")
    leaf_hashes = [leaf_hash(leaf) for leaf in leaves]
    root = merkle_root(leaf_hashes)
    check(root == doc["root"],
          f"Merkle root mismatch: recomputed {root}, committed {doc['root']}")
    check(revision_hash(doc) == doc["revision_hash"], "revision hash mismatch")
    return (f"OK manifest: {len(leaves)} leaves, root {doc['root'][:16]}…, "
            f"revision #{doc['revision_seq']} hash verified")


def verify_proof(doc: dict) -> str:
    leaves = doc.get("leaves")
    if leaves is None:
        return verify_legacy_proof(doc)

    # Key names are bound to the committed leaves per item: leaves are the
    # sole source of truth, and record_keys / leaf_hashes must match what they
    # derive to. Tampering with a key name, reordering entries or swapping a
    # leaf hash breaks a check below while the root stays unchanged.
    check(isinstance(leaves, list), "proof is missing the bound leaf list")
    keys = [leaf["record_key"] for leaf in leaves]
    check(keys == sorted(keys), "leaves are not sorted by record_key")
    check(len(keys) == len(set(keys)), "duplicate record_key in committed leaves")
    check(len(leaves) == doc["record_count"], "record_count does not match the leaves")
    if "record_keys" in doc:
        check(doc["record_keys"] == keys,
              "record_keys do not match the keys of the committed leaves")
    derived_hashes = [leaf_hash(leaf) for leaf in leaves]
    if "leaf_hashes" in doc:
        check(doc["leaf_hashes"] == derived_hashes,
              "leaf_hashes do not match hashes recomputed from the committed leaves")
    root = merkle_root(derived_hashes)
    check(root == doc["root"],
          f"Merkle root mismatch: recomputed {root}, committed {doc['root']}")
    check(revision_hash(doc) == doc["revision_hash"], "revision hash mismatch")

    target = doc["record_key"]
    if doc["type"] == "inclusion":
        check(target in keys, "record_key absent from the committed leaves")
        index = keys.index(target)
        check(doc["leaf_index"] == index, "leaf_index mismatch")
        check(doc["leaf"]["record_key"] == target, "leaf record_key mismatch")
        check(leaf_hash(doc["leaf"]) == derived_hashes[index],
              "recomputed leaf hash mismatch")
        check(doc["leaf_hash"] == derived_hashes[index],
              "leaf_hash does not match the committed leaf")
        folded = fold_path(derived_hashes[index], doc["path"])
        check(folded == root,
              f"Merkle path does not fold to the root: {folded} != {root}")
        return (f"OK inclusion proof: '{target}' is leaf #{index} "
                f"under root {root[:16]}…")
    check(doc["type"] == "non_inclusion", f"unknown proof type {doc['type']!r}")
    check(target not in keys,
          f"'{target}' IS present in the committed leaves — non-inclusion fails")
    return (f"OK non-inclusion proof: '{target}' is absent from the "
            f"{len(keys)}-leaf manifest with root {root[:16]}…")


def verify_legacy_proof(doc: dict) -> str:
    """Material emitted before the key-to-leaf binding existed.

    Legacy inclusion material carries the full leaf plus its sibling path and
    is self-contained, so it still verifies. Legacy non-inclusion material
    trusted an independent record_keys list beside the leaf hashes — key names
    were not bound to the commitment and absence could be forged under the
    genuine root by editing that list — so it is rejected.
    """
    check(doc.get("type") == "inclusion",
          "legacy non-inclusion proofs carry no key-to-leaf binding; "
          "refetch the proof from the current API")
    keys = doc["record_keys"]
    check(keys == sorted(keys), "record_keys are not sorted")
    check(len(keys) == doc["record_count"], "record_count does not match record_keys")
    check(len(doc["leaf_hashes"]) == len(keys), "leaf_hashes / record_keys length mismatch")
    root = merkle_root(doc["leaf_hashes"])
    check(root == doc["root"],
          f"Merkle root mismatch: recomputed {root}, committed {doc['root']}")
    leaf = doc["leaf"]
    check(leaf["record_key"] == doc["record_key"], "leaf record_key mismatch")
    check(doc["record_key"] in keys, "record_key absent from the key list")
    check(keys[doc["leaf_index"]] == doc["record_key"], "leaf_index mismatch")
    check(doc["leaf_hashes"][doc["leaf_index"]] == doc["leaf_hash"],
          "leaf_hash does not match the committed leaf hashes")
    check(leaf_hash(leaf) == doc["leaf_hash"], "recomputed leaf hash mismatch")
    folded = fold_path(doc["leaf_hash"], doc["path"])
    check(folded == doc["root"],
          f"Merkle path does not fold to the root: {folded} != {doc['root']}")
    return (f"OK inclusion proof (legacy format): '{doc['record_key']}' is leaf "
            f"#{doc['leaf_index']} under root {doc['root'][:16]}…")


def verify_chain(doc: dict) -> str:
    revisions = doc["revisions"]
    check(revisions, "no revisions in document")
    seal_id = doc["seal_id"]
    prev_hash = GENESIS_HASH
    for rev in revisions:
        full = {**rev, "seal_id": seal_id}
        check(rev["prev_revision_hash"] == prev_hash,
              f"revision #{rev['revision_seq']}: prev_revision_hash does not link the chain")
        check(revision_hash(full) == rev["revision_hash"],
              f"revision #{rev['revision_seq']}: revision hash mismatch")
        prev_hash = rev["revision_hash"]
    return (f"OK chain: {len(revisions)} revision(s) of seal {seal_id} "
            f"link correctly from genesis")


MODES = {"manifest": verify_manifest, "proof": verify_proof, "chain": verify_chain}


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] not in MODES:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    mode, path = argv[1], argv[2]
    try:
        raw = sys.stdin.read() if path == "-" else open(path, encoding="utf-8").read()
        doc = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAILED: cannot read JSON input: {exc}", file=sys.stderr)
        return 2
    try:
        print(MODES[mode](doc))
    except Failure as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1
    except (KeyError, TypeError) as exc:
        print(f"FAILED: malformed {mode} document: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
