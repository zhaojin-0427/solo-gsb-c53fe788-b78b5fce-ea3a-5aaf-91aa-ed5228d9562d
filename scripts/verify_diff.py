#!/usr/bin/env python3
"""Offline verification of seal comparison (diff) proofs.

Pure standard library — verifies the material returned by the API without
needing the service (or any dependency) at verification time:

  * input: POST /seals/compare  or  GET /seals/comparisons/{comparison_id}
    Both sides' committed leaves are the sole source of truth. The verifier
    re-derives every leaf hash and both Merkle roots from them (material
    smuggled in from another root fails here), re-anchors each side to its
    revision hash, re-derives the canonical added / removed / changed diff
    from the leaves alone — renaming a key, altering a leaf or dropping an
    entry breaks the exact comparison — and finally recomputes diff_hash
    over both ends' seal/revision hashes, roots and the diff list.

Hash spec (hash_version "v1"), domain-separated SHA-256:
  leaf     = sha256("dp-seal-leaf-v1|"     + canonical_json(leaf))
  node     = sha256("dp-seal-node-v1|"     + left_hex + "|" + right_hex)
  root     = fold(node) over leaf hashes, duplicating an odd last element at
             every level; the empty manifest hashes to EMPTY_ROOT
  revision = sha256("dp-seal-revision-v1|" + canonical_json(revision))
  diff     = sha256("dp-seal-diff-v1|"     + canonical_json(diff_payload))
  canonical_json = JSON, sorted keys, separators (",", ":"), UTF-8

Usage:
  python3 scripts/verify_diff.py comparison.json
  curl -s localhost:8000/seals/comparisons/$ID | python3 scripts/verify_diff.py -

Exit code 0 = verified, 1 = verification failed, 2 = usage error.
"""
from __future__ import annotations

import hashlib
import json
import sys

EMPTY_ROOT = hashlib.sha256(b"dp-seal-empty-root-v1").hexdigest()


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


def canonical_diff(left_leaves: list[dict], right_leaves: list[dict]) -> dict:
    left_by_key = {leaf["record_key"]: canonical_leaf(leaf) for leaf in left_leaves}
    right_by_key = {leaf["record_key"]: canonical_leaf(leaf) for leaf in right_leaves}
    added = [{"record_key": key, "leaf": right_by_key[key]}
             for key in sorted(right_by_key.keys() - left_by_key.keys())]
    removed = [{"record_key": key, "leaf": left_by_key[key]}
               for key in sorted(left_by_key.keys() - right_by_key.keys())]
    changed = []
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
    return {
        "seal_id": side["seal_id"],
        "revision_seq": side["revision_seq"],
        "revision_hash": side["revision_hash"],
        "root": side["root"],
    }


def diff_hash(payload: dict) -> str:
    return sha256_hex("dp-seal-diff-v1|" + canonical_json(payload))


class Failure(Exception):
    pass


def check(condition: bool, message: str) -> None:
    if not condition:
        raise Failure(message)


def verify_comparison(doc: dict) -> str:
    leaves_by_side: dict[str, list[dict]] = {}
    for side in ("left", "right"):
        sdoc = doc.get(side)
        check(isinstance(sdoc, dict), f"comparison is missing the {side} side")
        leaves = sdoc.get("leaves")
        check(isinstance(leaves, list), f"{side}: missing the committed leaves")
        keys = [leaf["record_key"] for leaf in leaves]
        check(keys == sorted(keys), f"{side}: leaves are not sorted by record_key")
        check(len(keys) == len(set(keys)), f"{side}: duplicate record_key in leaves")
        check(len(leaves) == sdoc["record_count"],
              f"{side}: record_count does not match the leaves")
        root = merkle_root([leaf_hash(leaf) for leaf in leaves])
        check(root == sdoc["root"],
              f"{side}: leaves do not fold to the committed Merkle root "
              f"(recomputed {root}, committed {sdoc['root']})")
        check(revision_hash(sdoc) == sdoc["revision_hash"],
              f"{side}: revision hash mismatch")
        leaves_by_side[side] = leaves

    recomputed = canonical_diff(leaves_by_side["left"], leaves_by_side["right"])
    check(doc.get("diff") == recomputed,
          "diff does not match the diff recomputed from the committed leaves")
    payload = {
        "left": diff_side_ref(doc["left"]),
        "right": diff_side_ref(doc["right"]),
        "diff": doc["diff"],
    }
    check(diff_hash(payload) == doc["diff_hash"], "diff_hash mismatch")
    counts = recomputed["counts"]
    return (f"OK comparison: +{counts['added']}/-{counts['removed']}/"
            f"~{counts['changed']} (unchanged {counts['unchanged']}), "
            f"diff_hash {doc['diff_hash'][:16]}… verified")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    try:
        raw = sys.stdin.read() if argv[1] == "-" else open(argv[1], encoding="utf-8").read()
        doc = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAILED: cannot read JSON input: {exc}", file=sys.stderr)
        return 2
    try:
        print(verify_comparison(doc))
    except Failure as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1
    except (KeyError, TypeError) as exc:
        print(f"FAILED: malformed comparison document: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
