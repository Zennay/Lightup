"""Fail-closed, offline overlap preview for fictional scope-worker change lists.

This is NOT evidence of real GitHub provenance or permission to merge/deploy.
It never reads git, files, networks, credentials, grants or authorization state.
"""
from __future__ import annotations

import json
import re
import sys

MAX_INPUT = 65536
PIN = re.compile(r"[0-9a-f]{40}\Z")
WORKER = re.compile(r"[a-z][a-z0-9_-]{1,47}\Z")
BRANCH = re.compile(r"[A-Za-z0-9_./-]{1,120}\Z")
SEGMENT = re.compile(r"[A-Za-z0-9_@+.-]{1,100}\Z")
FLAGS = ("authorized", "consent_verified", "dispatch_allowed",
         "merge_allowed", "deploy_allowed", "release_allowed")


class InvalidProposal(ValueError):
    """Malformed, untrusted or overlapping candidate changes."""


def _pairs(items):
    out = {}
    for name, value in items:
        if name in out:
            raise InvalidProposal("duplicate key")
        out[name] = value
    return out


def _reject_constant(_value):
    raise InvalidProposal("nonstandard JSON number")


def _safe_branch(value):
    return (type(value) is str and BRANCH.fullmatch(value) is not None
            and not value.startswith(("/", "-"))
            and not value.endswith(("/", "."))
            and ".." not in value
            and all(part not in (".", "..") for part in value.split("/"))
            and all(part for part in value.split("/")))


def _safe_path(value):
    if type(value) is not str or len(value) > 240 or not value:
        return False
    parts = value.split("/")
    return (len(parts) <= 16 and all(
        part not in (".", "..") and SEGMENT.fullmatch(part) is not None
        and not part.endswith(".") for part in parts))


def _canonical_decode(raw):
    if type(raw) is not bytes or not raw or len(raw) > MAX_INPUT:
        raise InvalidProposal("invalid input size")
    try:
        data = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                          parse_constant=_reject_constant)
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise InvalidProposal("invalid JSON") from exc
    # No alternate spellings, key orderings, whitespace or escaped aliases.
    try:
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True, allow_nan=False).encode("ascii")
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise InvalidProposal("noncanonical JSON") from exc
    if raw != canonical:
        raise InvalidProposal("noncanonical JSON")
    return data


def _conflicts(candidate: str, existing: set[str]) -> bool:
    return any(candidate == old or candidate.startswith(old + "/")
               or old.startswith(candidate + "/") for old in existing)


def _versioned_paths(item: dict, version: int) -> list[str]:
    """Flatten both sides of renames/copies; no Git path semantics inferred."""
    if version == 1:
        if set(item) != {"worker", "branch", "base_sha", "paths"}:
            raise InvalidProposal("v1 worker schema")
        paths = item["paths"]
        if type(paths) is not list or not (1 <= len(paths) <= 64):
            raise InvalidProposal("v1 path count")
        return paths

    if set(item) != {"worker", "branch", "base_sha", "changes"}:
        raise InvalidProposal("v2 worker schema")
    changes = item["changes"]
    if type(changes) is not list or not (1 <= len(changes) <= 64):
        raise InvalidProposal("v2 change count")
    paths = []
    for entry in changes:
        if type(entry) is not dict:
            raise InvalidProposal("v2 change schema")
        if set(entry) == {"op", "path"}:
            if type(entry["op"]) is not str or entry["op"] not in {
                    "add", "modify", "delete"}:
                raise InvalidProposal("v2 operation")
            paths.append(entry["path"])
        elif set(entry) == {"op", "path", "from_path"}:
            if type(entry["op"]) is not str or entry["op"] not in {
                    "rename", "copy"}:
                raise InvalidProposal("v2 source operation")
            paths.extend((entry["path"], entry["from_path"]))
        else:
            raise InvalidProposal("v2 fields")
    return paths


def check(raw: bytes) -> str:
    """Return REVIEW_ONLY or HOLD; never return an authorizing verdict.

    V1 accepts each worker's affected paths. V2 additionally accepts explicit
    bounded changes with both source and destination identities for rename/
    copy. Both protocols are fictional, read-only, and provenance-unverified.
    """
    try:
        doc = _canonical_decode(raw)
        if type(doc) is not dict or set(doc) != {"version", "base_sha", "proposals"}:
            raise InvalidProposal("schema")
        version = doc["version"]
        if type(version) is not int or version not in (1, 2):
            raise InvalidProposal("version")
        pin = doc["base_sha"]
        if type(pin) is not str or PIN.fullmatch(pin) is None:
            raise InvalidProposal("base")
        items = doc["proposals"]
        if type(items) is not list or not (2 <= len(items) <= 32):
            raise InvalidProposal("proposal count")
        workers, branches, prior_paths = set(), set(), set()
        for item in items:
            if type(item) is not dict:
                raise InvalidProposal("proposal shape")
            paths = _versioned_paths(item, version)
            worker, branch, base = item["worker"], item["branch"], item["base_sha"]
            if type(worker) is not str or WORKER.fullmatch(worker) is None:
                raise InvalidProposal("worker")
            if not _safe_branch(branch) or type(base) is not str or base != pin:
                raise InvalidProposal("branch or base")
            if worker in workers or branch.casefold() in branches:
                raise InvalidProposal("duplicate owner")
            workers.add(worker)
            branches.add(branch.casefold())
            local_paths = set()
            for path in paths:
                if not _safe_path(path):
                    raise InvalidProposal("path")
                folded = path.casefold()
                if _conflicts(folded, local_paths):
                    raise InvalidProposal("duplicate or parent-child path")
                local_paths.add(folded)
            for current in local_paths:
                if _conflicts(current, prior_paths):
                    raise InvalidProposal("cross-worker overlap")
            prior_paths.update(local_paths)
        return "REVIEW_ONLY"
    except (InvalidProposal, OverflowError, RecursionError, MemoryError):
        return "HOLD"


def _receipt(status):
    receipt = {"status": status}
    receipt.update({name: False for name in FLAGS})
    return json.dumps(receipt, sort_keys=True, separators=(",", ":"))


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        status = check(raw)
    except (OSError, ValueError, MemoryError):
        status = "HOLD"
    sys.stdout.write(_receipt(status) + "\n")
    return 3 if status == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
