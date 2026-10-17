"""Offline-only, non-authorizing compare-snapshot -> path-overlap preview.

Input must be a separately obtained and independently checked *normalized*
snapshot bundle. This does not call GitHub or attest a snapshot's origin,
file completeness, consent, release readiness or branch SHA validity.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

_PARENT = Path(__file__).resolve().with_name("review_scope_worker_overlap_offline_1540.py")
_spec = importlib.util.spec_from_file_location("scope1540_reviewer", _PARENT)
review = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(review)

_INPUT_FIELDS = {"version", "base_sha", "snapshots"}
_SNAPSHOT_FIELDS = {"worker", "branch", "base_sha", "head_sha",
                    "compare_status", "ahead_by", "behind_by",
                    "too_large", "expected_file_count", "files"}
_OPERATIONS = {"added": "add", "modified": "modify", "removed": "delete",
               "renamed": "rename", "copied": "copy"}


def _sha(value):
    return type(value) is str and review.PIN.fullmatch(value) is not None


def _convert(raw: bytes) -> bytes:
    doc = review._canonical_decode(raw)
    if type(doc) is not dict or set(doc) != _INPUT_FIELDS:
        raise review.InvalidProposal("snapshot root schema")
    if type(doc["version"]) is not int or doc["version"] != 1:
        raise review.InvalidProposal("snapshot version")
    base = doc["base_sha"]
    if not _sha(base):
        raise review.InvalidProposal("snapshot base")
    source = doc["snapshots"]
    if type(source) is not list or not 2 <= len(source) <= 32:
        raise review.InvalidProposal("snapshot count")
    normalized = []
    seen_heads = set()
    for snap in source:
        if type(snap) is not dict or set(snap) != _SNAPSHOT_FIELDS:
            raise review.InvalidProposal("snapshot field set")
        if (not _sha(snap["base_sha"]) or snap["base_sha"] != base
                or not _sha(snap["head_sha"])):
            raise review.InvalidProposal("snapshot refs")
        if snap["head_sha"] in seen_heads:
            raise review.InvalidProposal("duplicate source commit head")
        seen_heads.add(snap["head_sha"])
        if type(snap["compare_status"]) is not str or snap["compare_status"] != "ahead":
            raise review.InvalidProposal("snapshot compare relation")
        if (type(snap["ahead_by"]) is not int or not 1 <= snap["ahead_by"] <= 10000
                or type(snap["behind_by"]) is not int or snap["behind_by"] != 0
                or snap["too_large"] is not False):
            raise review.InvalidProposal("incomplete or divergent compare")
        files = snap["files"]
        expected = snap["expected_file_count"]
        if (type(expected) is not int or not 1 <= expected <= 64
                or type(files) is not list or len(files) != expected):
            raise review.InvalidProposal("incomplete file inventory")
        changes = []
        for file in files:
            if type(file) is not dict or "status" not in file or "filename" not in file:
                raise review.InvalidProposal("file schema")
            op = file["status"]
            if type(op) is not str or op not in _OPERATIONS:
                raise review.InvalidProposal("file status")
            if op in {"renamed", "copied"}:
                if set(file) != {"status", "filename", "previous_filename"}:
                    raise review.InvalidProposal("rename source field")
                changes.append({"op": _OPERATIONS[op], "path": file["filename"],
                                "from_path": file["previous_filename"]})
            else:
                if set(file) != {"status", "filename"}:
                    raise review.InvalidProposal("extra source field")
                changes.append({"op": _OPERATIONS[op], "path": file["filename"]})
        normalized.append({"worker": snap["worker"], "branch": snap["branch"],
                           "base_sha": base, "changes": changes})
    # The core validator owns ALL path, branch, worker, casefold and prefix
    # collision semantics. This adapter provides no independent approval.
    return json.dumps({"version": 2, "base_sha": base,
                       "proposals": normalized}, ensure_ascii=True,
                      sort_keys=True, separators=(",", ":")).encode("ascii")


def check(raw: bytes) -> str:
    try:
        prepared = _convert(raw)
        return review.check(prepared)
    except (review.InvalidProposal, UnicodeError, ValueError, TypeError,
            OverflowError, RecursionError, MemoryError):
        return "HOLD"


def main():
    try:
        data = sys.stdin.buffer.read(review.MAX_INPUT + 1)
        status = check(data)
    except (ValueError, OSError, MemoryError):
        status = "HOLD"
    sys.stdout.write(review._receipt(status) + "\n")
    return 3 if status == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
