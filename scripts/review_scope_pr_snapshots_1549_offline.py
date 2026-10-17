#!/usr/bin/env python3
"""Offline, non-authorizing normalized draft-PR snapshot -> review DAG adapter.

All input is an untrusted *claim*. This tool never calls GitHub, Git, a
network service, or an authorization/runtime API. Review-only is NOT approval.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

# Fixed adjacent module is part of the same exclusively owned, mode-pinned
# GitHub branch. -I intentionally drops the script directory from sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import review_scope_pr_dependencies_1549_offline as core  # noqa: E402

SNAPSHOT_KEYS = frozenset({"version", "root_sha", "pull_requests"})
PR_KEYS = frozenset({"number", "owner", "head_sha", "base_sha", "state", "draft"})
OFF_FLAGS = {**core.OFF_FLAGS, "source_authenticated": False, "merge_plan_approved": False}


def _receipt(status: str, waves: list[list[int]] | None = None) -> dict[str, object]:
    return {"status": status, "protocol": "PR_SNAPSHOT_V1",
            "waves": [] if waves is None else waves, **OFF_FLAGS}


def _transform(raw: bytes) -> bytes:
    if type(raw) is not bytes or not raw or len(raw) > core.MAX_INPUT or b"\\u" in raw:
        raise core.InvalidManifest("noncanonical snapshot")
    try:
        doc = json.loads(raw.decode("utf-8", "strict"),
                         object_pairs_hook=core._unique_pairs,
                         parse_constant=core._bad_constant)
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise core.InvalidManifest("snapshot JSON") from exc
    if type(doc) is not dict or doc.keys() != SNAPSHOT_KEYS:
        raise core.InvalidManifest("snapshot schema")
    if type(doc["version"]) is not int or doc["version"] != 1:
        raise core.InvalidManifest("snapshot version")
    root = doc["root_sha"]
    if not core._exact_sha(root):
        raise core.InvalidManifest("snapshot root")
    rows = doc["pull_requests"]
    if type(rows) is not list or not 1 <= len(rows) <= core.MAX_ENTRIES:
        raise core.InvalidManifest("snapshot count")

    heads: dict[str, int] = {}
    normalized: list[dict[str, object]] = []
    seen_numbers: set[int] = set()
    for row in rows:
        if type(row) is not dict or row.keys() != PR_KEYS:
            raise core.InvalidManifest("snapshot PR shape")
        number = row["number"]
        head = row["head_sha"]
        base = row["base_sha"]
        if not core._exact_id(number) or number in seen_numbers:
            raise core.InvalidManifest("snapshot PR number")
        if not core._exact_sha(head) or head in heads or head == root or head == base:
            raise core.InvalidManifest("snapshot head")
        if not core._exact_sha(base):
            raise core.InvalidManifest("snapshot base")
        if type(row["state"]) is not str or row["state"] != "open":
            raise core.InvalidManifest("snapshot closed")
        if type(row["draft"]) is not bool or row["draft"] is not True:
            raise core.InvalidManifest("snapshot not draft")
        owner = row["owner"]
        if type(owner) is not str or core.OWNER.fullmatch(owner) is None or owner.endswith("-"):
            raise core.InvalidManifest("snapshot owner")
        seen_numbers.add(number)
        heads[head] = number
        normalized.append(row)

    entries = []
    for row in normalized:
        base = row["base_sha"]
        if base == root:
            deps = []
        else:
            predecessor = heads.get(base)
            if predecessor is None or predecessor == row["number"]:
                raise core.InvalidManifest("unresolved predecessor")
            deps = [predecessor]
        entries.append({
            "id": row["number"], "owner": row["owner"],
            "head_sha": row["head_sha"], "base_sha": base,
            "depends_on": deps,
        })
    return json.dumps({"version": 1, "root_sha": root, "entries": entries},
                      ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def evaluate(raw: bytes) -> tuple[dict[str, object], int]:
    try:
        transformed = _transform(raw)
        receipt, exit_code = core.evaluate(transformed)
        if exit_code != 3:
            return _receipt("HOLD"), 2
        verified = _receipt("REVIEW_ONLY", receipt["waves"])
        verified["input_sha256"] = hashlib.sha256(raw).hexdigest()
        verified["derived_graph_sha256"] = receipt["input_sha256"]
        return verified, 3
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError, MemoryError):
        return _receipt("HOLD"), 2


def main() -> int:
    try:
        if len(sys.argv) != 1:
            raise core.InvalidManifest("unexpected CLI arguments")
        raw = core._read_complete_input(sys.stdin.buffer)
        receipt, exit_code = evaluate(raw)
    except (OSError, ValueError, TypeError, UnicodeError, MemoryError):
        receipt, exit_code = _receipt("HOLD"), 2
    try:
        line = json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
        count = sys.stdout.write(line)
        sys.stdout.flush()
        if type(count) is not int or count != len(line):
            return 2
    except (OSError, ValueError, UnicodeError, TypeError):
        return 2
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
