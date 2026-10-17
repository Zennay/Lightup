#!/usr/bin/env python3
"""Bounded fictional, non-authorizing LightUp PR dependency topology reviewer."""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict

MAX_INPUT = 131072
MAX_ENTRIES = 64
MAX_DEPS = 16
SHA = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
OWNER = re.compile(r"[a-z][a-z0-9-]{0,39}\Z", re.ASCII)
OFF_FLAGS = {key: False for key in (
    "can_authorize", "can_scan", "can_grant", "can_dispatch",
    "can_merge", "can_deploy", "can_release",
)}


class InvalidManifest(ValueError):
    """Any ambiguity must result in a generic HOLD, with no input echo."""


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise InvalidManifest("duplicate JSON key")
        output[key] = value
    return output


def _bad_constant(_: str) -> object:
    raise InvalidManifest("nonstandard JSON constant")


def _exact_sha(value: object) -> bool:
    return type(value) is str and value != "0" * 40 and SHA.fullmatch(value) is not None


def _exact_id(value: object) -> bool:
    return type(value) is int and 1 <= value <= 2_147_483_647


def _parse(raw: bytes) -> dict[str, object]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_INPUT:
        raise InvalidManifest("size")
    # All admitted keys and values are ASCII identities. Unicode escapes can
    # conceal byte-different spellings of the same branch/commit claim.
    if b"\\u" in raw:
        raise InvalidManifest("escaped identity")
    try:
        data = json.loads(raw.decode("utf-8", errors="strict"),
                          object_pairs_hook=_unique_pairs, parse_constant=_bad_constant)
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise InvalidManifest("JSON") from exc
    if type(data) is not dict or set(data) != {"version", "root_sha", "entries"}:
        raise InvalidManifest("envelope")
    if type(data["version"]) is not int or data["version"] != 1:
        raise InvalidManifest("version")
    if not _exact_sha(data["root_sha"]):
        raise InvalidManifest("root")
    if type(data["entries"]) is not list or not (1 <= len(data["entries"]) <= MAX_ENTRIES):
        raise InvalidManifest("entries")
    return data


def review(raw: bytes) -> list[list[int]]:
    """Return synthetic waves, not authenticated Git history or merge authority."""
    data = _parse(raw)
    root = data["root_sha"]
    by_id: dict[int, dict] = {}
    heads: set[str] = set()
    for entry in data["entries"]:
        if type(entry) is not dict or set(entry) != {"id", "owner", "head_sha", "base_sha", "depends_on"}:
            raise InvalidManifest("entry shape")
        number = entry["id"]
        owner = entry["owner"]
        head = entry["head_sha"]
        base = entry["base_sha"]
        deps = entry["depends_on"]
        if not _exact_id(number) or number in by_id:
            raise InvalidManifest("entry identity")
        if type(owner) is not str or OWNER.fullmatch(owner) is None or owner.endswith("-"):
            raise InvalidManifest("owner")
        if not _exact_sha(head) or not _exact_sha(base) or head in heads or head == root or head == base:
            raise InvalidManifest("SHA identity")
        if type(deps) is not list or len(deps) > MAX_DEPS:
            raise InvalidManifest("dependencies")
        if any(not _exact_id(d) for d in deps) or len(deps) != len(set(deps)) or number in deps:
            raise InvalidManifest("dependency identity")
        heads.add(head)
        by_id[number] = entry

    children: dict[int, set[int]] = defaultdict(set)
    remaining: dict[int, int] = {}
    for number, entry in by_id.items():
        deps = entry["depends_on"]
        if any(dep not in by_id for dep in deps):
            raise InvalidManifest("unknown dependency")
        # Deliberately restrictive advisory claim: root nodes must claim the
        # common base; stacked nodes must identify their exact base predecessor.
        if not deps and entry["base_sha"] != root:
            raise InvalidManifest("orphan base")
        if deps and entry["base_sha"] not in {by_id[d]["head_sha"] for d in deps}:
            raise InvalidManifest("base is not an explicit predecessor")
        remaining[number] = len(deps)
        for dep in deps:
            children[dep].add(number)

    waves: list[list[int]] = []
    frontier = sorted(n for n, count in remaining.items() if count == 0)
    visited = 0
    while frontier:
        waves.append(frontier)
        visited += len(frontier)
        next_frontier: list[int] = []
        for node in frontier:
            for child in sorted(children[node]):
                remaining[child] -= 1
                if remaining[child] == 0:
                    next_frontier.append(child)
        frontier = sorted(next_frontier)
    if visited != len(by_id):
        raise InvalidManifest("cycle")
    return waves


def evaluate(raw: bytes) -> tuple[dict[str, object], int]:
    try:
        waves = review(raw)
    except (InvalidManifest, ValueError, UnicodeError, TypeError, RecursionError, MemoryError):
        return {"status": "HOLD", "waves": [], **OFF_FLAGS}, 2
    return {"status": "REVIEW_ONLY", "waves": waves, **OFF_FLAGS}, 3


def _read_complete_input(stream: object) -> bytes:
    """Do not review a valid prefix until the complete bounded stream hits EOF.

    A short positive read is NOT EOF. Reject invalid stream types and I/O
    anomalies without emitting a review of an earlier valid prefix.
    """
    parts: list[bytes] = []
    size = 0
    while True:
        allowance = min(4096, MAX_INPUT + 1 - size)
        if allowance <= 0:
            raise InvalidManifest("oversize stdin")
        piece = stream.read(allowance)
        if type(piece) is not bytes or len(piece) > allowance:
            raise InvalidManifest("noncanonical stdin chunk")
        if not piece:
            break
        size += len(piece)
        if size > MAX_INPUT:
            raise InvalidManifest("oversize stdin")
        parts.append(piece)
    return b"".join(parts)


def main() -> int:
    try:
        if len(sys.argv) != 1:
            raise InvalidManifest("unexpected CLI arguments")
        raw = _read_complete_input(sys.stdin.buffer)
        receipt, code = evaluate(raw)
    except (OSError, ValueError, TypeError, MemoryError):
        receipt, code = {"status": "HOLD", "waves": [], **OFF_FLAGS}, 2
    try:
        line = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
        count = sys.stdout.write(line)
        sys.stdout.flush()
        if count != len(line):
            return 2
    except (OSError, ValueError, UnicodeError, TypeError):
        return 2
    return code


if __name__ == "__main__":
    sys.exit(main())
