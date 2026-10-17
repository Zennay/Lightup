#!/usr/bin/env python3
"""Offline, non-authorizing normalized draft-PR snapshot -> review DAG adapter.

All input is an untrusted *claim*. This tool never calls GitHub, Git, a
network service, or an authorization/runtime API. Review-only is NOT approval.
"""
from __future__ import annotations

import hashlib
import json
import re
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
    # Canonical semantic graph ordering: permutations change the raw-input
    # digest, but must not change the inferred graph fingerprint.
    entries.sort(key=lambda row: row["id"])
    return json.dumps({"version": 1, "root_sha": root, "entries": entries},
                      ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def _transform_two_read(doc: dict[str, object]) -> bytes:
    """Require two complete, consistent *claims*, never certify provenance."""
    if type(doc) is not dict or set(doc) != {
        "version", "root_sha", "first_read", "second_read"
    } or type(doc["version"]) is not int or doc["version"] != 2:
        raise core.InvalidManifest("double-read schema")
    root = doc["root_sha"]
    if not core._exact_sha(root):
        raise core.InvalidManifest("double-read root")

    graphs: list[bytes] = []
    for key in ("first_read", "second_read"):
        rows = doc[key]
        if type(rows) is not list or not 1 <= len(rows) <= core.MAX_ENTRIES:
            raise core.InvalidManifest("double-read count")
        snapshot = json.dumps(
            {"version": 1, "root_sha": root, "pull_requests": rows},
            ensure_ascii=True, separators=(",", ":"), sort_keys=True,
        ).encode("ascii")
        graphs.append(_transform(snapshot))
    if graphs[0] != graphs[1]:
        raise core.InvalidManifest("stale or conflicting double-read claims")
    return graphs[0]



# V3 is opt-in and *only* compares offline-supplied repository/branch
# claims. It cannot authenticate the issuer, complete PR population, or
# reconstruct Git ancestry. Forked PRs deliberately HOLD in this contract.
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,39}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z", re.ASCII)
REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,119}\Z", re.ASCII)
V3_PR_KEYS = PR_KEYS | frozenset({
    "base_repository", "head_repository", "base_ref", "head_ref",
})


def _valid_repo(value: object) -> bool:
    return (type(value) is str and REPO.fullmatch(value) is not None
            and ".." not in value and not value.endswith(".lock"))


def _valid_ref(value: object) -> bool:
    return (type(value) is str and REF.fullmatch(value) is not None
            and ".." not in value and "//" not in value
            and not value.endswith(("/", ".", ".lock"))
            and all(part and part not in (".", "..") and not part.startswith(".")
                    for part in value.split("/")))


def _transform_three_read_context(doc: dict[str, object]) -> tuple[bytes, str]:
    """Hold unless both untrusted snapshots agree on repo, branches and DAG."""
    if type(doc) is not dict or set(doc) != {
        "version", "repository", "root_sha", "root_ref",
        "first_read", "second_read",
    } or type(doc["version"]) is not int or doc["version"] != 3:
        raise core.InvalidManifest("repo-bound schema")

    repo, root, root_ref = doc["repository"], doc["root_sha"], doc["root_ref"]
    if not (_valid_repo(repo) and core._exact_sha(root) and _valid_ref(root_ref)):
        raise core.InvalidManifest("repo-bound identity")

    graphs: list[bytes] = []
    contexts: list[bytes] = []
    for key in ("first_read", "second_read"):
        rows = doc[key]
        if type(rows) is not list or not 1 <= len(rows) <= core.MAX_ENTRIES:
            raise core.InvalidManifest("repo-bound count")

        refs_by_sha = {root: root_ref}
        used_heads: set[str] = set()
        projected = []
        for row in rows:
            if type(row) is not dict or set(row) != V3_PR_KEYS:
                raise core.InvalidManifest("repo-bound PR shape")
            if row["base_repository"] != repo or row["head_repository"] != repo:
                raise core.InvalidManifest("cross-repository or fork identity")
            base_ref, head_ref = row["base_ref"], row["head_ref"]
            head_sha = row["head_sha"]
            if not (_valid_ref(base_ref) and _valid_ref(head_ref)
                    and head_ref != root_ref
                    and head_ref not in used_heads
                    and core._exact_sha(head_sha)
                    and head_sha not in refs_by_sha):
                raise core.InvalidManifest("invalid or duplicate branch")
            used_heads.add(head_ref)
            refs_by_sha[head_sha] = head_ref
            projected.append({name: row[name] for name in PR_KEYS})

        # Core first checks the bounded DAG, numeric IDs, open/draft state,
        # owner identity, missing predecessors, SHA cycles and root base.
        synthetic = json.dumps(
            {"version": 1, "root_sha": root, "pull_requests": projected},
            separators=(",", ":"), sort_keys=True, ensure_ascii=True,
        ).encode("ascii")
        graph = _transform(synthetic)
        for row in rows:
            if refs_by_sha.get(row["base_sha"]) != row["base_ref"]:
                raise core.InvalidManifest("base ref does not name predecessor")

        context = json.dumps({
            "repository": repo, "root_ref": root_ref, "root_sha": root,
            "rows": sorted(rows, key=lambda row: row["number"]),
        }, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode("ascii")
        graphs.append(graph)
        contexts.append(context)
    if graphs[0] != graphs[1] or contexts[0] != contexts[1]:
        raise core.InvalidManifest("repo/branch drift between reads")
    return graphs[0], hashlib.sha256(contexts[0]).hexdigest()


def evaluate(raw: bytes) -> tuple[dict[str, object], int]:
    protocol = "PR_SNAPSHOT_V1"
    try:
        if type(raw) is not bytes or not raw or len(raw) > core.MAX_INPUT or b"\\u" in raw:
            raise core.InvalidManifest("bounded source bytes required")
        doc = json.loads(raw.decode("utf-8", "strict"),
                         object_pairs_hook=core._unique_pairs,
                         parse_constant=core._bad_constant)
        bound_digest = None
        if type(doc) is dict and type(doc.get("version")) is int and doc["version"] == 3:
            protocol = "PR_SNAPSHOT_V3_REPO_BOUND_DOUBLE_READ"
            transformed, bound_digest = _transform_three_read_context(doc)
        elif type(doc) is dict and type(doc.get("version")) is int and doc["version"] == 2:
            protocol = "PR_SNAPSHOT_V2_DOUBLE_READ"
            transformed = _transform_two_read(doc)
        else:
            transformed = _transform(raw)
            protocol = "PR_SNAPSHOT_V1"
        receipt, exit_code = core.evaluate(transformed)
        if exit_code != 3:
            denied = _receipt("HOLD")
            denied["protocol"] = protocol
            return denied, 2
        verified = _receipt("REVIEW_ONLY", receipt["waves"])
        verified["protocol"] = protocol
        verified["input_sha256"] = hashlib.sha256(raw).hexdigest()
        verified["derived_graph_sha256"] = bound_digest or receipt["input_sha256"]
        return verified, 3
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError, MemoryError):
        denied = _receipt("HOLD")
        denied["protocol"] = protocol
        return denied, 2


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
