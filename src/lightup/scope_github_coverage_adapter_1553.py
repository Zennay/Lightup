"""Opt-in fail-closed adapter preview for synthetic GitHub compare intake (#1553).

Wraps the EXISTING installed GitHub ChangeSet ingestion, without modifying it.
Both the coverage claim and file records are fictional and not authenticated.
No returned output can confer release/scan/grant/dispatch authority.
"""
from __future__ import annotations

import json
import re
import sys
from typing import Any

from .github_changes import github_pull_request_changeset
from .scope_github_file_coverage_1553 import (
    _DENIED, _MAX_INPUT_BYTES, _good_path, _parse_constant, _strict_pairs, review,
)

_MAX_PATCH_BYTES = 32 * 1024
_MAX_CHANGED_LINES = 1_000_000
_RECORD_REQUIRED = frozenset({"filename", "status", "additions", "deletions"})
_RECORD_OPTIONAL = frozenset({"previous_filename", "patch"})
_STATUSES = frozenset({"added", "modified", "removed", "renamed", "copied", "changed"})
_HUNK = re.compile(
    r"@@ -(0|[1-9][0-9]*)(?:,(0|[1-9][0-9]*))? "
    r"\+(0|[1-9][0-9]*)(?:,(0|[1-9][0-9]*))? @@(?: .*)?\Z"
)


def _complete_patch_stats(patch: str, status: str) -> tuple[int, int] | None:
    """Reject inconsistent hunk coverage and status, never authenticate Git.

    The old/new file-coordinate gaps between consecutive hunks must be equal:
    those omitted regions are unchanged context, not unexplained edits.
    """
    if not patch or "\r" in patch:
        return None
    lines = patch.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    seen_hunk = False
    additions = removals = 0
    old_remaining = new_remaining = 0
    last_old_end: int | None = None
    last_new_end: int | None = None
    for line in lines:
        match = _HUNK.fullmatch(line)
        if match is not None:
            if seen_hunk and (old_remaining or new_remaining):
                return None
            old_start, new_start = int(match.group(1)), int(match.group(3))
            old_count = int(match.group(2) if match.group(2) is not None else 1)
            new_count = int(match.group(4) if match.group(4) is not None else 1)
            if any(n > _MAX_CHANGED_LINES for n in (
                old_start, new_start, old_count, new_count
            )):
                return None
            if (old_count > 0 and old_start == 0) or (new_count > 0 and new_start == 0):
                return None
            if status == "added" and (old_start != 0 or old_count != 0):
                return None
            if status == "removed" and (new_start != 0 or new_count != 0):
                return None
            if last_old_end is not None and last_new_end is not None:
                old_gap = old_start - last_old_end
                new_gap = new_start - last_new_end
                if old_gap < 0 or new_gap < 0 or old_gap != new_gap:
                    return None
            last_old_end = old_start + old_count
            last_new_end = new_start + new_count
            old_remaining, new_remaining = old_count, new_count
            seen_hunk = True
        elif not seen_hunk:
            return None
        elif line.startswith("+"):
            additions += 1
            new_remaining -= 1
        elif line.startswith("-"):
            removals += 1
            old_remaining -= 1
        elif line.startswith(" "):
            old_remaining -= 1
            new_remaining -= 1
        elif line == "\\ No newline at end of file":
            pass
        else:
            return None
        if old_remaining < 0 or new_remaining < 0:
            return None
    if (not seen_hunk or additions + removals == 0
            or old_remaining or new_remaining):
        return None
    if status == "added" and removals:
        return None
    if status == "removed" and additions:
        return None
    return additions, removals

def _output(status: str, file_count: int = 0, inferred_signals: int = 0) -> dict[str, object]:
    result: dict[str, object] = {
        "status": status,
        "reason": ("inferred_synthetic_coverage_not_authenticated"
                   if status == "REVIEW_ONLY" else "ambiguous_or_incomplete"),
        "not_authorization": True,
        "file_count": file_count if status == "REVIEW_ONLY" else 0,
        "inferred_signal_count": inferred_signals if status == "REVIEW_ONLY" else 0,
    }
    result.update({flag: False for flag in _DENIED})
    return result


def preview(coverage: object, records: object) -> dict[str, object]:
    """Guard the exact real-source adapter call with synthetic metadata matching.

    A successful preview only means the **two caller-provided synthetic views**
    agree, and the existing GitHub ingestion accepted the bounded data.
    It never verifies GitHub, repository ancestry or authentic permissions.
    """
    if review(coverage)["status"] != "REVIEW_ONLY" or type(coverage) is not dict:
        return _output("HOLD")
    expected = coverage["files"]
    if type(records) is not list or len(records) != len(expected):
        return _output("HOLD")

    paths = {entry["filename"] for entry in expected}
    seen: set[str] = set()
    snapshots: list[dict[str, Any]] = []
    for record in records:
        if type(record) is not dict:
            return _output("HOLD")
        keys = set(record)
        if not _RECORD_REQUIRED <= keys or not keys <= (_RECORD_REQUIRED | _RECORD_OPTIONAL):
            return _output("HOLD")

        name = record["filename"]
        status = record["status"]
        if (not _good_path(name) or name not in paths or name in seen
                or type(status) is not str or status not in _STATUSES):
            return _output("HOLD")
        seen.add(name)

        for field in ("additions", "deletions"):
            value = record[field]
            if type(value) is not int or not 0 <= value <= _MAX_CHANGED_LINES:
                return _output("HOLD")

        has_previous = "previous_filename" in record
        if (status == "renamed") != has_previous:
            return _output("HOLD")
        if has_previous and not _good_path(record["previous_filename"]):
            return _output("HOLD")
        if has_previous and record["previous_filename"] == name:
            return _output("HOLD")

        snapshot = {key: record[key] for key in _RECORD_REQUIRED}
        if has_previous:
            snapshot["previous_filename"] = record["previous_filename"]
        # A missing/binary/partial patch hides possibly security-sensitive lines.
        # Never infer a complete change from path metadata alone.
        if "patch" not in record:
            return _output("HOLD")
        patch = record["patch"]
        if type(patch) is not str:
            return _output("HOLD")
        try:
            if len(patch.encode("utf-8")) > _MAX_PATCH_BYTES:
                return _output("HOLD")
        except UnicodeError:
            return _output("HOLD")
        if _complete_patch_stats(patch, status) != (
            record["additions"], record["deletions"]
        ):
            return _output("HOLD")
        snapshot["patch"] = patch
        snapshots.append(snapshot)

    if seen != paths:
        return _output("HOLD")

    try:
        changeset = github_pull_request_changeset(
            client_id="fictional-offline-review",
            repository="fictional/example",
            pr_number=1,
            base_sha=coverage["observed_base_sha"],
            head_sha=coverage["observed_head_sha"],
            files=tuple(snapshots),
            too_large=False,
        )
    except (TypeError, ValueError, KeyError, UnicodeError, RecursionError, OverflowError):
        return _output("HOLD")

    if len(changeset.objects) != len(snapshots):
        return _output("HOLD")
    return _output("REVIEW_ONLY", len(changeset.objects), len(changeset.semantic_signals))


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    result = _output("HOLD")
    try:
        if arguments != ["--synthetic-only"]:
            raise ValueError("wrong mode")
        raw = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
        if len(raw) > _MAX_INPUT_BYTES:
            raise ValueError("too large")
        envelope = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_parse_constant,
        )
        if type(envelope) is dict and set(envelope) == {"coverage", "records"}:
            result = preview(envelope["coverage"], envelope["records"])
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        result = _output("HOLD")
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 3 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
