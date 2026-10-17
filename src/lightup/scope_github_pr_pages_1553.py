"""Offline, non-authorizing adapter for *normalized* GitHub PR file pages (#1553).

Input is fictional and UNAUTHENTICATED. In particular, the snapshots and
pages must eventually be fetched through a trusted, authenticated GitHub
client by a separate source owner. This module has no network, target, grant,
handler, persistence or release capability.
"""
from __future__ import annotations

import json
import re
import sys

from .scope_github_coverage_adapter_1553 import _output, preview
from .scope_github_file_coverage_1553 import (
    _MAX_INPUT_BYTES, _MAX_FILES, _SHA, _VERSION, _parse_constant,
    _strict_pairs, _good_path,
)

_PAGE_SIZE = 100
_SOURCE = "LIGHTUP-FICTIONAL-GITHUB-REST-PAGES-V1"
_META_FIELDS = frozenset({
    "version", "synthetic_only", "repository", "pr_number",
    "base_sha", "head_sha", "changed_files",
})
_PAGE_FIELDS = frozenset({"page", "per_page", "files"})
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


def _metadata_valid(value: object) -> bool:
    if type(value) is not dict or set(value) != _META_FIELDS:
        return False
    repository = value["repository"]
    return (
        type(value["version"]) is str
        and value["version"] == _SOURCE
        and value["synthetic_only"] is True
        and type(repository) is str
        and len(repository) <= 180
        and _REPOSITORY.fullmatch(repository) is not None
        and all(part not in {".", ".."} for part in repository.split("/"))
        and type(value["pr_number"]) is int
        and 1 <= value["pr_number"] <= 1_000_000_000
        and type(value["base_sha"]) is str
        and _SHA.fullmatch(value["base_sha"]) is not None
        and type(value["head_sha"]) is str
        and _SHA.fullmatch(value["head_sha"]) is not None
        and value["base_sha"] != value["head_sha"]
        and type(value["changed_files"]) is int
        and 1 <= value["changed_files"] <= _MAX_FILES
    )


def review_pages(before: object, pages: object, after: object) -> dict[str, object]:
    """Check pagination and PR metadata stability before real source intake.

    A consistent *fictional* set is REVIEW_ONLY, NEVER authenticated or PASS.
    """
    if not _metadata_valid(before) or not _metadata_valid(after):
        return _output("HOLD")
    if before != after or type(pages) is not list:
        return _output("HOLD")

    expected_count = before["changed_files"]
    page_count = (expected_count + _PAGE_SIZE - 1) // _PAGE_SIZE
    if len(pages) != page_count:
        return _output("HOLD")
    all_records: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, page in enumerate(pages, start=1):
        if type(page) is not dict or set(page) != _PAGE_FIELDS:
            return _output("HOLD")
        if type(page["page"]) is not int or page["page"] != index:
            return _output("HOLD")
        if type(page["per_page"]) is not int or page["per_page"] != _PAGE_SIZE:
            return _output("HOLD")
        items = page["files"]
        expected_on_page = min(_PAGE_SIZE, expected_count - len(all_records))
        if type(items) is not list or len(items) != expected_on_page:
            return _output("HOLD")
        for item in items:
            if type(item) is not dict or not _good_path(item.get("filename")):
                return _output("HOLD")
            filename = item["filename"]
            if filename in seen:
                return _output("HOLD")
            seen.add(filename)
            all_records.append(item)

    if len(all_records) != expected_count or len(seen) != expected_count:
        return _output("HOLD")

    # Count/page status are derived from the (fictional) PR metadata and
    # actual supplied pages. They can no longer diverge *inside this gate*.
    claims = {
        "version": _VERSION,
        "synthetic_only": True,
        "expected_base_sha": before["base_sha"],
        "expected_head_sha": before["head_sha"],
        "observed_base_sha": after["base_sha"],
        "observed_head_sha": after["head_sha"],
        "expected_changed_files": expected_count,
        "files": [{"filename": item["filename"]} for item in all_records],
        "has_next_page": False,
        "truncated": False,
    }
    return preview(claims, all_records)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    result = _output("HOLD")
    try:
        if args != ["--synthetic-pages-only"]:
            raise ValueError("unauthorized mode")
        raw = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
        if len(raw) > _MAX_INPUT_BYTES:
            raise ValueError("oversized")
        packet = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_pairs, parse_constant=_parse_constant,
        )
        if type(packet) is dict and set(packet) == {"before", "pages", "after"}:
            result = review_pages(packet["before"], packet["pages"], packet["after"])
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        result = _output("HOLD")
    # Never print caller data/paths/SHAs/diff text or validation exceptions.
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 3 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
