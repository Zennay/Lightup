"""Offline, non-authorizing GitHub changed-file completeness review (#1553).

This accepts only fictional caller-supplied metadata: it NEVER contacts GitHub,
verifies a caller's identity, verifies actual Git ancestry, or issues authority.
Even coherent data can produce only REVIEW_ONLY (exit 3), never an approval.
"""
from __future__ import annotations

import json
import re
import sys
from typing import Any

_VERSION = "LIGHTUP-FICTIONAL-GITHUB-FILE-COVERAGE-V1"
_MAX_INPUT_BYTES = 131_072
_MAX_FILES = 300  # GitHub compare file arrays are bounded; larger reviews HOLD.
_MAX_FILENAME_BYTES = 4096
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_FIELDS = frozenset({
    "version", "synthetic_only", "expected_base_sha", "expected_head_sha",
    "observed_base_sha", "observed_head_sha", "expected_changed_files",
    "files", "has_next_page", "truncated",
})
_FILE_FIELDS = frozenset({"filename"})
_DENIED = ("authorize", "grant", "scan", "handler", "dispatch",
           "merge", "deploy", "release")


def _reject(*_: object) -> None:
    # Deliberately discard file paths and untrusted content from all errors.
    raise ValueError("ambiguous offline coverage metadata")


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            _reject()
        out[key] = value
    return out


def _parse_constant(_: str) -> None:
    _reject()


def _sha(value: object) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def _good_path(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        return False
    # A lexical identity check only. It is NOT Git/OS path validation.
    return (0 < size <= _MAX_FILENAME_BYTES
            and not value.startswith("/")
            and not value.endswith("/")
            and "\\" not in value
            and all(ord(c) >= 32 and ord(c) != 127 for c in value)
            and all(part not in ("", ".", "..") for part in value.split("/")))


def review(payload: object) -> dict[str, object]:
    """Return fixed, privacy-minimal HOLD or REVIEW_ONLY; never approve.

    Caller-provided 'expected_changed_files' is not verified provenance. The
    check only detects inconsistencies; matched counts cannot prove completeness.
    """
    status = "HOLD"
    if type(payload) is dict and set(payload) == _FIELDS:
        if (
            payload["version"] == _VERSION
            and type(payload["version"]) is str
            and payload["synthetic_only"] is True
            and all(_sha(payload[k]) for k in (
                "expected_base_sha", "expected_head_sha",
                "observed_base_sha", "observed_head_sha"))
            and payload["expected_base_sha"] == payload["observed_base_sha"]
            and payload["expected_head_sha"] == payload["observed_head_sha"]
            and payload["expected_base_sha"] != payload["expected_head_sha"]
            and type(payload["expected_changed_files"]) is int
            and 1 <= payload["expected_changed_files"] <= _MAX_FILES
            and type(payload["has_next_page"]) is bool
            and payload["has_next_page"] is False
            and type(payload["truncated"]) is bool
            and payload["truncated"] is False
            and type(payload["files"]) is list
            and len(payload["files"]) == payload["expected_changed_files"]
        ):
            paths: set[str] = set()
            for entry in payload["files"]:
                if type(entry) is not dict or set(entry) != _FILE_FIELDS:
                    break
                name = entry["filename"]
                if not _good_path(name) or name in paths:
                    break
                paths.add(name)
            else:
                status = "REVIEW_ONLY"

    result: dict[str, object] = {
        "status": status,
        "reason": ("metadata_consistent_not_verified"
                   if status == "REVIEW_ONLY" else "ambiguous_or_incomplete"),
        "not_authorization": True,
    }
    result.update({flag: False for flag in _DENIED})
    return result


def review_json(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or len(raw) > _MAX_INPUT_BYTES:
        _reject()
    payload = json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=_strict_pairs,
        parse_constant=_parse_constant,
    )
    return review(payload)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    verdict: dict[str, object]
    try:
        if args != ["--synthetic-only"]:
            _reject()
        raw = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
        verdict = review_json(raw)
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        verdict = review(None)
    # No user-supplied fields, filenames, SHA values or exceptions in output.
    sys.stdout.write(json.dumps(verdict, sort_keys=True, separators=(",", ":")) + "\n")
    return 3 if verdict["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
