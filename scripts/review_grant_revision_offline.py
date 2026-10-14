#!/usr/bin/env python3
"""Strict, non-authorizing local JSON entrypoint for grant revision review.

Always exits nonzero: 3=REVIEW_ONLY, 2=HOLD. It cannot grant execution.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import sys

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.grant_revision_batch_review import review_grant_revision_batch


MAX_FILE_BYTES = 65536
GRANT_KEYS = frozenset({
    "grant_id", "client_id", "engagement_id", "approved_by", "reference",
    "scope", "valid_from", "valid_until", "recurring_retest_allowed",
})
SCOPE_KEYS = frozenset({
    "assets", "excluded_assets", "allowed_capabilities", "max_risk",
})
AUTHORITY_FIELDS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "merge_approved", "release_approved",
)


def _duplicate_free_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _no_constant(_: str) -> None:
    raise ValueError("nonfinite number")


def _read_regular_file(path: str) -> object:
    # A symlink, named pipe or character device may leak information or hang;
    # never let an untrusted review CLI read one as a snapshot.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        details = os.fstat(fd)
        if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_FILE_BYTES:
            raise ValueError("untrusted input file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        if not raw or len(raw) > MAX_FILE_BYTES:
            raise ValueError("invalid input size")
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicate_free_object,
            parse_constant=_no_constant,
        )
    finally:
        os.close(fd)


def _text(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= 256:
        raise ValueError("invalid text shape")
    return value


def _tuple_of_text(value: object) -> tuple[str, ...]:
    if type(value) is not list or len(value) > 128:
        raise ValueError("invalid tuple shape")
    return tuple(_text(item) for item in value)


def _utc(value: object) -> datetime:
    if type(value) is not str or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        value,
    ) is None:
        raise ValueError("noncanonical UTC")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _scope(value: object) -> ScopeDefinition:
    if type(value) is not dict or frozenset(value) != SCOPE_KEYS:
        raise ValueError("invalid scope fields")
    risk = value["max_risk"]
    if type(risk) is not int:
        raise ValueError("invalid risk identity")
    try:
        canonical_risk = RiskLevel(risk)
    except ValueError as exc:
        raise ValueError("invalid risk value") from exc
    return ScopeDefinition(
        assets=_tuple_of_text(value["assets"]),
        excluded_assets=_tuple_of_text(value["excluded_assets"]),
        allowed_capabilities=_tuple_of_text(value["allowed_capabilities"]),
        max_risk=canonical_risk,
    )


def _grant(value: object) -> AuthorizationGrant:
    if type(value) is not dict or frozenset(value) != GRANT_KEYS:
        raise ValueError("invalid grant fields")
    if type(value["recurring_retest_allowed"]) is not bool:
        raise ValueError("invalid retest identity")
    return AuthorizationGrant(
        grant_id=_text(value["grant_id"]),
        client_id=_text(value["client_id"]),
        engagement_id=_text(value["engagement_id"]),
        approved_by=_text(value["approved_by"]),
        reference=_text(value["reference"]),
        scope=_scope(value["scope"]),
        valid_from=_utc(value["valid_from"]),
        valid_until=_utc(value["valid_until"]),
        recurring_retest_allowed=value["recurring_retest_allowed"],
    )


def _batch(value: object) -> tuple[tuple[AuthorizationGrant, AuthorizationGrant], ...]:
    if type(value) is not dict or frozenset(value) != {"revisions"}:
        raise ValueError("invalid envelope")
    revisions = value["revisions"]
    if type(revisions) is not list or not 1 <= len(revisions) <= 32:
        raise ValueError("invalid revision count")
    result = []
    for row in revisions:
        if type(row) is not dict or frozenset(row) != {"current", "proposed"}:
            raise ValueError("invalid pair")
        result.append((_grant(row["current"]), _grant(row["proposed"])))
    return tuple(result)


def review_local_file(path: str) -> dict[str, object]:
    try:
        snapshot = _batch(_read_regular_file(path))
        result = review_grant_revision_batch(snapshot)
        fields: dict[str, object] = {
            "verdict": result.verdict,
            "reason_code": result.reason_code,
            "reviewed_count": result.reviewed_count,
            "narrowed_count": result.narrowed_count,
        }
    except (OSError, ValueError, TypeError, OverflowError, UnicodeError, RecursionError):
        fields = {
            "verdict": "HOLD", "reason_code": "invalid_offline_snapshot",
            "reviewed_count": 0, "narrowed_count": 0,
        }
    fields.update({key: False for key in AUTHORITY_FIELDS})
    return fields


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline non-authorizing grant revision review")
    parser.add_argument("snapshot", type=Path, help="Local regular JSON file only; never a target")
    args = parser.parse_args(argv)
    result = review_local_file(str(args.snapshot))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 3 if result["verdict"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    sys.exit(main())
