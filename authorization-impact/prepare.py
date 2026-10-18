#!/usr/bin/env python3
"""Prepare a private, non-authorizing offline Scope Impact Map handoff.

Only original, previously exported Casebook source files are accepted.
This command does NOT log in, query a database, authorize, revoke, or execute.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

SOURCE_LIMIT = 524288
APP_LIMIT = 524288
FALSE_FLAGS = (
    "source_authenticated",
    "client_consent_verified",
    "operator_consent_verified",
    "authorization_granted",
    "execution_allowed",
    "release_approved",
)


class Refused(Exception):
    """Reject malformed, ambiguous, or unsafe operator inputs."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Refused("duplicate key")
        result[key] = value
    return result


def _constant(_: str) -> Any:
    raise Refused("nonfinite constant")


def _literal(value: object) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 180
        and all(31 < ord(c) != 127 for c in value)
    )


def _count(value: object, upper: int) -> bool:
    return type(value) is int and 0 <= value <= upper


def _read_private(path: Path, limit: int, require_private: bool = True) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise Refused("no safe no-follow support")
    descriptor = os.open(path, flags | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or (require_private and before.st_mode & 0o077):
            raise Refused("source must be an owner-private regular file")
        if before.st_size < 2 or before.st_size > limit:
            raise Refused("source length")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            block = os.read(descriptor, min(65536, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(raw) != before.st_size or len(raw) > limit:
            raise Refused("source changed during reading")
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            raise Refused("source revision changed")
        return raw
    finally:
        os.close(descriptor)


def _validate_source(raw: bytes) -> None:
    """Admit the same bounded original Casebook contract used by the browser.

    A successfully packaged source must be displayable by standalone.html;
    no partial or contradictory provenance can be repackaged as a handoff.
    """
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_constant,
        )
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise Refused("invalid JSON") from exc
    if (
        type(document) is not dict
        or document.get("schema") != "lightup.auth_casebook.v1"
        or document.get("status") != "REVIEW_ONLY"
        or not _literal(document.get("client_id"))
        or not _literal(document.get("as_of"))
        or not all(document.get(field) is False for field in FALSE_FLAGS)
    ):
        raise Refused("not an original non-authorizing Casebook snapshot")
    counts = document.get("declared_counts")
    if type(counts) is not dict:
        raise Refused("absent aggregate")
    kinds = (
        ("requests", "request_id"),
        ("engagements", "engagement_id"),
        ("grants", "grant_id"),
        ("risk_approvals", "approval_id"),
    )
    identities: dict[str, set[str]] = {}
    for kind, identifier in kinds:
        rows = document.get(kind)
        if type(rows) is not list or len(rows) > 200:
            raise Refused("invalid record family")
        if not _count(counts.get(kind), 200) or counts[kind] != len(rows):
            raise Refused("inconsistent aggregate")
        found: set[str] = set()
        for row in rows:
            if type(row) is not dict or not _literal(row.get(identifier)):
                raise Refused("invalid source record")
            if row[identifier] in found:
                raise Refused("duplicate source ID")
            found.add(row[identifier])
        identities[kind] = found
    count_fields = (
        "grant_link_hold",
        "risk_tenant_hold",
        "case_attention_hold",
        "foreign_tenant_row_count",
        "recorded_window_review",
        "risk_provenance_hold",
        "pending_risk_review",
    )
    if any(not _count(counts.get(name), 500) for name in count_fields):
        raise Refused("invalid source summary")
    overview = document.get("case_overview")
    if type(overview) is not list or len(overview) != len(document["engagements"]):
        raise Refused("invalid original case overview")
    case_ids: set[str] = set()
    case_attentions = {
        "HOLD_SOURCE_PROVENANCE",
        "HOLD_CLOSED_ENGAGEMENT_WITH_GRANTS",
        "RISK_DECISION_PENDING_SOURCE_REVIEW",
        "EXPIRED_GRANT_SOURCE_REVIEW",
        "FUTURE_GRANT_SOURCE_REVIEW",
        "REVIEW_ONLY_UNVERIFIED_GRANT_LINK",
        "NO_GRANT_RECORDED",
    }
    for row in overview:
        if (
            type(row) is not dict
            or not _literal(row.get("engagement_id"))
            or row["engagement_id"] not in identities["engagements"]
            or row["engagement_id"] in case_ids
            or not _literal(row.get("status"))
            or row.get("attention") not in case_attentions
            or not _literal(row.get("next_review_action"))
            or not _count(row.get("grant_count"), 200)
            or not _count(row.get("risk_record_count"), 200)
        ):
            raise Refused("invalid case overview")
        case_ids.add(row["engagement_id"])
        eid = row["engagement_id"]
        if (
            row["grant_count"] != sum(g.get("engagement_id") == eid for g in document["grants"])
            or row["risk_record_count"] != sum(
                r.get("engagement_id") == eid for r in document["risk_approvals"]
            )
        ):
            raise Refused("case/source relationship mismatch")
    if len(case_ids) != len(document["engagements"]):
        raise Refused("incomplete case coverage")
    if counts["case_attention_hold"] != sum(
        row["attention"].startswith("HOLD_") for row in overview
    ):
        raise Refused("case attention summary mismatch")
    for row in document["requests"]:
        if (
            not _literal(row.get("status"))
            or not _literal(row.get("requested_mode"))
            or not _literal(row.get("created_at"))
            or type(row.get("decision_recorded")) is not bool
        ):
            raise Refused("invalid recorded request")
    for row in document["engagements"]:
        if not _literal(row.get("status")) or not _literal(row.get("created_at")):
            raise Refused("invalid recorded engagement")
    window_types = {
        "HOLD_INVALID_RECORDED_WINDOW",
        "EXPIRED_RECORDED_WINDOW",
        "FUTURE_RECORDED_WINDOW",
        "WITHIN_RECORDED_WINDOW_NOT_AUTHORITY",
    }
    for row in document["grants"]:
        if (
            (row.get("engagement_id") is not None and not _literal(row.get("engagement_id")))
            or (row.get("approved_request_id") is not None and not _literal(row.get("approved_request_id")))
            or not _literal(row.get("request_link_observation"))
            or row.get("validity_observation") not in window_types
        ):
            raise Refused("invalid grant record")
    if counts["grant_link_hold"] != sum(
        row["request_link_observation"].startswith("HOLD_") for row in document["grants"]
    ):
        raise Refused("grant link summary mismatch")
    if counts["recorded_window_review"] != sum(
        row["validity_observation"] != "WITHIN_RECORDED_WINDOW_NOT_AUTHORITY"
        for row in document["grants"]
    ):
        raise Refused("grant window summary mismatch")
    risk_types = {
        "HOLD_RISK_SOURCE_IDENTITY_OR_STATUS",
        "HOLD_RISK_PENDING_WITH_DECISION",
        "HOLD_RISK_DECIDER_PROVENANCE",
        "RISK_DECISION_PENDING_REVIEW",
        "RISK_DECISION_RECORDED_UNVERIFIED",
    }
    for row in document["risk_approvals"]:
        if (
            (row.get("engagement_id") is not None and not _literal(row.get("engagement_id")))
            or not _literal(row.get("status"))
            or type(row.get("source_tenant_matches")) is not bool
            or row.get("decision_provenance_observation") not in risk_types
        ):
            raise Refused("invalid recorded risk")
    if counts["risk_provenance_hold"] != sum(
        row["decision_provenance_observation"].startswith("HOLD_")
        for row in document["risk_approvals"]
    ):
        raise Refused("risk provenance summary mismatch")
    if counts["pending_risk_review"] != sum(
        row["decision_provenance_observation"] == "RISK_DECISION_PENDING_REVIEW"
        for row in document["risk_approvals"]
    ):
        raise Refused("pending risk summary mismatch")

def _write_private(dirfd: int, name: str, data: bytes) -> dict[str, object]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(name, flags, 0o600, dir_fd=dirfd)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }


def publish_bytes(
    original: bytes, destination: Path, *,
    fresh_original_auth: bool = False, review_raw: bytes | None = None,
) -> None:
    """Package original source bytes; does not authenticate or change the source.

    The optional provenance label records which trusted caller performed the
    authentication. It does not change the source's six false authority flags.
    """
    if type(original) is not bytes or not 2 <= len(original) <= SOURCE_LIMIT:
        raise Refused("source length")
    _validate_source(original)
    if review_raw is not None:
        # Delayed import deliberately preserves standalone use of prepare.py.
        from review_binding import admit_private_review
        admit_private_review(original, review_raw)
    app = _read_private(Path(__file__).resolve().with_name("standalone.html"), APP_LIMIT, require_private=False)
    from app_integrity import InvalidApp, admit_standalone
    try:
        admit_standalone(app)
    except InvalidApp as exc:
        raise Refused("offline app CSP integrity") from exc

    provenance_note = (
        "Fresh original Casebook password authentication and tenant isolation "
        "preceded this packet. This does not verify action-time consent, STOP "
        "state, grant authority, source authenticity, or future permissions.\\n"
        if fresh_original_auth else
        "An existing separately exported Casebook file was locally packaged. "
        "Its origin and freshness are not authenticated by this operation.\\n"
    )
    instructions = (
        "LIGHTUP PRIVATE SCOPE IMPACT MAP — REVIEW_ONLY / HOLD\\n\\n"
        "1. Open standalone.html in an offline browser.\\n"
        "2. Import casebook.json through 'Load PRIVATE Casebook JSON'.\\n"
        "3. Inspect source links and add human-only notes.\\n"
        "4. Export counts or confirm a PRIVATE recipient for human notes.\\n"
        + ("5. If present, restore PRIVATE-review.json through Restore PRIVATE notes.\\n" if review_raw is not None else "")
        + "\\n"
        + provenance_note
        + "Recorded source state is retrospective; no current live authorization.\\n"
        "A SHA-256 is a byte fingerprint, not an issuer signature.\\n"
        "Keep the entire folder owner-only and never upload PRIVATE data.\\n"
        "No network/model/scan/consent/grant/STOP/release change occurs here.\\n"
        "Original CI, owner/security/privacy, actual separate consent and "
        "action-time revocation plus HUMAN GO remain required.\\n"
    ).encode("utf-8")

    # Creating the final name exclusively means no previous workspace can be
    # replaced, even on a retry. Clean up only files created by this command.
    os.mkdir(destination, 0o700)
    dirfd: int | None = None
    created: list[str] = []
    complete = False
    try:
        dirfd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        os.fchmod(dirfd, 0o700)
        files: dict[str, dict[str, object]] = {}
        for name, raw in (
            ("casebook.json", original),
            ("standalone.html", app),
            ("START-HERE.txt", instructions),
        ):
            created.append(name)
            files[name] = _write_private(dirfd, name, raw)
        if review_raw is not None:
            created.append("PRIVATE-review.json")
            files["PRIVATE-review.json"] = _write_private(dirfd, "PRIVATE-review.json", review_raw)
        manifest = {
            "schema": "lightup.scope_impact_workspace.v1",
            "status": "REVIEW_ONLY",
            "authority": {name: False for name in FALSE_FLAGS},
            "files": files,
            "source_authenticated": False,
            "notes": "Checksums are untrusted byte fingerprints, not issuer/consent proof.",
        }
        created.append("manifest.json")
        _write_private(
            dirfd, "manifest.json",
            (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
        os.fsync(dirfd)
        complete = True
    except BaseException:
        if dirfd is not None:
            for name in reversed(created):
                try:
                    os.unlink(name, dir_fd=dirfd)
                except OSError:
                    pass
        raise
    finally:
        if dirfd is not None:
            os.close(dirfd)
        # Leave no incomplete workspace. Never remove a pre-existing directory.
        if not complete:
            try:
                os.rmdir(destination)
            except OSError:
                pass


def publish(source: Path, destination: Path, *, review: Path | None = None) -> None:
    """Strict original private-source and optional matching human-note handoff."""
    original = _read_private(source, SOURCE_LIMIT)
    review_raw = _read_private(review, 262144) if review is not None else None
    publish_bytes(original, destination, review_raw=review_raw)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Package a private existing authenticated Casebook JSON for offline human source review."
    )
    parser.add_argument("casebook", type=Path, help="Existing original 0600 Casebook JSON")
    parser.add_argument("workspace", type=Path, help="New exclusively created private directory")
    parser.add_argument("--review", type=Path, help="Optional owner-private human note JSON for this EXACT source revision")
    args = parser.parse_args()
    try:
        publish(args.casebook, args.workspace, review=args.review)
    except (Refused, OSError, ValueError, TypeError):
        print("HOLD: private original-source handoff was refused; check source and permissions.", file=sys.stderr)
        return 3
    print("REVIEW_ONLY: owner-private offline Scope Impact Map workspace created; never authorization.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
