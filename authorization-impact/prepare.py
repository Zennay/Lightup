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
    overview = document.get("case_overview")
    if type(overview) is not list or len(overview) != len(document["engagements"]):
        raise Refused("invalid original case overview")
    for key in (
        "grant_link_hold",
        "risk_tenant_hold",
        "case_attention_hold",
        "foreign_tenant_row_count",
        "recorded_window_review",
        "risk_provenance_hold",
        "pending_risk_review",
    ):
        if not _count(counts.get(key), 500):
            raise Refused("invalid source summary")


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


def publish(source: Path, destination: Path) -> None:
    original = _read_private(source, SOURCE_LIMIT)
    _validate_source(original)
    app = _read_private(Path(__file__).resolve().with_name("standalone.html"), APP_LIMIT, require_private=False)
    if b"<title>LightUp | Scope Impact Map</title>" not in app:
        raise Refused("unexpected bundled app")

    instructions = (
        "LIGHTUP PRIVATE SCOPE IMPACT MAP — REVIEW_ONLY / HOLD\n\n"
        "1. Open standalone.html in an offline browser.\n"
        "2. Import casebook.json through 'Load PRIVATE Casebook JSON'.\n"
        "3. Inspect stored source relationships and add human-only notes.\n"
        "4. Export anonymous counts, or confirm a private recipient for PRIVATE notes.\n\n"
        "The source was exported separately by the unchanged original Casebook\n"
        "authentication workflow. This packaging step does not authenticate\n"
        "its origin, assert current consent, revoke a grant or authorize scans.\n"
        "A SHA-256 is only a byte revision identifier, not proof of issuer.\n"
        "The entire folder contains private information: keep access owner-only.\n"
        "No network, model, grant, STOP, scan, deployment or authorization work.\n"
        "Mandatory original approvals, current revocation and HUMAN GO remain.\n"
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Package a private existing authenticated Casebook JSON for offline human source review."
    )
    parser.add_argument("casebook", type=Path, help="Existing original 0600 Casebook JSON")
    parser.add_argument("workspace", type=Path, help="New exclusively created private directory")
    args = parser.parse_args()
    try:
        publish(args.casebook, args.workspace)
    except (Refused, OSError, ValueError, TypeError):
        print("HOLD: private original-source handoff was refused; check source and permissions.", file=sys.stderr)
        return 3
    print("REVIEW_ONLY: owner-private offline Scope Impact Map workspace created; never authorization.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
