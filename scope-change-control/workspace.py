"""Private one-command Casebook source-delta workspace.

Creates one new owner-only directory with the original previous bytes,
a freshly authenticated original Casebook source, the private human review,
an anonymous aggregate, and the existing offline UI. All creation is local,
exclusive and never confers authorization or action-time STOP status.
"""
from __future__ import annotations

import argparse
from getpass import getpass
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys

from lightup.auth_casebook import CasebookHold, authenticated_casebook

from refresh import MAX_SOURCE, ReviewHold, _admit, _diff, _private_read

MAX_UI = 128 * 1024
MAX_WORKSPACE_FILE = 512 * 1024
AUTHORITY = {
    "original_source_verified": False,
    "source_authenticated": False,
    "client_consent_verified": False,
    "operator_consent_verified": False,
    "authorization_granted": False,
    "execution_allowed": False,
    "release_approved": False,
    "action_time_revocation_verified": False,
}
FILES = (
    "OLDER-ORIGINAL.json",
    "NEWER-ORIGINAL.json",
    "PRIVATE-review.json",
    "aggregate.json",
    "standalone.html",
    "START-HERE.txt",
    "manifest.json",
)


def canonical_json(data: object) -> bytes:
    return (json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True,
                       allow_nan=False) + "\n").encode("utf-8")


def read_original_bytes(path: str, expected_digest: str) -> bytes:
    """Re-read via no-follow descriptor and reject changed original bytes."""
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or not 2 <= info.st_size <= MAX_SOURCE):
            raise ReviewHold("private original source not admitted")
        with os.fdopen(fd, "rb") as file:
            fd = None
            raw = file.read(MAX_SOURCE + 1)
        if len(raw) > MAX_SOURCE or sha256(raw).hexdigest() != expected_digest:
            raise ReviewHold("original source changed between reads")
        return raw
    except OSError:
        raise ReviewHold("private original source unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)


def read_local_offline_ui() -> bytes:
    """Copy the existing built browser UI, never execute it or fetch a URL."""
    file = Path(__file__).with_name("standalone.html")
    fd = None
    try:
        fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 100 <= info.st_size <= MAX_UI:
            raise ReviewHold("local portable UI not admitted")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            body = stream.read(MAX_UI + 1)
        # The full bundled UI has no external scripts/styles, network, or storage.
        if (len(body) > MAX_UI or not body.startswith(b"<!doctype html>")
                or b"connect-src 'none'" not in body
                or b"script-src 'sha256-" not in body
                or b"style-src 'sha256-" not in body
                or b'<script>' not in body or b"<style>" not in body
                or b"<script src=" in body or b'<link rel="stylesheet"' in body):
            raise ReviewHold("portable local UI source not admitted")
        return body
    except OSError:
        raise ReviewHold("portable local UI unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)


def publish_private_workspace(destination: str, payloads: dict[str, bytes]) -> None:
    """No-replace directory, no-follow directory fd, 0600 files, manifest last.

    Only our just-created directory can be removed on an ordinary failure.
    Files are written completely and fsynced before the manifest is published.
    """
    if type(destination) is not str or not destination:
        raise ReviewHold("missing private workspace directory")
    path = Path(destination)
    parent_fd = work_fd = None
    created = False
    completed = False
    written: list[str] = []
    try:
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        parent_info = os.fstat(parent_fd)
        if parent_info.st_mode & 0o022:
            raise ReviewHold("workspace parent must not be writable by group/others")
        if path.name in ("", ".", ".."):
            raise ReviewHold("workspace path must be new child directory")
        os.mkdir(path.name, 0o700, dir_fd=parent_fd)
        created = True
        work_fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        os.fchmod(work_fd, 0o700)
        for name in FILES:
            body = payloads[name]
            if type(body) is not bytes or not 1 <= len(body) <= MAX_WORKSPACE_FILE:
                raise ReviewHold("private workspace artifact size not admitted")
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=work_fd)
            written.append(name)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(body)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                os.close(fd)
        os.fsync(work_fd)
        os.fsync(parent_fd)
        completed = True
    except OSError:
        raise ReviewHold("private workspace could not be completed") from None
    finally:
        if work_fd is not None:
            if created and not completed:
                for name in reversed(written):
                    try:
                        os.unlink(name, dir_fd=work_fd)
                    except OSError:
                        pass
            os.close(work_fd)
        if parent_fd is not None:
            if created and not completed:
                try:
                    os.rmdir(path.name, dir_fd=parent_fd)
                except OSError:
                    pass
            os.close(parent_fd)


def prepare(database: str, email: str, password: str, client: str | None,
            previous: str) -> tuple[dict[str, bytes], dict]:
    old, old_digest = _private_read(previous)
    old_index = _admit(old)
    del old_index  # Original per-family shape accepted before authentication.
    now = authenticated_casebook(database, email=email, password=password, client_id=client)
    # A changed original client or source schema fails before writing any packet.
    human = _diff(old, now, old_digest)
    old_bytes = read_original_bytes(previous, old_digest)
    new_bytes = canonical_json(now)
    new_digest = sha256(new_bytes).hexdigest()
    human["source_sha256_unsigned"][1] = new_digest
    human_bytes = canonical_json(human)
    # No client, record IDs, hashes, source dates or raw data in aggregate.
    anonymous = {
        "schema": "lightup.casebook_change_aggregate.v1",
        "disposition": "HOLD_HUMAN_REVIEW",
        "snapshot_count": 2,
        **AUTHORITY,
        **human["aggregate_without_original_ids"],
    }
    ui = read_local_offline_ui()
    start = (
        "LIGHTUP CASEBOOK CHANGE CONTROL | PRIVATE OFFLINE OPERATOR WORKSPACE\n"
        "INCUBATE M3/M7 - PLAN/LAB ONLY - DRAFT/HOLD - NEVER A PERMIT\n\n"
        "1. On a trusted offline workstation, open standalone.html locally.\n"
        "2. Choose OLDER-ORIGINAL.json in the first file picker.\n"
        "3. Choose NEWER-ORIGINAL.json in the second file picker.\n"
        "4. Review recorded source deltas and assign HUMAN follow-up stages.\n"
        "5. Export anonymous aggregate, or confirm private recipient and export PRIVATE review.\n"
        "6. When reopening unchanged sources, restore the browser's prior private review.\n\n"
        "PRIVATE-review.json is a native CLI human dossier and is NOT browser-stage\n"
        "restore format. It is informational only and cannot authorize activity.\n"
        "A source SHA or an approved recorded grant NEVER proves current permission,\n"
        "consent, action-time STOP clearance, revocation or source authenticity.\n"
        "All original hosted/VPS CI, security/privacy, owner and HUMAN GO gates remain.\n"
    ).encode("utf-8")
    payloads = {
        "OLDER-ORIGINAL.json": old_bytes,
        "NEWER-ORIGINAL.json": new_bytes,
        "PRIVATE-review.json": human_bytes,
        "aggregate.json": canonical_json(anonymous),
        "standalone.html": ui,
        "START-HERE.txt": start,
    }
    manifest = {
        "schema": "lightup.casebook_change_private_workspace.v1",
        "disposition": "HOLD_HUMAN_REVIEW",
        "source_snapshots_atomic_together": False,
        "source_hashes_unsigned": True,
        **AUTHORITY,
        "files": {
            name: {"sha256_unsigned": sha256(body).hexdigest(), "bytes": len(body)}
            for name, body in payloads.items()
        },
    }
    payloads["manifest.json"] = canonical_json(manifest)
    return payloads, anonymous


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="LightUp original Casebook history + freshly authenticated read → complete private offline workspace (HOLD only).")
    parser.add_argument("--database", required=True, help="existing original local DomainStore SQLite")
    parser.add_argument("--email", required=True, help="original account login")
    parser.add_argument("--client", help="operator's exact original tenant; own tenant for clients")
    parser.add_argument("--previous", required=True, help="private original previous Casebook JSON (owner 0600)")
    parser.add_argument("--workspace", required=True, help="NEW private directory under a trusted owner-private parent")
    args = parser.parse_args(argv)
    try:
        outputs, summary = prepare(args.database, args.email, getpass("Original account password: "),
                                   args.client, args.previous)
        publish_private_workspace(args.workspace, outputs)
        print(json.dumps({"disposition": "HOLD_HUMAN_REVIEW",
                          "private_workspace_created": True,
                          "aggregate": summary,
                          "authorization_granted": False,
                          "execution_allowed": False}, sort_keys=True))
        return 2
    except (ReviewHold, CasebookHold, OSError, ValueError, TypeError):
        print("HOLD: original source, current account or private workspace unavailable", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
