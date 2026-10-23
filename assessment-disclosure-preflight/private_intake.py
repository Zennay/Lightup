"""PRIVATE offline intake of already-exported HUMAN review files.

This deliberately does not validate the original lab evidence, authorize
assessments, move/delete browser downloads, scan, or contact any network.
It delegates complete source-bound HUMAN re-admission to original reconcile.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

import reconcile

MAX_DOWNLOAD = 256 * 1024
ROOM_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
RECEIPT = "PRIVATE-receipt.json"
REVIEWER_FORMATS = {
    "csv": ".csv", "vault": ".luhd", "bundle": ".luhb"
}
DECISIONS = "PRIVATE-reconcile-decisions.csv"
RESULT_CSV = "PRIVATE-browser-reconciled-human.csv"
RESULT_BUNDLE = "PRIVATE-browser-reconciled-human.luhb"
COUNTS = "PRIVATE-browser-reconciled-counts.csv"
INVENTORY = "PRIVATE-intake-inventory.json"


def source_copy(path: str) -> bytes:
    """Allow browser downloads with imperfect permissions, but not aliases.

    Download permissions are not evidence of trust: the source can remain
    readable in Downloads after this command and needs HUMAN cleanup.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    listed = os.stat(path, follow_symlinks=False)
    fd = os.open(path, flags)
    try:
        first = os.fstat(fd)
        fingerprint = lambda obj: (obj.st_dev, obj.st_ino, obj.st_mode, obj.st_uid,
                                    obj.st_nlink, obj.st_size, obj.st_mtime_ns, obj.st_ctime_ns)
        if (not stat.S_ISREG(first.st_mode) or first.st_uid != os.geteuid()
            or first.st_nlink != 1 or not 0 < first.st_size <= MAX_DOWNLOAD
            or fingerprint(first) != fingerprint(listed)):
            raise ValueError("PRIVATE input not admitted")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            content = stream.read(MAX_DOWNLOAD + 1)
        after = os.fstat(fd)
        if len(content) != first.st_size or fingerprint(first) != fingerprint(after):
            raise ValueError("PRIVATE input changed during read")
        return content
    finally:
        os.close(fd)


def user_private_parent(path: str) -> tuple[int, str]:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    handle = os.open(path, flags)
    info = os.fstat(handle)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
        stat.S_IMODE(info.st_mode) & 0o077):
        os.close(handle)
        raise ValueError("PRIVATE parent must be user-owned 0700")
    return handle, os.path.abspath(path)


def admit_and_copy(inputs: list[tuple[str, str]], folder: int) -> list[dict]:
    """Write explicitly named new 0600 files with no overwrites."""
    rows: list[dict] = []
    seen: set[tuple[int, int]] = set()
    for local_name, source_path in inputs:
        # All received roles must come from independently named source inodes.
        info = os.stat(source_path, follow_symlinks=False)
        identity = (info.st_dev, info.st_ino)
        if identity in seen:
            raise ValueError("same browser download supplied for multiple roles")
        seen.add(identity)
        content = source_copy(source_path)
        fd = os.open(local_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=folder)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as output:
                output.write(content)
                output.flush()
            os.fsync(fd)
        finally:
            os.close(fd)
        rows.append({"role": local_name, "bytes": len(content),
                     "sha256": hashlib.sha256(content).hexdigest()})
    os.fsync(folder)
    return rows


def publish_inventory(folder: int, rows: list[dict], mode: str, floor: int) -> None:
    inventory = {
        "schema": "lightup.private_offline_human_intake.v1",
        "status": "REVIEW_ONLY",
        "human_reopened": True,
        "transfer_mode": mode,
        "minimum_cohort": floor,
        "source_authenticated": False,
        "independent_review_verified": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "authorization_granted": False,
        "release_allowed": False,
        "signed": False,
        "files": rows,
    }
    raw = (json.dumps(inventory, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(INVENTORY, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                 getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=folder)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(folder)


def stage(args: argparse.Namespace) -> int:
    if not ROOM_PATTERN.fullmatch(args.room) or not 5 <= args.minimum_cohort <= 12:
        raise ValueError("invalid PRIVATE room or privacy floor")
    encrypted = args.result_bundle is not None
    result_name = RESULT_BUNDLE if encrypted else RESULT_CSV
    reviewer_inputs = []
    review_args = []
    for role in ("a", "b"):
        mode, path = next((kind, getattr(args, role + "_" + kind))
                          for kind in REVIEWER_FORMATS
                          if getattr(args, role + "_" + kind) is not None)
        original_name = "PRIVATE-original-reviewer-" + role.upper() + REVIEWER_FORMATS[mode]
        reviewer_inputs.append((original_name, path))
        review_args.extend(["--" + role + "-" + mode, original_name])
    inputs = [
        (RECEIPT, args.receipt),
        *reviewer_inputs,
        (DECISIONS, args.decisions),
        (result_name, args.result_bundle if encrypted else args.result_csv),
        (COUNTS, args.counts),
    ]
    # Read and admit every downloaded source before allocating the result room.
    # Never use the browser download's basename in PRIVATE inventory or stdout.
    parent_fd, parent_path = user_private_parent(args.private_parent)
    room_fd = None
    created = False
    success = False
    try:
        for _, source in inputs:
            if source is None:
                raise ValueError("missing PRIVATE source")
        os.mkdir(args.room, mode=0o700, dir_fd=parent_fd)
        created = True
        room_fd = os.open(args.room, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                          getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        room_path = os.path.join(parent_path, args.room)
        rows = admit_and_copy(inputs, room_fd)
        received_flags = [
            "reopen", "--receipt", os.path.join(room_path, RECEIPT),
            "--decisions", os.path.join(room_path, DECISIONS),
            "--private-output-dir", room_path,
            "--received-counts", os.path.join(room_path, COUNTS),
            "--minimum-cohort", str(args.minimum_cohort),
        ]
        for index in range(0, len(review_args), 2):
            received_flags += [review_args[index],
                               os.path.join(room_path, review_args[index + 1])]
        if encrypted:
            received_flags += ["--encrypt-result", "--received-bundle",
                               os.path.join(room_path, RESULT_BUNDLE)]
        else:
            received_flags += ["--received-csv", os.path.join(room_path, RESULT_CSV)]
        # Existing original strict parser checks ALL ORIGINAL source-bound rows,
        # reviewer byte identities, decision reasons and suppressed counts.
        if reconcile.main(received_flags) != 2:
            raise ValueError("original HUMAN source-bound reopening refused")
        publish_inventory(room_fd, rows,
                          "PRIVATE_ENCRYPTED_BUNDLE" if encrypted else "PRIVATE_PLAINTEXT_CSV",
                          args.minimum_cohort)
        os.fsync(parent_fd)
        success = True
        print("REVIEW_ONLY: complete source-bound HUMAN handoff copied to a new owner-only PRIVATE room")
        print("Original browser downloads were NOT moved, deleted, or secured by this operation.")
        print("The unsigned PRIVATE inventory is not consent, source authenticity or release.")
        return 2
    finally:
        if not success and room_fd is not None:
            # Remove only files created here; no original download is changed.
            for name, _ in inputs:
                try:
                    os.unlink(name, dir_fd=room_fd)
                except FileNotFoundError:
                    pass
            try:
                os.unlink(INVENTORY, dir_fd=room_fd)
            except FileNotFoundError:
                pass
        if room_fd is not None:
            os.close(room_fd)
        if created and not success:
            try:
                os.rmdir(args.room, dir_fd=parent_fd)
            except OSError:
                pass
        os.close(parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Safely receive complete original PRIVATE HUMAN browser downloads; no authorization")
    parser.add_argument("--private-parent", required=True,
                        help="existing user-owned 0700 directory")
    parser.add_argument("--room", required=True,
                        help="NEW alphanumeric/private HUMAN room name (never overwritten)")
    parser.add_argument("--receipt", required=True, help="original PRIVATE source-free receipt")
    for role in ("a", "b"):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--" + role + "-csv",
                           help="original HUMAN reviewer " + role.upper() + " plaintext CSV")
        group.add_argument("--" + role + "-vault",
                           help="original HUMAN reviewer " + role.upper() + " encrypted .luhd")
        group.add_argument("--" + role + "-bundle",
                           help="original HUMAN reviewer " + role.upper() + " encrypted .luhb")
    parser.add_argument("--decisions", required=True, help="original 7-column HUMAN A/B/HOLD decisions CSV")
    result = parser.add_mutually_exclusive_group(required=True)
    result.add_argument("--result-csv", help="original complete browser-generated PRIVATE HUMAN plaintext CSV")
    result.add_argument("--result-bundle", help="original complete browser-generated PRIVATE HUMAN .luhb")
    parser.add_argument("--counts", required=True, help="separate original small-cohort suppressed counts CSV")
    parser.add_argument("--minimum-cohort", type=int, default=5,
                        help="original privacy floor, 5 through 12")
    args = parser.parse_args()
    try:
        return stage(args)
    except (OSError, ValueError, TypeError, MemoryError):
        print("HOLD: PRIVATE HUMAN intake refused, no room published or authority", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
