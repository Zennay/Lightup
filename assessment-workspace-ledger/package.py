#!/usr/bin/env python3
"""Deterministic source-only offline distribution builder and inventory inspector.

No private source data, scanning, model, permissions, authentication or network.
The manifest SHA256 is an unsigned local software identity inventory only.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import zipfile

from ledger import Hold, canonical, object_unique, private_parent, reject, literal_false_authority

ROOT = Path(__file__).resolve().parent
PREFIX = "LightUp-Workspace-Ledger/"
NAMES = (
    "PRIVATE-CALENDAR-DECISION-OPTIONS.md",
    "portfolio_operator_calendar_decision_handoff.py",
    "portfolio_operator_calendar_decisions.py",
    "portfolio_operator_calendar_decision_studio.py",
    "portfolio_operator_calendar_decision_studio.js",
    "portfolio-operator-calendar-decision-studio.html",
    "portfolio_operator_calendar_continuity.py",
    "portfolio_operator_calendar_history.py",
    "portfolio_operator_calendar_studio.js",
    "portfolio_operator_calendar_studio.py",
    "portfolio-operator-calendar-studio.html",
    "portfolio_operator_calendar.py", "README.md", "ledger.py", "browser_studio.py", "compare.py", "continuity.py",
    "console.py", "human_revisions.py", "browser_intake.py", "history.py", "history_human.py", "history_studio.py",
    "history_team.py", "history_team_browser.py", "history_actions.py",
    "history_actions_browser.py", "history_owner_brief.py",
    "history_progress.py", "portfolio.py", "portfolio_delta.py", "portfolio_owner_packets.py", "portfolio_dayboard.py", "portfolio_focus.py", "portfolio_focus_review.py", "portfolio_focus_history.py", "portfolio_focus_owner_handoff.py", "portfolio_owner_reply.py", "portfolio_owner_inbox.py", "portfolio_owner_inbox_review.py", "portfolio_owner_attention.py", "portfolio_inbox_history.py", "portfolio_inbox_timeline.py", "portfolio_inbox_timeline_selection.py", "portfolio_inbox_timeline_batch.py", "portfolio_inbox_owner_return.py", "portfolio_inbox_owner_return_studio.py", "portfolio_inbox_owner_reconcile.py", "portfolio_owner_inbox_viewer.py", "portfolio_owner_followup.py", "portfolio_owner_change_briefs.py", "portfolio_owner_change_board.py", "portfolio_owner_change_history.py", "portfolio_owner_change_history_studio.py", "portfolio_owner_change_history_studio.js", "portfolio-owner-change-history-studio.html", "portfolio_owner_change_board.js", "portfolio-owner-change-board.html", "portfolio_owner_followup_studio.py", "portfolio_owner_followup_studio.js", "portfolio-owner-followup-studio.html", "portfolio_owner_inbox_viewer.js", "portfolio-owner-inbox-viewer.html", "portfolio_inbox_owner_return_studio.js", "portfolio-inbox-owner-return-studio.html", "portfolio_inbox_timeline.js", "portfolio-inbox-timeline.html", "portfolio_inbox_studio.py", "portfolio_inbox_studio.js", "portfolio-inbox-studio.html", "portfolio_owner_studio.py", "portfolio_owner_studio.js", "portfolio-owner-studio.html", "portfolio_focus_studio.py", "portfolio_focus_studio.js", "portfolio-focus-studio.html", "package.py", "standalone.html",
)
SCHEMA = "lightup.private.workspace-ledger-software.v56"
V55_SCHEMA = "lightup.private.workspace-ledger-software.v55"
V55_NAMES = tuple(n for n in NAMES if n != "PRIVATE-CALENDAR-DECISION-OPTIONS.md")
V54_SCHEMA = "lightup.private.workspace-ledger-software.v54"
V54_NAMES = tuple(n for n in V55_NAMES if n != "portfolio_operator_calendar_decision_handoff.py")
V53_SCHEMA = "lightup.private.workspace-ledger-software.v53"
V53_NAMES = tuple(n for n in V54_NAMES if n not in (
    "portfolio_operator_calendar_decisions.py",
    "portfolio_operator_calendar_decision_studio.py",
    "portfolio_operator_calendar_decision_studio.js",
    "portfolio-operator-calendar-decision-studio.html",
))
V52_SCHEMA = "lightup.private.workspace-ledger-software.v52"
V52_NAMES = tuple(n for n in V53_NAMES if n != "portfolio_operator_calendar_continuity.py")
V51_SCHEMA = "lightup.private.workspace-ledger-software.v51"
V51_NAMES = tuple(n for n in V52_NAMES if n != "portfolio_operator_calendar_history.py")
V50_SCHEMA = "lightup.private.workspace-ledger-software.v50"
V50_NAMES = tuple(n for n in V51_NAMES if n not in (
    "portfolio_operator_calendar_studio.js",
    "portfolio_operator_calendar_studio.py",
    "portfolio-operator-calendar-studio.html",
))
V49_SCHEMA = "lightup.private.workspace-ledger-software.v49"
V49_NAMES = tuple(n for n in V50_NAMES if n != "portfolio_operator_calendar.py")
V48_SCHEMA = "lightup.private.workspace-ledger-software.v48"
V48_NAMES = tuple(V49_NAMES)
V47_SCHEMA = "lightup.private.workspace-ledger-software.v47"
V47_NAMES = tuple(n for n in V48_NAMES if n not in (
    "portfolio_owner_change_history_studio.py",
    "portfolio_owner_change_history_studio.js",
    "portfolio-owner-change-history-studio.html",
))
V46_SCHEMA = "lightup.private.workspace-ledger-software.v46"
V46_NAMES = tuple(n for n in V47_NAMES if n != "portfolio_owner_change_history.py")
V45_SCHEMA = "lightup.private.workspace-ledger-software.v45"
V45_NAMES = tuple(n for n in V46_NAMES if n not in (
    "portfolio_owner_change_board.py","portfolio_owner_change_board.js",
    "portfolio-owner-change-board.html",
))
V44_SCHEMA = "lightup.private.workspace-ledger-software.v44"
V44_NAMES = tuple(n for n in V45_NAMES if n != "portfolio_owner_change_briefs.py")
V43_SCHEMA = "lightup.private.workspace-ledger-software.v43"
V43_NAMES = tuple(n for n in V44_NAMES if n not in (
    "portfolio_owner_followup_studio.py","portfolio_owner_followup_studio.js",
    "portfolio-owner-followup-studio.html",
))
V42_SCHEMA = "lightup.private.workspace-ledger-software.v42"
V42_NAMES = tuple(n for n in V43_NAMES if n != "portfolio_owner_followup.py")
V41_SCHEMA = "lightup.private.workspace-ledger-software.v41"
V41_NAMES = tuple(n for n in V42_NAMES if n not in (
    "portfolio_owner_inbox_viewer.py", "portfolio_owner_inbox_viewer.js",
    "portfolio-owner-inbox-viewer.html",
))
V40_SCHEMA = "lightup.private.workspace-ledger-software.v40"
V40_NAMES = tuple(n for n in V41_NAMES if n != "portfolio_inbox_owner_reconcile.py")
V39_SCHEMA = "lightup.private.workspace-ledger-software.v39"
V39_NAMES = tuple(n for n in V40_NAMES if n not in (
    "portfolio_inbox_owner_return_studio.py",
    "portfolio_inbox_owner_return_studio.js",
    "portfolio-inbox-owner-return-studio.html",
))
V38_SCHEMA = "lightup.private.workspace-ledger-software.v38"
V38_NAMES = tuple(n for n in V39_NAMES if n != "portfolio_inbox_owner_return.py")
V37_SCHEMA = "lightup.private.workspace-ledger-software.v37"
V37_NAMES = tuple(V38_NAMES)
V36_SCHEMA = "lightup.private.workspace-ledger-software.v36"
V36_NAMES = tuple(n for n in V38_NAMES if n != "portfolio_inbox_timeline_batch.py")
V35_SCHEMA = "lightup.private.workspace-ledger-software.v35"
V35_NAMES = tuple(n for n in V36_NAMES if n != "portfolio_inbox_timeline_selection.py")
V34_SCHEMA = "lightup.private.workspace-ledger-software.v34"
V34_NAMES = tuple(n for n in V35_NAMES if n not in ("portfolio_inbox_timeline.py", "portfolio_inbox_timeline.js", "portfolio-inbox-timeline.html"))
LATEST_SCHEMA = "lightup.private.workspace-ledger-software.v33"
LATEST_NAMES = tuple(V34_NAMES)
CURRENT_PRIOR_SCHEMA = "lightup.private.workspace-ledger-software.v32"
CURRENT_PRIOR_NAMES = tuple(V34_NAMES)
MIDDLE_SCHEMA = "lightup.private.workspace-ledger-software.v31"
MIDDLE_NAMES = tuple(n for n in V34_NAMES if n != "portfolio_inbox_history.py")
PRIOR_SCHEMA = "lightup.private.workspace-ledger-software.v30"
PRIOR_NAMES = tuple(n for n in MIDDLE_NAMES if n != "portfolio_owner_attention.py")
RECENT_SCHEMA = "lightup.private.workspace-ledger-software.v29"
RECENT_NAMES = tuple(n for n in PRIOR_NAMES if n not in (
    "portfolio_inbox_studio.py", "portfolio_inbox_studio.js", "portfolio-inbox-studio.html"))
PREVIOUS_SCHEMA = "lightup.private.workspace-ledger-software.v28"
PREVIOUS_NAMES = tuple(n for n in RECENT_NAMES if n != "portfolio_owner_inbox_review.py")
LEGACY_SCHEMA = "lightup.private.workspace-ledger-software.v27"
LEGACY_NAMES = tuple(n for n in PREVIOUS_NAMES if n not in (
    "portfolio_owner_studio.py", "portfolio_owner_studio.js", "portfolio-owner-studio.html"))
OLDER_SCHEMA = "lightup.private.workspace-ledger-software.v26"
OLDER_NAMES = tuple(n for n in LEGACY_NAMES if n != "portfolio_owner_inbox.py")
OLDEST_SCHEMA = "lightup.private.workspace-ledger-software.v25"
OLDEST_NAMES = tuple(n for n in OLDER_NAMES if n != "portfolio_owner_reply.py")
ANCIENT_SCHEMA = "lightup.private.workspace-ledger-software.v24"
ANCIENT_NAMES = tuple(n for n in OLDEST_NAMES if n != "portfolio_focus_owner_handoff.py")
FIRST_SCHEMA = "lightup.private.workspace-ledger-software.v23"
FIRST_NAMES = tuple(n for n in ANCIENT_NAMES if n != "portfolio_focus_history.py")
BASE_SCHEMA = "lightup.private.workspace-ledger-software.v22"
BASE_NAMES = tuple(n for n in FIRST_NAMES if n not in (
    "portfolio_focus_studio.py", "portfolio_focus_studio.js", "portfolio-focus-studio.html"))
ORIGIN_SCHEMA = "lightup.private.workspace-ledger-software.v21"
ORIGIN_NAMES = tuple(n for n in BASE_NAMES if n != "portfolio_focus_review.py")
ANCIENT_BASE_SCHEMA = "lightup.private.workspace-ledger-software.v20"
ANCIENT_BASE_NAMES = tuple(n for n in ORIGIN_NAMES if n != "portfolio_focus.py")
FIRST_BASE_SCHEMA = "lightup.private.workspace-ledger-software.v19"
FIRST_BASE_NAMES = tuple(n for n in ANCIENT_BASE_NAMES if n != "portfolio_dayboard.py")
ORIGINAL_SCHEMA = "lightup.private.workspace-ledger-software.v18"
ORIGINAL_NAMES = tuple(n for n in FIRST_BASE_NAMES if n != "portfolio_owner_packets.py")
MINIMUM_SCHEMA = "lightup.private.workspace-ledger-software.v17"
MINIMUM_NAMES = tuple(n for n in ORIGINAL_NAMES if n != "portfolio_delta.py")
ZERO_SCHEMA = "lightup.private.workspace-ledger-software.v16"
ZERO_NAMES = tuple(n for n in MINIMUM_NAMES if n != "portfolio.py")
FLAGS = {
    "authorization": False, "consent": False,
    "verified_finding": False, "release_approval": False,
}
MAX_FILE = 1_048_576
MAX_TOTAL = 6_291_456


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_source(name):
    if name not in NAMES:
        reject("PRIVATE HOLD: software source not allowlisted")
    fd = os.open(ROOT / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > MAX_FILE:
            reject("PRIVATE HOLD: unsupported or nonregular software source")
        payload = bytearray()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > MAX_FILE:
                reject("PRIVATE HOLD: software size changed during read")
        after = os.fstat(fd)
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ) or len(payload) != info.st_size:
            reject("PRIVATE HOLD: software source changed while packaging")
        return bytes(payload)
    finally:
        os.close(fd)


def bundle():
    entries = [(name, read_source(name)) for name in NAMES]
    manifest = {
        "schema": SCHEMA,
        "authority": FLAGS,
        "includes_customer_data": False,
        "files": [{"path": name, "bytes": len(data), "sha256": sha256(data)}
                  for name, data in entries],
    }
    entries.append(("manifest.json", json.dumps(
        manifest, ensure_ascii=False, sort_keys=True, indent=2
    ).encode("utf-8") + b"\n"))
    result = io.BytesIO()
    with zipfile.ZipFile(result, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as dst:
        for name, data in entries:
            info = zipfile.ZipInfo(PREFIX + name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100600 << 16
            dst.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return result.getvalue()


def write_private_exclusive(path: Path, payload: bytes):
    """Write one complete owner-only file without following or replacing a path."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    identity = None
    try:
        info = os.fstat(fd)
        identity = (info.st_dev, info.st_ino)
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                reject("PRIVATE HOLD: incomplete software artifact write")
            offset += written
        os.fsync(fd)
    except BaseException:
        if identity is not None:
            unlink_if_same(path, identity)
        raise
    finally:
        os.close(fd)
    return identity


def unlink_if_same(path: Path, identity):
    """Remove only the regular file inode created by this operation."""
    try:
        info = os.stat(path, follow_symlinks=False)
        if stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == identity:
            os.unlink(path)
    except OSError:
        pass


def read_checksum_sidecar(path: Path, expected: str):
    """Require an exact, stable, owner-only detached checksum file."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600 or
                before.st_size <= 0 or before.st_size > 256):
            reject("PRIVATE HOLD: detached checksum sidecar type/permissions")
        raw = bytearray()
        while True:
            chunk = os.read(fd, 257 - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > 256:
                reject("PRIVATE HOLD: detached checksum sidecar size")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ) or len(raw) != before.st_size:
            reject("PRIVATE HOLD: detached checksum sidecar changed while reading")
        try:
            value = bytes(raw).decode("ascii")
        except UnicodeDecodeError:
            reject("PRIVATE HOLD: detached checksum sidecar encoding")
        if value != expected:
            reject("PRIVATE HOLD: detached checksum does not match archive bytes")
    finally:
        os.close(fd)


def build(args):
    dest = Path(args.output)
    if not dest.is_absolute() or dest.suffix.lower() != ".zip":
        reject("PRIVATE HOLD: output requires an absolute .zip filename")
    private_parent(str(dest.parent))
    if dest.is_relative_to(ROOT):
        reject("PRIVATE HOLD: output must be outside source checkout")
    contents = bundle()
    digest = sha256(contents)
    identity = write_private_exclusive(dest, contents)
    sidecar = Path(str(dest) + ".sha256") if getattr(args, "sha256_sidecar", False) else None
    if sidecar is not None:
        try:
            write_private_exclusive(sidecar, (digest + "  " + dest.name + "\n").encode("ascii"))
        except BaseException:
            unlink_if_same(dest, identity)
            raise
    print("PRIVATE REVIEW_ONLY: offline software-only archive produced (unsigned inventory)")
    print("Archive: " + str(dest))
    print("SHA256: " + digest)
    if sidecar is not None:
        print("SHA256 sidecar: " + str(sidecar))
    return 2


def unique_object(pairs):
    return object_unique(pairs)


def inspect(args):
    path = Path(args.archive)
    if not path.is_absolute():
        reject("PRIVATE HOLD: absolute source-only ZIP path required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > MAX_TOTAL:
            reject("PRIVATE HOLD: archive size/type")
        raw = bytearray()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > MAX_TOTAL:
                reject("PRIVATE HOLD: archive byte limit")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ) or len(raw) != before.st_size:
            reject("PRIVATE HOLD: archive changed during inspection")
    finally:
        os.close(fd)
    if getattr(args, "sha256_sidecar", False):
        read_checksum_sidecar(
            Path(str(path) + ".sha256"),
            sha256(bytes(raw)) + "  " + path.name + "\n",
        )
        print("Detached SHA256 sidecar matches archive bytes (unsigned).")
    with zipfile.ZipFile(io.BytesIO(raw), "r") as src:
        entries = src.infolist()
        stored = [entry.filename for entry in entries]
        profiles = ((NAMES, SCHEMA), (V55_NAMES, V55_SCHEMA), (V54_NAMES, V54_SCHEMA), (V53_NAMES, V53_SCHEMA), (V52_NAMES, V52_SCHEMA), (V51_NAMES, V51_SCHEMA), (V50_NAMES, V50_SCHEMA), (V49_NAMES, V49_SCHEMA), (V48_NAMES, V48_SCHEMA), (V47_NAMES, V47_SCHEMA), (V46_NAMES, V46_SCHEMA), (V45_NAMES, V45_SCHEMA), (V44_NAMES, V44_SCHEMA), (V43_NAMES, V43_SCHEMA), (V42_NAMES, V42_SCHEMA), (V41_NAMES, V41_SCHEMA), (V40_NAMES, V40_SCHEMA), (V39_NAMES, V39_SCHEMA), (V38_NAMES, V38_SCHEMA), (V37_NAMES, V37_SCHEMA), (V36_NAMES, V36_SCHEMA), (V35_NAMES, V35_SCHEMA), (V34_NAMES, V34_SCHEMA), (LATEST_NAMES, LATEST_SCHEMA), (CURRENT_PRIOR_NAMES, CURRENT_PRIOR_SCHEMA), (MIDDLE_NAMES, MIDDLE_SCHEMA), (PRIOR_NAMES, PRIOR_SCHEMA), (RECENT_NAMES, RECENT_SCHEMA), (PREVIOUS_NAMES, PREVIOUS_SCHEMA), (LEGACY_NAMES, LEGACY_SCHEMA), (OLDER_NAMES, OLDER_SCHEMA), (OLDEST_NAMES, OLDEST_SCHEMA), (ANCIENT_NAMES, ANCIENT_SCHEMA), (FIRST_NAMES, FIRST_SCHEMA), (BASE_NAMES, BASE_SCHEMA), (ORIGIN_NAMES, ORIGIN_SCHEMA), (ANCIENT_BASE_NAMES, ANCIENT_BASE_SCHEMA), (FIRST_BASE_NAMES, FIRST_BASE_SCHEMA), (ORIGINAL_NAMES, ORIGINAL_SCHEMA), (MINIMUM_NAMES, MINIMUM_SCHEMA), (ZERO_NAMES, ZERO_SCHEMA))
        selected = next((
            (names, schema) for names, schema in profiles
            if stored == [PREFIX + name for name in names] + [PREFIX + "manifest.json"]
        ), None)
        if selected is None:
            reject("PRIVATE HOLD: ZIP entries are missing/reordered/extra/duplicate")
        selected_names, selected_schema = selected
        content = {}
        total = 0
        for entry, name in zip(entries, list(selected_names) + ["manifest.json"]):
            if entry.flag_bits & 1 or entry.file_size <= 0 or entry.file_size > MAX_FILE or (
                entry.external_attr >> 16
            ) & 0o170000 not in (0, 0o100000):
                reject("PRIVATE HOLD: encrypted/symlink/unsupported ZIP entry")
            if entry.compress_type != zipfile.ZIP_DEFLATED:
                reject("PRIVATE HOLD: unexpected ZIP encoding")
            total += entry.file_size
            if total > MAX_TOTAL:
                reject("PRIVATE HOLD: uncompressed software size")
            data = src.read(entry)
            if len(data) != entry.file_size:
                reject("PRIVATE HOLD: ZIP data length")
            content[name] = data
    try:
        manifest = json.loads(content["manifest.json"].decode("utf-8"),
                              object_pairs_hook=unique_object,
                              parse_constant=lambda _: reject("PRIVATE HOLD: nonfinite manifest"))
    except (ValueError, UnicodeError) as exc:
        raise Hold("PRIVATE HOLD: invalid manifest") from exc
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema", "authority", "includes_customer_data", "files"
    } or manifest["schema"] != selected_schema or not literal_false_authority(manifest["authority"], FLAGS) or (
        manifest["includes_customer_data"] is not False
    ):
        reject("PRIVATE HOLD: source-only manifest schema/authority")
    rows = manifest["files"]
    if not isinstance(rows, list) or len(rows) != len(selected_names):
        reject("PRIVATE HOLD: wrong manifest source count")
    for row, name in zip(rows, selected_names):
        data = content[name]
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"} or (
            row["path"] != name or type(row["bytes"]) is not int or row["bytes"] != len(data)
            or row["sha256"] != sha256(data)
        ):
            reject("PRIVATE HOLD: ZIP bytes disagree with manifest")
    if getattr(args, "compare_source", False):
        if selected_schema != SCHEMA:
            print("PRIVATE HOLD: historical archive cannot match the current source allowlist.")
            print("Archive schema: " + selected_schema + "; current schema: " + SCHEMA)
            return 3
        mismatches = [name for name in NAMES if content[name] != read_source(name)]
        if mismatches:
            print("PRIVATE HOLD: archive/source drift in allowlisted files: " + ", ".join(mismatches))
            return 3
        print("Current source parity: exact match for " + str(len(NAMES)) +
              " allowlisted files (unsigned).")
    print("PRIVATE REVIEW_ONLY: software archive internal file hashes and schema match")
    if selected_schema != SCHEMA:
        print("HISTORICAL " + selected_schema.rsplit(".", 1)[-1] +
              " software-only ZIP: newer portfolio modules may be absent.")
    print("UNSIGNED SHA256: " + sha256(raw))
    print("This is NOT software publisher authentication, approval, verified security, or consent.")
    return 2


def main():
    parser = argparse.ArgumentParser(description="Offline fixed-file software ZIP build or unsigned inventory inspection")
    sub = parser.add_subparsers(dest="action", required=True)
    make = sub.add_parser("build", help="Build a new source-only ZIP outside checkout")
    make.add_argument("--output", required=True)
    make.add_argument("--sha256-sidecar", action="store_true",
                      help="Write an adjacent exclusive .sha256 sidecar (unsigned)")
    check = sub.add_parser("inspect", help="Read a source-only ZIP and verify bounded unsigned internal SHA manifest")
    check.add_argument("--archive", required=True)
    check.add_argument("--sha256-sidecar", action="store_true",
                       help="Require and verify the adjacent .sha256 sidecar")
    check.add_argument("--compare-source", action="store_true",
                       help="Require exact current source parity; HOLD on stale/historical archives")
    args = parser.parse_args()
    try:
        return build(args) if args.action == "build" else inspect(args)
    except (Hold, OSError, ValueError, KeyError, zipfile.BadZipFile, RuntimeError):
        print("PRIVATE HOLD: software archive operation refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
