"""Read-only combined original Casebook + Window Review private room inspector.

No import of scanner/executor, no grant, consent, original DB, or network.
Reuses BOTH immutable existing owner product inspectors and verifies original
source-byte identity between their two workspaces. Always HUMAN HOLD.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

from lightup.auth_casebook import AUTHORITY
from refresh import ReviewHold
from workspace_inspect import inspect_workspace as inspect_original_change_control
from combined_room import _read_private, _strict_json, _launchpad, FALSE_AUTHORITY

MAX_ROOM_MANIFEST = 32768


def _directory(path: Path) -> None:
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077):
            raise ReviewHold("private operations directory not admitted")
    except OSError:
        raise ReviewHold("private operations directory unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)


def _original_window_inspector():
    # Import the OWNED original source from the merged branch without copying,
    # altering or taking over its implementation. It has no external side effects.
    script = Path(__file__).resolve().parent.parent / "scope-window-review" / "workspace_inspect.py"
    if not script.is_file() or script.is_symlink():
        raise ReviewHold("original Window Review inspector absent")
    spec = importlib.util.spec_from_file_location("_lightup_original_window_reader", script)
    if spec is None or spec.loader is None:
        raise ReviewHold("original Window Review module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.inspect, module.WorkspaceHold


def inspect_private_room(room: str) -> dict:
    root = Path(room)
    _directory(root)
    change = root / "change-control"
    window = root / "window-review"
    _directory(change)
    _directory(window)

    # Child source inspectors are product source readers, not QA programs.
    change_result = inspect_original_change_control(str(change))
    window_inspect, WindowHold = _original_window_inspector()
    try:
        window_result = window_inspect(window)
    except WindowHold:
        raise ReviewHold("original Window Review source/manifest inconsistent") from None

    complete = _strict_json(_read_private(root / "COMPLETE-MANIFEST.json",
                                          max_size=MAX_ROOM_MANIFEST))
    if (complete.get("schema") != "lightup.scope_operations_private_room.v1"
            or complete.get("status") != "HOLD_HUMAN_REVIEW"
            or complete.get("source_snapshots_atomic_together") is not False
            or complete.get("unsigned_digest_only") is not True
            or any(complete.get(key) is not False for key in FALSE_AUTHORITY)
            or type(complete.get("room_files")) is not dict
            or type(complete.get("original_child_manifests")) is not dict):
        raise ReviewHold("private room metadata falsely asserts authority or is incomplete")
    room_files = {
        "OPEN-ROOM.html": _read_private(root / "OPEN-ROOM.html"),
        "READ-FIRST.txt": _read_private(root / "READ-FIRST.txt"),
    }
    expected = {"OPEN-ROOM.html": _launchpad(), "READ-FIRST.txt": room_files["READ-FIRST.txt"]}
    if room_files["OPEN-ROOM.html"] != expected["OPEN-ROOM.html"]:
        raise ReviewHold("private launchpad no longer matches original-source-free offline app")
    if (complete["room_files"] != {
            name: sha256(body).hexdigest() for name, body in room_files.items()}):
        raise ReviewHold("private launchpad or operator instructions changed")
    actual_child_manifests = {
        "change-control/manifest.json": sha256(_read_private(change / "manifest.json")).hexdigest(),
        "window-review/human-review-manifest.json": sha256(
            _read_private(window / "human-review-manifest.json")).hexdigest(),
    }
    if actual_child_manifests != complete["original_child_manifests"]:
        raise ReviewHold("private child manifest drift")
    new = _read_private(change / "NEWER-ORIGINAL.json")
    old = _read_private(change / "OLDER-ORIGINAL.json")
    window_source = _read_private(window / "original-private-casebook.json")
    if (window_source != new
            or complete["original_newer_sha256_unsigned"] != sha256(new).hexdigest()
            or complete["original_prior_sha256_unsigned"] != sha256(old).hexdigest()):
        raise ReviewHold("window review and change control use different original source bytes")
    schedule = complete.get("human_schedule")
    if (type(schedule) is not dict or set(schedule) != {
            "lead_days","future_days","daily_capacity"}
            or type(schedule["lead_days"]) is not int
            or type(schedule["future_days"]) is not int
            or type(schedule["daily_capacity"]) is not int
            or not 0 <= schedule["lead_days"] <= 30
            or not 1 <= schedule["future_days"] <= 366
            or not 1 <= schedule["daily_capacity"] <= 64):
        raise ReviewHold("local human planning parameters inconsistent")
    return {
        "status": "HOLD_HUMAN_REVIEW",
        "private_room_complete": True,
        "offline_apps": 3,
        "original_source_bytes_same_across_products": True,
        "unsigned_file_coherence_only": True,
        "historical_changes": change_result["changed_original_record_count"],
        "original_engagements_in_window_inbox": window_result["engagement_cases"],
        "original_unrecorded_grants_in_inbox": window_result["without_recorded_grant"],
        "action_time_revocation_verified": False,
        **AUTHORITY,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only privacy-minimal original LightUp combined room inspector — HUMAN HOLD.")
    parser.add_argument("--room", required=True, help="existing owner-private Scope Operations Room")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(inspect_private_room(args.room), sort_keys=True))
        return 2
    except (ReviewHold, OSError, TypeError, ValueError, KeyError):
        print("HOLD: private combined room incomplete or original source disagreement", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
