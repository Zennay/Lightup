"""Unified PRIVATE LightUp Scope Operations Room from ORIGINAL Casebook sources.

One existing account login, one current source snapshot, two independent held
read-only operator products. All artifacts are owner-private; never a grant,
consent, STOP clearance, scan, dispatcher, release approval, or target contact.
Do not use for production without the original required independent gates.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
from getpass import getpass
from hashlib import sha256
from html import escape
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

from lightup.auth_casebook import CasebookHold
from workspace import (
    ReviewHold, prepare as prepare_change_control,
    publish_private_workspace, canonical_json,
)

PRIVATE_FILES = ("OLDER-ORIGINAL.json", "NEWER-ORIGINAL.json",
                 "PRIVATE-review.json", "aggregate.json",
                 "standalone.html", "START-HERE.txt", "manifest.json")
WINDOW_FILES = ("original-private-casebook.json", "human-review-board.html",
                "human-engagement-inbox.html", "human-review-agenda.json",
                "human-review-calendar.ics", "human-review-manifest.json")
FALSE_AUTHORITY = {
    "source_authenticated": False,
    "client_consent_verified": False,
    "operator_consent_verified": False,
    "authorization_granted": False,
    "execution_allowed": False,
    "release_approved": False,
    "action_time_revocation_verified": False,
}


def _read_private(path: Path, *, max_size: int = 3_145_728) -> bytes:
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or not 1 <= info.st_size <= max_size):
            raise ReviewHold("private generated report not admitted")
        with os.fdopen(fd, "rb") as src:
            fd = None
            body = src.read(max_size + 1)
        if len(body) > max_size:
            raise ReviewHold("private generated report oversized")
        return body
    except OSError:
        raise ReviewHold("private generated report not available") from None
    finally:
        if fd is not None:
            os.close(fd)


def _strict_json(raw: bytes) -> dict:
    from refresh import _duplicate_pairs
    try:
        doc = json.loads(raw.decode("utf-8", "strict"),
                         object_pairs_hook=_duplicate_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(
                             ReviewHold("noncanonical JSON constant")))
        if type(doc) is not dict:
            raise ReviewHold("private source envelope malformed")
        return doc
    except (UnicodeError, json.JSONDecodeError):
        raise ReviewHold("private source envelope unreadable") from None


def _private_file(path: Path, payload: bytes) -> None:
    if type(payload) is not bytes or not 1 <= len(payload) <= 3_145_728:
        raise ReviewHold("invalid private output size")
    fd = None
    try:
        fd = os.open(path, os.O_WRONLY | os.O_EXCL | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as dst:
            fd = None
            dst.write(payload)
            dst.flush()
            os.fsync(dst.fileno())
    except OSError:
        raise ReviewHold("private file publication denied") from None
    finally:
        if fd is not None:
            os.close(fd)


def _launchpad() -> bytes:
    """Static three-app navigation, no private source record embedded."""
    style = (
        "*{box-sizing:border-box}body{background:#0c1422;color:#f4f8ff;"
        "font:16px/1.6 system-ui,sans-serif;max-width:950px;margin:auto;padding:35px 22px}"
        "h1{font-size:clamp(2rem,5vw,3.6rem);line-height:1.12;margin:16px 0}"
        "h2{font-size:1.2rem}p{color:#b4c5d7}main{display:grid;gap:17px;margin-top:30px}"
        "article{background:#162438;border:1px solid #31455d;padding:25px;border-radius:18px}"
        "a{color:#9df2d9}a:focus-visible{outline:3px solid #fff;outline-offset:4px}"
        "strong{color:#ffdda0}.tag{letter-spacing:.09em;font-size:.8rem;color:#82e5c6}"
        "footer{margin-top:40px;border-top:1px solid #34475c;padding-top:20px;font-size:.85rem}"
    )
    hash64 = base64.b64encode(sha256(style.encode("utf-8")).digest()).decode("ascii")
    csp = ("default-src 'none'; style-src 'sha256-" + hash64 +
           "'; connect-src 'none'; img-src 'none'; script-src 'none'; "
           "object-src 'none'; form-action 'none'; base-uri 'none'")
    # Only static relative links to three exact known locally copied owner applications.
    html = (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"" + escape(csp, quote=True) + "\">"
        "<title>LightUp · Private Scope Operations Room</title><style>" + style + "</style>"
        "</head><body><div class=\"tag\">LIGHTUP / PRIVATE / OFFLINE / REVIEW ONLY</div>"
        "<h1>Scope Operations Room</h1>"
        "<p>Two independent original-source observation workflows, one local source. "
        "No network calls, authentication assertion, live grant, STOP clearance or dispatch.</p>"
        "<p><strong>INCUBATE M3/M7 · DRAFT/HOLD · HUMAN REVIEW</strong></p><main>"
        "<article><h2>1 · Casebook Change Control</h2>"
        "<p>Compare the older and the newer original private Casebook snapshots. "
        "Restore native human review from matching source bytes; record private action notes.</p>"
        "<p><a href=\"change-control/standalone.html\">Open Change Control</a></p>"
        "</article><article><h2>2 · Original grant-window review</h2>"
        "<p>Inspect recorded grant windows and planned human follow-ups. "
        "Historic windows never imply current permission.</p>"
        "<p><a href=\"window-review/human-review-board.html\">Open Window Review</a></p>"
        "</article><article><h2>3 · Every-engagement original attention inbox</h2>"
        "<p>Includes original engagements with zero recorded grants and pending "
        "risk/source HOLD; no invented grant or clearance.</p>"
        "<p><a href=\"window-review/human-engagement-inbox.html\">Open Human Inbox</a></p>"
        "</article></main><footer><p>PRIVATE source files live in the two local "
        "subdirectories. Do not upload a folder or review dossier to a public service. "
        "Offline SHA-256 verifies selected bytes only. The original account authentication "
        "does not persist as a grant or consent; independent at-use revocation, source-owner, "
        "security/privacy, exact-head CI and explicit human GO are still required.</p>"
        "</footer></body></html>\n"
    )
    return html.encode("utf-8")


def build(database: str, email: str, password: str, client: str | None,
          previous: str, destination: str, *, lead_days: int,
          future_days: int, daily_capacity: int) -> dict:
    if (not 0 <= lead_days <= 30 or not 1 <= future_days <= 366
            or not 1 <= daily_capacity <= 64):
        raise ReviewHold("invalid human scheduling horizon")
    output = Path(destination)
    if not output.name or output.name in (".", "..") or output.exists() or output.is_symlink():
        raise ReviewHold("new private operations directory required")
    parent = output.parent
    pinfo = parent.lstat()
    if (not stat.S_ISDIR(pinfo.st_mode) or stat.S_ISLNK(pinfo.st_mode)
            or pinfo.st_uid != os.geteuid() or pinfo.st_mode & 0o022):
        raise ReviewHold("operations parent must be trusted and non-world-writable")
    # Original login occurs once. Exact original current source is reused from the
    # output below by the independent original Window Review child program.
    files, anonymous = prepare_change_control(database, email, password, client, previous)
    root_created = False
    completed = False
    try:
        os.mkdir(output, 0o700)
        root_created = True
        os.chmod(output, 0o700)
        change = output / "change-control"
        window = output / "window-review"
        publish_private_workspace(str(change), files)
        original = change / "NEWER-ORIGINAL.json"
        script = Path(__file__).resolve().parent.parent / "scope-window-review" / "window_review.py"
        if not script.is_file() or script.is_symlink():
            raise ReviewHold("original Window Review module is not installed")
        # Original owner program is executed only in its *offline import* mode.
        # It must not see a password, DB path, real target or untrusted URL.
        command = [
            # Preserve owner-script sibling imports while ignoring external Python env.
            # Python -I suppresses the script directory and breaks original
            # board_html/workspace_bundle imports; -E -S -B keeps those local.
            sys.executable, "-E", "-S", "-B", str(script),
            "--casebook", str(original), "--workspace", str(window),
            "--lead-days", str(lead_days), "--future-days", str(future_days),
            "--daily-capacity", str(daily_capacity),
        ]
        try:
            runner = subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=40, check=False,
                cwd=str(script.parent), env={"PATH": "/usr/bin:/bin"},
                close_fds=True,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise ReviewHold("original offline Window Review could not finish") from None
        if runner.returncode not in (2, 3):
            raise ReviewHold("original Window Review unavailable")
        manifest_window = _strict_json(_read_private(window / "human-review-manifest.json"))
        expected_source = sha256(files["NEWER-ORIGINAL.json"]).hexdigest()
        if (manifest_window.get("schema") != "lightup.scope_window_workspace.v1"
                or manifest_window.get("original_source_sha256") != expected_source
                or _read_private(window / "original-private-casebook.json") != files["NEWER-ORIGINAL.json"]
                or any(manifest_window.get(k) is not False for k in (
                    "authorization_granted", "execution_allowed", "release_approved"))):
            raise ReviewHold("original Window Review diverged from authenticated source")
        for family, names in (("change-control", PRIVATE_FILES),
                              ("window-review", WINDOW_FILES)):
            for name in names:
                _read_private(output / family / name)
        room = _launchpad()
        _private_file(output / "OPEN-ROOM.html", room)
        help_text = (
            "LightUp PRIVATE Scope Operations Room — DRAFT/HOLD, NOT A PERMIT\n"
            "Offline only. Open OPEN-ROOM.html on a trusted workstation.\n"
            "Change Control: import change-control/OLDER-ORIGINAL.json and\n"
            "change-control/NEWER-ORIGINAL.json in its local standalone page.\n"
            "The original Window Review board and the every-engagement inbox\n"
            "derive from that exact SAME newly authenticated Casebook export.\n"
            "Native CLI review is a retrospective PRIVATE human dossier, never consent.\n"
            "Keep every file private. Missing source rows DO NOT imply revocation.\n"
            "No active scan, grant, release, STOP mutation or action-time clearance.\n"
        ).encode("utf-8")
        _private_file(output / "READ-FIRST.txt", help_text)
        manifest = {
            "schema": "lightup.scope_operations_private_room.v1",
            "status": "HOLD_HUMAN_REVIEW",
            "source_snapshots_atomic_together": False,
            "unsigned_digest_only": True,
            "original_newer_sha256_unsigned": expected_source,
            "original_prior_sha256_unsigned": sha256(files["OLDER-ORIGINAL.json"]).hexdigest(),
            "room_files": {
                "OPEN-ROOM.html": sha256(room).hexdigest(),
                "READ-FIRST.txt": sha256(help_text).hexdigest(),
            },
            "original_child_manifests": {
                "change-control/manifest.json": sha256(files["manifest.json"]).hexdigest(),
                "window-review/human-review-manifest.json": sha256(
                    _read_private(window / "human-review-manifest.json")).hexdigest(),
            },
            "human_schedule": {
                "lead_days": lead_days, "future_days": future_days,
                "daily_capacity": daily_capacity,
            },
            **FALSE_AUTHORITY,
        }
        _private_file(output / "COMPLETE-MANIFEST.json", canonical_json(manifest))
        fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        completed = True
        return {
            "status": "HOLD_HUMAN_REVIEW",
            "private_room_written": True,
            "applications": 3,
            "private_subworkspaces": 2,
            "anonymous_change_count": anonymous["changed_record_count"],
            "authorization_granted": False,
            "execution_allowed": False,
            "release_approved": False,
        }
    except (OSError, ValueError, KeyError):
        raise ReviewHold("private operations room could not be completed") from None
    finally:
        if root_created and not completed:
            # Entire tree belongs exclusively to this newly created private
            # directory; never clean outside it, never follow links.
            shutil.rmtree(output)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create one original-authenticated PRIVATE offline Scope Operations Room (HOLD only).")
    parser.add_argument("--database", required=True, help="existing original DomainStore SQLite file")
    parser.add_argument("--email", required=True, help="existing original account email")
    parser.add_argument("--client", help="exact original tenant selection; required for operators")
    parser.add_argument("--previous", required=True, help="older original owner-0600 Casebook JSON")
    parser.add_argument("--room", required=True, help="new PRIVATE room directory under a trusted parent")
    parser.add_argument("--lead-days", type=int, default=7)
    parser.add_argument("--future-days", type=int, default=45)
    parser.add_argument("--daily-capacity", type=int, default=8)
    args = parser.parse_args(argv)
    try:
        result = build(
            args.database, args.email, getpass("Existing original account password: "),
            args.client, args.previous, args.room,
            lead_days=args.lead_days, future_days=args.future_days,
            daily_capacity=args.daily_capacity,
        )
        print(json.dumps(result, sort_keys=True))
        return 2
    except (ReviewHold, CasebookHold, OSError, ValueError, TypeError):
        print("HOLD: original account, private source or operations room unavailable", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
