#!/usr/bin/env python3
"""Owner-private LightUp operator continuity (paths only, NEVER authority).

Explicitly save an operator's local paths to a new 0700 workspace and
create an offline click-through page. No original evidence, notes, secrets,
automatic source re-admission, client identity verification or target actions.
"""
from __future__ import annotations

import html
import json
import os
from pathlib import Path
import re
import stat
import shutil

SCHEMA = "lightup.private.assessment-operator-workspace.v1"
AUTHORITY = {"may_scan": False, "may_grant": False, "may_release": False,
             "may_share": False, "may_delete": False, "verified_consent": False,
             "verified_source": False, "verified_finding": False}
NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,39}\Z")
MAX_PATH = 4096
MAX_JSON = 131072
ROOT = Path(__file__).resolve().parent.parent

# These are existing outputs only. Source inputs are NEVER linked or copied.
PAGES = {
    "initial_kit": ("Original private briefing and HUMAN studios", ("OPEN-PRIVATE.html",)),
    "curation_kit": ("PRIVATE source selection", ("OPEN-PRIVATE.html",)),
    "selected_kit": ("PRIVATE selected findings", ("OPEN-PRIVATE.html",)),
    "portfolio_kit": ("Original PRIVATE agenda portfolio", ("OPEN-PRIVATE.html",)),
    "benchmark_kit": ("Original PRIVATE benchmark", ("OPEN-PRIVATE.html",)),
    "trajectory_kit": ("Original PRIVATE cohort timeline", ("OPEN-PRIVATE.html",)),
    "reviewer_kit": ("Original HUMAN reviewer room", ("OPEN-PRIVATE.html",)),
    "ledger_kit": ("Original byte snapshot ledger", ("OPEN-PRIVATE.html",)),
    "notes_kit": ("Original PRIVATE HUMAN notes", ("OPEN-PRIVATE.html",)),
    "remediation_kit": ("Original source-bound HUMAN casebook", ("START-HERE.html", "OPEN-PRIVATE.html")),
    "team_kit": ("Original PRIVATE HUMAN team handoff", ("OPEN-PRIVATE.html",)),
    "evidence_preparation": ("Original PRIVATE evidence selection editor",
                             ("PRIVATE-source-free-selection-studio.html",)),
    "evidence_dossier": ("Original selected-only evidence dossier",
                         ("PRIVATE-curated-dossier.html", "PRIVATE-HUMAN-interactive-workroom.html",
                          "PRIVATE-next-HUMAN-question-proposal.html")),
    "recipient_preparation": ("PRIVATE recipient question studio",
                              ("PRIVATE-recipient-browser-studio.html",)),
    "sender_preparation": ("PRIVATE sender triage studio",
                           ("PRIVATE-sender-triage-browser.html",)),
    "disclosure_workroom": ("Source-free HUMAN disclosure editor", ("OPEN-PRIVATE.html",)),
    "disclosure_review": ("Original PRIVATE HUMAN disclosure decision", ("PRIVATE-human-followup.html",)),
    "retention_workroom": ("Original HUMAN retention and drift", ("PRIVATE-HUMAN-retention-history.html",
                           "PRIVATE-HUMAN-source-drift.html")),
}


class Hold(ValueError):
    """Strict offline confidentiality or admission refusal."""


def private(path: Path, directory: bool) -> bool:
    try:
        info = path.lstat()
        return (info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) & 0o077 == 0
                and (stat.S_ISDIR(info.st_mode) if directory
                     else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                     and 0 < info.st_size <= MAX_JSON))
    except OSError:
        return False


def clean_paths(session) -> dict[str, str]:
    values = {}
    for field in session.__dataclass_fields__:
        value = getattr(session, field)
        if (type(value) is not str or len(value) > MAX_PATH
                or any(ord(c) < 32 or ord(c) == 127 for c in value)):
            raise Hold("unsafe local session value")
        values[field] = value
    return values


def original_page(folder: str, filenames: tuple[str, ...]) -> Path | None:
    if not folder or len(folder) > MAX_PATH:
        return None
    path = Path(folder)
    if not path.is_absolute() or not private(path, True):
        return None
    for file in filenames:
        candidate = path / file
        try:
            info = candidate.lstat()
            if (stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                    and stat.S_IMODE(info.st_mode) & 0o077 == 0
                    and info.st_nlink == 1 and 0 < info.st_size <= 8 * 1024 * 1024):
                return candidate
        except OSError:
            pass
    return None


def launch_page(paths: dict[str, str]) -> bytes:
    items = []
    for field, (label, filenames) in PAGES.items():
        file = original_page(paths.get(field, ""), filenames)
        if file is None:
            continue
        # Only file: links; never an HTTP/HTTPS URL or arbitrary input path.
        href = file.as_uri()
        if not href.startswith("file:///"):
            continue
        items.append('<li><a rel="noopener noreferrer" href="' +
                     html.escape(href, quote=True) + '">' + html.escape(label) +
                     "</a><span>Original locally generated owner-private page</span></li>")
    links = "".join(items) if items else (
        "<li>No original owner-private output page is currently accessible. "
        "Choose a source workflow manually.</li>")
    doc = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp PRIVATE operator session</title>
<style>body{background:#edf3f7;color:#173345;font:16px/1.6 system-ui;max-width:850px;margin:3rem auto;padding:0 1rem}
main{padding:2rem;border:1px solid #ccd8e4;border-radius:16px;background:white}
a{color:#165e8d;font-weight:650}li{margin:1rem 0}span{display:block;color:#596d80}
.warn{color:#843a20;font-weight:700}</style><main>
<h1>LightUp PRIVATE operator workspace</h1>
<p class="warn">REVIEW_ONLY / HOLD — these bookmarks convey NO permission or source authenticity.</p>
<p>Bookmarked original local workrooms only; all source inputs, client details,
review decisions, private notes and credentials remain OUTSIDE this launcher.
No script, data refresh, network, scan, grant, delete, retest or dispatch runs.</p>
<ul>""" + links + """</ul>
<p>Use the companion owner-private session JSON to restore entered local paths
in the original console, after deliberate HUMAN confirmation. The JSON can
still reveal PRIVATE directory names and must never be shared. A missing
link means unavailable locally, not permission to ignore or recreate a source.</p>
<p>Original client/operator consent, revocation-at-use, owner/provenance,
privacy/security review and explicit HUMAN GO remain unverified.
Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.</p></main></html>""")
    return doc.encode("utf-8")


def private_write(parent: Path, filename: str, data: bytes) -> None:
    if not data or len(data) > MAX_JSON:
        raise Hold("private document exceeds size bound")
    fd = os.open(parent / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())


def save(session, parent_name: str, prefix: str) -> tuple[Path, Path]:
    if not NAME.fullmatch(prefix):
        raise Hold("invalid unique owner-private workroom name")
    parent = Path(parent_name).resolve(strict=True)
    if parent == ROOT or ROOT in parent.parents or not private(parent, True):
        raise Hold("owner-private 0700 parent outside checkout required")
    values = clean_paths(session)
    # Preserve the actual newly selected PRIVATE parent on resume rather than
    # an outdated earlier-session parent, without mutating the live session
    # until publication has completed.
    values["parent"] = str(parent)
    room = parent / prefix
    if os.path.lexists(room):
        raise Hold("original PRIVATE session room exists; never overwrite")
    content = {"schema": SCHEMA, "status": "REVIEW_ONLY",
               "authority": AUTHORITY, "paths": values}
    json_bytes = (json.dumps(content, sort_keys=True, ensure_ascii=True,
                              separators=(",", ":")) + "\n").encode("ascii")
    page = launch_page(values)
    room.mkdir(mode=0o700)
    try:
        if not private(room, True):
            raise Hold("new PRIVATE workroom mode refused")
        private_write(room, "PRIVATE-SESSION.json", json_bytes)
        private_write(room, "OPEN-PRIVATE.html", page)
        fd = os.open(room, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        # Remove only this exclusively allocated new room, never original sources.
        shutil.rmtree(room)
        raise Hold("could not save exact PRIVATE session")
    return room / "PRIVATE-SESSION.json", room / "OPEN-PRIVATE.html"


def unique_pairs(items: list[tuple[str, object]]) -> dict:
    output = {}
    for key, value in items:
        if key in output:
            raise Hold("duplicate original private session key")
        output[key] = value
    return output


def restore(session, filename: str) -> dict[str, str]:
    path = Path(filename)
    if (not path.is_absolute() or ROOT in path.parents or
            not private(path, False) or not private(path.parent, True)):
        raise Hold("existing owner-private 0600 session + 0700 parent outside checkout required")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_JSON:
            raise Hold("invalid private session file")
        raw = os.read(fd, MAX_JSON + 1)
        after = os.fstat(fd)
        if ((before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) !=
                (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns)
                or len(raw) != before.st_size):
            raise Hold("private session changed while reading")
    finally:
        os.close(fd)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(Hold("unsupported number")))
    except (UnicodeError, ValueError):
        raise Hold("private source session is not canonical JSON") from None
    if (type(doc) is not dict or set(doc) != {"schema", "status", "authority", "paths"}
            or doc["schema"] != SCHEMA or doc["status"] != "REVIEW_ONLY"
            or type(doc["authority"]) is not dict or set(doc["authority"]) != set(AUTHORITY)
            or any(type(doc["authority"][key]) is not bool
                   or doc["authority"][key] is not False for key in AUTHORITY)
            or type(doc["paths"]) is not dict
            or set(doc["paths"]) != set(session.__dataclass_fields__)):
        raise Hold("original private path-only session schema/authority mismatch")
    # Atomic user-approved path restoration, no auto-open, subprocess or scan.
    updates = doc["paths"]
    if any(type(value) is not str or len(value) > MAX_PATH or
           any(ord(c) < 32 or ord(c) == 127 for c in value)
           for value in updates.values()):
        raise Hold("unsafe restored source path")
    return dict(updates)
