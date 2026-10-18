#!/usr/bin/env python3
"""Private static portable LightUp team room packet; no execution or authority."""
from __future__ import annotations

from hashlib import sha256
from io import BytesIO
from zipfile import ZipFile, ZipInfo, ZIP_STORED, BadZipFile
import re

SCHEMA = "lightup.assessment_remediation_team_room_packet.v1"
HANDOFF = "lightup.assessment_remediation_team_handoff.v1"
FLAGS = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")
MEMBERS = ("README.txt", "manifest.json", "review/private-handoff.json",
           "review/team-room.html")
CAP = 1024 * 1024
DOC_CAP = 262144
ROOM_CAP = 131072
README = (
    "LIGHTUP — PRIVATE HUMAN TEAM ROOM / DRAFT-HOLD\n"
    "Contains confidential original scenario/finding IDs and human-only notes.\n"
    "No original client CSV, lab records, passwords, target execution or authority.\n"
    "Extract into a privately owned directory; open review/team-room.html offline\n"
    "and select review/private-handoff.json in its local file picker.\n"
    "The returned file is unsigned. Operator must independently verify sender.\n"
    "No permission, consent, source authenticity, retest or release is granted.\n"
).encode("utf-8")


def _check(condition, message):
    if condition:
        raise ValueError(message)


def _write(zf, name, content):
    info = ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = ZIP_STORED
    info.create_system = 3
    info.external_attr = 0o100600 << 16
    zf.writestr(info, content)


def _manifest(handoff, page):
    return {
        "schema": SCHEMA,
        "source_integrity_not_authentication": True,
        "entries": [
            {"path": "review/private-handoff.json", "bytes": len(handoff),
             "sha256": sha256(handoff).hexdigest()},
            {"path": "review/team-room.html", "bytes": len(page),
             "sha256": sha256(page).hexdigest()},
        ],
        **{key: False for key in FLAGS}
    }


def pack(handoff, room, encode):
    """Receive already admitted owner-only original room bytes; return private ZIP."""
    _check(not 0 < len(handoff) <= DOC_CAP or not 0 < len(room) <= ROOM_CAP,
           "private source exceeds bounded original team room sizes")
    manifest = encode(_manifest(handoff, room))
    mem = BytesIO()
    with ZipFile(mem, "w") as zf:
        _write(zf, "README.txt", README)
        _write(zf, "manifest.json", manifest)
        _write(zf, "review/private-handoff.json", handoff)
        _write(zf, "review/team-room.html", room)
    result = mem.getvalue()
    _check(len(result) > CAP, "team ZIP too large")
    return result


def inspect(blob, decode):
    """Read-only exact member integrity, never a source identity or permission verdict."""
    _check(not 0 < len(blob) <= CAP, "private room size invalid")
    try:
        with ZipFile(BytesIO(blob), "r") as zf:
            infos = zf.infolist()
            _check(len(infos) != len(MEMBERS) or
                   {item.filename for item in infos} != set(MEMBERS),
                   "invalid private room member set")
            data = {}
            for info in infos:
                _check(info.filename not in MEMBERS or info.is_dir() or
                       info.compress_type != ZIP_STORED or info.file_size < 1 or
                       info.file_size > CAP or
                       (info.external_attr >> 16) != 0o100600,
                       "unsafe private room ZIP metadata")
                data[info.filename] = zf.read(info)
    except (BadZipFile, EOFError, RuntimeError, ValueError, OSError) as error:
        raise ValueError("invalid private team room ZIP") from error
    _check(data["README.txt"] != README,
           "private packet operator instructions changed")
    document = decode(data["manifest.json"])
    keys = {"schema", "source_integrity_not_authentication", "entries", *FLAGS}
    _check(type(document) is not dict or set(document) != keys or
           document["schema"] != SCHEMA or
           document["source_integrity_not_authentication"] is not True or
           any(document[k] is not False for k in FLAGS),
           "invalid packet integrity-only claims")
    entries = document["entries"]
    _check(type(entries) is not list or len(entries) != 2,
           "private source manifest entries missing")
    for record, name, maximum in (
        (entries[0], "review/private-handoff.json", DOC_CAP),
        (entries[1], "review/team-room.html", ROOM_CAP),
    ):
        value = data[name]
        _check(type(record) is not dict or set(record) !=
               {"path", "bytes", "sha256"} or record["path"] != name or
               type(record["bytes"]) is not int or record["bytes"] != len(value) or
               not 0 < len(value) <= maximum or
               record["sha256"] != sha256(value).hexdigest(),
               "private room byte source mismatch")
    handoff = decode(data["review/private-handoff.json"])
    _check(type(handoff) is not dict or
           handoff.get("schema") != HANDOFF or
           any(handoff.get(key) is not False for key in FLAGS) or
           not re.fullmatch(r"[0-9a-f]{64}", str(handoff.get("team_room_source_sha256"))) or
           handoff["team_room_source_sha256"] !=
           sha256(data["review/team-room.html"]).hexdigest(),
           "portable team source hash or authority changed")
    return handoff
