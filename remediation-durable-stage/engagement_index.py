"""Owner-private cross-source HUMAN draft continuity for one engagement.

Single-journal-folder safety aid; never claims cross-machine exclusion,
client consent or native Apply. Source-key registration is fsynced before
publishing another encrypted original HUMAN draft.
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import os
import stat

import request_handoff as bridge

original = bridge.original
KIND = "lightup.private_human_engagement_source_index"
LIMIT = 64 * 1024
MAX_REVISIONS = 96


def _sha(value: object) -> str:
    return hashlib.sha256(original.canonical(value)).hexdigest()


def _name(packet: dict) -> str:
    return "engagement-" + _sha({
        "client": packet["client_reference"],
        "engagement": packet["engagement_reference"],
    })


def _load(folder: Path, packet: dict, vault, private_file) -> dict:
    name = _name(packet)
    target = folder / (name + ".json")
    empty = {"kind": KIND, "schema_version": 1, "engagement_key": name,
             "sources": []}
    if not target.exists() and not target.is_symlink():
        return empty
    private_file(target)
    raw = vault._private_input(target, LIMIT)
    data = original.human._json(raw, LIMIT)
    if (type(data) is not dict
            or set(data) != set(empty)
            or data["kind"] != KIND
            or type(data["schema_version"]) is not int
            or data["schema_version"] != 1
            or data["engagement_key"] != name
            or original.canonical(data) != raw):
        raise ValueError("Untrusted engagement HUMAN continuity index.")
    ids = data["sources"]
    if (type(ids) is not list or len(ids) > MAX_REVISIONS
            or len(ids) != len(set(ids))
            or any(type(item) is not str or len(item) != 64 or
                   any(c not in "0123456789abcdef" for c in item)
                   for item in ids)):
        raise ValueError("Malformed previous source-revision inventory.")
    return data


def inspect(folder: Path, packet: dict, vault, private_file,
            read_journal) -> tuple[dict, int]:
    """Read all registered source revisions; missing previous record is HOLD."""
    data = _load(folder, packet, vault, private_file)
    unresolved = 0
    for name in data["sources"]:
        path = folder / (name + ".json")
        if not path.exists() or path.is_symlink():
            raise ValueError("Registered original HUMAN source journal missing.")
        history = read_journal(folder, name, vault)
        # An index entry without a durable source journal means a stage
        # might have been interrupted between intent and original publication.
        if not history["cycles"]:
            raise ValueError("Incomplete registered HUMAN source reservation.")
        if any(row["state"] in ("pending", "staged") for row in history["cycles"]):
            unresolved += 1
    return data, unresolved


def reserve(folder: Path, packet: dict, source_key: str, vault, private_file,
            read_journal, write_journal) -> None:
    """Do not start a fresh source revision while any older one has open work."""
    data, unresolved = inspect(folder, packet, vault, private_file, read_journal)
    if unresolved:
        raise ValueError("An earlier engagement source has an unresolved HUMAN draft.")
    if source_key not in data["sources"]:
        if len(data["sources"]) >= MAX_REVISIONS:
            raise ValueError("PRIVATE engagement index capacity reached.")
        data["sources"].append(source_key)
        # The existing private writer does atomic replace and fsync.
        # This reservation precedes the first pending draft journal.
        write_journal(folder, _name(packet), data)
