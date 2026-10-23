#!/usr/bin/env python3
"""Unsigned deterministic byte-correlation manifest for PRIVATE offline workspace.

Not a signature, consent, source authenticity or trust in browser content.
"""
from __future__ import annotations
from hashlib import sha256

from portfolio import FLAGS, Hold, decode_json, encode
from archive import reject_authority

SCHEMA = "lightup.assessment_portfolio_private_content_manifest.v1"
FIELDS = {"schema", "source_count", "reference_date", "entries",
          "planning_not_permission", *FLAGS}
ENTRY_FIELDS = {"name", "size_bytes", "sha256"}
MAX_CONTENT = 16 * 1024 * 1024


def build(files, summary):
    if (type(files) is not dict or not 1 <= len(files) <= 20
            or "private-workspace-content-map.json" in files
            or type(summary) is not dict):
        raise Hold("invalid package manifest inputs")
    rows = []
    for name, content in sorted(files.items()):
        if (type(name) is not str or "/" in name or "\\" in name
                or name in ("", ".", "..") or type(content) is not bytes
                or not 0 < len(content) <= MAX_CONTENT):
            raise Hold("invalid local package content")
        rows.append({"name": name, "size_bytes": len(content),
                     "sha256": sha256(content).hexdigest()})
    result = {"schema": SCHEMA, "source_count": summary["agenda_count"],
              "reference_date": summary["reference_date"],
              "entries": rows, "planning_not_permission": True,
              **{flag: False for flag in FLAGS}}
    return encode(result)


def verify(archive, mapped, source_count, reference_date):
    document = decode_json(archive.read("private-workspace-content-map.json"))
    reject_authority(document)
    if (type(document) is not dict or set(document) != FIELDS
            or document["schema"] != SCHEMA
            or document["planning_not_permission"] is not True
            or type(document["source_count"]) is not int
            or document["source_count"] != source_count
            or document["reference_date"] != reference_date
            or type(document["entries"]) is not list
            or len(document["entries"]) != len(mapped)
            or any(document[flag] is not False for flag in FLAGS)):
        raise Hold("unknown private workspace content map")
    expected = set(mapped)
    seen = set()
    for entry in document["entries"]:
        if (type(entry) is not dict or set(entry) != ENTRY_FIELDS
                or type(entry["name"]) is not str
                or entry["name"] not in expected or entry["name"] in seen
                or type(entry["size_bytes"]) is not int
                or not 0 < entry["size_bytes"] <= MAX_CONTENT
                or type(entry["sha256"]) is not str
                or len(entry["sha256"]) != 64
                or any(c not in "0123456789abcdef" for c in entry["sha256"])):
            raise Hold("invalid private workspace member fingerprint")
        seen.add(entry["name"])
        content = archive.read(entry["name"])
        if (len(content) != entry["size_bytes"]
                or sha256(content).hexdigest() != entry["sha256"]):
            raise Hold("original workspace component differs from saved byte correlation")
    if seen != expected:
        raise Hold("incomplete private workspace member map")
