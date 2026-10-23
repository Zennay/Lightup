#!/usr/bin/env python3
"""Read-only, source-UNAUTHENTICATED private original HUMAN workspace inspection.

This inspects a packet as data, with no lab execution, consent, grants or GO.
For actual ORIGINAL source-byte matching use one_command.py --reopen-workspace.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
from io import BytesIO
import sys
from zipfile import ZipFile, BadZipFile, ZIP_STORED

from portfolio import (FLAGS, Hold, read_regular, decode_json, encode,
                       load_one, summarize, private, MAX_BYTES)
from content_map import verify as verify_content_map
from one_command import SCHEMA, MAX_WORKSPACE_BYTES
from agenda import selected_day

BASE = {
    "workspace-home.html", "collaboration-guide.html", "START-HERE.txt",
    "index.html", "interactive-capacity-studio.html",
    "original-human-review-studio.html", "private-source-bindings.json",
    "aggregate.html", "aggregate.json", "aggregate.csv",
    "private-workspace-content-map.json"
}
ADDED = {"private-original-source-map.json", "ORIGINAL-HUMAN-START-HERE.txt"}
MAP_FIELDS = {"schema", "reference_date", "source_count", "sources",
              "claimed_status", "planning_not_permission", *FLAGS}
ROW_FIELDS = {"slot", "original_manifest_sha256", "original_choices_sha256",
              "derived_original_agenda_sha256", "original_source_count",
              "claimed_status"}
HEX = set("0123456789abcdef")


def digest(value):
    return type(value) is str and len(value) == 64 and set(value) <= HEX


def inspect(path):
    raw = read_regular(path, MAX_WORKSPACE_BYTES)
    if not 0 < len(raw) <= MAX_WORKSPACE_BYTES:
        raise Hold("invalid original workspace")
    with ZipFile(BytesIO(raw), "r") as archive:
        infos = archive.infolist()
        if not 14 <= len(infos) <= 25:
            raise Hold("unexpected original workspace members")
        names = [item.filename for item in infos]
        if len(names) != len(set(names)):
            raise Hold("duplicate original workspace member")
        for info in infos:
            if (info.filename in ("", ".", "..")
                    or "/" in info.filename or "\\" in info.filename
                    or info.is_dir() or info.compress_type != ZIP_STORED
                    or info.flag_bits & 1 or info.file_size <= 0
                    or info.file_size > MAX_WORKSPACE_BYTES
                    or info.compress_size != info.file_size
                    or (info.external_attr >> 16) & 0o7777 != 0o600):
                raise Hold("original workspace member boundary invalid")
        source_map = decode_json(archive.read("private-original-source-map.json"))
        if (type(source_map) is not dict or set(source_map) != MAP_FIELDS
                or source_map["schema"] != SCHEMA
                or type(source_map["source_count"]) is not int
                or not 1 <= source_map["source_count"] <= 12
                or type(source_map["reference_date"]) is not str
                or source_map["planning_not_permission"] is not True
                or source_map["claimed_status"] not in ("REVIEW_ONLY", "HOLD")
                or any(source_map[flag] is not False for flag in FLAGS)):
            raise Hold("unknown original private source map")
        reference = source_map["reference_date"]
        selected_day(reference)
        count = source_map["source_count"]
        expected = BASE | ADDED | {
            f"original-private-agenda-{i:02d}.json" for i in range(1, count + 1)
        }
        if set(names) != expected:
            raise Hold("unexpected original workspace layout")
        rows = source_map["sources"]
        if type(rows) is not list or len(rows) != count:
            raise Hold("incomplete original private source map")
        agendas = []
        seen_originals = set()
        for i, row in enumerate(rows, 1):
            if (type(row) is not dict or set(row) != ROW_FIELDS
                    or type(row["slot"]) is not int or row["slot"] != i
                    or not all(digest(row[key]) for key in (
                        "original_manifest_sha256", "original_choices_sha256",
                        "derived_original_agenda_sha256"))
                    or type(row["original_source_count"]) is not int
                    or not 1 <= row["original_source_count"] <= 64
                    or row["claimed_status"] not in ("REVIEW_ONLY", "HOLD")
                    or row["original_manifest_sha256"] in seen_originals):
                raise Hold("invalid original source ordinal or correlation")
            seen_originals.add(row["original_manifest_sha256"])
            data = archive.read(f"original-private-agenda-{i:02d}.json")
            if not 0 < len(data) <= MAX_BYTES:
                raise Hold("invalid original agenda size")
            admitted = load_one(None, reference, raw=data)
            if (admitted["sha256"] != row["derived_original_agenda_sha256"]
                    or admitted["status"] != row["claimed_status"]
                    or len(admitted["rows"]) != row["original_source_count"]):
                raise Hold("original agenda differs from unsigned source map")
            agendas.append(admitted)
        summary = summarize(agendas, reference)
        if summary["claimed_status"] != source_map["claimed_status"]:
            raise Hold("original HOLD status differs")
        if archive.read("aggregate.json") != encode(summary):
            raise Hold("anonymous aggregate disagrees with original agendas")
        if archive.read("private-source-bindings.json") != encode(private(agendas, summary)):
            raise Hold("private source bindings disagree with original agendas")
        verify_content_map(archive, BASE - {"private-workspace-content-map.json"},
                           count, reference)
        if not archive.read("ORIGINAL-HUMAN-START-HERE.txt").startswith(
                b"LIGHTUP SINGLE-COMMAND ORIGINAL HUMAN ASSESSMENT WORKSPACE\n"):
            raise Hold("unknown original packet description")
        return count, summary["claimed_status"]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="READ-ONLY PRIVATE original HUMAN ZIP byte consistency, NOT source authentication or GO")
    parser.add_argument("--workspace", required=True,
                        help="Existing owner-private original workspace ZIP (0600), no extraction")
    args = parser.parse_args(argv)
    try:
        count, status = inspect(args.workspace)
        print(f"PRIVATE_ORIGINAL_WORKSPACE_CONTENT_REVIEW_ONLY agendas={count} — NO GO")
        return 3 if status == "HOLD" else 2
    except (Hold, OSError, BadZipFile, ValueError, KeyError, TypeError,
            UnicodeError, RecursionError, OverflowError, EOFError, RuntimeError):
        print("PRIVATE_ORIGINAL_WORKSPACE_HOLD — unverified or changed private packet",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
