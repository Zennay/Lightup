#!/usr/bin/env python3
"""Offline bounded integrity inspection of an already-created coordination ZIP.

Never extracts or runs files, assesses targets, authenticates senders or grants.
A self-declared SHA-256 manifest is *not* an independent signature or trust.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
from io import BytesIO
import stat
import sys
from zipfile import ZipFile, BadZipFile, ZIP_DEFLATED

from archive import FLAGS, Hold, decode_json, encode, publish, read_regular

MAX_PACKET = 2 * 1024 * 1024
MAX_EXPANDED = 3 * 1024 * 1024
MAX_MEMBER = 512 * 1024
ALLOW = frozenset((
    "README.txt", "receipt.json", "archive-index.json",
    "archive-dashboard.html", "index.html", "human-worklist.json",
    "human-worklist.html", "archive-studio.html", "human-agenda.html",
    "packet-integrity.json"
))
REQUIRED = frozenset((
    "README.txt", "receipt.json", "archive-index.json",
    "archive-dashboard.html", "index.html", "packet-integrity.json"
))


def packet_receipt(data):
    with ZipFile(BytesIO(data)) as zf:
        entries = zf.infolist()
        if not 6 <= len(entries) <= len(ALLOW) or zf.comment:
            raise Hold("invalid review ZIP size")
        names = {}
        total = 0
        for entry in entries:
            name = entry.filename
            if (name not in ALLOW or name in names or entry.flag_bits & 1 or
                    entry.compress_type != ZIP_DEFLATED or
                    not stat.S_ISREG(entry.external_attr >> 16) or
                    entry.file_size <= 0 or entry.file_size > MAX_MEMBER):
                raise Hold("unsafe ZIP member")
            names[name] = entry
            total += entry.file_size
            if total > MAX_EXPANDED:
                raise Hold("expanded packet too large")
        if not REQUIRED.issubset(names):
            raise Hold("missing original review files")
        records = decode_json(zf.read("packet-integrity.json"))
        if type(records) is not dict or set(records) != {
            "schema", "packet_mode", "members", "member_count",
            "authenticated", *FLAGS
        } or records["schema"] != "lightup.assessment_archive_packet_integrity.v1":
            raise Hold("unsupported packet source")
        mode = records["packet_mode"]
        if (mode not in ("OWNER_PRIVATE", "AGGREGATE_ONLY") or
                records["authenticated"] is not False or
                any(records[key] is not False for key in FLAGS)):
            raise Hold("authority claim in index")
        index = records["members"]
        if type(index) is not list or type(records["member_count"]) is not int or (
                records["member_count"] != len(index) or len(index) != len(entries)-1):
            raise Hold("invalid index count")
        listed = set()
        for row in index:
            if type(row) is not dict or set(row) != {"name", "size_bytes", "sha256"}:
                raise Hold("malformed member receipt")
            name, size, digest = row["name"], row["size_bytes"], row["sha256"]
            if (type(name) is not str or name not in names or name == "packet-integrity.json" or
                    name in listed or type(size) is not int or
                    size != names[name].file_size or type(digest) is not str or
                    len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)):
                raise Hold("member receipt differs")
            listed.add(name)
            # Read only, *never* extract/write the member. ZipFile checks CRC.
            if sha256(zf.read(name)).hexdigest() != digest:
                raise Hold("member bytes differ")
        if listed != set(names) - {"packet-integrity.json"}:
            raise Hold("member collection mismatch")
        receipt = decode_json(zf.read("receipt.json"))
        if type(receipt) is not dict or receipt.get("schema") != (
                "lightup.assessment_archive_coordination_packet.v1"):
            raise Hold("malformed original packet receipt")
        if (receipt.get("packet_mode") != mode or receipt.get("is_authentication") is not False or
                receipt.get("original_data_included") is not False or
                any(receipt.get(key) is not False for key in FLAGS) or
                type(receipt.get("source_count")) is not int or
                not 2 <= receipt["source_count"] <= 64 or
                receipt.get("claimed_status") not in ("HOLD", "REVIEW_ONLY")):
            raise Hold("unsupported original packet authority")
        if (receipt.get("has_human_followup") is not ("human-worklist.json" in names) or
            receipt.get("has_human_agenda") is not ("human-agenda.html" in names) or
            (receipt.get("has_human_agenda") and not receipt.get("has_human_followup")) or
            type(receipt.get("has_local_archive_history")) is not bool):
            raise Hold("contradictory packet contents")
        archive = decode_json(zf.read("archive-index.json"))
        if not isinstance(archive, dict) or archive.get("source_count") != receipt["source_count"] or (
                "authorized" in archive and archive["authorized"] is not False):
            raise Hold("original archive index differs")
        if any(archive.get(key) is not False for key in FLAGS):
            raise Hold("unsupported archive claims")
        if mode == "AGGREGATE_ONLY":
            if ("archive-studio.html" in names or "local_manifest_sha256" in receipt or
                    archive.get("schema") != "lightup.assessment_archive_aggregate.v1" or
                    "entries" in archive or "items" in archive):
                raise Hold("private source hidden data in aggregate mode")
            if "human-worklist.json" in names:
                human = decode_json(zf.read("human-worklist.json"))
                if type(human) is not dict or "items" in human or (
                    human.get("source_count") != receipt["source_count"]):
                    raise Hold("private human data in aggregate index")
        else:
            if archive.get("schema") != "lightup.assessment_archive.v1":
                raise Hold("missing original owner-private index")
            fingerprint = receipt.get("local_manifest_sha256")
            if type(fingerprint) is not str or len(fingerprint) != 64 or any(
                    c not in "0123456789abcdef" for c in fingerprint):
                raise Hold("original private index fingerprint missing")
        return {
            "schema": "lightup.assessment_archive_packet_inspection.v1",
            "status": receipt["claimed_status"],
            "packet_mode": mode,
            "source_count": receipt["source_count"],
            "member_count": len(names),
            "optional_human_followup": receipt["has_human_followup"],
            "optional_human_agenda": receipt["has_human_agenda"],
            "optional_private_studio": "archive-studio.html" in names,
            "bytes_match_declared_sha256": True,
            "sender_authenticated": False,
            "source_provenance_verified": False,
            **{key: False for key in FLAGS},
        }


def inspect(args):
    document = packet_receipt(read_regular(args.packet, MAX_PACKET))
    if args.output:
        publish(args.output, encode(document))
    print("PRIVATE_COORDINATION_PACKET_BYTES_MATCHED — SENDER NOT AUTHENTICATED; NO AUTHORITY")
    print("MODE=" + document["packet_mode"] + " SOURCES=" + str(document["source_count"]) +
          " ENTRIES=" + str(document["member_count"]) + " STATE=" + document["status"])
    return 2 if document["status"] == "REVIEW_ONLY" else 3


def main(argv=None):
    p = argparse.ArgumentParser(description="Inspect original local coordination ZIP bytes, never trust, extract or execute it.")
    p.add_argument("packet", help="Explicit previously-created local ZIP path")
    p.add_argument("--output", help="Optional NEW private non-identifying inspection JSON")
    args = p.parse_args(argv)
    try:
        return inspect(args)
    except (Hold, OSError, ValueError, TypeError, UnicodeError, KeyError,
            OverflowError, RecursionError, BadZipFile):
        print("PACKET_INSPECTION_HOLD — invalid, modified or untrusted local ZIP", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
