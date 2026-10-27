#!/usr/bin/env python3
"""Private portable human-only assessment/remediation room. No target execution."""
from __future__ import annotations

import argparse
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import re
import sys
from zipfile import ZipFile, ZipInfo, ZIP_STORED, BadZipFile

from bridge import (
    AGG_SCHEMA, FLAGS, LINK_SCHEMA, MAX_LINKS, STAGES, bounded_text, fail_if, private_dir,
)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "assessment-archive"))
from archive import Hold, decode_json, encode, publish, read_regular

SCHEMA = "lightup.assessment_remediation_room.v1"
MAX_TOTAL = 8 * 1024 * 1024
FILE_MAP = {
    "review/index.html": ("private.html", 4 * 1024 * 1024),
    "review/private-links.json": ("links.json", MAX_LINKS),
    "review/aggregate.json": ("aggregate.json", 65536),
    "review/agenda.csv": ("private-agenda.csv", 262144),
}
README = (
    "LIGHTUP PRIVATE LAB → FINDING FOLLOW-UP ROOM\n"
    "Confidential original scenario/finding identifiers and notes may be present.\n"
    "Offline HUMAN REVIEW ONLY; source snapshots are unsigned.\n"
    "Original source SHA-256 values are content digests, not client identity or permission.\n"
    "This archive does not prove same engagement, evidence, remediation, consent,\n"
    "authorization, scan safety or release readiness. Verify recipient separately.\n"
    "Extract only into a private owner-only directory and open review/index.html.\n"
    "Never host this private report on the public Internet.\n"
).encode("utf-8")


def read_sources(folder, prefix):
    data = {}
    originals = {}
    for archive_name, (suffix, limit) in FILE_MAP.items():
        path = folder / (prefix + "-" + suffix)
        payload = read_regular(str(path), limit)
        originals[path] = sha256(payload).hexdigest()
        data[archive_name] = payload
    aggregate = decode_json(data["review/aggregate.json"])
    links = decode_json(data["review/private-links.json"])
    fail_if(type(aggregate) is not dict or aggregate.get("schema") != AGG_SCHEMA or
            aggregate.get("status") not in ("REVIEW_ONLY", "HOLD") or
            any(aggregate.get(k) is not False for k in FLAGS) or
            type(aggregate.get("human_link_count")) is not int,
            "invalid original aggregate output")
    fail_if(type(links) is not dict or set(links) != {
        "schema", "comparison_sha256", "findings_sha256", "links", *FLAGS
    } or links["schema"] != LINK_SCHEMA or
            any(links[k] is not False for k in FLAGS) or
            type(links.get("links")) is not list or
            aggregate["human_link_count"] != len(links["links"]),
            "original linked-source dossier does not match aggregate")
    pairs = set()
    for link in links["links"]:
        fail_if(type(link) is not dict or set(link) != {
            "scenario_id", "finding_id", "stage", "reviewer", "next_action", "note"
        }, "private manual link does not follow original schema")
        scenario, finding = link["scenario_id"], link["finding_id"]
        fail_if(type(scenario) is not str or type(finding) is not str or
                not 0 < len(scenario) <= 256 or not 0 < len(finding) <= 256 or
                link["stage"] not in STAGES or
                not bounded_text(link["reviewer"], 100) or
                not bounded_text(link["next_action"], 300) or
                not bounded_text(link["note"], 500) or
                (scenario, finding) in pairs,
                "private original manual link is invalid or repeated")
        pairs.add((scenario, finding))
    for digest in (links["comparison_sha256"], links["findings_sha256"]):
        fail_if(type(digest) is not str or
                re.fullmatch("[0-9a-f]{64}", digest) is None,
                "source byte fingerprint invalid")
    try:
        decoded_agenda = data["review/agenda.csv"].decode("utf-8")
    except UnicodeError as err:
        raise Hold("invalid private agenda encoding") from err
    fail_if(not decoded_agenda.startswith('"scenario_id","source_status",'),
            "private agenda does not match native original report")
    fail_if(not data["review/index.html"].startswith(b"<!doctype html>") or
            b"<script" in data["review/index.html"].lower(),
            "private report must be original scriptless output")
    return data, originals, aggregate["status"]


def add_file(zf, name, payload):
    info = ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = ZIP_STORED
    info.create_system = 3
    info.external_attr = 0o100600 << 16
    zf.writestr(info, payload)


def create_room(args):
    fail_if(re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,39}", args.prefix) is None,
            "invalid original output prefix")
    folder = private_dir(args.output_dir)
    data, originals, status = read_sources(folder, args.prefix)
    destination = folder / (args.prefix + "-private-room.zip")
    fail_if(os.path.lexists(destination), "private room already exists")
    manifest = {
        "schema": SCHEMA,
        "status": status,
        "entries": [
            {"name": name, "bytes": len(payload), "sha256": sha256(payload).hexdigest()}
            for name, payload in sorted(data.items())
        ],
        "source_provenance": "unsigned_exact_byte_bindings_only",
        **{flag: False for flag in FLAGS},
    }
    package = BytesIO()
    with ZipFile(package, mode="w") as zf:
        add_file(zf, "README.txt", README)
        add_file(zf, "manifest.json", encode(manifest))
        for name, payload in sorted(data.items()):
            add_file(zf, name, payload)
    body = package.getvalue()
    fail_if(len(body) > MAX_TOTAL, "private room exceeds maximum bound")
    for original_name, (suffix, limit) in FILE_MAP.items():
        path = folder / (args.prefix + "-" + suffix)
        fail_if(sha256(read_regular(str(path), limit)).hexdigest() != originals[path],
                "private original source changed before room publication")
    publish(destination, body)
    print("PRIVATE_ASSESSMENT_ROOM_" + status)
    print("Source-bound private portable human room published as an exclusive 0600 ZIP.")
    return 3 if status == "HOLD" else 2


def inspect_room(path):
    data = read_regular(path, MAX_TOTAL)
    try:
        with ZipFile(BytesIO(data)) as zf:
            names = zf.namelist()
            expected = {"README.txt", "manifest.json", *FILE_MAP}
            fail_if(len(names) != len(expected) or set(names) != expected,
                    "private package entries missing, duplicated or unexpected")
            payloads = {}
            for info in zf.infolist():
                fail_if(info.filename not in expected or info.is_dir() or
                        info.compress_type != ZIP_STORED or
                        info.file_size > MAX_TOTAL or info.file_size <= 0 or
                        (info.external_attr >> 16) != 0o100600,
                        "unsafe original ZIP member")
                payloads[info.filename] = zf.read(info)
        manifest = decode_json(payloads["manifest.json"])
        fail_if(type(manifest) is not dict or set(manifest) != {
            "schema", "status", "entries", "source_provenance", *FLAGS
        } or manifest["schema"] != SCHEMA or
                manifest["status"] not in ("REVIEW_ONLY", "HOLD") or
                manifest["source_provenance"] != "unsigned_exact_byte_bindings_only" or
                any(manifest[k] is not False for k in FLAGS),
                "private manifest unsupported or claiming authority")
        entries = manifest["entries"]
        fail_if(type(entries) is not list or len(entries) != len(FILE_MAP),
                "private manifest has incomplete source list")
        if payloads["README.txt"] != README:
            raise Hold("private room marker mismatch")
        for expected_name, entry in zip(sorted(FILE_MAP), entries):
            payload = payloads[expected_name]
            fail_if(type(entry) is not dict or set(entry) != {
                "name", "bytes", "sha256"
            } or entry["name"] != expected_name or
                    type(entry["bytes"]) is not int or entry["bytes"] != len(payload) or
                    entry["sha256"] != sha256(payload).hexdigest() or
                    len(payload) > FILE_MAP[expected_name][1],
                    "private original byte manifest mismatch")
        # Inspector checks the original private linkage envelope without reinterpreting
        # source identity as an authenticated authorization or remediation outcome.
        links = decode_json(payloads["review/private-links.json"])
        fail_if(type(links) is not dict or set(links) != {
            "schema", "comparison_sha256", "findings_sha256", "links", *FLAGS
        } or links["schema"] != LINK_SCHEMA or
                any(links[flag] is not False for flag in FLAGS) or
                type(links["links"]) is not list or len(links["links"]) > 512,
                "private room human source links are malformed")
        data = decode_json(payloads["review/aggregate.json"])
        fail_if(data.get("status") != manifest["status"] or
                data.get("schema") != AGG_SCHEMA or
                data.get("human_link_count") != len(links["links"]) or
                any(data.get(flag) is not False for flag in FLAGS),
                "private human room/source review status mismatched")
        print("PRIVATE_ASSESSMENT_ROOM_" + manifest["status"])
        print("Original private room byte consistency only; not authenticated or authorized.")
        return 3 if manifest["status"] == "HOLD" else 2
    except (BadZipFile, EOFError, RuntimeError) as err:
        raise Hold("corrupt original private room") from err


def main(argv=None):
    parser = argparse.ArgumentParser(description=(
        "Pack or inspect an existing original private human lab-to-finding "
        "follow-up room; never authorizes a scan or release."
    ))
    sub = parser.add_subparsers(dest="action", required=True)
    bundle = sub.add_parser("bundle")
    bundle.add_argument("--output-dir", required=True, help="Existing private owner-only directory")
    bundle.add_argument("--prefix", required=True, help="Original bridge.py output prefix")
    inspect = sub.add_parser("inspect")
    inspect.add_argument("private_room")
    args = parser.parse_args(argv)
    try:
        return create_room(args) if args.action == "bundle" else inspect_room(args.private_room)
    except (Hold, OSError, ValueError, KeyError, TypeError, OverflowError,
            UnicodeError, RecursionError):
        print("PRIVATE_ASSESSMENT_ROOM_HOLD — invalid, changed or unsafe private packet",
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
