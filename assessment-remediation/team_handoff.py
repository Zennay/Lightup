#!/usr/bin/env python3
"""Private non-authorizing human-review handoff/return.

The recipient may edit human stage, reviewer, next action and notes only.
The original owner must accept the return against the EXACT base document;
no original lab/comparison/findings sources, grants or retest statuses change.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import os
from pathlib import Path
import re
import sys

from bridge import (
    FLAGS, LINK_SCHEMA, MAX_LINKS, STAGES, bounded_text, fail_if,
    private_dir,
)

HERE = Path(__file__).resolve().parent
sys.path.insert(1, str(HERE.parent / "assessment-archive"))
from archive import Hold, decode_json, encode, publish, read_regular

TEAM_SCHEMA = "lightup.assessment_remediation_team_handoff.v1"
RETURN_SCHEMA = "lightup.assessment_remediation_team_return.v1"
FIELDS = ("stage", "reviewer", "next_action", "note")
IDENTITIES = ("scenario_id", "finding_id")
DOC_KEYS = {"schema", "comparison_sha256", "findings_sha256", "links", *FLAGS}
HEADER_KEYS = {"schema", "original_links_sha256", "comparison_sha256",
               "findings_sha256", "entries", *FLAGS}
ENTRY_KEYS = {*IDENTITIES, *FIELDS}


def hash_string(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None


def admit_original(raw):
    document = decode_json(raw)
    fail_if(type(document) is not dict or set(document) != DOC_KEYS
            or document["schema"] != LINK_SCHEMA
            or any(document[k] is not False for k in FLAGS)
            or not hash_string(document["comparison_sha256"])
            or not hash_string(document["findings_sha256"]),
            "original operator mapping schema/authority invalid")
    entries = document["links"]
    fail_if(type(entries) is not list or len(entries) > 512,
            "too many original human links")
    seen = set()
    for item in entries:
        validate_entry(item)
        identity = tuple(item[key] for key in IDENTITIES)
        fail_if(identity in seen, "duplicate original scenario/finding pair")
        seen.add(identity)
    return document


def validate_entry(row):
    fail_if(type(row) is not dict or set(row) != ENTRY_KEYS,
            "team entry has changed original source/link schema")
    for name in IDENTITIES:
        value = row[name]
        fail_if(type(value) is not str or not value or len(value) > 256 or
                value != value.strip() or
                any(ord(char) < 32 or ord(char) > 126 for char in value),
                "team entry identity not canonical")
    fail_if(type(row["stage"]) is not str or row["stage"] not in STAGES or
            not bounded_text(row["reviewer"], 100) or
            not bounded_text(row["next_action"], 300) or
            not bounded_text(row["note"], 500),
            "human-only update fields malformed")


def envelope(schema, original_raw, source):
    return {
        "schema": schema,
        "original_links_sha256": sha256(original_raw).hexdigest(),
        "comparison_sha256": source["comparison_sha256"],
        "findings_sha256": source["findings_sha256"],
        "entries": source["links"],
        **{name: False for name in FLAGS},
    }


def read_team(raw, schema):
    doc = decode_json(raw)
    expected = HEADER_KEYS | (
        {"team_room_source_sha256"} if schema == TEAM_SCHEMA else set()
    )
    fail_if(type(doc) is not dict or set(doc) != expected or
            doc["schema"] != schema or
            not hash_string(doc["original_links_sha256"]) or
            not hash_string(doc["comparison_sha256"]) or
            not hash_string(doc["findings_sha256"]) or
            (schema == TEAM_SCHEMA and
             not hash_string(doc["team_room_source_sha256"])) or
            any(doc[k] is not False for k in FLAGS),
            "unsupported team handoff or authority claim")
    fail_if(type(doc["entries"]) is not list or len(doc["entries"]) > 512,
            "invalid private team entry count")
    found = set()
    for item in doc["entries"]:
        validate_entry(item)
        ident = tuple(item[k] for k in IDENTITIES)
        fail_if(ident in found, "ambiguous human team pair")
        found.add(ident)
    return doc


def target(output_dir, prefix, suffix):
    fail_if(type(prefix) is not str or
            re.fullmatch("[A-Za-z][A-Za-z0-9_-]{0,39}", prefix) is None,
            "invalid private output prefix")
    path = private_dir(output_dir) / (prefix + suffix)
    fail_if(os.path.lexists(path), "private destination already exists")
    return path


def prepare(args):
    original = read_regular(args.links, MAX_LINKS)
    mapping = admit_original(original)
    if args.scenario:
        selected_scenarios = set(args.scenario)
        fail_if(len(args.scenario) != len(selected_scenarios) or
                len(selected_scenarios) > 64 or
                any(type(v) is not str or not v for v in selected_scenarios),
                "ambiguous private scenario selection")
        selected_links = [
            row for row in mapping["links"]
            if row["scenario_id"] in selected_scenarios
        ]
        fail_if(not selected_links or
                {row["scenario_id"] for row in selected_links} != selected_scenarios,
                "a chosen scenario has no existing human original links")
        filtered = {**mapping, "links": selected_links}
    else:
        filtered = mapping
    handoff = envelope(TEAM_SCHEMA, original, filtered)
    # Team draft is an untrusted human annotation workflow, not a verified
    # source or signed authority; original finding data is not embedded.
    portable = read_regular(str(HERE / "team-room.html"), 131072)
    source_hash = sha256(portable).hexdigest()
    handoff["team_room_source_sha256"] = source_hash
    destination = target(args.output_dir, args.prefix, "-team-handoff.json")
    page_destination = target(args.output_dir, args.prefix, "-team-room.html")
    kit_destination = target(args.output_dir, args.prefix, "-private-team-kit.zip")
    published = encode(handoff)
    fail_if(len(published) > MAX_LINKS, "team handoff exceeds private document bound")
    if (sha256(read_regular(args.links, MAX_LINKS)).digest() != sha256(original).digest()
            or sha256(read_regular(str(HERE / "team-room.html"), 131072)).hexdigest() != source_hash):
        raise Hold("private source or offline team room changed during handoff")
    # Each independent file is fsynced, exclusive and 0600. No source
    # mutation and no silent replacement of an existing team return.
    from team_packet import pack
    kit = pack(published, portable, encode)
    publish(destination, published)
    publish(page_destination, portable)
    publish(kit_destination, kit)
    print("PRIVATE_TEAM_HANDOFF_CREATED — UNAUTHENTICATED HUMAN NOTES ONLY")
    print("Private JSON, standalone offline HTML and integrity-bound team ZIP created.")
    print("This artifact conveys NO permission, consent, scan, retest or verified fix.")
    return 2


def receive(args):
    original_raw = read_regular(args.links, MAX_LINKS)
    source = admit_original(original_raw)
    returned_raw = read_regular(args.returned, MAX_LINKS)
    team = read_team(returned_raw, RETURN_SCHEMA)
    fail_if(team["original_links_sha256"] != sha256(original_raw).hexdigest()
            or team["comparison_sha256"] != source["comparison_sha256"]
            or team["findings_sha256"] != source["findings_sha256"],
            "team return no longer matches exact original baseline")
    original_by_identity = {
        (row["scenario_id"], row["finding_id"]): row
        for row in source["links"]
    }
    received_by_identity = {
        (row["scenario_id"], row["finding_id"]): row
        for row in team["entries"]
    }
    if args.handoff:
        source_handoff_raw = read_regular(args.handoff, MAX_LINKS)
        source_handoff = read_team(source_handoff_raw, TEAM_SCHEMA)
        fail_if(source_handoff["original_links_sha256"] != sha256(original_raw).hexdigest()
                or source_handoff["comparison_sha256"] != source["comparison_sha256"]
                or source_handoff["findings_sha256"] != source["findings_sha256"],
                "private selected source handoff no longer binds the owner baseline")
        expected_pairs = {
            (row["scenario_id"], row["finding_id"]): row
            for row in source_handoff["entries"]
        }
        fail_if(any(key not in original_by_identity or
                    original_by_identity[key] != value
                    for key, value in expected_pairs.items()),
                "selected private human handoff altered source baseline content")
    else:
        expected_pairs = original_by_identity
    fail_if(set(received_by_identity) != set(expected_pairs),
            "team return attempted original source identity/link membership edits")
    updated = []
    updated_count = 0
    for current in source["links"]:
        ident = (current["scenario_id"], current["finding_id"])
        proposed = received_by_identity.get(ident, current)
        if any(proposed[key] != current[key] for key in FIELDS):
            updated_count += 1
        updated.append({
            "scenario_id": current["scenario_id"],
            "finding_id": current["finding_id"],
            **{key: proposed[key] for key in FIELDS},
        })
    latest = {**source, "links": updated}
    from team_diff import describe
    private_diff, aggregate = describe(
        source["links"], updated, sha256(original_raw).hexdigest()
    )
    destination = target(args.output_dir, args.prefix, "-reviewed-links.json")
    diff_destination = target(args.output_dir, args.prefix, "-private-team-diff.html")
    aggregate_destination = target(args.output_dir, args.prefix, "-human-changes.json")
    render_requested = args.comparison is not None or args.findings_csv is not None
    fail_if(render_requested and not (args.comparison and args.findings_csv)
            or args.bundle and not render_requested,
            "both original sources are required for direct private dossier creation")
    if render_requested:
        from bridge import (
            MAX_COMPARE, MAX_FINDINGS, original_comparison, original_findings,
            links_document,
        )
        comparison = read_regular(args.comparison, MAX_COMPARE)
        findings_source = read_regular(args.findings_csv, MAX_FINDINGS)
        admitted_compare = original_comparison(comparison)
        admitted_findings = original_findings(findings_source)
        links_document(
            encode(latest),
            sha256(comparison).hexdigest(),
            sha256(findings_source).hexdigest(),
            {row["scenario_id"] for row in admitted_compare["comparisons"]},
            admitted_findings,
        )
        directory = private_dir(args.output_dir)
        for suffix in (
            "-private.html", "-links.json", "-aggregate.json",
            "-private-agenda.csv",
            *(("-private-room.zip",) if args.bundle else ())
        ):
            fail_if(os.path.lexists(directory / (args.prefix + suffix)),
                    "complete private dossier destination already exists")
    # No manual changes to real original client data or lab reports:
    # this is a new strict mapping v1, accepted later only by bridge.py
    # when both separately authorized exported sources match.
    admitted = admit_original(encode(latest))
    fail_if(len(admitted["links"]) != len(source["links"]),
            "team update changed membership")
    fail_if(read_regular(args.links, MAX_LINKS) != original_raw or
            read_regular(args.returned, MAX_LINKS) != returned_raw or
            (args.handoff and read_regular(args.handoff, MAX_LINKS) != source_handoff_raw),
            "human team baseline/selected handoff/return changed during receipt")
    publish(destination, encode(latest))
    publish(diff_destination, private_diff)
    publish(aggregate_destination, encode(aggregate))
    print("PRIVATE_TEAM_RETURN_ACCEPTED — " + str(updated_count) +
          " human-only notes changed; " + str(len(updated)) +
          " original source links preserved.")
    print("Private scriptless before/after human dossier and ID-free change counts created.")
    print("The return was NOT sender-authenticated; operator must verify human recipient.")
    if render_requested:
        from types import SimpleNamespace
        from bridge import run as render_original_sources
        status = render_original_sources(SimpleNamespace(
            comparison=args.comparison,
            findings_csv=args.findings_csv,
            links=str(destination),
            output_dir=args.output_dir,
            prefix=args.prefix,
            bundle=args.bundle,
        ))
        if args.bundle:
            from packet import create_room
            create_room(SimpleNamespace(
                output_dir=args.output_dir, prefix=args.prefix
            ))
        print("Latest PRIVATE source-bound human dossier rendered; source security "
              "status remains unverified and never grants GO.")
        return status
    print("Use the new mapping with unchanged original source exports through bridge.py.")
    return 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=(
        "Prepare/readmitted human-only private team notes without access, scan,"
        " client permission, source finding or retest-status mutation."
    ))
    sub = parser.add_subparsers(dest="action", required=True)
    for name in ("prepare", "receive"):
        command = sub.add_parser(name)
        command.add_argument("--links", required=True, help="Original private source-bound links JSON")
        command.add_argument("--output-dir", required=True, help="Existing owner-only 0700 folder")
        command.add_argument("--prefix", required=True, help="New unused output name prefix")
        if name == "prepare":
            command.add_argument("--scenario", action="append", default=[],
                                 help="Select existing original scenario IDs for minimal team disclosure")
        if name == "receive":
            command.add_argument("--handoff",
                                 help="Original source handoff JSON, required for any selected subset return")
            command.add_argument("--returned", required=True,
                                 help="Human team-return JSON exported from team room")
            command.add_argument("--comparison", help="Optional exact original canonical benchmark JSON")
            command.add_argument("--findings-csv", help="Optional exact original authenticated findings CSV")
            command.add_argument("--bundle", action="store_true",
                                 help="With both original sources, also produce confidential room ZIP")
    inspection = sub.add_parser("inspect", help="Read-only private team ZIP integrity")
    inspection.add_argument("private_team_kit")
    args = parser.parse_args(argv)
    try:
        if args.action == "inspect":
            from team_packet import inspect, CAP
            handoff = inspect(read_regular(args.private_team_kit, CAP), decode_json)
            read_team(encode(handoff), TEAM_SCHEMA)
            print("PRIVATE_TEAM_KIT_INTEGRITY_ONLY — not sender-authenticated or authorized")
            return 2
        return prepare(args) if args.action == "prepare" else receive(args)
    except (Hold, OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError):
        print("PRIVATE_TEAM_HANDOFF_HOLD — private source/return changed or invalid",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
