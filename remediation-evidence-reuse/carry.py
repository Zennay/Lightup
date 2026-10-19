#!/usr/bin/env python3
"""Explicit same-original-source PRIVATE HUMAN triage continuity.

No transfer between source revisions or changed HUMAN question identities.
No original LightUp Apply, evidence admission beyond existing local envelopes,
client identity proof, scan, grant, consent, legal action or verified fix.
"""
from __future__ import annotations

import argparse
from collections import Counter
import getpass
import json
from pathlib import Path
import sys

from review import Hold, private_publish, private_read, require
from triage import (STAGES, admit_session, canonical, fresh_original_bytes,
                    make_session, selected_sources, sha, single_host_lock)


def exact_inputs(current: Path, previous: Path | None):
    from argparse import Namespace
    return selected_sources(current, previous)


def state_from_files(current: Path, previous: Path | None) -> tuple[dict, bytes, bytes | None]:
    source, prior, actual, earlier = exact_inputs(current, previous)
    return make_session(source, prior, actual, earlier), actual, earlier


def bridge(old: dict, fresh: dict) -> tuple[dict, dict]:
    for field in ("source_sha256", "client_reference", "engagement_reference"):
        require(old[field] == fresh[field],
                "Original finding-source revision or self-declared client/engagement changed: HOLD")
    # Preserve only literal HUMAN question identities; a revised proposed question is new work.
    old_map = {(row["finding_id"], row["local_sha256"]): row for row in old["records"]}
    new_map = {(row["finding_id"], row["local_sha256"]): row for row in fresh["records"]}
    require(len(old_map) == len(old["records"]) and
            len(new_map) == len(fresh["records"]),
            "Ambiguous HUMAN finding/fingerprint identity")
    missing = set(old_map) - set(new_map)
    require(not missing,
            "An existing HUMAN follow-up disappeared from the new local packet. Preserve original session and review separately; carry refused.")
    changed = [key for key in old_map if old_map[key]["reasons"] != new_map[key]["reasons"]]
    require(not changed,
            "An existing HUMAN question changed reasons. Review it manually; old stage cannot be carried silently.")
    copied = 0
    changed_stages = Counter()
    for key, row in new_map.items():
        original = old_map.get(key)
        if original is None:
            continue
        row["stage"] = original["stage"]
        row["human_note"] = original["human_note"]
        row["updated_utc"] = original["updated_utc"]
        copied += 1
        changed_stages[row["stage"]] += 1
    summary = {
        "kind": "lightup.anonymous_private_human_same_source_continuity",
        "schema_version": 1,
        "disposition": "HUMAN_REVIEW_ONLY_NO_AUTHORITY",
        "old_question_slots": len(old_map),
        "carried_identical_human_question_slots": copied,
        "new_human_question_slots": len(new_map) - copied,
        "human_stages_carried": {stage: changed_stages.get(stage, 0) for stage in STAGES},
        "notice": "Same original source *claims* only. No authenticated history, apply, consent or evidence verification.",
    }
    return fresh, summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Private HUMAN review continuation across changing exports of identical original source")
    parser.add_argument("action", choices=("preview", "carry"))
    parser.add_argument("--old-current", type=Path, required=True,
                        help="The exact 0600 input used to start previous HUMAN inbox")
    parser.add_argument("--old-previous", type=Path,
                        help="Prior same-source input, only if previous inbox was based on it")
    parser.add_argument("--old-session", type=Path, required=True,
                        help="Existing source-byte-bound PRIVATE HUMAN session, never altered")
    parser.add_argument("--new-current", type=Path, required=True,
                        help="New PRIVATE export with *identical original* finding SHA and context")
    parser.add_argument("--new-previous", type=Path,
                        help="Prior input if needed for new HUMAN question set")
    parser.add_argument("--output", type=Path, help="Unused PRIVATE 0600 output session path for carry")
    args = parser.parse_args()
    try:
        require((args.action == "carry") == (args.output is not None),
                "Only carry accepts an exclusive new --output")
        source_paths = (args.old_current, args.old_previous, args.old_session,
                        args.new_current, args.new_previous)
        if args.output:
            require(args.output not in source_paths,
                    "Never overwrite original source, session or previous packet")
        old_expected, old_current_bytes, old_previous_bytes = state_from_files(
            args.old_current, args.old_previous)
        new_expected, new_current_bytes, new_previous_bytes = state_from_files(
            args.new_current, args.new_previous)
        require(old_expected["source_packet_sha256"] != new_expected["source_packet_sha256"] or
                old_expected["previous_packet_sha256"] != new_expected["previous_packet_sha256"],
                "Original PRIVATE packets are identical; use the existing HUMAN session")
        with single_host_lock(args.old_session):
            old_session_bytes = private_read(args.old_session)
            old_session = admit_session(old_session_bytes, old_expected)
            next_session, summary = bridge(old_session, new_expected)
            print(json.dumps(summary, indent=2, sort_keys=True))
            if args.action == "preview":
                return 2
            require(sys.stdin.isatty() and sys.stderr.isatty(),
                    "HUMAN continuity requires a trusted interactive terminal")
            confirmation = getpass.getpass(
                "Type CARRY SAME ORIGINAL HUMAN SOURCE to create a NEW PRIVATE session: ")
            require(confirmation == "CARRY SAME ORIGINAL HUMAN SOURCE",
                    "No continuity without explicit HUMAN acknowledgement")
            from argparse import Namespace
            fresh_original_bytes(Namespace(current=args.old_current,
                                           previous=args.old_previous),
                                 old_current_bytes, old_previous_bytes)
            fresh_original_bytes(Namespace(current=args.new_current,
                                           previous=args.new_previous),
                                 new_current_bytes, new_previous_bytes)
            require(private_read(args.old_session) == old_session_bytes,
                    "Older HUMAN session changed while confirming continuity")
            # The new one remains bound to *the new packet bytes* and exact proposal.
            private_publish(args.output, canonical(next_session))
            print("New PRIVATE HUMAN continuation created. Old session/source remain untouched.")
        return 2
    except (Hold, OSError, ValueError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
