#!/usr/bin/env python3
"""Atomic human-only reconciliation of independent private team return cohorts.

A common source-bound owner baseline can be split across disjoint human
review teams, and all returns can then be reconciled exactly ONCE without
either team having to update live findings, grants, lab metrics or permissions.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import os
from pathlib import Path
import re
import sys
from types import SimpleNamespace

from bridge import (
    FLAGS, MAX_COMPARE, MAX_FINDINGS, MAX_LINKS, fail_if,
    links_document, original_comparison, original_findings,
    private_dir, run as create_original_dossier,
)
from team_diff import describe
from team_workboard import render as render_private_workboard
from team_handoff import (
    TEAM_SCHEMA, RETURN_SCHEMA, IDENTITIES, FIELDS, admit_original,
    read_team,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(1, str(ROOT / "assessment-archive"))
from archive import Hold, decode_json, encode, publish, read_regular


def packet_pairs(entries):
    return {(item["scenario_id"], item["finding_id"]): item
            for item in entries}


def combine(args):
    handoffs = args.team_handoff
    returns = args.team_return
    fail_if(type(args.prefix) is not str or
            re.fullmatch("[A-Za-z][A-Za-z0-9_-]{0,39}", args.prefix) is None,
            "invalid private output name")
    fail_if(not 2 <= len(handoffs) <= 12 or len(handoffs) != len(returns),
            "2–12 explicit private handoff/return pairs required")
    folder = private_dir(args.output_dir)
    baseline_raw = read_regular(args.links, MAX_LINKS)
    base = admit_original(baseline_raw)
    baseline_digest = sha256(baseline_raw).hexdigest()
    old = packet_pairs(base["links"])
    snapshots = [(args.links, baseline_raw)]
    edited = {}
    handled = set()
    team_records = []
    for position, (handoff_path, returned_path) in enumerate(
        zip(handoffs, returns), 1
    ):
        handoff_raw = read_regular(handoff_path, MAX_LINKS)
        returned_raw = read_regular(returned_path, MAX_LINKS)
        snapshots.extend(((handoff_path, handoff_raw),
                          (returned_path, returned_raw)))
        claimed = read_team(handoff_raw, TEAM_SCHEMA)
        reply = read_team(returned_raw, RETURN_SCHEMA)
        fail_if(claimed["original_links_sha256"] != baseline_digest or
                reply["original_links_sha256"] != baseline_digest or
                any(claimed[key] != base[key] or reply[key] != base[key]
                    for key in ("comparison_sha256", "findings_sha256")),
                "team returns have unrelated exact source baselines")
        selected = packet_pairs(claimed["entries"])
        returned = packet_pairs(reply["entries"])
        fail_if(not selected or set(selected) != set(returned),
                "team return attempts to alter assigned original source pairs")
        fail_if(any(key not in old or old[key] != pair
                    for key, pair in selected.items()),
                "team handoff source snapshots differ from owner mapping")
        fail_if(set(selected) & handled,
                "overlapping private team assignments cannot be silently merged")
        handled.update(selected)
        revisions = 0
        for key, row in returned.items():
            if any(old[key][field] != row[field] for field in FIELDS):
                revisions += 1
            edited[key] = row
        team_records.append({
            "team_ordinal": position,
            "handoff_sha256": sha256(handoff_raw).hexdigest(),
            "return_sha256": sha256(returned_raw).hexdigest(),
            "assigned_pairs": [
                {"scenario_id": key[0], "finding_id": key[1]}
                for key in selected
            ],
            "human_modified_pair_count": revisions,
            **{flag: False for flag in FLAGS},
        })
    final_links = []
    for original in base["links"]:
        key = tuple(original[k] for k in IDENTITIES)
        row = edited.get(key, original)
        final_links.append({
            "scenario_id": original["scenario_id"],
            "finding_id": original["finding_id"],
            **{field: row[field] for field in FIELDS},
        })
    merged = {**base, "links": final_links}
    admit_original(encode(merged))
    private_diff, aggregate = describe(
        base["links"], final_links, baseline_digest
    )
    aggregate["schema"] = "lightup.assessment_remediation_multi_team_counts.v1"
    aggregate["private_team_count"] = len(handoffs)
    aggregate["assigned_pair_count"] = len(handled)
    aggregate["unassigned_pair_count"] = len(old) - len(handled)
    manifest = {
        "schema": "lightup.assessment_remediation_multi_team_source_map.v1",
        "original_links_sha256": baseline_digest,
        "comparison_sha256": base["comparison_sha256"],
        "findings_sha256": base["findings_sha256"],
        "team_count": len(team_records),
        "team_sources": team_records,
        **{flag: False for flag in FLAGS},
    }
    workboard_html, workboard_csv = render_private_workboard(
        base["links"], final_links, team_records, baseline_digest
    )
    outputs = {
        "-reviewed-links.json": encode(merged),
        "-private-multi-team-diff.html": private_diff,
        "-human-changes.json": encode(aggregate),
        "-private-team-selection.json": encode(manifest),
        "-private-team-workboard.html": workboard_html,
        "-private-team-actions.csv": workboard_csv,
    }
    paths = [(folder / (args.prefix + suffix), data)
             for suffix, data in outputs.items()]
    if not args.preview_only:
        fail_if(any(os.path.lexists(path) for path, _ in paths),
                "an owner-only multi-team output already exists")
    do_render = bool(args.comparison or args.findings_csv)
    fail_if(do_render and not (args.comparison and args.findings_csv)
            or args.bundle and not do_render,
            "original comparison and findings must both be supplied to render")
    if do_render:
        raw_comparison = read_regular(args.comparison, MAX_COMPARE)
        raw_findings = read_regular(args.findings_csv, MAX_FINDINGS)
        original = original_comparison(raw_comparison)
        findings = original_findings(raw_findings)
        links_document(
            encode(merged), sha256(raw_comparison).hexdigest(),
            sha256(raw_findings).hexdigest(),
            {entry["scenario_id"] for entry in original["comparisons"]},
            findings,
        )
        snapshots.extend(((args.comparison, raw_comparison),
                          (args.findings_csv, raw_findings)))
        for suffix in ("-private.html", "-links.json", "-aggregate.json",
                       "-private-agenda.csv",
                       *(("-private-room.zip",) if args.bundle else ())):
            if not args.preview_only:
                fail_if(os.path.lexists(folder / (args.prefix + suffix)),
                        "private dossier/ZIP destination already exists")
    for path, payload in snapshots:
        maximum = (MAX_FINDINGS if do_render and path == args.findings_csv
                   else MAX_COMPARE if do_render and path == args.comparison
                   else MAX_LINKS)
        fail_if(read_regular(path, maximum) != payload,
                "an original private team/source snapshot changed")
    if args.preview_only:
        # All original source, exact membership, allowed human-only updates,
        # optional original render binding and TOCTOU source rechecks passed.
        # This mode deliberately writes no file, runs no model and issues no grant.
        counts = aggregate["new_human_stage_counts"]
        print("PRIVATE_MULTI_TEAM_PREVIEW_ONLY — source-bound HUMAN counts, NO GO")
        print("Teams=" + str(len(team_records)) + " assigned=" + str(len(handled)) +
              " unassigned=" + str(len(old) - len(handled)) +
              " human_modified=" + str(aggregate["changed_human_pair_count"]))
        print("Human stages: " + ", ".join(
            str(name) + "=" + str(counts[name]) for name in
            ("needs_review", "investigating", "documented")))
        print("No private data, source IDs, notes, file, network or authority published.")
        return 2
    # Original complete baseline remains untouched. Publish distinct exclusive
    # fsynced owner-only files. Each file is atomic; the full set is not one
    # filesystem transaction. Do not delete files written for an operator.
    for path, data in paths:
        publish(path, data)
    if do_render:
        status = create_original_dossier(SimpleNamespace(
            comparison=args.comparison, findings_csv=args.findings_csv,
            links=str(folder / (args.prefix + "-reviewed-links.json")),
            output_dir=args.output_dir, prefix=args.prefix,
            bundle=args.bundle,
        ))
        if args.bundle:
            from packet import create_room
            create_room(SimpleNamespace(
                output_dir=args.output_dir, prefix=args.prefix
            ))
        print("PRIVATE_MULTI_TEAM_DOSSIER_" +
              ("REVIEW_ONLY" if status == 2 else "HOLD"))
        return status
    print("PRIVATE_MULTI_TEAM_HUMAN_RETURN_CREATED — " +
          str(len(team_records)) + " disjoint team returns reconciled.")
    print("No original source, finding, permission, scanner or retest changed.")
    print("Human team identities were NOT independently authenticated.")
    return 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=(
        "Reconcile 2–12 non-overlapping human-only returns against ONE "
        "exact unchanged private original owner baseline; no source authority."
    ))
    parser.add_argument("--links", required=True)
    parser.add_argument("--team-handoff", action="append", default=[], required=True,
                        help="Original exact private source-bound team handoff")
    parser.add_argument("--team-return", action="append", default=[], required=True,
                        help="Corresponding team's unsigned return, same order")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--comparison", help="Optional original canonical cohort comparison JSON")
    parser.add_argument("--findings-csv", help="Optional original authenticated client findings CSV")
    parser.add_argument("--preview-only", action="store_true",
                        help="Strict source-bound dry run: counts-only stdout, no files, never GO")
    parser.add_argument("--bundle", action="store_true",
                        help="When original sources supplied, also publish private review ZIP")
    args = parser.parse_args(argv)
    try:
        return combine(args)
    except (Hold, OSError, ValueError, TypeError, KeyError,
            OverflowError, UnicodeError, RecursionError):
        print("PRIVATE_MULTI_TEAM_HOLD — conflicting/untrusted original team sources",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
