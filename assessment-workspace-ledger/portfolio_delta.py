#!/usr/bin/env python3
"""PRIVATE offline diff between two already-produced cross-case HUMAN portfolios.

Original assessment-kit bytes are NOT reopened. Original HUMAN entries are
unsigned and remain historical proposals; changes never prove security work,
authorization, recipient identity, appointment, remediation, or consent.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import date
import csv
import html
import io
import json
import os
from pathlib import Path
import shutil
import sys

from history_actions import STATES, PRIORITIES
from ledger import (
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page,
    hexhash, literal_false_authority, new_private, object_unique,
    read_owner_file, reject, safe_human, write_private,
)

SCHEMA = "lightup.private.workspace-ledger-human-portfolio.v1"
FIELDS = ("human_status", "human_priority", "proposed_day",
          "proposed_owner", "next_human_step")
ROW_KEYS = {
    "case_ordinal", "case_context_sha256", "original_action_packet_sha256",
    "transition", "kit_ordinal", *FIELDS,
}
DOC_KEYS = {
    "schema", "authority", "historical_only", "sources_reopened",
    "recipient_authenticated", "consent_assumed", "actions_dispatched",
    "owner_filter_is_unauthenticated_human_label", "proposed_owner_filter",
    "cases", "human_case_counts", "human_proposals",
}
COLUMNS = (
    "local_case", "historical_transition", "kit", "human_change",
    "changed_human_fields", "old_human_status", "new_human_status",
    "old_human_owner", "new_human_owner", "old_proposed_day",
    "new_proposed_day", "old_next_human_step", "new_next_human_step",
)
MAX_ROWS = 2048


def valid_day(s):
    if type(s) is not str or len(s) not in (0, 10):
        return False
    if not s:
        return True
    if len(s) != 10 or s[4] != "-" or s[7] != "-" or not (
        s[:4] + s[5:7] + s[8:]
    ).isdigit():
        return False
    try:
        return date.fromisoformat(s).isoformat() == s
    except ValueError:
        return False


def read_portfolio(path):
    raw = read_owner_file(path, MAX_MANIFEST)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=object_unique,
                         parse_constant=lambda _: reject("PRIVATE HOLD: nonfinite HUMAN JSON"))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise Hold("PRIVATE HOLD: malformed historical HUMAN portfolio JSON") from exc
    if (type(doc) is not dict or set(doc) != DOC_KEYS or doc["schema"] != SCHEMA
        or not literal_false_authority(doc["authority"])
        or doc["historical_only"] is not True
        or any(doc[field] is not False for field in (
            "sources_reopened", "recipient_authenticated",
            "consent_assumed", "actions_dispatched"
        )) or type(doc["owner_filter_is_unauthenticated_human_label"]) is not bool):
        reject("PRIVATE HOLD: invalid historical HUMAN-only authority/schema")
    selected = doc["owner_filter_is_unauthenticated_human_label"]
    owner = doc["proposed_owner_filter"]
    if selected:
        if type(owner) is not str or not owner or owner != owner.strip():
            reject("PRIVATE HOLD: invalid selected HUMAN owner")
        safe_human(owner, 80)
    elif owner is not None:
        reject("PRIVATE HOLD: unfiltered portfolio cannot declare an owner")
    cases = doc["cases"]
    stats = doc["human_case_counts"]
    rows = doc["human_proposals"]
    if (type(cases) is not list or not 1 <= len(cases) <= 8 or
        type(stats) is not list or len(stats) != len(cases) or
        type(rows) is not list or len(rows) > MAX_ROWS):
        reject("PRIVATE HOLD: invalid bounded portfolio populations")
    identities = {}
    for c in cases:
        if (type(c) is not dict or set(c) != {
            "case_ordinal", "context_sha256", "original_human_actions_sha256",
            "original_human_plan_sha256"
        } or type(c["case_ordinal"]) is not int or
            not 1 <= c["case_ordinal"] <= 8 or
            any(not hexhash(c[field]) for field in (
                "context_sha256", "original_human_actions_sha256",
                "original_human_plan_sha256"
            )) or c["case_ordinal"] in identities):
            reject("PRIVATE HOLD: invalid/duplicate source case identity")
        identities[c["case_ordinal"]] = c
    totals = {}
    for stat in stats:
        if (type(stat) is not dict or set(stat) != {
            "case_ordinal", "original_human_rows", "human_proposals",
            "human_status_counts"
        } or type(stat["case_ordinal"]) is not int or
            stat["case_ordinal"] not in identities or
            stat["case_ordinal"] in totals or
            any(type(stat[field]) is not int or not 0 <= stat[field] <= MAX_ROWS
                for field in ("original_human_rows", "human_proposals")) or
            stat["human_proposals"] > stat["original_human_rows"] or
            type(stat["human_status_counts"]) is not dict or
            any(k not in STATES or type(v) is not int or v < 0
                for k, v in stat["human_status_counts"].items()) or
            sum(stat["human_status_counts"].values()) !=
                stat["original_human_rows"]):
            reject("PRIVATE HOLD: contradictory HUMAN case status totals")
        totals[stat["case_ordinal"]] = stat
    if set(totals) != set(identities):
        reject("PRIVATE HOLD: source case count missing")
    tracked = {}
    status = {i: Counter() for i in identities}
    for row in rows:
        if type(row) is not dict or set(row) != ROW_KEYS:
            reject("PRIVATE HOLD: unexpected HUMAN action row")
        case_id = row["case_ordinal"]
        if type(case_id) is not int or case_id not in identities:
            reject("PRIVATE HOLD: HUMAN row references unknown case")
        origin = identities[case_id]
        if (row["case_context_sha256"] != origin["context_sha256"] or
            row["original_action_packet_sha256"] != origin["original_human_actions_sha256"] or
            type(row["transition"]) is not int or
            not 1 <= row["transition"] <= 11 or
            type(row["kit_ordinal"]) is not int or
            not 1 <= row["kit_ordinal"] <= 12 or
            row["human_status"] not in STATES or row["human_status"] == "unassigned" or
            row["human_priority"] not in PRIORITIES or
            not valid_day(row["proposed_day"])):
            reject("PRIVATE HOLD: changed/unknown original HUMAN row identity")
        for field, limit in (("proposed_owner", 80), ("next_human_step", 240)):
            value = row[field]
            if type(value) is not str or "\n" in value or "\t" in value:
                reject("PRIVATE HOLD: invalid HUMAN proposal")
            safe_human(value, limit)
        if selected and row["proposed_owner"] != owner:
            reject("PRIVATE HOLD: owner-filtered portfolio leaks another HUMAN owner")
        key = (case_id, row["transition"], row["kit_ordinal"])
        if key in tracked:
            reject("PRIVATE HOLD: duplicate original HUMAN action key")
        tracked[key] = row
        status[case_id][row["human_status"]] += 1
    if any(totals[i]["human_proposals"] != sum(status[i].values())
           for i in identities):
        reject("PRIVATE HOLD: case counts disagree with source-bound HUMAN rows")
    if selected and any(totals[i]["original_human_rows"] !=
                        totals[i]["human_proposals"] for i in identities):
        reject("PRIVATE HOLD: filtered portfolio count disclosed other owners")
    if raw != canonical(doc):
        reject("PRIVATE HOLD: HUMAN portfolio not canonical original bytes")
    return raw, doc, identities, tracked


def compare(previous, current):
    old, now = previous[3], current[3]
    keys = sorted(set(old) | set(now))
    differences = []
    summary = Counter()
    for key in keys:
        left, right = old.get(key), now.get(key)
        kind = "added" if left is None else "removed" if right is None else (
            "changed" if any(left[f] != right[f] for f in FIELDS) else "unchanged"
        )
        summary[kind] += 1
        if kind == "unchanged":
            continue
        changed = [f for f in FIELDS if left is not None and right is not None
                   and left[f] != right[f]]
        differences.append({
            "local_case": key[0], "historical_transition": key[1],
            "kit": key[2], "human_change": kind,
            "changed_human_fields": changed,
            "old_human_proposal": {f: left[f] for f in FIELDS} if left else None,
            "new_human_proposal": {f: right[f] for f in FIELDS} if right else None,
        })
    return differences, dict(summary)


def row_csv(differences):
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(COLUMNS)
    for change in differences:
        old, new = change["old_human_proposal"] or {}, change["new_human_proposal"] or {}
        writer.writerow([
            change["local_case"], change["historical_transition"], change["kit"],
            change["human_change"], ";".join(change["changed_human_fields"]),
            old.get("human_status", ""), new.get("human_status", ""),
            old.get("proposed_owner", ""), new.get("proposed_owner", ""),
            old.get("proposed_day", ""), new.get("proposed_day", ""),
            old.get("next_human_step", ""), new.get("next_human_step", ""),
        ])
    return buffer.getvalue()


def summary_html(previous, current, changes, summary, shifted,
                 newly_visible=(), no_longer_visible=()):
    bits = [
        "<p>PRIVATE HUMAN proposals from two expressly selected historical unsigned "
        "portfolio packets. The original case context identities must match "
        "exactly by local case number. Original source kit files were NOT "
        "reopened; no actual work, recipient, consent, security finding, "
        "remediation, grant or calendar booking is verified.</p>",
        "<p>Proposals added: " + str(summary.get("added", 0)) +
        "; removed from local HUMAN view: " + str(summary.get("removed", 0)) +
        "; edited: " + str(summary.get("changed", 0)) +
        "; unchanged: " + str(summary.get("unchanged", 0)) + ".</p>",
        "<p>Original signed/reviewed chain verified: NO. Historical original "
        "HUMAN packet changes in " + str(shifted) +
        " shared local case slots (unsigned metadata only). Newly visible "
        "owner-filtered case slots: " + str(len(newly_visible)) +
        "; no longer visible: " + str(len(no_longer_visible)) +
        ". Visibility is HUMAN proposal membership, NOT source removal, a "
        "verified fix, a revoked authorization or completed security work.</p>",
        "<p><a href='PRIVATE-HUMAN-delta.html'>Open PRIVATE source-bound "
        "HUMAN change details</a>. Confidential owner/action text is omitted "
        "from this overview and remains in the owner-private detail and CSV.</p>",
    ]
    return html_page("LightUp PRIVATE multi-case HUMAN follow-up delta", "".join(bits))


def changes_html(changes):
    body = [
        "<p>PRIVATE unverified HUMAN planning changes only. Previous and new "
        "values may identify people; never use this as real security evidence, "
        "recipient authentication, a work-completion log or disclosure approval.</p>",
        "<table><thead><tr><th>Case / transition / kit</th><th>Type</th>"
        "<th>Changed fields</th><th>Old HUMAN text</th><th>New HUMAN text</th>"
        "</tr></thead><tbody>",
    ]
    for item in changes:
        old = item["old_human_proposal"] or {}
        new = item["new_human_proposal"] or {}
        def render_text(row):
            return html.escape("; ".join(f + ": " + str(row.get(f, ""))
                                         for f in FIELDS), quote=True)
        body.append(
            "<tr><td>" + str(item["local_case"]) + " / " +
            str(item["historical_transition"]) + " / " + str(item["kit"]) +
            "</td><td>" + html.escape(item["human_change"]) + "</td><td>" +
            html.escape(", ".join(item["changed_human_fields"])) +
            "</td><td>" + render_text(old) + "</td><td>" +
            render_text(new) + "</td></tr>"
        )
    body.append("</tbody></table><a href='OPEN-PRIVATE.html'>Private summary</a>")
    return html_page("LightUp PRIVATE original HUMAN proposal revisions", "".join(body))


def run(args):
    if (not isinstance(args.before, str) or not isinstance(args.after, str) or
        not os.path.isabs(args.before) or not os.path.isabs(args.after) or
        os.path.normpath(args.before) != args.before or
        os.path.normpath(args.after) != args.after or args.before == args.after):
        reject("PRIVATE HOLD: choose two distinct canonical original portfolios")
    previous = read_portfolio(args.before)
    current = read_portfolio(args.after)
    old, now = previous[1], current[1]
    if (old["owner_filter_is_unauthenticated_human_label"] !=
        now["owner_filter_is_unauthenticated_human_label"] or
        old["proposed_owner_filter"] != now["proposed_owner_filter"]):
        reject("PRIVATE HOLD: incompatible per-owner HUMAN disclosure filter")
    before_ids, after_ids = previous[2], current[2]
    overlap = set(before_ids) & set(after_ids)
    filtered = old["owner_filter_is_unauthenticated_human_label"]
    if (not overlap or (not filtered and set(before_ids) != set(after_ids)) or
        any(before_ids[i]["context_sha256"] != after_ids[i]["context_sha256"]
            for i in overlap)):
        reject("PRIVATE HOLD: different or unanchored ORIGINAL case identities")
    # Owner-filtered views omit all cases without proposals for that exact
    # HUMAN owner. A case may appear/disappear WITHOUT source drift. Only
    # permit this within a shared unchanged original-case anchor; two
    # unrelated all-disjoint collections must fail closed.
    newly_visible = sorted(set(after_ids) - set(before_ids))
    no_longer_visible = sorted(set(before_ids) - set(after_ids))
    changes, counts = compare(previous, current)
    changed_packets = sum(
        before_ids[i]["original_human_actions_sha256"] !=
        after_ids[i]["original_human_actions_sha256"] for i in overlap
    )
    # Second read: no stored historical input may drift during presentation.
    if digest(read_portfolio(args.before)[0]) != digest(previous[0]) or (
        digest(read_portfolio(args.after)[0]) != digest(current[0])
    ):
        reject("PRIVATE HOLD: original stored HUMAN portfolio bytes changed")
    output = {
        "schema": "lightup.private.workspace-ledger-human-portfolio-delta.v1",
        "authority": FLAGS, "historical_only": True,
        "sources_reopened": False, "actions_dispatched": False,
        "recipient_authenticated": False, "verified_remediation": False,
        "old_portfolio_sha256": digest(previous[0]),
        "new_portfolio_sha256": digest(current[0]),
        "owner_filter_is_unauthenticated_human_label":
            old["owner_filter_is_unauthenticated_human_label"],
        "proposed_owner_filter": old["proposed_owner_filter"],
        "human_change_counts": counts,
        "human_changes": changes,
        "changed_original_human_packet_slots": changed_packets,
        "newly_visible_human_case_slots": newly_visible,
        "no_longer_visible_human_case_slots": no_longer_visible,
        "shared_original_case_anchor_count": len(overlap),
    }
    encoded = canonical(output)
    if len(encoded) > MAX_MANIFEST:
        reject("PRIVATE HOLD: HUMAN comparison exceeds native private manifest bound")
    private_csv = row_csv(changes)
    if len(private_csv.encode("utf-8")) > MAX_MANIFEST:
        reject("PRIVATE HOLD: HUMAN delta CSV exceeds private admission bound")
    folder = new_private(args.private_parent)
    try:
        write_private(folder, "OPEN-PRIVATE.html",
                      summary_html(previous, current, changes, counts, changed_packets,
                                   newly_visible, no_longer_visible))
        write_private(folder, "PRIVATE-HUMAN-delta.html", changes_html(changes))
        write_private(folder, "PRIVATE-HUMAN-delta.csv", private_csv)
        write_private(folder, "PRIVATE-HUMAN-delta.json", encoded)
    except BaseException:
        shutil.rmtree(folder)
        raise
    print("PRIVATE HOLD: compared two historical HUMAN proposal collections only")
    print(str(Path(folder) / "OPEN-PRIVATE.html"))
    return 3


def main():
    p = argparse.ArgumentParser(
        description="PRIVATE source-context-exact historical cross-case HUMAN follow-up delta"
    )
    p.add_argument("--before", required=True,
                   help="Previously generated 0600 PRIVATE-HUMAN-portfolio.json")
    p.add_argument("--after", required=True,
                   help="New distinct owner-private 0600 PRIVATE-HUMAN-portfolio.json")
    p.add_argument("--private-parent", required=True,
                   help="Existing owner-private 0700 parent outside original source checkout")
    args = p.parse_args()
    try:
        return run(args)
    except (Hold, OSError, ValueError, TypeError, UnicodeError, csv.Error):
        print("PRIVATE HOLD: original offline HUMAN portfolio comparison refused",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
