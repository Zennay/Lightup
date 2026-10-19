#!/usr/bin/env python3
"""Offline engagement-wide HUMAN handoff inbox from source-bound PRIVATE journals.

Reuses existing original-authenticated source/evidence admission upstream; this
read-only desk observes LOCAL HUMAN statuses, not native Apply or consent.
"""
from __future__ import annotations

from collections import Counter
import hashlib
from html import escape
from pathlib import Path
import stat
import os

import engagement_index as index
import request_handoff as handoff

original = handoff.original
MAX_HTML = 192 * 1024
LABELS = {
    "pending_no_file": ("Pending, no encrypted file", "Check whether the interrupted local intent truly published nothing; independently confirm before resolving."),
    "pending_has_file": ("Pending, encrypted file exists", "Reopen native encrypted draft with the original password and perform explicit HUMAN recovery/closeout."),
    "staged_not_observed": ("Staged, not in CURRENT HUMAN source", "Independently inspect the original native Request Desk; no assumption of Apply."),
    "staged_open": ("Staged, HUMAN work open", "Review current original reported stage and response; do not create a second draft."),
    "staged_human_closed": ("Staged, HUMAN reports closed", "Eligible for separate original-native encrypted draft review and explicit LOCAL HUMAN closeout."),
    "reviewed_current_missing": ("Locally reviewed, current HUMAN record missing", "HOLD: source changed, inspect past HUMAN context independently."),
    "reviewed_current_open": ("Locally reviewed, CURRENT HUMAN reports open", "HOLD: original HUMAN status continuity changed, review with source owner."),
    "reviewed_current_closed": ("Locally reviewed, HUMAN still reports closed", "No action inferred: HUMAN state is not native Apply or consent."),
    "aborted_unpublished": ("Locally aborted without published file", "No signed absence proof; retain HUMAN operator record."),
    "staged_file_missing": ("Encrypted stage file missing", "HOLD: restore original private ciphertext or consult source owner."),
    "staged_file_changed": ("Encrypted stage bytes changed", "HOLD: recorded original-native encrypted draft mismatch."),
}
CAUTION = ("These are LOCAL HUMAN bookkeeping observations. Current original "
           "authentication and material bytes do not prove historical native "
           "Apply, independent reviewer identity, signed consent, legal holds, "
           "actual remediation, verified finding, retest, or authorization.")


def _ref(row: dict) -> str:
    return hashlib.sha256(original.canonical({
        "finding_id": row["finding_id"],
        "linked_sha256": row["linked_sha256"],
        "request_id": row["request_id"],
    })).hexdigest()


def _current_references(packet: dict) -> dict[str, str]:
    originals = packet.get("human_requests", [])
    if type(originals) is not list:
        raise ValueError("Malformed CURRENT native HUMAN records.")
    found = {}
    for row in originals:
        ref = _ref(row)
        if ref in found:
            raise ValueError("Repeated current native HUMAN request identity.")
        found[ref] = row["human_stage"]
    return found


def _material_indicator(entry: dict, vault, private_file) -> str:
    if entry["state"] == "aborted_unpublished":
        return "not_required"
    path = Path(entry["output"])
    handoff.source._hold_if_not_private_directory(path.parent)
    if not path.exists() and not path.is_symlink():
        return "missing"
    private_file(path)
    if entry["state"] == "pending" and not entry["sha256"]:
        return "exists_unverified"
    raw = vault._private_input(path, vault.MAX_VAULT)
    sha = hashlib.sha256(raw).hexdigest()
    if not entry["sha256"] or sha != entry["sha256"]:
        return "changed"
    return "local_cipher_sha_matched"


def _classification(entry: dict, stages: dict[str, str], material: str) -> tuple[str, Counter]:
    refs = entry["requests"]
    counts = Counter(stages.get(ref, "not_observed") for ref in refs)
    if material == "changed":
        label = "staged_file_changed"
    elif entry["state"] == "pending":
        label = "pending_no_file" if material == "missing" else "pending_has_file"
    elif entry["state"] == "staged" and material == "missing":
        label = "staged_file_missing"
    elif entry["state"] == "staged":
        label = ("staged_not_observed" if counts["not_observed"] else
                 "staged_human_closed" if counts["closed_human"] == len(refs)
                 else "staged_open")
    elif entry["state"] == "reviewed":
        label = ("reviewed_current_missing" if counts["not_observed"] else
                 "reviewed_current_closed" if counts["closed_human"] == len(refs)
                 else "reviewed_current_open")
    else:
        label = "aborted_unpublished"
    return label, counts


def collect(folder: Path, packet: dict, vault, private_file,
            read_journal, current_source: str) -> tuple[list[dict], dict]:
    """Original-current account/material already admitted by journal.main()."""
    index_doc, _ = index.inspect(folder, packet, vault, private_file, read_journal)
    live = _current_references(packet)
    keys = index_doc["sources"]
    rows = []
    totals = Counter()
    for source_ordinal, key in enumerate(keys, 1):
        doc = read_journal(folder, key, vault)
        for cycle_ordinal, entry in enumerate(doc["cycles"], 1):
            material = _material_indicator(entry, vault, private_file)
            label, counts = _classification(entry, live, material)
            rows.append({
                "source_ordinal": source_ordinal,
                "cycle_ordinal": cycle_ordinal,
                "current_revision": key == current_source,
                "local_state": entry["state"],
                "attention": label,
                "draft_count": len(entry["requests"]),
                "reported_closed": counts["closed_human"],
                "reported_unobserved": counts["not_observed"],
                "reported_other": sum(v for k, v in counts.items()
                                      if k not in ("closed_human", "not_observed")),
                "cipher_indicator": material,
            })
            totals[label] += 1
            totals["draft_references"] += len(entry["requests"])
    totals["source_revisions"] = len(keys)
    totals["cycles"] = len(rows)
    totals["human_attention"] = sum(1 for row in rows if row["attention"] not in (
        "reviewed_current_closed", "aborted_unpublished"))
    return rows, dict(totals)


def show(rows: list[dict], totals: dict) -> None:
    print("PRIVATE engagement HUMAN inbox · no original Apply or consent")
    print("Registered source revisions:", totals["source_revisions"],
          "· local cycles:", totals["cycles"],
          "· HUMAN attention:", totals["human_attention"])
    for row in rows:
        label, next_step = LABELS[row["attention"]]
        print("Source", row["source_ordinal"], "· cycle", row["cycle_ordinal"],
              "·", "CURRENT" if row["current_revision"] else "historical",
              "·", label, "· drafts", row["draft_count"])
        print("  HUMAN next step:", next_step)
    print(CAUTION)


def html(rows: list[dict], totals: dict) -> bytes:
    e = lambda value: escape(str(value), quote=True)
    out = []
    for row in rows:
        label, advice = LABELS[row["attention"]]
        out.append("<tr><td>" + str(row["source_ordinal"]) + "/" +
                   str(row["cycle_ordinal"]) + "</td><td>" +
                   ("Current" if row["current_revision"] else "Earlier") +
                   "</td><td>" + e(label) + "</td><td>" +
                   str(row["draft_count"]) + "</td><td>" +
                   str(row["reported_closed"]) + "</td><td>" +
                   str(row["reported_unobserved"]) + "</td><td>" +
                   e(advice) + "</td></tr>")
    content = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; connect-src 'none'; script-src 'none'; img-src 'none'; font-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>PRIVATE engagement HUMAN inbox</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:1200px;margin:2rem auto;
background:#f2f5f7;color:#1b2630;padding:1rem}header,section,footer{background:#fff;
border:1px solid #cad3dc;padding:1.3rem;border-radius:12px;margin-bottom:1rem}
h1{line-height:1.2}table{width:100%;border-collapse:collapse}
td,th{border-bottom:1px solid #cbd6df;padding:.7rem;text-align:left;vertical-align:top;
overflow-wrap:anywhere}th{font-size:.85rem}tr:nth-child(even){background:#f3f6f8}
.summary{font-size:1.15rem}</style></head><body>
<header><h1>PRIVATE HUMAN engagement handoff inbox</h1>
<p>Original CURRENT authenticated source plus local registered ORIGINAL source
revision journals. HUMAN-reported states, not verified historical authorization
or native Apply. Review historical requests independently.</p></header>
<section class="summary"><p>Source revisions: <b>""" + str(totals["source_revisions"]) + """</b> ·
Local cycles: <b>""" + str(totals["cycles"]) + """</b> ·
HUMAN attention: <b>""" + str(totals["human_attention"]) + """</b></p></section>
<section><h2>Current and earlier local HUMAN handoffs</h2>
<table><thead><tr><th>Source/cycle</th><th>Revision</th><th>HUMAN situation</th>
<th>Drafts</th><th>Currently HUMAN-closed</th><th>Not observed</th>
<th>Next HUMAN action</th></tr></thead><tbody>""" + "".join(out) + """</tbody></table></section>
<footer><p>""" + e(CAUTION) + """ This 0600 offline scriptless file has no
customer names, original source SHA, native request IDs, finding fingerprints,
private notes, encrypted file paths, evidence content or provider links.
No network, browsing scripts or automatic Apply. Not an audit certificate,
a grant, or authorization to scan, publish, delete, close a legal hold or retest.
Local journals elsewhere and older unindexed work remain outside this view.
</p></footer></body></html>"""
    payload = content.encode("utf-8", "strict")
    if len(payload) > MAX_HTML:
        raise ValueError("PRIVATE HUMAN engagement inbox exceeds bounded size.")
    return payload
