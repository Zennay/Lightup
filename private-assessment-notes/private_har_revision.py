"""Original-bound offline HUMAN HAR revision handoff, always HOLD.

Compare two independently admitted owner-private workflows. Produce a
newer-workflow-only CSV proposal and source-free review desk. Never infer
source authenticity, actual PII masking, consent, release or scan authority.
"""
from __future__ import annotations

from collections import Counter
import csv
from hashlib import sha256
from html import escape
import io
import json
import os
from pathlib import Path
import shutil
import tempfile

from notes import (FALSE_FLAGS, Hold, file_new, load_workroom,
                   private_directory, private_input, save_json)
from private_har_workflow import admit as admit_workflow, MANIFEST
from private_har_progress import _edited, reopen_progress
from private_har_worklist import FIELDS, entries

SCHEMA = "lightup.private_har_original_revision_handoff.v2"
CSV_NAME = "PRIVATE-HAR-REVISION-edited-actions.csv"
DECISIONS_NAME = "PRIVATE-HAR-REVISION-decision-guide.csv"
MAX_HTML_SIZE = 256 * 1024
PAGE_NAME = "OPEN-PRIVATE-HAR-REVISION.html"
RECEIPT_NAME = "PRIVATE-HAR-REVISION-receipt.json"
MAX_SIZE = 65536
NON_FINAL = frozenset(("PENDING_HUMAN", "IN_PROGRESS",
                       "SOURCE_OWNER_NEEDED", "WITHHOLD"))


def _admit(older_workflow: str, newer_workflow: str,
           older_progress_room: str):
    old_room = private_directory(older_workflow)
    new_room = private_directory(newer_workflow)
    if old_room == new_room:
        raise Hold("HOLD: HAR revision requires two separate original workrooms")
    old_original, old_cues = admit_workflow(str(old_room))
    new_original, new_cues = admit_workflow(str(new_room))
    if old_original == new_original or old_cues == new_cues:
        raise Hold("HOLD: HAR revision cannot reuse original source/cue packets")
    old_progress = private_directory(older_progress_room)
    if old_progress == new_room or old_progress == new_original or old_progress == new_cues:
        raise Hold("HOLD: old HUMAN status packet may not be a new workflow")
    if reopen_progress(str(old_original), str(old_cues), str(old_progress)) != 3:
        raise Hold("HOLD: prior original PRIVATE HUMAN progress refused")
    _old_binding, old_sources, old_rows = load_workroom(old_original)
    _new_binding, new_sources, new_rows = load_workroom(new_original)
    raw = private_input(str(
        old_progress / "PRIVATE-HAR-HUMAN-edited-actions.csv"), MAX_SIZE)
    past = _edited(raw, entries(old_rows))
    return (old_room, new_room, old_original, new_original,
            old_progress, old_sources, new_sources, past, new_rows)


def _proposal(old_sources: list[dict], new_sources: list[dict],
              past: list[dict], new_rows: list[dict]):
    old_by_slot = {source["ordinal"]: source for source in old_sources}
    old_tasks = {(int(row["original_ordinal"]), row["review_area"]):
                 row for row in past}
    withheld_slots = {int(row["original_ordinal"]) for row in past
                      if row["human_status"] == "WITHHOLD"}
    source_labels = {}
    for item in new_sources:
        slot = item["ordinal"]
        original = old_by_slot.get(slot)
        if original is None:
            label = "NEW_ORIGINAL_POSITION"
        elif all(item[name] == original[name] for name in (
                "source_sha256_unsigned", "source_bytes",
                "output_sha256_unsigned", "output_bytes")):
            label = "IDENTICAL_ORIGINAL_POSITION_BYTES"
        else:
            label = "CHANGED_OR_MOVED_ORIGINAL_POSITION"
        source_labels[slot] = label

    proposed = []
    counts = Counter()
    old_reviewed_reset = 0
    kept_withhold = 0
    instructions = []
    for action in entries(new_rows):
        record = dict(action)
        slot = int(record["original_ordinal"])
        before = old_tasks.get((slot, record["review_area"]))
        unchanged = source_labels[slot] == "IDENTICAL_ORIGINAL_POSITION_BYTES"
        action_same = (before is not None and all(
            str(before[key]) == str(record[key]) for key in FIELDS[:4]))
        old_state = before["human_status"] if before else "NO_OLD_TASK"
        if slot in withheld_slots:
            # Withhold is monotonic across local revisions. The source owner
            # must explicitly make any later change via the HUMAN Studio.
            next_state = "WITHHOLD"
            reason = "PRIOR_WITHHOLD_REQUIRES_NEW_OWNER_DECISION"
            kept_withhold += 1
        elif not unchanged:
            next_state = "PENDING_HUMAN"
            reason = "NEW_OR_CHANGED_ORIGINAL_REQUIRES_REVIEW"
        elif not action_same:
            next_state = "PENDING_HUMAN"
            reason = "NEW_OR_CHANGED_TASK_REQUIRES_REVIEW"
        elif old_state == "HUMAN_REVIEWED":
            next_state = "PENDING_HUMAN"
            reason = "PRIOR_HUMAN_REVIEWED_MUST_BE_RECONFIRMED"
            old_reviewed_reset += 1
        elif old_state in NON_FINAL:
            next_state = old_state
            reason = "NON_FINAL_HUMAN_STATUS_RETAINED_FOR_IDENTICAL_SOURCE"
        else:
            next_state = "PENDING_HUMAN"
            reason = "UNMATCHED_HUMAN_ACTION_REQUIRES_REVIEW"
        record["human_status"] = next_state
        record["human_notes"] = ""
        proposed.append(record)
        instructions.append({
            "original_ordinal": slot,
            "review_area": record["review_area"],
            "original_byte_relation": source_labels[slot],
            "prior_manual_status": old_state,
            "proposed_manual_status": next_state,
            "new_manual_decision_reason": reason,
            "original_review_required": "YES",
        })
        counts[reason] += 1

    removed = sorted(set(old_by_slot) - {row["ordinal"] for row in new_sources})
    return (proposed, source_labels, removed, counts,
            old_reviewed_reset, kept_withhold, instructions)


def _csv(rows: list[dict]) -> bytes:
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=FIELDS, lineterminator="\r\n")
    writer.writeheader()
    writer.writerows({field: row[field] for field in FIELDS} for row in rows)
    return handle.getvalue().encode("utf-8")


def _decision_guide(instructions: list[dict]) -> bytes:
    fields = ("original_ordinal", "review_area", "original_byte_relation",
              "prior_manual_status", "proposed_manual_status",
              "new_manual_decision_reason", "original_review_required")
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\r\n")
    writer.writeheader()
    writer.writerows(instructions)
    return stream.getvalue().encode("utf-8")


def _page(new_workflow: Path, source_labels: dict[int, str],
          removed: list[int], actions: list[dict], reasons: Counter,
          reviewed_reset: int, withheld: int,
          instructions: list[dict]) -> bytes:
    lines = []
    for ordinal, label in sorted(source_labels.items()):
        affected = [row for row in actions if
                    row["original_ordinal"] == ordinal]
        stat = Counter(row["human_status"] for row in affected)
        lines.append(
            "<tr><th scope='row'>Original #" + str(ordinal) + "</th><td>" +
            escape(label.replace("_", " ")) + "</td><td>" +
            str(len(affected)) + "</td><td>" + str(stat["PENDING_HUMAN"]) +
            "</td><td>" + str(stat["WITHHOLD"]) + "</td><td>" +
            str(stat["IN_PROGRESS"] + stat["SOURCE_OWNER_NEEDED"]) +
            "</td></tr>"
        )
    action_lines = "".join(
        "<tr><th scope='row'>Original #" + str(item["original_ordinal"]) +
        "</th><td>" + escape(item["review_area"].replace("_", " ")) +
        "</td><td>" + escape(item["prior_manual_status"]) +
        "</td><td>" + escape(item["proposed_manual_status"]) +
        "</td><td>" +
        escape(item["new_manual_decision_reason"].replace("_", " ")) +
        "</td></tr>" for item in instructions
    )
    reason_list = "".join("<li>" + escape(label.replace("_", " ")) +
                          ": " + str(reasons[label]) + "</li>"
                          for label in sorted(reasons))
    removed_list = ", ".join("Original #" + str(n) for n in removed)
    # Linking only to a sibling owned original source room; a new revision
    # proposal can never link back to a prior private client content packet.
    wf_link = "../" + escape(new_workflow.name, quote=True)
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';form-action 'none';base-uri 'none';object-src 'none';img-src 'none'">
<title>LightUp PRIVATE HAR original revision workroom</title>
<style>body{font:16px/1.55 system-ui;max-width:990px;margin:2rem auto;padding:1rem;
color:#173249}aside{padding:1rem;background:#fff0e7;border-left:5px solid #ab5633}
section{padding:1.1rem;border:1px solid #cbd5df;margin:1rem 0}
table{width:100%;border-collapse:collapse}
th,td{padding:.7rem;border:1px solid #c7d2dd;text-align:left}
thead{background:#f2f6f8}
a{color:#155b8c}
@media print{section{break-inside:avoid}}</style>
<h1>PRIVATE HAR HUMAN original revision handoff</h1>
<aside><b>INCUBATE / REVIEW_ONLY / HOLD. NOT AUTHORIZATION.</b>
The earlier source-bound HUMAN statuses were never independently verified.
No source identity, consent, privacy assurance, finding, share permission,
scan authority or approval to deploy is inferred. SHA-256 here only relates
locally admitted PRIVATE bytes; it is NOT trusted external provenance.
Identical original positions may still contain real secrets or personal data.
No raw source, client name, source path, digest, URL or HUMAN note appears.
No network, scripts, model, target access, recipient or dispatch.</aside>
<p>New original positions: """ + str(len(source_labels)) +
"""; new original-position review actions: """ + str(len(actions)) +
""". Previously HUMAN_REVIEWED actions reset: """ + str(reviewed_reset) +
"""; conservative withheld actions retained: """ + str(withheld) +
""". Removed earlier positions (not imported): """ +
escape(removed_list or "none") + """.</p>
<section><h2>New original positions and manual review requirements</h2>
<table><thead><tr><th>Position</th><th>Original byte relation</th><th>Tasks</th>
<th>Pending HUMAN</th><th>Withhold</th><th>Other unfinished</th>
</tr></thead><tbody>""" + "".join(lines) + """</tbody></table>
<p>Comparison pairs sources by original position, not by inferred identity.
Any changed, moved, added or missing source must be independently checked.
A previous WITHHOLD is never automatically weakened.</p></section>
<section><h2>How statuses were transferred</h2><ul>""" +
reason_list + """</ul>
<p><b>Human-reviewed is ALWAYS reset to pending</b> even when the original
input bytes and task are unchanged. Only nonfinal stages may carry over
when both original source bytes and task identity remain unchanged.
These are private HUMAN planning hints, not findings or clearance.</p>
<h3>Action-by-action decisions requiring HUMAN attention</h3>
<p><a href='PRIVATE-HAR-REVISION-decision-guide.csv'>Open PRIVATE
decision guide CSV</a>. This is a source-minimal human planning hint.</p>
<table><thead><tr><th>Original</th><th>Task area</th><th>Prior
self-report</th><th>New proposed stage</th><th>Why</th></tr>
</thead><tbody>""" + action_lines + """</tbody></table></section>
<section><h2>Continue in newer owner-private workflow</h2>
<ol><li><a href='""" + wf_link + """/OPEN-PRIVATE-HAR-WORKFLOW.html'>Open
the newer original-bound PRIVATE HAR workflow</a> and independently
inspect original source material held by its rightful owner.</li>
<li>Open the newer offline HAR Status Studio, choose its local
<b>Resume CSV</b> input and select the separate owner-private
<code>PRIVATE-HAR-REVISION-edited-actions.csv</code> from this
new revision packet. Confirm all original actions and labels yourself.</li>
<li>Export a new complete HUMAN CSV from the Studio, save it in
owner-only storage and <b>chmod 0600</b>. Only then invoke
<code>notes.py har-review-progress --workflow-room &lt;new-workflow&gt;
--edited-actions &lt;human-reviewed-csv&gt; --private-parent
&lt;new-private-parent&gt;</code>.</li></ol>
<p>This document never auto-imports, approves, reconciles human note text,
communicates across clients or changes original receipts.</p></section>
<footer>All reports HOLD. Before release: verified original source-owner
evidence, security/privacy/browser review, exact-head mandatory CI,
real separately authenticated current client and operator consent with
at-use revocation and explicit HUMAN GO.</footer></html>"""
    ).encode("utf-8")


def _make(older_workflow: str, newer_workflow: str,
          older_progress_room: str, private_parent: str):
    parent = private_directory(private_parent)
    (old_wf, new_wf, old_original, new_original, old_status,
     old_sources, new_sources, past, newer_rows) = _admit(
        older_workflow, newer_workflow, older_progress_room)
    if parent != new_wf.parent:
        raise Hold("HOLD: revision CSV must be linked to newer private workflow")
    (proposal, labels, removed, reasons, reviewed_reset,
     withheld, instructions) = _proposal(
        old_sources, new_sources, past, newer_rows)
    csv_bytes = _csv(proposal)
    guide = _decision_guide(instructions)
    # The revised CSV must already be a valid immutable *new* native
    # action template. This is product admission, never a release gate.
    if _edited(csv_bytes, entries(newer_rows)) != [
        {key: str(row[key]) for key in FIELDS} for row in proposal
    ]:
        raise Hold("HOLD: invalid new PRIVATE HUMAN action proposal")
    html = _page(new_wf, labels, removed, proposal,
                 reasons, reviewed_reset, withheld, instructions)
    if not (0 < len(csv_bytes) <= MAX_SIZE
            and 0 < len(guide) <= MAX_SIZE
            and 0 < len(html) <= MAX_HTML_SIZE):
        raise Hold("HOLD: revised PRIVATE HUMAN packet exceeded size limit")
    receipt = {
        "schema": SCHEMA, "claimed_status": "HOLD",
        "source_comparison_by_original_ordinal_not_identity": True,
        "manual_statuses_unverified_and_not_permissions": True,
        "older_workflow_receipt_sha256_unsigned": sha256(private_input(
            str(old_wf / MANIFEST), MAX_SIZE)).hexdigest(),
        "newer_workflow_receipt_sha256_unsigned": sha256(private_input(
            str(new_wf / MANIFEST), MAX_SIZE)).hexdigest(),
        "prior_HUMAN_status_receipt_sha256_unsigned": sha256(private_input(
            str(old_status / "PRIVATE-HAR-status-receipt.json"), MAX_SIZE
        )).hexdigest(),
        "new_original_count": len(new_sources),
        "new_action_count": len(proposal),
        "original_ordinal_relation": [
            {"ordinal": index, "manual_original_relation": labels[index]}
            for index in sorted(labels)
        ],
        "removed_old_original_positions": removed,
        "reviewed_statuses_reset": reviewed_reset,
        "conservative_withholds_retained": withheld,
        "revised_csv_sha256_unsigned": sha256(csv_bytes).hexdigest(),
        "decision_guide_sha256_unsigned": sha256(guide).hexdigest(),
        "revised_html_sha256_unsigned": sha256(html).hexdigest(),
        **{flag: False for flag in FALSE_FLAGS},
    }
    raw_receipt = (json.dumps(receipt, indent=2, sort_keys=True,
                              ensure_ascii=False) + "\n").encode("utf-8")
    return csv_bytes, guide, html, raw_receipt


def create(older_workflow: str, newer_workflow: str,
           older_progress_room: str, private_parent: str) -> int:
    parent = private_directory(private_parent)
    csv_bytes, guide, html, receipt = _make(
        older_workflow, newer_workflow, older_progress_room, str(parent))
    output = Path(tempfile.mkdtemp(
        prefix="PRIVATE-lightup-har-revision-", dir=parent))
    os.chmod(output, 0o700)
    completed = False
    try:
        file_new(output / CSV_NAME, csv_bytes)
        file_new(output / DECISIONS_NAME, guide)
        file_new(output / PAGE_NAME, html)
        file_new(output / RECEIPT_NAME, receipt)
        completed = True
        print("HOLD: new original PRIVATE HAR revision proposal generated")
        print("OPEN LOCALLY: " + str(output / PAGE_NAME))
        print("NEWER ORIGINAL ACTION CSV: " + str(output / CSV_NAME))
        return 3
    finally:
        if not completed:
            shutil.rmtree(output)


def reopen(older_workflow: str, newer_workflow: str,
           older_progress_room: str, revision_room: str) -> int:
    output = private_directory(revision_room)
    if output.parent != private_directory(newer_workflow).parent:
        raise Hold("HOLD: revised proposal must remain beside newer original")
    csv_bytes, guide, html, receipt = _make(
        older_workflow, newer_workflow, older_progress_room,
        str(output.parent))
    for name, expected in (
        (CSV_NAME, csv_bytes),
        (DECISIONS_NAME, guide),
        (PAGE_NAME, html),
        (RECEIPT_NAME, receipt),
    ):
        if private_input(str(output / name),
                         MAX_HTML_SIZE if name == PAGE_NAME else MAX_SIZE) != expected:
            raise Hold("HOLD: original-bound HAR revision packet changed")
    print("HOLD: immutable original-source revision proposal reopened")
    print("OPEN LOCALLY: " + str(output / PAGE_NAME))
    return 3
