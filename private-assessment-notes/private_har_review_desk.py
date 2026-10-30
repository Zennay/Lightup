"""Source-bound PRIVATE HAR HUMAN operations desk; no target activity or clearance."""
from __future__ import annotations

from collections import Counter
from contextlib import redirect_stdout
import csv
from hashlib import sha256
from html import escape
import io
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

from notes import (FALSE_FLAGS, Hold, file_new, load_workroom,
                   private_directory, private_input, read_json, save_json)
from private_har_workflow import admit as admit_workflow, MANIFEST
from private_har_progress import _edited, reopen_progress, STATES
from private_har_worklist import entries
from private_har_history import _longitudinal

SCHEMA = "lightup.private_har_review_desk.v1"
SCHEMA_V2 = "lightup.private_har_review_desk.v2"
MAX_ROUNDS = 8
MAX_SIZE = 256 * 1024
PAGE = "OPEN-PRIVATE-HAR-DESK.html"
CSV = "PRIVATE-HAR-NEXT-ACTIONS.csv"
SOURCE_CSV = "PRIVATE-HAR-SOURCE-QUEUE.csv"
RECEIPT = "PRIVATE-HAR-DESK-receipt.json"
ROUND_NAME = re.compile(r"PRIVATE-lightup-har-human-status-[a-zA-Z0-9_-]{8,32}")
CSV_FIELDS = (
    "original_ordinal", "review_area", "literal_cue_count",
    "latest_manual_status", "prior_manual_status",
    "changed_rounds", "reopened_after_human_marked_review",
    "human_follow_up",
)


def _admit(workflow_room: str, progress_rooms: list[str]):
    if not 1 <= len(progress_rooms) <= MAX_ROUNDS:
        raise Hold("HOLD: PRIVATE HAR desk requires 1–8 original human rounds")
    room = private_directory(workflow_room)
    original, cues = admit_workflow(str(room))
    parent = private_directory(str(room.parent))
    if not all(folder.parent == parent for folder in (original, cues)):
        raise Hold("HOLD: source-bound workflow requires private sibling rooms")
    roots = []
    for path in progress_rooms:
        folder = private_directory(path)
        if folder.parent != parent or not ROUND_NAME.fullmatch(folder.name):
            raise Hold("HOLD: select only private sibling HUMAN status packets")
        if folder in roots:
            raise Hold("HOLD: duplicate original human status round")
        roots.append(folder)
    _bind, _meta, sources = load_workroom(original)
    roster = entries(sources)
    chronology = []
    receipts = []
    for path in roots:
        with redirect_stdout(io.StringIO()):
            if reopen_progress(str(original), str(cues), str(path)) != 3:
                raise Hold("HOLD: original HUMAN status packet admission refused")
        raw = private_input(
            str(path / "PRIVATE-HAR-HUMAN-edited-actions.csv"), 65536)
        parsed = _edited(raw, roster)
        chronology.append([item["human_status"] for item in parsed])
        receipts.append(sha256(private_input(
            str(path / "PRIVATE-HAR-status-receipt.json"), 65536
        )).hexdigest())
    return room, original, cues, roots, roster, chronology, receipts


def _follow_up(item: dict) -> str:
    status = item["last_human_status"]
    if status == "WITHHOLD":
        return "Keep withheld; ask original source holder privately"
    if status == "SOURCE_OWNER_NEEDED":
        return "Original source owner must inspect source privately"
    if item["reopened_after_human_marked_review"]:
        return "Previously reviewed label reversed; revisit original privately"
    if status == "IN_PROGRESS":
        return "Continue original-only HUMAN review"
    if status == "PENDING_HUMAN":
        return "Inspect original privately; no privacy inference"
    return "HUMAN_REVIEWED is unverified; independent review still required"


def _details(roster: list[dict], history: list[list[str]]):
    record = _longitudinal(roster, history)
    for item in record:
        item["human_follow_up"] = _follow_up(item)
        item["prior_manual_status"] = (
            item["status_by_round"][-2] if len(history) > 1
            else "NO_PRIOR_ROUND"
        )
    return record


def _export_csv(rows: list[dict]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDS,
                            lineterminator="\r\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({
            "original_ordinal": row["original_ordinal"],
            "review_area": row["review_area"],
            "literal_cue_count": row["literal_cue_count"],
            "latest_manual_status": row["last_human_status"],
            "prior_manual_status": row["prior_manual_status"],
            "changed_rounds": row["manually_changed_rounds"],
            "reopened_after_human_marked_review":
                row["reopened_after_human_marked_review"],
            "human_follow_up": row["human_follow_up"],
        })
    return output.getvalue().encode("utf-8")


def _source_queue(rows: list[dict]) -> bytes:
    """Source-ordinal-only operator work sequence, never risk scoring."""
    fields = ("original_ordinal", "manual_work_sequence", "action_count",
              "withheld", "source_owner_needed", "in_progress",
              "pending_human", "human_marked_reviewed",
              "reopened_after_human_marked_review")
    grouped: dict[int, list[dict]] = {}
    for item in rows:
        grouped.setdefault(item["original_ordinal"], []).append(item)
    records = []
    for ordinal, items in grouped.items():
        counts = Counter(x["last_human_status"] for x in items)
        reopened = sum(bool(x["reopened_after_human_marked_review"])
                       for x in items)
        label = ("WITHHELD_HUMAN_ATTENTION" if counts["WITHHOLD"] else
                 "SOURCE_OWNER_REQUIRED" if counts["SOURCE_OWNER_NEEDED"] else
                 "REOPENED_MANUAL_REVIEW" if reopened else
                 "CONTINUE_MANUAL_REVIEW" if counts["IN_PROGRESS"] else
                 "PENDING_MANUAL_REVIEW" if counts["PENDING_HUMAN"] else
                 "INDEPENDENT_REVIEW_STILL_REQUIRED")
        records.append({
            "original_ordinal": ordinal,
            "manual_work_sequence": label,
            "action_count": len(items),
            "withheld": counts["WITHHOLD"],
            "source_owner_needed": counts["SOURCE_OWNER_NEEDED"],
            "in_progress": counts["IN_PROGRESS"],
            "pending_human": counts["PENDING_HUMAN"],
            "human_marked_reviewed": counts["HUMAN_REVIEWED"],
            "reopened_after_human_marked_review": reopened,
        })
    sequence = (
        "WITHHELD_HUMAN_ATTENTION", "SOURCE_OWNER_REQUIRED",
        "REOPENED_MANUAL_REVIEW", "CONTINUE_MANUAL_REVIEW",
        "PENDING_MANUAL_REVIEW", "INDEPENDENT_REVIEW_STILL_REQUIRED",
    )
    records.sort(key=lambda row: (sequence.index(row["manual_work_sequence"]),
                                  row["original_ordinal"]))
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\r\n")
    writer.writeheader()
    writer.writerows(records)
    return handle.getvalue().encode("utf-8")


def _page(workflow: Path, original: Path, cues: Path,
          progress: list[Path], rows: list[dict]) -> bytes:
    # All URI components are regenerated from strict local sibling-name
    # admissions, never from source content or user-supplied HTML.
    n = len(progress)
    totals = Counter(item["last_human_status"] for item in rows)
    needs = sum(item["last_human_status"] != "HUMAN_REVIEWED"
                for item in rows)
    revised = sum(bool(item["reopened_after_human_marked_review"])
                  for item in rows)
    by_original: dict[int, list[dict]] = {}
    for item in rows:
        by_original.setdefault(item["original_ordinal"], []).append(item)
    priority = {
        "WITHHOLD": 0, "SOURCE_OWNER_NEEDED": 1,
        "IN_PROGRESS": 2, "PENDING_HUMAN": 3, "HUMAN_REVIEWED": 4,
    }
    sections = []
    for ordinal, items in by_original.items():
        sorted_items = sorted(items, key=lambda r: (
            priority[r["last_human_status"]], -r["literal_cue_count"]))
        counts = Counter(item["last_human_status"] for item in sorted_items)
        lines = []
        for item in sorted_items:
            lines.append(
                "<tr><th scope='row'>" +
                escape(item["review_area"].replace("_", " ")) +
                "</th><td>" + str(item["literal_cue_count"]) +
                "</td><td>" + escape(item["last_human_status"]) +
                "</td><td>" + escape(item["prior_manual_status"]) +
                "</td><td>" + str(item["manually_changed_rounds"]) +
                "</td><td>" + escape(item["human_follow_up"]) +
                "</td></tr>"
            )
        # Reporting status counts is NOT declaring anything approved.
        sections.append(
            "<section id='original-" + str(ordinal) +
            "'><h2>Original #" + str(ordinal) + "</h2><p>" +
            str(len(sorted_items)) + " source-minimal task(s), " +
            str(counts["WITHHOLD"]) + " withheld and " +
            str(counts["SOURCE_OWNER_NEEDED"]) +
            " require original source owner.</p><div class='scroll'><table>"
            "<thead><tr><th>Private action area</th><th>Literal cues</th>"
            "<th>Latest manual status</th><th>Previous</th>"
            "<th>Changed rounds</th><th>HUMAN next action</th>"
            "</tr></thead><tbody>" + "".join(lines) +
            "</tbody></table></div></section>"
        )
    # Anchor navigation is ordered by manual operational follow-up, never
    # automated severity/verified risk. Includes all original positions.
    sequence = (
        "WITHHELD_HUMAN_ATTENTION", "SOURCE_OWNER_REQUIRED",
        "REOPENED_MANUAL_REVIEW", "CONTINUE_MANUAL_REVIEW",
        "PENDING_MANUAL_REVIEW", "INDEPENDENT_REVIEW_STILL_REQUIRED",
    )
    quick = sorted(
        ((item["original_ordinal"], item["manual_work_sequence"])
         for item in csv.DictReader(io.StringIO(_source_queue(rows).decode("utf-8")))),
        key=lambda item: (sequence.index(item[1]), int(item[0])),
    )
    quick_links = "".join(
        "<li><a href='#original-" + escape(index, quote=True) +
        "'>Original #" + escape(index) + "</a> — " +
        escape(label.replace("_", " ")) + "</li>"
        for index, label in quick
    )
    round_links = []
    for idx, folder in enumerate(progress, start=1):
        prefix = "../" + escape(folder.name, quote=True)
        round_links.append(
            "<li>Operator-ordered review round " + str(idx) +
            ': <a href="' + prefix +
            '/PRIVATE-HAR-HUMAN-status.html">manual status report</a>'
            ' · <a href="' + prefix +
            '/PRIVATE-HAR-HUMAN-edited-actions.csv">resume CSV in local studio'
            "</a> (owner-private; no upload)</li>"
        )
    original_link = "../" + escape(original.name, quote=True)
    cue_link = "../" + escape(cues.name, quote=True)
    workflow_link = "../" + escape(workflow.name, quote=True)
    current = "../" + escape(progress[-1].name, quote=True)
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';form-action 'none';base-uri 'none';object-src 'none';img-src 'none'">
<title>LightUp PRIVATE HAR HUMAN next-action desk</title>
<style>:root{font:16px/1.55 system-ui;color:#1c3448;background:#eef3f7}
*{box-sizing:border-box}body{max-width:1200px;margin:auto;padding:1rem}
header,section,footer{background:white;border:1px solid #cbd4dc;
border-radius:12px;padding:1.2rem;margin:1rem 0}
aside{background:#fff0e6;border-left:5px solid #a85a31;padding:1rem}
h1{font-size:clamp(1.4rem,3vw,2.2rem)}
a{color:#145981}a:focus-visible{outline:3px solid #c47d20}
.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse}
th,td{padding:.6rem;border-bottom:1px solid #c8d2dd;text-align:left}
thead{background:#eff4f8}
li{margin:.5rem 0}
@media print{body{background:white}section{break-inside:avoid}}</style>
<header><h1>PRIVATE HAR HUMAN next-action desk</h1>
<aside><b>INCUBATE / PLAN-LAB ONLY / UNVERIFIED / HOLD.</b> No status
is independently verified; even HUMAN_REVIEWED is not a privacy/security
approval, verified finding, consent, grant, source owner signoff or permission
to scan, share, disclose or deploy. Literal markers are not verified masks.
This local page is scriptless and contains NO raw original source,
identities, paths, filenames of selected inputs, URLs, cryptographic source
hashes, credentials, HUMAN free-text notes or network functions.</aside>
<p>Manual rounds in operator-supplied order: """ + str(n) +
""". Original sources: """ + str(len(by_original)) +
"""; tasks: """ + str(len(rows)) +
""". Currently not human-marked reviewed: """ + str(needs) +
"""; previously HUMAN_REVIEWED then later reopened: """ +
str(revised) + """. These are coordination counters, not clearance.</p></header>
<section><h2>Manual work-order navigation</h2><p>Task order is derived
solely from self-reported HUMAN statuses; it is not severity, a
verified security finding or approval. Every original stays listed.</p>
<ol>""" + quick_links + """</ol>
<p><a href='PRIVATE-HAR-SOURCE-QUEUE.csv'>Open source-minimal queue CSV</a>
(owner-only directory; importing elsewhere may expose PRIVATE metadata).</p></section>
<section><h2>Continue original owner-private review</h2>
<ul><li><a href='""" + original_link + """/OPEN-PRIVATE.html'>Open original
HUMAN notes workspace</a> (masked copies can still contain secrets)</li>
<li><a href='""" + cue_link + """/PRIVATE-HAR-STUDIO.html'>Edit source-minimal
HAR HUMAN status in the offline browser Studio</a></li>
<li><a href='""" + workflow_link +
"""/OPEN-PRIVATE-HAR-WORKFLOW.html'>Open original immutable HAR
workflow launcher</a></li>
<li><a href='""" + current +
"""/PRIVATE-HAR-HUMAN-edited-actions.csv'>Open most recent private manual
CSV draft</a> — select it with the Studio local resume picker; downloaded
copies may have unsafe filesystem permissions.</li></ul>
<p>The Studio cannot save to native workrooms: export a complete local CSV,
place it in owner-only storage (0600), and run
<code>notes.py har-review-progress --workflow-room &lt;original-workflow&gt;
--edited-actions &lt;private-edited-csv&gt;
--private-parent &lt;owner-only-parent&gt;</code> for a new HOLD round.</p></section>
<section><h2>Reopen earlier human-status rounds</h2>
<ol>""" + "".join(round_links) + """</ol><p>Round order is manually
supplied, not trusted chronology. No packet is overwritten.</p></section>""" +
"".join(sections) + """
<footer>Consult original source owner and independent security/privacy
reviewers. Exact-head CI, actual distinct client/operator consent with
revocation-at-use and explicit HUMAN GO remain separate release requirements.
No local status is a shortcut.</footer></html>""").encode("utf-8")


def _build(workflow_room: str, progress_rooms: list[str], output_parent: str,
           legacy: bool = False):
    parent = private_directory(output_parent)
    room, original, cues, progress, roster, history, receipt_hashes = _admit(
        workflow_room, progress_rooms)
    if parent != room.parent:
        raise Hold("HOLD: desk links require original owner-private sibling folder")
    rows = _details(roster, history)
    csv_bytes = _export_csv(rows)
    source_queue = _source_queue(rows)
    page = _page(room, original, cues, progress, rows)
    from private_har_print_agenda import NAME as AGENDA, build as print_agenda
    agenda = b"" if legacy else print_agenda(source_queue, len(progress))
    if not legacy:
        link = ("<section><h2>Printable original-position HUMAN agenda</h2>"
                "<p><a href='" + AGENDA + "'>Open print-only manual checklist</a> "
                "for ALL original source slots. It is source-minimal, unsigned, "
                "not consent, privacy clearance, a verified finding or PASS.</p></section>")
        page = page.replace(
            b"<section><h2>Continue original owner-private review</h2>",
            link.encode("utf-8") +
            b"<section><h2>Continue original owner-private review</h2>")
    payloads = (page, csv_bytes, source_queue) if legacy else (page, csv_bytes, source_queue, agenda)
    if not all(0 < len(value) <= MAX_SIZE for value in payloads):
        raise Hold("HOLD: PRIVATE HAR desk output exceeds bound")
    metadata = {
        "schema": SCHEMA if legacy else SCHEMA_V2,
        "claimed_status": "HOLD",
        "unverified_manual_status_only": True,
        "round_order_declared_not_attested": True,
        "original_review_workflow_receipt_sha256_unsigned": sha256(
            private_input(str(room / MANIFEST), 65536)).hexdigest(),
        "progress_receipt_sha256_unsigned_in_operator_order": receipt_hashes,
        "source_count": len({record["original_ordinal"] for record in rows}),
        "task_count": len(rows),
        "manual_round_count": len(progress),
        "desk_html_sha256_unsigned": sha256(page).hexdigest(),
        "desk_csv_sha256_unsigned": sha256(csv_bytes).hexdigest(),
        "source_queue_sha256_unsigned": sha256(source_queue).hexdigest(),
        **{name: False for name in FALSE_FLAGS},
    }
    if not legacy:
        metadata["print_agenda_sha256_unsigned"] = sha256(agenda).hexdigest()
    receipt = (json.dumps(metadata, indent=2, sort_keys=True,
                          ensure_ascii=False) + "\n").encode("utf-8")
    return page, csv_bytes, source_queue, agenda, receipt


def create(workflow_room: str, progress_rooms: list[str],
           private_parent: str, created_room: list[Path] | None = None) -> int:
    parent = private_directory(private_parent)
    page, csv_bytes, source_queue, agenda, receipt = _build(
        workflow_room, progress_rooms, str(parent))
    result = Path(tempfile.mkdtemp(
        prefix="PRIVATE-lightup-har-desk-", dir=parent))
    os.chmod(result, 0o700)
    finished = False
    try:
        file_new(result / PAGE, page)
        file_new(result / CSV, csv_bytes)
        file_new(result / SOURCE_CSV, source_queue)
        from private_har_print_agenda import NAME as AGENDA
        file_new(result / AGENDA, agenda)
        file_new(result / RECEIPT, receipt)
        finished = True
        if created_room is not None:
            created_room.append(result)
        print("HOLD: original-bound PRIVATE HAR HUMAN next-action desk prepared")
        print("OPEN LOCALLY: " + str(result / PAGE))
        return 3
    finally:
        if not finished:
            shutil.rmtree(result)


def reopen(workflow_room: str, progress_rooms: list[str],
           desk_room: str) -> int:
    room = private_directory(desk_room)
    if not re.fullmatch(r"PRIVATE-lightup-har-desk-[a-zA-Z0-9_-]{8,32}",
                        room.name):
        raise Hold("HOLD: invalid owner-private HAR desk folder")
    recorded = read_json(room / RECEIPT, MAX_SIZE)
    if type(recorded) is not dict or recorded.get("schema") not in (SCHEMA, SCHEMA_V2):
        raise Hold("HOLD: unsupported original HAR HUMAN desk receipt")
    legacy = recorded["schema"] == SCHEMA
    page, csv_bytes, source_queue, agenda, receipt = _build(
        workflow_room, progress_rooms, str(room.parent), legacy=legacy)
    from private_har_print_agenda import NAME as AGENDA
    expected_files = [(PAGE, page), (CSV, csv_bytes),
                      (SOURCE_CSV, source_queue), (RECEIPT, receipt)]
    if not legacy:
        expected_files.append((AGENDA, agenda))
        # V2 output is a closed immutable packet. Unexpected sidecars,
        # including accidental browser downloads, must not be silently
        # mistaken for a reviewed/receipt-bound artifact.
        expected_names = {name for name, _ in expected_files}
        actual_names = {entry.name for entry in room.iterdir()}
        if actual_names != expected_names:
            raise Hold("HOLD: PRIVATE HAR v2 desk inventory changed")
    for name, expected in expected_files:
        if private_input(str(room / name), MAX_SIZE) != expected:
            raise Hold("HOLD: original-bound PRIVATE HAR desk bytes changed")
    print("HOLD: original-bound PRIVATE HAR HUMAN desk reopened read-only")
    print("OPEN LOCALLY: " + str(room / PAGE))
    return 3
