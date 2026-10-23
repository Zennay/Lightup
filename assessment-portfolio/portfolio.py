#!/usr/bin/env python3
"""Offline cross-agenda human coordination portfolio. No target/network/authorization calls."""
from __future__ import annotations

import argparse
import base64
from collections import Counter
from datetime import date, timedelta
from hashlib import sha256
from html import escape
import csv
import io
import json
import os
import stat
import sys
import unicodedata
import human_workbook
import capacity
import capacity_studio

AGENDA_SCHEMA = "lightup.archive_human_agenda.v1"
PORTFOLIO_SCHEMA = "lightup.assessment_portfolio_aggregate.v1"
FOCUSED_SCHEMA = "lightup.assessment_portfolio_aggregate.v2"
MAX_AGENDA = 128 * 1024
MAX_AGENDAS = 12
MAX_TOTAL = MAX_AGENDA * MAX_AGENDAS
FLAGS = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")
STAGES = (
    "PENDING_ORIGINAL", "NEEDS_ORIGINAL_EVIDENCE", "NEEDS_SOURCE_OWNER",
    "NEEDS_PRIVACY_REVIEW", "AWAITING_INPUT", "HUMAN_DISCUSSION",
)
ROLES = ("unassigned", "source_owner", "reviewer", "privacy", "operator")
DATE_BUCKETS = (
    "PAST_PLANNED_DATE", "PLANNED_FOR_REFERENCE_DAY",
    "FUTURE_PLANNED_DATE", "UNSCHEDULED",
)
KINDS = (
    "completed_lab_case_claim", "completed_lab_cohort_claim",
    "offline_comparison_claim", "studio_catalog_draft",
    "other_lightup_draft", "private_review_zip_claim",
)
GUIDANCE = {
    "completed_lab_case_claim": "Compare source-run facts with the original isolated lab scenario and provenance.",
    "completed_lab_cohort_claim": "Check original cohort membership and source-bound baseline/candidate choices.",
    "offline_comparison_claim": "Discuss flagged source metrics using the canonical original comparator.",
    "studio_catalog_draft": "Review scenario authorship, declared ground truth and separate numeric lab bindings.",
    "other_lightup_draft": "Confirm original producer/schema and assess privacy before sharing details.",
    "private_review_zip_claim": "Inspect with the original review-pack tool and verify the responsible source owner.",
}
BUCKET_ORDER = {value: index for index, value in enumerate(DATE_BUCKETS)}
STYLE = """*{box-sizing:border-box}body{margin:0;background:#f3f5f8;color:#17212f;font:16px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.hero,main,section,footer{max-width:1240px;margin:0 auto;padding:1rem}.hero{padding-top:2rem}.kicker{font-size:.75rem;letter-spacing:.08em;text-transform:uppercase;font-weight:750;color:#475569}h1{font-size:clamp(2rem,4vw,3rem);line-height:1.1;margin:.4rem 0}.state{padding:.8rem 1rem;border:1px solid #b6c1d0;border-left:5px solid #9a5b18;background:#fff7ed;border-radius:.45rem;font-weight:700}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.7rem}.card,section{background:white;border:1px solid #dbe1e8;border-radius:.65rem;margin:.8rem auto}.card{padding:.9rem}.value{font-size:1.6rem;font-weight:800;display:block}.label{font-size:.82rem;color:#536174}.tablewrap{overflow:auto;border:1px solid #e0e5eb;border-radius:.45rem;margin:.7rem 0}table{border-collapse:collapse;width:100%;font-size:.86rem}th,td{border-bottom:1px solid #e0e5eb;border-right:1px solid #edf0f4;padding:.55rem;text-align:left;vertical-align:top}th{background:#eef2f6}tbody tr:nth-child(even){background:#fafbfd}.note{font-size:.9rem;color:#536174}footer{font-size:.85rem;color:#64748b}@media print{body{background:white;font-size:10pt}.hero,main,section,footer{max-width:none;padding:.35rem}.card,section{break-inside:avoid}table{font-size:8pt}th,td{padding:.25rem}}"""
class Hold(Exception):
    pass

def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Hold("ambiguous JSON keys")
        result[key] = value
    return result

def reject_constant(_value):
    raise Hold("invalid JSON constant")

def reject_float(_value):
    raise Hold("unexpected floating-point value")

def parse_date(value, *, nullable=False):
    if value is None and nullable:
        return None
    if type(value) is not str or len(value) != 10:
        raise Hold("invalid date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise Hold("invalid date") from error
    if parsed.isoformat() != value or not 2020 <= parsed.year <= 2100:
        raise Hold("invalid date")
    return parsed

def open_directory_nofollow(path):
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise Hold("platform lacks required no-follow directory support")
    absolute = os.path.abspath(os.fspath(path))
    parts = [part for part in absolute.split(os.sep) if part]
    fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts:
            next_fd = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = next_fd
        return fd, absolute
    except Exception:
        os.close(fd)
        raise

def read_private_agenda(path):
    absolute = os.path.abspath(os.fspath(path))
    parent_path, name = os.path.dirname(absolute), os.path.basename(absolute)
    if name in ("", ".", ".."):
        raise Hold("invalid input path")
    parent_fd, _ = open_directory_nofollow(parent_path)
    try:
        fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_fd,
        )
    finally:
        os.close(parent_fd)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 0 < before.st_size <= MAX_AGENDA):
            raise Hold("input is not an owner-private bounded regular file")
        raw = stream.read(MAX_AGENDA + 1)
        after = os.fstat(stream.fileno())
        signature_before = (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_ctime_ns, before.st_uid, before.st_mode, before.st_nlink,
        )
        signature_after = (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
            after.st_ctime_ns, after.st_uid, after.st_mode, after.st_nlink,
        )
        if len(raw) != before.st_size or signature_before != signature_after:
            raise Hold("input changed during admission")
    try:
        text = raw.decode("utf-8", errors="strict")
        doc = json.loads(
            text, object_pairs_hook=unique_pairs,
            parse_constant=reject_constant, parse_float=reject_float,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Hold("invalid private agenda JSON") from error
    validate_agenda(doc)
    return absolute, raw, doc

def validate_count_map(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise Hold("invalid count map")
    if any(type(value[key]) is not int or value[key] < 0 for key in keys):
        raise Hold("invalid count value")

def date_bucket(review_date, reference_day):
    if review_date is None:
        return "UNSCHEDULED"
    parsed = parse_date(review_date)
    if parsed < reference_day:
        return "PAST_PLANNED_DATE"
    if parsed == reference_day:
        return "PLANNED_FOR_REFERENCE_DAY"
    return "FUTURE_PLANNED_DATE"

def validate_agenda(doc):
    expected = {
        "schema", "claimed_status", "reference_date", "source_count",
        "human_stage_counts", "neutral_role_counts", "date_bucket_counts",
        "planning_not_permission", "items", *FLAGS,
    }
    if type(doc) is not dict or set(doc) != expected or doc["schema"] != AGENDA_SCHEMA:
        raise Hold("wrong agenda schema")
    if any(doc[key] is not False for key in FLAGS) or doc["planning_not_permission"] is not True:
        raise Hold("agenda contains contradictory authority metadata")
    if doc["claimed_status"] not in ("HOLD", "REVIEW_ONLY"):
        raise Hold("unknown source status")
    reference = parse_date(doc["reference_date"])
    count = doc["source_count"]
    items = doc["items"]
    if type(count) is not int or not 2 <= count <= 64 or type(items) is not list or len(items) != count:
        raise Hold("invalid agenda item count")
    validate_count_map(doc["human_stage_counts"], STAGES)
    validate_count_map(doc["neutral_role_counts"], ROLES)
    validate_count_map(doc["date_bucket_counts"], DATE_BUCKETS)
    seen_slots = set()
    stage_counts, role_counts, date_counts = Counter(), Counter(), Counter()
    expected_item = {"slot", "source_kind", "stage", "next_role", "review_date", "date_bucket", "suggested_human_question"}
    for item in items:
        if type(item) is not dict or set(item) != expected_item:
            raise Hold("invalid agenda item shape")
        slot = item["slot"]
        if type(slot) is not int or not 1 <= slot <= count or slot in seen_slots:
            raise Hold("invalid or duplicate source slot")
        seen_slots.add(slot)
        kind, stage, role = item["source_kind"], item["stage"], item["next_role"]
        if kind not in KINDS or stage not in STAGES or role not in ROLES:
            raise Hold("unknown agenda classification")
        if item["suggested_human_question"] != GUIDANCE[kind]:
            raise Hold("non-canonical human question")
        review_date = item["review_date"]
        parse_date(review_date, nullable=True)
        bucket = date_bucket(review_date, reference)
        if item["date_bucket"] != bucket:
            raise Hold("inconsistent source date bucket")
        stage_counts[stage] += 1
        role_counts[role] += 1
        date_counts[bucket] += 1
    if seen_slots != set(range(1, count + 1)):
        raise Hold("incomplete source slots")
    if any(doc["human_stage_counts"][key] != stage_counts[key] for key in STAGES):
        raise Hold("stage counts do not match agenda items")
    if any(doc["neutral_role_counts"][key] != role_counts[key] for key in ROLES):
        raise Hold("role counts do not match agenda items")
    if any(doc["date_bucket_counts"][key] != date_counts[key] for key in DATE_BUCKETS):
        raise Hold("date counts do not match agenda items")

def collect(agendas, reference_day):
    if not 2 <= len(agendas) <= MAX_AGENDAS:
        raise Hold("select 2–12 original private agenda exports")
    documents, seen_digests, total_bytes = [], set(), 0
    source_dirs = set()
    rows = []
    for agenda_slot, (absolute, raw, doc) in enumerate(agendas, 1):
        total_bytes += len(raw)
        if total_bytes > MAX_TOTAL:
            raise Hold("total source size exceeded")
        digest = sha256(raw).digest()
        if digest in seen_digests:
            raise Hold("duplicate agenda export")
        seen_digests.add(digest)
        source_dirs.add(os.path.dirname(absolute))
        documents.append(doc)
        for item in doc["items"]:
            rows.append({
                "agenda_slot": agenda_slot,
                "source_slot": item["slot"],
                "source_kind": item["source_kind"],
                "stage": item["stage"],
                "next_role": item["next_role"],
                "review_date": item["review_date"],
                "date_bucket": date_bucket(item["review_date"], reference_day),
                "suggested_human_question": item["suggested_human_question"],
            })
    return documents, rows, source_dirs

def aggregate(documents, rows, reference_day):
    stage_counts = Counter(row["stage"] for row in rows)
    role_counts = Counter(row["next_role"] for row in rows)
    date_counts = Counter(row["date_bucket"] for row in rows)
    claimed_status_counts = Counter(doc["claimed_status"] for doc in documents)
    status = "HOLD" if claimed_status_counts["HOLD"] else "REVIEW_ONLY"
    return {
        "schema": PORTFOLIO_SCHEMA,
        "status": status,
        "reference_date": reference_day.isoformat(),
        "agenda_count": len(documents),
        "item_count": len(rows),
        "claimed_status_counts": {key: claimed_status_counts[key] for key in ("HOLD", "REVIEW_ONLY")},
        "human_stage_counts": {key: stage_counts[key] for key in STAGES},
        "neutral_role_counts": {key: role_counts[key] for key in ROLES},
        "date_bucket_counts": {key: date_counts[key] for key in DATE_BUCKETS},
        "role_date_bucket_counts": {
            role: {bucket: sum(1 for row in rows if row["next_role"] == role and row["date_bucket"] == bucket)
                   for bucket in DATE_BUCKETS}
            for role in ROLES
        },
        "planning_not_permission": True,
        **{key: False for key in FLAGS},
    }

def render_private_agenda_matrix(summary, rows):
    """Private per-source ordinal workload, excluded from anonymous aggregates."""
    grouped = {slot: [] for slot in range(1, summary["agenda_count"] + 1)}
    for row in rows:
        if row["agenda_slot"] not in grouped:
            raise Hold("private source ordinal outside admitted range")
        grouped[row["agenda_slot"]].append(row)
    cols = ("Agenda", "HUMAN items", *ROLES, *DATE_BUCKETS, "Open source ordinal")
    head = "<thead><tr>" + "".join("<th>" + escape(value) + "</th>" for value in cols) + "</tr></thead>"
    body = []
    for slot, selected in grouped.items():
        first = min(selected, key=lambda row: (row["source_slot"], ROLES.index(row["next_role"]))) if selected else None
        link = (
            "<a href='#agenda-" + str(slot) + "-slot-" + str(first["source_slot"]) +
            "'>Go to source slot " + str(first["source_slot"]) + "</a>"
            if first else "No rows in the current selection — NOT a completed assessment"
        )
        count_roles = Counter(row["next_role"] for row in selected)
        count_dates = Counter(row["date_bucket"] for row in selected)
        values = ["Agenda " + str(slot).zfill(2), str(len(selected))]
        values.extend(str(count_roles[role]) for role in ROLES)
        values.extend(str(count_dates[bucket]) for bucket in DATE_BUCKETS)
        body.append("<tr>" + "".join("<td>" + escape(value) + "</td>" for value in values) +
                    "<td>" + link + "</td></tr>")
    return (
        "<section><h2>PRIVATE per-agenda HUMAN attention</h2>"
        "<p class='note'>Shows local original agenda ordinals, not source identities or authentic chronology."
        " Values reflect only the current fixed selection and never prove remediation, consent or completion."
        " The anonymous JSON/CSV exports do not contain per-agenda counts.</p>"
        "<div class='tablewrap'><table>" + head + "<tbody>" + "".join(body) +
        "</tbody></table></div></section>"
    )


def render_private_schedule_clusters(rows):
    """Original human date proposals grouped privately, never calendar collision proof."""
    groups = {}
    for row in rows:
        if row["review_date"] is not None:
            key = (row["review_date"], row["next_role"])
            groups.setdefault(key, []).append(row)
    heavy = [
        (key, members) for key, members in sorted(groups.items())
        if len(members) >= 2
    ]
    table = []
    for (planned_day, role), members in heavy:
        agendas = len({item["agenda_slot"] for item in members})
        ordinal_links = ", ".join(
            "<a href='#agenda-" + str(item["agenda_slot"]) + "-slot-" +
            str(item["source_slot"]) + "'>A" + str(item["agenda_slot"]).zfill(2) +
            " / S" + str(item["source_slot"]).zfill(2) + "</a>"
            for item in sorted(members, key=lambda record: (
                record["agenda_slot"], record["source_slot"]
            ))
        )
        table.append(
            "<tr><td>" + escape(planned_day) + "</td><td>" + escape(role) + "</td>"
            "<td>" + str(len(members)) + "</td><td>" + str(agendas) + "</td>"
            "<td>" + ordinal_links + "</td></tr>"
        )
    body = (
        "<div class='tablewrap'><table><thead><tr><th>Human proposed day</th>"
        "<th>Suggested neutral role</th><th>Human agenda items</th>"
        "<th>Different agenda slots</th><th>PRIVATE ordinal drilldown</th>"
        "</tr></thead><tbody>" + "".join(table) + "</tbody></table></div>"
        if table else "<p class='note'>No same-role / same-date proposal clusters in this current selection."
        " This does not mean work is completed.</p>"
    )
    return (
        "<section><h2>PRIVATE same-day HUMAN attention clusters</h2>"
        "<p class='note'>At least two original items have the same proposed date and neutral role."
        " This is a local planning observation only; it does not establish that any person is assigned,"
        " that meetings overlap, deadlines exist, or a security finding is validated."
        " Only source ordinals appear here, never original source identities or target values.</p>"
        + body + "</section>"
    )


def render_private_html(summary, rows):
    style_hash = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    table_head = (
        "<thead><tr><th>Agenda slot</th><th>Source slot</th><th>Source kind</th>"
        "<th>Human stage</th><th>Neutral role</th><th>Proposed review date</th>"
        "<th>Date bucket</th><th>Suggested human question</th></tr></thead>"
    )
    sections = []
    for role in ROLES:
        selected = [row for row in rows if row["next_role"] == role]
        if not selected:
            continue
        selected.sort(key=lambda row: (
            BUCKET_ORDER[row["date_bucket"]], row["review_date"] or "9999-12-31",
            row["agenda_slot"], row["source_slot"],
        ))
        body = "".join(
            "<tr id='agenda-" + str(row["agenda_slot"]) + "-slot-" + str(row["source_slot"]) + "'>" +
            "".join("<td>" + escape(str(value)) + "</td>" for value in (
                "Agenda " + str(row["agenda_slot"]).zfill(2),
                "Slot " + str(row["source_slot"]).zfill(2),
                row["source_kind"], row["stage"], row["next_role"],
                row["review_date"] or "Not specified", row["date_bucket"],
                row["suggested_human_question"],
            )) + "</tr>"
            for row in selected
        )
        sections.append(
            "<section><h2>Neutral role: " + escape(role) + "</h2>"
            "<p>" + str(len(selected)) + " human-planning items. Role labels are proposals, not identities or assignments.</p>"
            "<div class='tablewrap'><table>" + table_head + "<tbody>" + body + "</tbody></table></div></section>"
        )
    status = "HOLD" if summary["status"] == "HOLD" else "REVIEW_ONLY"
    matrix_rows = []
    for role in ROLES:
        counts = summary["role_date_bucket_counts"][role]
        values = [role] + [counts[bucket] for bucket in DATE_BUCKETS] + [sum(counts.values())]
        matrix_rows.append("<tr>" + "".join("<td>" + escape(str(value)) + "</td>" for value in values) + "</tr>")
    matrix = (
        "<section><h2>Workload by neutral role and proposed date</h2>"
        "<p class=\"note\">Aggregate planning counts only; roles are not identities or assignments.</p>"
        "<div class=\"tablewrap\"><table><thead><tr><th>Neutral role</th>"
        "<th>Past proposed date</th><th>Reference day</th><th>Future proposed date</th>"
        "<th>Unscheduled</th><th>Total</th></tr></thead><tbody>" + "".join(matrix_rows) +
        "</tbody></table></div></section>"
    )
    cards = "".join(
        "<div class='card'><span class='value'>" + str(summary["date_bucket_counts"][key]) +
        "</span><span class='label'>" + escape(label) + "</span></div>"
        for key, label in (
            ("PAST_PLANNED_DATE", "Past proposed dates"),
            ("PLANNED_FOR_REFERENCE_DAY", "Reference-day plans"),
            ("FUTURE_PLANNED_DATE", "Future proposed dates"),
            ("UNSCHEDULED", "No proposed date"),
        )
    )
    selected_view = summary.get("view_selection")
    view_note = (
        "<p class='state'>PRIVATE FILTERED VIEW / HUMAN PLANNING ONLY: role " +
        escape(selected_view["neutral_role"]) + " · stage " +
        escape(selected_view["human_stage"]) + " · bucket " +
        escape(selected_view["date_bucket"]) +
        (" · exact day " + escape(selected_view["proposed_review_day"])
         if "proposed_review_day" in selected_view else "") +
        (" · source kind " + escape(selected_view["source_kind"])
         if "source_kind" in selected_view else "") +
        (" · day window " + escape(selected_view["proposed_date_from"]) + " to " +
         escape(selected_view["proposed_date_through"])
         if "proposed_date_from" in selected_view else "") +
        ". Counts and rows apply only to this explicit selection, not all admitted agendas.</p>"
        if selected_view else ""
    )
    empty_note = (
        "<p class='note'>No admitted HUMAN planning items match this selection. "
        "No missing item is evidence of a resolved issue.</p>" if not rows else ""
    )
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'sha256-" +
        style_hash + "'; img-src 'none'; script-src 'none'; connect-src 'none'; "
        "form-action 'none'; base-uri 'none'\">"
        "<title>LightUp — Private Assessment Portfolio</title><style>" + STYLE + "</style></head><body>"
        "<header class='hero'><div class='kicker'>LIGHTUP / ASSESSMENT RUNTIME / OFFLINE</div>"
        "<h1>Cross-agenda human coordination</h1>"
        "<p>Reference day: " + escape(summary["reference_date"]) +
        ". Compare only previously generated private human agendas. All source details remain local.</p>"
        "<div class='state'>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · " + status +
        " · NOT AUTHORIZED</div>" + view_note + "</header>"
        "<main><div class='cards'>" + cards + "</div>" + empty_note +
        "<p class='note'>" + str(summary["agenda_count"]) + " selected agendas · " +
        str(summary["item_count"]) + " human-planning items. Input order is a local ordinal only, not authenticated chronology.</p></main>"
        + matrix + render_private_agenda_matrix(summary, rows) + render_private_schedule_clusters(rows) + "".join(sections) +
        "<section><h2>Boundary and interpretation</h2><p class='note'>Past proposed dates are discussion prompts, not legal deadlines,"
        " verified finding age, security severity, authorization expiry or proof of a missed action. Missing sources are not treated as fixed."
        " No original paths, filenames, hashes, target labels, client identities or HUMAN notes are shown. The source claims and suggested questions remain unverified."
        " No assessment, network request, grant, scan, retest, remediation or release action is performed.</p></section>"
        "<footer>Static scriptless private HTML. Source bytes are not embedded in this artifact.</footer></body></html>"
    )
    return html.encode("utf-8")

# Fixed JavaScript enhances only the already admitted PRIVATE table rows.
# It performs no fetch, worker, storage, evaluation, submission or export.
INTERACTIVE_SCRIPT = "\"use strict\";\nconst panel = document.getElementById(\"privateFilterPanel\");\nif (panel) {\n  const roleSections = Array.from(document.querySelectorAll(\"section\")).filter(\n    section => (section.querySelector(\"h2\")?.textContent || \"\").startsWith(\"Neutral role:\")\n  );\n  const entries = roleSections.flatMap(section =>\n    Array.from(section.querySelectorAll(\"tbody tr\")).map(row => ({\n      section, row, cells: Array.from(row.cells, cell => cell.textContent || \"\")\n    }))\n  );\n  const controls = {\n    role: document.getElementById(\"localRole\"),\n    stage: document.getElementById(\"localStage\"),\n    bucket: document.getElementById(\"localBucket\"),\n    query: document.getElementById(\"localSearch\")\n  };\n  const counter = document.getElementById(\"visibleHumanItems\");\n  const shown = () => entries.filter(item => !item.row.hidden && !item.section.hidden);\n  const update = () => {\n    let visible = 0;\n    for (const item of entries) {\n      const accepted = (!controls.role.value || item.cells[4] === controls.role.value)\n        && (!controls.stage.value || item.cells[3] === controls.stage.value)\n        && (!controls.bucket.value || item.cells[6] === controls.bucket.value)\n        && (!controls.query.value.trim() ||\n            item.cells.join(\" \").toLocaleLowerCase().includes(controls.query.value.trim().toLocaleLowerCase()));\n      item.row.hidden = !accepted;\n      if (accepted) visible++;\n    }\n    for (const section of roleSections)\n      section.hidden = !Array.from(section.querySelectorAll(\"tbody tr\")).some(row => !row.hidden);\n    counter.textContent = visible + \" of \" + entries.length\n      + \" private HUMAN planning rows shown. Filtering is only a view, never an approval.\";\n    document.getElementById(\"privatePrintContext\").textContent =\n      \"Printed PRIVATE HUMAN row subset — visible \" + visible + \"/\" + entries.length\n      + \"; role: \" + (controls.role.value || \"all\") + \"; stage: \" + (controls.stage.value || \"all\")\n      + \"; date bucket: \" + (controls.bucket.value || \"all\") + \"; text search: \"\n      + (controls.query.value.trim() || \"(none)\")\n      + \". Local unverified proposals only; no grants, approval or automatic action.\";\n    document.getElementById(\"exportVisibleHumanRows\").disabled = visible === 0;\n  };\n  for (const input of Object.values(controls)) input.addEventListener(\"input\", update);\n  document.getElementById(\"resetLocalFilters\").addEventListener(\"click\", () => {\n    for (const input of Object.values(controls)) input.value = \"\";\n    update();\n    controls.query.focus();\n  });\n  const csvCell = value => {\n    // Fixed schema rows, but defensively protect exports against formula interpretation.\n    let text = String(value).replace(/[\\u0000-\\u001f\\u007f-\\u009f\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2069]/g, \" \");\n    if (/^[\\s\\u00a0]*[=+\\-@]/u.test(text)) text = \"'\" + text;\n    return '\"' + text.replace(/\"/g, '\"\"') + '\"';\n  };\n  document.getElementById(\"exportVisibleHumanRows\").addEventListener(\"click\", () => {\n    const rows = shown();\n    if (!rows.length) return;\n    const header = [\n      \"agenda_slot\", \"source_slot\", \"source_kind\", \"human_stage\", \"neutral_role\",\n      \"proposed_review_date\", \"date_bucket\", \"suggested_human_question\", \"authority_status\"\n    ];\n    const values = rows.map(item => [...item.cells.map((cell, index) =>\n      index === 0 ? cell.replace(/^Agenda /, \"\") :\n      index === 1 ? cell.replace(/^Slot /, \"\") :\n      index === 5 && cell === \"Not specified\" ? \"\" : cell\n    ), \"REVIEW_ONLY\"]);\n    const lines = [header, ...values].map(row => row.map(csvCell).join(\",\")).join(\"\\r\\n\") + \"\\r\\n\";\n    const blob = new Blob([lines], { type: \"text/csv;charset=utf-8\" });\n    const url = URL.createObjectURL(blob);\n    const link = document.createElement(\"a\");\n    link.href = url;\n    link.download = \"lightup-PRIVATE-visible-HUMAN-rows.csv\";\n    link.rel = \"noopener\";\n    link.click();\n    setTimeout(() => URL.revokeObjectURL(url), 5000);\n  });\n  document.getElementById(\"printVisibleHumanRows\").addEventListener(\"click\", () => window.print());\n  update();\n}"

def render_interactive_html(summary, rows):
    """Optional CSP-pinned local reviewer UI, never an authority or target workflow."""
    from_base = render_private_html(summary, rows).decode("utf-8")
    script_hash = base64.b64encode(sha256(INTERACTIVE_SCRIPT.encode("utf-8")).digest()).decode("ascii")
    def options(values):
        return "<option value=''>All</option>" + "".join(
            "<option value='" + escape(value) + "'>" + escape(value) + "</option>"
            for value in values
        )
    controls = (
        "<section id='privateFilterPanel' aria-label='Local private HUMAN planning filters'>"
        "<h2>Explore the PRIVATE human work queue</h2>"
        "<p class='note'>This private screen only filters previously admitted rows. No data is uploaded, stored or approved.</p>"
        "<label for='localRole'>Suggested role</label><select id='localRole'>" + options(ROLES) + "</select> "
        "<label for='localStage'>HUMAN stage</label><select id='localStage'>" + options(STAGES) + "</select> "
        "<label for='localBucket'>Proposed date</label><select id='localBucket'>" + options(DATE_BUCKETS) + "</select> "
        "<label for='localSearch'>Search private table</label><input id='localSearch' type='search' maxlength='120' "
        "autocomplete='off' placeholder='Fixed questions or slot ordinals'> "
        "<button type='button' id='resetLocalFilters'>Clear local filters</button>"
        "<p id='visibleHumanItems' role='status' aria-live='polite'></p>"

        "<button type='button' id='exportVisibleHumanRows'>Download visible rows (PRIVATE CSV)</button> "
        "<button type='button' id='printVisibleHumanRows'>Print visible PRIVATE queue</button>"
        "<p class='note'><strong>PRIVATE ONLY:</strong> downloads and print may retain local sensitive planning metadata."
        " No original URL, client identity, free-text HUMAN notes, permission or assessment result is included.</p>"
        "</section>"
    )
    extra_css = (
        "#privateFilterPanel label{display:inline-block;margin:.4rem .35rem .25rem 0;font-weight:650}"
        "#privateFilterPanel select,#privateFilterPanel input,#privateFilterPanel button{"
        "border:1px solid #a9b5c4;background:#fff;color:#17212f;border-radius:.35rem;"
        "font:inherit;padding:.4rem .55rem;margin:.2rem}"
        "#privateFilterPanel button{cursor:pointer;background:#eef2f6}"
        "#privateFilterPanel button:disabled{opacity:.5;cursor:not-allowed}"
        "[hidden]{display:none!important}"
        "@media print{#privateFilterPanel,main,section:not(.privateRoleWorklist){display:none!important}"
        "section[hidden],tr[hidden]{display:none!important}"
        ".hero #privatePrintContext{display:block!important}}"
    )
    inline_style = STYLE + extra_css
    style_from = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    style_to = base64.b64encode(sha256(inline_style.encode("utf-8")).digest()).decode("ascii")
    if (from_base.count("<main>") != 1 or from_base.count("script-src 'none'") != 1
            or from_base.count("<style>" + STYLE + "</style>") != 1
            or from_base.count("sha256-" + style_from) != 1
            or from_base.count("</body>") != 1):
        raise Hold("unexpected private HTML template")
    from_base = from_base.replace("<main>", controls + "<main>", 1)
    # Print only filtered role rows, never the unfiltered private global matrices.
    from_base = from_base.replace(
        "<section><h2>Neutral role: ", "<section class='privateRoleWorklist'><h2>Neutral role: "
    )
    # Keep the precise visible filter selection on paper, but not the controls.
    from_base = from_base.replace(
        "</header>", "<p id='privatePrintContext' class='note'>PRIVATE HUMAN filtered view, not authorized.</p></header>", 1
    )
    from_base = from_base.replace("script-src 'none'", "script-src 'sha256-" + script_hash + "'", 1)
    from_base = from_base.replace("<style>" + STYLE + "</style>", "<style>" + inline_style + "</style>", 1)
    from_base = from_base.replace("sha256-" + style_from, "sha256-" + style_to, 1)
    return from_base.replace("</body>", "<script>" + INTERACTIVE_SCRIPT + "</script></body>", 1).encode("utf-8")


def render_private_routing_csv(rows):
    """Explicit PRIVATE per-item human handoff. Never an anonymous public export.

    All value-bearing fields come from exact admitted enums, ordinals, ISO dates,
    or one of the fixed generic human questions. No original source field appears.
    """
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow((
        "agenda_slot", "source_slot", "source_kind", "human_stage",
        "neutral_role", "proposed_review_date", "proposed_date_bucket",
        "suggested_human_question", "authority_status",
    ))
    for row in sorted(rows, key=lambda item: (
        ROLES.index(item["next_role"]), BUCKET_ORDER[item["date_bucket"]],
        item["review_date"] or "9999-12-31", item["agenda_slot"], item["source_slot"],
    )):
        writer.writerow((
            row["agenda_slot"], row["source_slot"], row["source_kind"],
            row["stage"], row["next_role"], row["review_date"] or "",
            row["date_bucket"], row["suggested_human_question"], "REVIEW_ONLY",
        ))
    return stream.getvalue().encode("utf-8")


def source_calendar_fingerprints(documents):
    """Stable source-scoped local identities; never authenticates source authorship."""
    return [
        sha256(json.dumps(document, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":")).encode("utf-8")).hexdigest()
        for document in documents
    ]


def render_private_calendar(rows, reference_day, documents):
    """Opt-in inert PRIVATE proposed HUMAN date notes; never calendar invites."""
    fingerprints = source_calendar_fingerprints(documents)
    def fold(line):
        # All emitted vocabulary/ordinals are bounded ASCII. RFC 5545 continuation.
        if not line.isascii() or any(ord(c) < 32 or ord(c) > 126 for c in line):
            raise Hold("unexpected calendar text outside fixed ASCII vocabulary")
        return "\r\n ".join(line[index:index + 74] for index in range(0, len(line), 74))

    lines = [
        "BEGIN:VCALENDAR", "VERSION:2.0",
        "PRODID:-//LightUp//Private Human Discussion Proposals v1//EN",
        "CALSCALE:GREGORIAN",
        "X-WR-CALNAME:LightUp PRIVATE proposed HUMAN discussions",
        "X-LIGHTUP-AUTHORIZED:FALSE",
        "X-LIGHTUP-REVIEW-ONLY:TRUE",
    ]
    stamp = reference_day.strftime("%Y%m%d") + "T000000Z"
    for row in sorted(rows, key=lambda value: (
        value["review_date"] or "9999-12-31",
        value["agenda_slot"], value["source_slot"],
    )):
        if row["review_date"] is None:
            continue  # No invented dates or scheduled events for UNSCHEDULED.
        start = parse_date(row["review_date"])
        end = start + timedelta(days=1)  # All-day end is exclusive, per RFC 5545.
        identity = (
            str(row["agenda_slot"]) + "/" + fingerprints[row["agenda_slot"] - 1] + "/" +
            str(row["source_slot"]) + "/" + row["review_date"] + "/" + row["next_role"] + "/" + row["stage"] +
            "/" + reference_day.isoformat()
        )
        uid = sha256(identity.encode("ascii")).hexdigest() + "@offline.lightup.invalid"
        event = [
            "BEGIN:VEVENT",
            "UID:" + uid,
            "DTSTAMP:" + stamp,
            "DTSTART;VALUE=DATE:" + start.strftime("%Y%m%d"),
            "DTEND;VALUE=DATE:" + end.strftime("%Y%m%d"),
            "STATUS:TENTATIVE",
            "TRANSP:TRANSPARENT",
            "SUMMARY:LightUp PRIVATE proposed HUMAN discussion (not a deadline)",
            "DESCRIPTION:Unverified proposal only. Agenda " + str(row["agenda_slot"]) +
            " / source slot " + str(row["source_slot"]) + ". Role " + row["next_role"] +
            ". Stage " + row["stage"] + ". No consent\\nNo grant\\nNo scan or dispatch.",
            "END:VEVENT",
        ]
        lines.extend(event)
    lines.append("END:VCALENDAR")
    return ("\r\n".join(fold(line) for line in lines) + "\r\n").encode("ascii")




def render_private_role_day_csv(rows):
    """Offline human-staffing counts with optional source ordinals; PRIVATE only."""
    groups = {}
    for row in rows:
        key = (row["review_date"], row["next_role"])
        groups.setdefault(key, []).append(row)
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow((
        "original_proposed_day", "suggested_neutral_role", "human_items",
        "distinct_original_agendas", "original_source_ordinals", "authority_status",
    ))
    for (day, role), members in sorted(groups.items(), key=lambda item: (
        item[0][0] is None, item[0][0] or "9999-12-31", ROLES.index(item[0][1])
    )):
        ordinals = ";".join(
            "A" + str(row["agenda_slot"]).zfill(2) + "/S" + str(row["source_slot"]).zfill(2)
            for row in sorted(members, key=lambda value: (value["agenda_slot"], value["source_slot"]))
        )
        writer.writerow((
            day or "", role, len(members),
            len({row["agenda_slot"] for row in members}), ordinals, "REVIEW_ONLY",
        ))
    return output.getvalue().encode("utf-8")


def render_private_day_brief(summary, rows):
    """Static source-free printable per-day HUMAN attention brief with local drilldown."""
    style_hash = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    groups = {}
    for row in rows:
        groups.setdefault((row["review_date"], row["next_role"]), []).append(row)
    sections = []
    ordered = sorted(groups.items(), key=lambda item: (
        item[0][0] is None, item[0][0] or "9999-12-31",
        ROLES.index(item[0][1])
    ))
    for (proposed_date, role), members in ordered:
        row_links = []
        for row in sorted(members, key=lambda item: (item["agenda_slot"], item["source_slot"])):
            number = "A" + str(row["agenda_slot"]).zfill(2) + "/S" + str(row["source_slot"]).zfill(2)
            anchor = ("assessment-portfolio-private.html#agenda-" +
                      str(row["agenda_slot"]) + "-slot-" + str(row["source_slot"]))
            row_links.append(
                "<li><a href='" + anchor + "'>" + number + "</a> · " +
                escape(row["stage"]) + " · " + escape(row["source_kind"]) +
                " · " + escape(row["suggested_human_question"]) + "</li>"
            )
        headings = "No date proposed" if proposed_date is None else "Original proposed day: " + proposed_date
        sections.append(
            "<section><h2>" + escape(headings) + " · neutral role " + escape(role) + "</h2>"
            "<p class='note'>" + str(len(members)) + " HUMAN items from " +
            str(len({row["agenda_slot"] for row in members})) +
            " original agenda slots. No appointment or reviewer assignment is implied.</p>"
            "<ol>" + "".join(row_links) + "</ol></section>"
        )
    selected = summary.get("view_selection")
    scope = (
        "Filtered: " + escape(selected["neutral_role"]) + " / " +
        escape(selected["human_stage"]) + " / " +
        escape(selected["date_bucket"]) +
        (" / proposed day " + escape(selected["proposed_review_day"])
         if "proposed_review_day" in selected else "") +
        (" / kind " + escape(selected["source_kind"])
         if "source_kind" in selected else "") +
        (" / proposed window " + escape(selected["proposed_date_from"]) + " to " +
         escape(selected["proposed_date_through"])
         if "proposed_date_from" in selected else "")
        if selected else "All admitted HUMAN items"
    )
    empty = (
        "<section><h2>Empty proposed work queue</h2>"
        "<p>No rows match this view. This is NOT a completion or approval verdict.</p></section>"
        if not sections else ""
    )
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'sha256-" + style_hash + "'; script-src 'none'; "
        "connect-src 'none'; form-action 'none'; base-uri 'none'\">"
        "<title>LightUp PRIVATE HUMAN day brief</title><style>" + STYLE + "</style>"
        "</head><body><header class='hero'><div class='kicker'>PRIVATE / OFFLINE / HUMAN ONLY</div>"
        "<h1>Human role-day attention brief</h1>"
        "<p>Planning reference " + escape(summary["reference_date"]) + " · " + scope +
        " · " + str(len(rows)) + " proposed human items.</p>"
        "<div class='state'>INCUBATE M3/M7 · " + escape(summary["status"]) +
        " · REVIEW ONLY · NOT AUTHORIZED</div>"
        "<p class='note'>Dates and neutral roles are unsigned source claims, NOT scheduled meetings, "
        "authorizations, real findings or proof of remediation. Open links only within "
        "the same PRIVATE owner-only bundle. No network or active action.</p></header>"
        "<main>" + "".join(sections) + empty + "</main>"
        "<footer>LightUp private planning draft; no approved client scope, grant, "
        "verified consent, scanner invocation or release.</footer></body></html>"
    )
    return html.encode("utf-8")


def render_private_cluster_calendar(rows, reference_day, documents):
    """One transparent all-day proposal per role/day; no meeting or authority."""
    fingerprints = source_calendar_fingerprints(documents)
    clusters = {}
    for row in rows:
        if row["review_date"] is not None:
            key = (row["review_date"], row["next_role"])
            clusters.setdefault(key, []).append(row)
    lines = [
        "BEGIN:VCALENDAR", "VERSION:2.0",
        "PRODID:-//LightUp//Private HUMAN role-day proposals v1//EN",
        "CALSCALE:GREGORIAN",
        "X-WR-CALNAME:LightUp PRIVATE HUMAN role-day proposals",
        "X-LIGHTUP-REVIEW-ONLY:TRUE",
        "X-LIGHTUP-AUTHORIZED:FALSE",
    ]
    stamp = reference_day.strftime("%Y%m%d") + "T000000Z"
    for (day, role), members in sorted(clusters.items()):
        start = parse_date(day)
        end = start + timedelta(days=1)
        identities = sorted(
            str(row["agenda_slot"]) + ":" + fingerprints[row["agenda_slot"] - 1] + ":" +
            str(row["source_slot"]) + ":" + row["stage"]
            for row in members
        )
        identity = "/".join((reference_day.isoformat(), day, role, *identities))
        uid = sha256(("lightup-human-role-day-v1:" + identity).encode("ascii")).hexdigest()
        unique_agendas = len({row["agenda_slot"] for row in members})
        lines.extend((
            "BEGIN:VEVENT",
            "UID:" + uid + "@offline.lightup.invalid",
            "DTSTAMP:" + stamp,
            "DTSTART;VALUE=DATE:" + start.strftime("%Y%m%d"),
            "DTEND;VALUE=DATE:" + end.strftime("%Y%m%d"),
            "STATUS:TENTATIVE",
            "TRANSP:TRANSPARENT",
            "SUMMARY:LightUp PRIVATE HUMAN role-day proposal (not booked)",
            "DESCRIPTION:Unverified HUMAN planning only. Role " + role +
            ". Items " + str(len(members)) + ". Agenda slots " +
            str(unique_agendas) +
            ". Refer to PRIVATE original workroom. No permission or confirmed meeting.",
            "END:VEVENT",
        ))
    lines.append("END:VCALENDAR")
    # Only source-admitted fixed ASCII vocabulary, neutral roles and YYYYMMDD
    # are emitted; fold physical lines to RFC 5545's 75-octet boundary.
    for line in lines:
        if not line.isascii() or any(ord(char) < 32 or ord(char) > 126 for char in line):
            raise Hold("unexpected role-day calendar text")
    return ("\r\n".join(
        "\r\n ".join(line[i:i + 74] for i in range(0, len(line), 74))
        for line in lines
    ) + "\r\n").encode("ascii")


def render_counts_csv(summary):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(("dimension", "value", "count"))
    if "view_selection" in summary:
        for dimension, chosen in summary["view_selection"].items():
            writer.writerow(("view_selection", dimension, chosen))
    writer.writerow(("summary", "agenda_count", summary["agenda_count"]))
    writer.writerow(("summary", "item_count", summary["item_count"]))
    for key, count in summary["claimed_status_counts"].items():
        writer.writerow(("source_status", key, count))
    for key, count in summary["human_stage_counts"].items():
        writer.writerow(("human_stage", key, count))
    for key, count in summary["neutral_role_counts"].items():
        writer.writerow(("neutral_role", key, count))
    for role in ROLES:
        for bucket in DATE_BUCKETS:
            writer.writerow(("role_date_bucket", role + "|" + bucket, summary["role_date_bucket_counts"][role][bucket]))
    for key, count in summary["date_bucket_counts"].items():
        writer.writerow(("date_bucket", key, count))
    return stream.getvalue().encode("utf-8")

def open_output_directory(path):
    fd, absolute = open_directory_nofollow(path)
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        os.close(fd)
        raise Hold("output directory must be owned by the current user and mode 0700")
    return fd, absolute

def publish_bundle(directory_fd, artifacts):
    created = []
    try:
        for name, data in artifacts:
            fd = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600, dir_fd=directory_fd,
            )
            created.append(name)
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        os.fsync(directory_fd)
    except Exception:
        for name in reversed(created):
            try:
                os.unlink(name, dir_fd=directory_fd)
            except OSError:
                pass
        try:
            os.fsync(directory_fd)
        except OSError:
            pass
        raise


def render_artifacts(documents, rows, reference_day, *, selection=None, interactive=False,
                     calendar=False, calendar_clusters=False, day_brief=False, role_day_csv=False,
                     home=False, workbook=False, capacity_limits=None,
                     alternative_capacity_limits=None, capacity_browser_studio=False,
                     human_entries=None, previous_human_entries=None,
                     human_history_entries=None):
    """Deterministic private bytes used identically for create and reopen.

    A filtered handoff has an explicit v2 view contract; unchanged full
    portfolios retain the original v1 schema and original four-file format.
    """
    summary = aggregate(documents, rows, reference_day)
    if selection:
        summary["schema"] = FOCUSED_SCHEMA
        summary["view_selection"] = selection
    result = [
        ("assessment-portfolio-private.html", render_private_html(summary, rows)),
        ("assessment-portfolio-private-routing.csv", render_private_routing_csv(rows)),
        ("assessment-portfolio-anonymous.json",
         (json.dumps(summary, ensure_ascii=False, indent=2) + "\n").encode("utf-8")),
        ("assessment-portfolio-anonymous.csv", render_counts_csv(summary)),
    ]
    if interactive:
        result.append(("assessment-portfolio-private-explorer.html", render_interactive_html(summary, rows)))
    if calendar:
        result.append(("assessment-portfolio-private-proposals.ics", render_private_calendar(rows, reference_day, documents)))
    if calendar_clusters:
        result.append(("assessment-portfolio-private-role-day.ics",
                       render_private_cluster_calendar(rows, reference_day, documents)))
    if role_day_csv:
        result.append(("assessment-portfolio-private-role-day.csv",
                       render_private_role_day_csv(rows)))
    if capacity_limits is not None:
        result.extend(capacity.render_private_capacity(rows, reference_day, capacity_limits, ROLES))
    if alternative_capacity_limits is not None:
        if capacity_limits is None:
            raise Hold("alternative capacity requires original declared capacity")
        result.extend(capacity.render_private_capacity_comparison(
            rows, reference_day, capacity_limits, alternative_capacity_limits, ROLES))
    if capacity_browser_studio:
        if capacity_limits is None:
            raise Hold("capacity scenario browser requires operator-declared PRIVATE limit")
        result.append(capacity_studio.render(rows, reference_day,
                                             capacity_limits, alternative_capacity_limits, ROLES))
    if day_brief:
        result.append(("assessment-portfolio-private-day-brief.html",
                       render_private_day_brief(summary, rows)))
    if workbook:
        result.append(("assessment-portfolio-human-workbook.html",
                       human_workbook.render_worksheet(rows, reference_day.isoformat())))
    if human_entries is not None:
        result.append(("assessment-portfolio-private-HUMAN-return.html",
                       human_workbook.render_private_return(human_entries, reference_day.isoformat())))
        result.append(("assessment-portfolio-private-HUMAN-return.csv",
                       human_workbook.render_private_csv(human_entries)))
        result.append(("assessment-portfolio-private-HUMAN-summary.json",
                       human_workbook.render_private_summary_json(human_entries, reference_day.isoformat())))
    if previous_human_entries is not None:
        if human_entries is None:
            raise Hold("HUMAN comparison requires an original-bound current HUMAN worksheet")
        result.append(("assessment-portfolio-private-HUMAN-delta.html",
                       human_workbook.render_private_comparison_html(
                           previous_human_entries, human_entries, reference_day.isoformat())))
        result.append(("assessment-portfolio-private-HUMAN-delta.json",
                       human_workbook.render_private_comparison_json(
                           previous_human_entries, human_entries, reference_day.isoformat())))
    if human_history_entries is not None:
        if human_entries is not None or previous_human_entries is not None:
            raise Hold("multi-round HUMAN history cannot be combined with pairwise HUMAN inputs")
        result.append(("assessment-portfolio-private-HUMAN-timeline.html",
                       human_workbook.render_private_timeline_html(
                           human_history_entries, reference_day.isoformat())))
        result.append(("assessment-portfolio-private-HUMAN-timeline.json",
                       human_workbook.render_private_timeline_json(
                           human_history_entries, reference_day.isoformat())))
        result.append(("assessment-portfolio-private-HUMAN-timeline.csv",
                       human_workbook.render_private_timeline_csv(
                           human_history_entries, reference_day.isoformat())))
    if home or workbook or human_entries is not None or human_history_entries is not None:
        result.append(("assessment-portfolio-private-HUMAN-home.html",
                       human_workbook.render_private_home(
                           [name for name, _ in result], reference_day.isoformat())))
    if any(len(data) > 1_048_576 for _, data in result):
        raise Hold("private portfolio artifact exceeds bounded 1 MiB publication limit")
    return result


def verify_existing_bundle(directory_fd, expected):
    """Read only: require exact inventory, owner-only regular files and original bytes."""
    names = {name for name, _ in expected}
    if set(os.listdir(directory_fd)) != names:
        raise Hold("private bundle inventory differs from canonical originals")
    for name, canonical in expected:
        fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                    or before.st_size != len(canonical)):
                raise Hold("private bundle file has unsafe metadata or changed size")
            observed = stream.read(len(canonical) + 1)
            after = os.fstat(stream.fileno())
            signature = lambda info: (
                info.st_dev, info.st_ino, info.st_size, info.st_mode,
                info.st_uid, info.st_nlink, info.st_mtime_ns, info.st_ctime_ns,
            )
            if signature(before) != signature(after) or observed != canonical:
                raise Hold("private bundle bytes differ from original canonical source")


def readmit_unchanged_sources(admitted):
    """Reopen original sources immediately before publication/reopen, fail on drift."""
    for absolute, raw, _ in admitted:
        reopened, reread, _ = read_private_agenda(absolute)
        if reopened != absolute or reread != raw:
            raise Hold("original private agenda changed after initial admission")

def read_private_agenda_manifest(path):
    """Private LF-delimited absolute source paths; does not read targets or run work."""
    absolute = os.path.abspath(os.fspath(path))
    parent_fd, _ = open_directory_nofollow(os.path.dirname(absolute))
    try:
        fd = os.open(
            os.path.basename(absolute),
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_fd,
        )
    finally:
        os.close(parent_fd)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 0 < before.st_size <= 32768):
            raise Hold("source list must be owner-private bounded regular text")
        raw = stream.read(32769)
        after = os.fstat(stream.fileno())
        signature = lambda item: (
            item.st_dev, item.st_ino, item.st_size, item.st_uid, item.st_mode,
            item.st_nlink, item.st_mtime_ns, item.st_ctime_ns,
        )
        if len(raw) != before.st_size or signature(before) != signature(after):
            raise Hold("source list changed during admission")
    if not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise Hold("source list must be LF-delimited with no NUL or CR")
    try:
        # Do not treat Unicode separators or bidi controls as hidden extra paths.
        decoded = raw.decode("utf-8", errors="strict")
        paths = decoded.split("\n")[:-1]
    except UnicodeError as error:
        raise Hold("source list is not UTF-8") from error
    if not 2 <= len(paths) <= MAX_AGENDAS:
        raise Hold("source list must contain 2–12 agenda paths")
    if len(set(paths)) != len(paths):
        raise Hold("duplicate paths in source list")
    for candidate in paths:
        if (not os.path.isabs(candidate) or os.path.normpath(candidate) != candidate
                or not 1 <= len(candidate) <= 2048
                or any(unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp")
                       for ch in candidate)):
            raise Hold("invalid path in owner-private source list")
    return absolute, paths


def read_private_human_history_manifest(path):
    """Read a private ordered list of original-bound HUMAN response paths."""
    absolute, paths = read_private_agenda_manifest(path)
    if not 2 <= len(paths) <= 8:
        raise Hold("HUMAN history list must contain 2–8 response paths")
    return absolute, paths


def run(args):
    if not hasattr(os, "O_NOFOLLOW"):
        raise Hold("platform lacks no-follow file support")
    if args.preview_only:
        if args.output_dir or args.verify_output_dir:
            raise Hold("read-only preview cannot select an output directory or reopen mode")
    elif not args.output_dir:
        raise Hold("select an output directory or use --preview-only")
    reference_day = parse_date(args.as_of)
    if args.restore_private_capacity_json and (
        args.private_capacity_plan or args.daily_capacity is not None
        or args.role_capacity or args.alternate_daily_capacity is not None
        or args.alternate_role_capacity
    ):
        raise Hold("choose saved PRIVATE capacity scenario OR manual capacity inputs")
    capacity_limits = capacity.configure(
        args.private_capacity_plan, args.daily_capacity, args.role_capacity, ROLES,
    )
    alternative_capacity_limits = capacity.configure(
        args.alternate_daily_capacity is not None or bool(args.alternate_role_capacity),
        args.alternate_daily_capacity, args.alternate_role_capacity, ROLES,
    )
    if alternative_capacity_limits is not None and capacity_limits is None:
        raise Hold("alternative capacity scenario requires the original PRIVATE capacity plan")
    if args.private_capacity_studio and capacity_limits is None and not args.restore_private_capacity_json:
        raise Hold("private capacity scenario studio needs original declared capacity")
    if bool(args.focus_from) != bool(args.focus_through):
        raise Hold("planning window needs both first and last proposed dates")
    if args.focus_day and args.focus_from:
        raise Hold("select either one original proposed date or a date window")
    first_day = last_day = None
    if args.focus_from:
        first_day, last_day = parse_date(args.focus_from), parse_date(args.focus_through)
        if first_day > last_day or (last_day - first_day).days > 90:
            raise Hold("planning window must be ordered and no longer than 91 days")
    if bool(args.agendas_file) == bool(args.agendas):
        raise Hold("choose either --agendas-file or 2–12 positional source agendas")
    manifest_path = None
    selected_agendas = args.agendas
    if args.agendas_file:
        manifest_path, selected_agendas = read_private_agenda_manifest(args.agendas_file)
    history_manifest_path = None
    history_paths = args.human_history
    if args.human_history_file:
        if args.human_history:
            raise Hold("choose --human-history or --human-history-file, not both")
        history_manifest_path, history_paths = read_private_human_history_manifest(
            args.human_history_file
        )
    if not 2 <= len(selected_agendas) <= MAX_AGENDAS:
        raise Hold("select 2–12 original private agenda exports")
    admitted = [read_private_agenda(path) for path in selected_agendas]
    documents, rows, source_dirs = collect(admitted, reference_day)
    if manifest_path:
        source_dirs.add(os.path.dirname(manifest_path))
    scenario_path = (os.path.abspath(args.restore_private_capacity_json)
                     if args.restore_private_capacity_json else None)
    if scenario_path:
        source_dirs.add(os.path.dirname(scenario_path))
    if history_paths:
        if args.human_responses or args.previous_human_responses:
            raise Hold("choose multi-round HUMAN history or pairwise HUMAN inputs, not both")
        if not 2 <= len(history_paths) <= 8:
            raise Hold("HUMAN history requires 2–8 separately saved rounds")
        history_paths = [os.path.abspath(path) for path in history_paths]
        if len(set(history_paths)) != len(history_paths):
            raise Hold("HUMAN history paths must be unique and manually ordered")
        # Every response room and optional private path list remain separate from output.
        for path in history_paths:
            source_dirs.add(os.path.dirname(path))
        if history_manifest_path:
            source_dirs.add(os.path.dirname(history_manifest_path))
    else:
        if args.previous_human_responses and not args.human_responses:
            raise Hold("HUMAN comparison requires a current response source")
        if args.human_responses:
            # Keep source/return and output rooms separate before ANY publication.
            source_dirs.add(os.path.dirname(os.path.abspath(args.human_responses)))
        if args.previous_human_responses:
            if (os.path.abspath(args.previous_human_responses) == os.path.abspath(args.human_responses)):
                raise Hold("HUMAN comparison sources cannot alias the same path")
            source_dirs.add(os.path.dirname(os.path.abspath(args.previous_human_responses)))
    output_fd, output_path = None, None
    if not args.preview_only:
        output_fd, output_path = open_output_directory(args.output_dir)
    try:
        if output_path is not None:
            for source_dir in source_dirs:
                common = os.path.commonpath((output_path, source_dir))
                if common in (output_path, source_dir):
                    raise Hold("output directory must be separate from source rooms")
        selection = None
        if (args.focus_role or args.focus_stage or args.focus_bucket or args.focus_day
            or args.focus_kind or first_day is not None):
            selection = {
                "neutral_role": args.focus_role or "ALL",
                "human_stage": args.focus_stage or "ALL",
                "date_bucket": args.focus_bucket or "ALL",
            }
            if args.focus_day:
                selection["proposed_review_day"] = parse_date(args.focus_day).isoformat()
            if args.focus_kind:
                selection["source_kind"] = args.focus_kind
            if first_day is not None:
                selection["proposed_date_from"] = first_day.isoformat()
                selection["proposed_date_through"] = last_day.isoformat()
            rows = [
                row for row in rows
                if (not args.focus_role or row["next_role"] == args.focus_role)
                and (not args.focus_stage or row["stage"] == args.focus_stage)
                and (not args.focus_bucket or row["date_bucket"] == args.focus_bucket)
                and (not args.focus_day or row["review_date"] == selection["proposed_review_day"])
                and (not args.focus_kind or row["source_kind"] == args.focus_kind)
                and (first_day is None or (row["review_date"] is not None and
                     first_day.isoformat() <= row["review_date"] <= last_day.isoformat()))
            ]
        scenario_raw = None
        if scenario_path:
            scenario_raw, scenario_doc = human_workbook.read_private_response(
                scenario_path, open_directory_nofollow
            )
            capacity_limits, alternative_capacity_limits = capacity_studio.admit_private_scenario(
                scenario_doc, rows, reference_day, ROLES
            )
        responses_raw, human_entries = None, None
        if args.human_responses:
            # Explicit private HUMAN input; never edits original admitted agendas.
            response_path = os.path.abspath(args.human_responses)
            responses_raw, responses = human_workbook.read_private_response(
                response_path, open_directory_nofollow
            )
            human_entries = human_workbook.validate_response(
                responses, rows, reference_day.isoformat()
            )
        history_raw, history_entries = [], None
        if args.human_history:
            history_entries = []
            for supplied_path in args.human_history:
                response_path = os.path.abspath(supplied_path)
                raw_response, response = human_workbook.read_private_response(
                    response_path, open_directory_nofollow
                )
                entries = human_workbook.validate_response(
                    response, rows, reference_day.isoformat()
                )
                history_raw.append((response_path, raw_response))
                history_entries.append(entries)
        previous_bytes, previous_entries = None, None
        if args.previous_human_responses:
            previous_bytes, earlier = human_workbook.read_private_response(
                args.previous_human_responses, open_directory_nofollow
            )
            previous_entries = human_workbook.validate_response(
                earlier, rows, reference_day.isoformat()
            )
        outputs = render_artifacts(
            documents, rows, reference_day, selection=selection,
            interactive=args.private_explorer, calendar=args.private_calendar,
            calendar_clusters=args.private_calendar_clusters,
            day_brief=args.private_day_brief,
            role_day_csv=args.private_role_day_csv,
            home=args.private_home,
            workbook=args.private_human_workbook,
            capacity_limits=capacity_limits,
            alternative_capacity_limits=alternative_capacity_limits,
            capacity_browser_studio=args.private_capacity_studio,
            human_entries=human_entries,
            previous_human_entries=previous_entries,
            human_history_entries=history_entries,
        )
        readmit_unchanged_sources(admitted)
        if scenario_path:
            reopened, _ = human_workbook.read_private_response(
                scenario_path, open_directory_nofollow
            )
            if reopened != scenario_raw:
                raise Hold("PRIVATE HUMAN capacity scenario changed before publication")
        if args.human_responses:
            reopened, _ = human_workbook.read_private_response(
                args.human_responses, open_directory_nofollow
            )
            if reopened != responses_raw:
                raise Hold("HUMAN worksheet source changed before publication")
        if args.previous_human_responses:
            original, _ = human_workbook.read_private_response(
                args.previous_human_responses, open_directory_nofollow
            )
            if original != previous_bytes:
                raise Hold("previous HUMAN source changed before publication")
        for history_path, original_bytes in history_raw:
            reopened, _ = human_workbook.read_private_response(
                history_path, open_directory_nofollow
            )
            if reopened != original_bytes:
                raise Hold("HUMAN history source changed before publication")
        if manifest_path:
            _, reopened_paths = read_private_agenda_manifest(manifest_path)
            if reopened_paths != selected_agendas:
                raise Hold("private selection list changed before publication")
        if history_manifest_path:
            _, reopened_history_paths = read_private_human_history_manifest(
                history_manifest_path
            )
            if reopened_history_paths != history_paths:
                raise Hold("private HUMAN history list changed before publication")
        if args.preview_only:
            role_counts = Counter(row["next_role"] for row in rows)
            bucket_counts = Counter(row["date_bucket"] for row in rows)
            stage_counts = Counter(row["stage"] for row in rows)
            roles = ",".join(role + ":" + str(role_counts.get(role, 0)) for role in ROLES)
            buckets = ",".join(bucket + ":" + str(bucket_counts.get(bucket, 0)) for bucket in DATE_BUCKETS)
            stages = ",".join(stage + ":" + str(stage_counts.get(stage, 0)) for stage in STAGES)
            capacity_lines = []
            for label, limits in (
                ("declared", capacity_limits),
                ("alternate", alternative_capacity_limits),
            ):
                if limits is None:
                    continue
                capacity_rows, undated = capacity.collect(rows, limits, ROLES)
                overloaded = sum(1 for item in capacity_rows if item["items_above_declared_limit"] > 0)
                excess = sum(item["items_above_declared_limit"] for item in capacity_rows)
                capacity_lines.append(
                    label + "_capacity_groups=" + str(len(capacity_rows)) +
                    " " + label + "_over_limit_groups=" + str(overloaded) +
                    " " + label + "_excess_items=" + str(excess) +
                    " " + label + "_undated_items=" + str(sum(len(items) for items in undated.values()))
                )
            output_bytes = sum(len(content) for _name, content in outputs)
            print(
                "ASSESSMENT_PORTFOLIO_PREVIEW_REVIEW_ONLY agendas=" + str(len(documents)) +
                " items=" + str(len(rows)) +
                " artifacts=" + str(len(outputs)) +
                " rendered_bytes=" + str(output_bytes) +
                " roles[" + roles + "] buckets[" + buckets + "] stages[" + stages + "]" +
                (" " + " ".join(capacity_lines) if capacity_lines else "") +
                " — PLANNING ONLY; capacity is an explicit hypothetical assumption, no output directory opened, no files written, NOT AUTHORIZED"
            )
            return 0
        if args.verify_output_dir:
            verify_existing_bundle(output_fd, outputs)
        else:
            publish_bundle(output_fd, outputs)
    finally:
        if output_fd is not None:
            os.close(output_fd)
    print(("ASSESSMENT_PORTFOLIO_VERIFIED" if args.verify_output_dir else "ASSESSMENT_PORTFOLIO_CREATED") + " agendas=" + str(len(documents)) +
          " items=" + str(len(rows)) + " — PLANNING ONLY; NOT AUTHORIZED")
    return 0

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Aggregate original private human agendas offline; no target or authorization calls."
    )
    parser.add_argument("--as-of", required=True, help="Explicit planning reference day YYYY-MM-DD")
    parser.add_argument("--output-dir", help="Existing owner-only directory, mode 0700 (omit only with --preview-only)")
    parser.add_argument("--preview-only", action="store_true",
                        help="Admit and render in memory, print aggregate counts/size only, never open/write output files")
    parser.add_argument("--verify-output-dir", action="store_true",
                        help="Read-only exact reopen of a previously created PRIVATE bundle and chosen options")
    parser.add_argument("--focus-role", choices=ROLES,
                        help="Create or reopen a PRIVATE workroom limited to one suggested neutral role")
    parser.add_argument("--focus-stage", choices=STAGES,
                        help="Restrict PRIVATE human workroom to one non-authorizing HUMAN stage")
    parser.add_argument("--focus-bucket", choices=DATE_BUCKETS,
                        help="Restrict PRIVATE human workroom to one date bucket relative to --as-of")
    parser.add_argument("--focus-day", metavar="YYYY-MM-DD",
                        help="Restrict HUMAN planning to one exact originally proposed date")
    parser.add_argument("--focus-from", metavar="YYYY-MM-DD",
                        help="Include original HUMAN review dates from this day (requires --focus-through)")
    parser.add_argument("--focus-through", metavar="YYYY-MM-DD",
                        help="Include original HUMAN review dates through this day (max 91 calendar days)")
    parser.add_argument("--focus-kind", choices=KINDS,
                        help="Restrict PRIVATE HUMAN workroom to one original fixed source kind")
    parser.add_argument("--private-explorer", action="store_true",
                        help="Add a CSP-pinned offline interactive PRIVATE HUMAN queue, no storage/network")
    parser.add_argument("--private-calendar", action="store_true",
                        help="Add a PRIVATE date-only tentative calendar, no invitations or alarms")
    parser.add_argument("--private-calendar-clusters", action="store_true",
                        help="Add one inert PRIVATE tentative role/day proposal per same-date HUMAN workload")
    parser.add_argument("--private-home", action="store_true",
                        help="Add source-bound scriptless PRIVATE start screen for any selected packet assets")
    parser.add_argument("--private-capacity-plan", action="store_true",
                        help="PRIVATE HUMAN items vs explicitly declared daily role-limit assumption desk")
    parser.add_argument("--daily-capacity", type=int,
                        help="Operator-declared 1–128 HUMAN proposals per neutral role and proposed day")
    parser.add_argument("--role-capacity", action="append", default=[], metavar="ROLE=N",
                        help="Optional explicit daily HUMAN item assumption for a fixed neutral role")
    parser.add_argument("--restore-private-capacity-json", metavar="PRIVATE_JSON",
                        help="Reopen browser v2 PRIVATE HUMAN capacity assumptions against exact current source rows, no authority")
    parser.add_argument("--private-capacity-studio", action="store_true",
                        help="Add hash-CSP-pinned offline PRIVATE browser capacity scenario editor (requires declared capacity)")
    parser.add_argument("--alternate-daily-capacity", type=int,
                        help="Optional second explicit 1–128 proposed items/day scenario (requires original PRIVATE capacity plan)")
    parser.add_argument("--alternate-role-capacity", action="append", default=[], metavar="ROLE=N",
                        help="Optional neutral role override for the second manual capacity scenario")
    parser.add_argument("--private-role-day-csv", action="store_true",
                        help="Add offline PRIVATE role/day staffing and source-ordinal spreadsheet CSV")
    parser.add_argument("--private-day-brief", action="store_true",
                        help="Add scriptless PRIVATE by-day and role printable HUMAN brief with original ordinal links")
    parser.add_argument("--private-human-workbook", action="store_true",
                        help="Add offline HUMAN discussion worksheet with local JSON download, no authority")
    parser.add_argument("--human-responses",
                        help="Owner-private 0600 saved HUMAN worksheet JSON for strict original-bound return")
    parser.add_argument("--previous-human-responses",
                        help="Second earlier operator-selected PRIVATE HUMAN response for local delta (requires --human-responses)")
    parser.add_argument("--human-history", action="append", default=[], metavar="PRIVATE_HUMAN_JSON",
                        help="One owner-private 0600 source-bound HUMAN response; repeat 2–8 times in manual comparison order")
    parser.add_argument("--human-history-file",
                        help="Owner-private mode-0600 LF-delimited list of 2–8 absolute HUMAN response paths in manual order")
    parser.add_argument("--agendas-file", help="Owner-private mode-0600 LF-delimited list of 2–12 absolute agenda paths")
    parser.add_argument("agendas", nargs="*", help="2–12 original private JSON agenda exports (or use --agendas-file)")
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (Hold, human_workbook.Hold, OSError, ValueError, TypeError, UnicodeError, KeyError,
            OverflowError, RecursionError, csv.Error):
        print("ASSESSMENT_PORTFOLIO_HOLD — invalid, unsafe, or incompatible private source/output", file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
