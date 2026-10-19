#!/usr/bin/env python3
"""Original-source-current, HUMAN-only reconciliation of a durable staged draft.

Reads the exact original-native encrypted stage and current native HUMAN
workroom. No Apply, signature, consent, state change, scan or retest.
"""
from __future__ import annotations

from collections import Counter
import hashlib
from html import escape
from pathlib import Path

import request_handoff as bridge
import reconcile as source_reconcile

original = bridge.original
MAX_HTML = 128 * 1024
STAGES = ("staged", "reviewed")

def _request_ref(row: dict) -> str:
    return hashlib.sha256(original.canonical({
        "finding_id": row["finding_id"],
        "linked_sha256": row["linked_sha256"],
        "request_id": row["request_id"],
    })).hexdigest()

def collect(record: dict, args, vault, envelope: dict, current: dict,
            *, pending_recovery: bool = False) -> tuple[list[dict], dict]:
    """Admit native encrypted stage against CURRENT source, including crash recovery."""
    if pending_recovery:
        if record["state"] != "pending" or record["sha256"]:
            raise ValueError("Only a genuinely interrupted pending HUMAN intent can recover.")
    elif record["state"] not in STAGES:
        raise ValueError("Only a completed staged or reviewed HUMAN packet can be reconciled.")
    destination = Path(record["output"])
    # Reject symlinks/hardlinks and unsafe private path before reading ciphertext.
    bridge.source._hold_if_not_private_directory(destination.parent)
    info = destination.lstat()
    import os, stat
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or info.st_nlink != 1):
        raise ValueError("Native original encrypted HUMAN draft is not owner-private.")
    encrypted = vault._private_input(destination, vault.MAX_VAULT)
    if (not pending_recovery
            and hashlib.sha256(encrypted).hexdigest() != record["sha256"]):
        raise ValueError("Original native HUMAN stage ciphertext changed.")
    csv = original.human._unb64(
        envelope["original_csv_base64"], original.ORIGINAL.MAX_CSV_BYTES)
    staged = source_reconcile._private_workroom(
        destination, args, vault, envelope, current, csv)
    stage_rows = staged["human_requests"]
    expected = set(record["requests"])
    if not expected or len(expected) != len(record["requests"]):
        raise ValueError("Incomplete or duplicate journal stage references.")
    original_stage = {}
    for row in stage_rows:
        ref = _request_ref(row)
        if ref not in expected:
            continue
        if (ref in original_stage
                or row["request_kind"] != "followup_question"
                or row["human_stage"] != "draft"
                or row["assignee"] or row["due_date"] or row["human_response"]
                or not row["instructions"].startswith(bridge.INTRO)):
            raise ValueError("Original native encrypted HUMAN staging identity changed.")
        original_stage[ref] = row
    if set(original_stage) != expected:
        raise ValueError("Original native encrypted draft omits recorded HUMAN selection.")
    now_by_id = {row["request_id"]: row for row in current["human_requests"]}
    rows, totals = [], Counter()
    for ordinal, ref in enumerate(record["requests"], 1):
        draft = original_stage[ref]
        now = now_by_id.get(draft["request_id"])
        if now is None:
            status = "not_observed"
            content_changed = False
            response_present = False
            assignment_present = False
        else:
            if (now["finding_id"] != draft["finding_id"]
                    or now["linked_sha256"] != draft["linked_sha256"]
                    or now["request_kind"] != draft["request_kind"]):
                raise ValueError("Original HUMAN request ID was rebound: HOLD.")
            status = now["human_stage"]
            content_changed = any(now[key] != draft[key] for key in (
                "instructions", "assignee", "due_date", "human_response"))
            response_present = bool(now["human_response"])
            assignment_present = bool(now["assignee"])
        rows.append({
            "ordinal": ordinal,
            "status": status,
            "human_text_changed": content_changed,
            "response_present": response_present,
            "assignment_present": assignment_present,
        })
        totals[status] += 1
        if content_changed:
            totals["human_text_changed"] += 1
    totals["selected"] = len(rows)
    totals["closed_human"] += 0
    totals["not_observed"] += 0
    totals["remaining_unclosed"] = sum(row["status"] != "closed_human" for row in rows)
    if pending_recovery:
        # This hash is internal to one CLI operation, never published in
        # terminal reports or PRIVATE HTML. It pins the admitted ciphertext
        # so no different file can be promoted after HUMAN password prompts.
        totals["_admitted_encrypted_sha256"] = hashlib.sha256(encrypted).hexdigest()
    # Unverified human status, never native Apply or legal/consent outcome.
    return rows, dict(totals)

def print_review(rows: list[dict], totals: dict) -> None:
    print("ORIGINAL HUMAN request delivery review (not Apply or consent)")
    print("Originally staged:", totals["selected"],
          "· not observed in current workroom:", totals["not_observed"],
          "· reported closed_human:", totals["closed_human"],
          "· still not closed:", totals["remaining_unclosed"],
          "· HUMAN content changed:", totals.get("human_text_changed", 0))
    for row in rows:
        print("HUMAN request", row["ordinal"], "· current original reported stage:",
              row["status"], "· content changed:", row["human_text_changed"])
    print("All labels are unverified HUMAN workroom data. No security or legal authority.")

def html_review(rows: list[dict], totals: dict) -> bytes:
    e = lambda v: escape(str(v), quote=True)
    tablerows = "".join(
        "<tr><td>" + str(row["ordinal"]) +
        "</td><td>" + e(row["status"]) +
        "</td><td>" + ("Yes" if row["human_text_changed"] else "No") +
        "</td><td>" + ("Yes" if row["response_present"] else "No") +
        "</td><td>" + ("Yes" if row["assignment_present"] else "No") +
        "</td></tr>" for row in rows
    )
    html = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; connect-src 'none'; script-src 'none'; img-src 'none'; font-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>PRIVATE original HUMAN delivery review</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:950px;margin:auto;padding:2rem;
background:#f1f4f6;color:#18242c}header,section,footer{background:#fff;padding:1.25rem;
border:1px solid #bcc8cf;border-radius:12px;margin-bottom:1rem}
table{border-collapse:collapse;width:100%;table-layout:fixed}
th,td{text-align:left;word-break:break-word;border-bottom:1px solid #d0d8dd;padding:.6rem}
th{font-size:.85rem}strong{font-size:1.3rem}</style></head>
<body><header><h1>PRIVATE original HUMAN draft delivery</h1>
<p>Source-current original native HUMAN statuses, locally compared to the exact
original encrypted staged draft. This is not proof of native Apply, signed
reviewer identity, action-time client/operator consent, validated remediation,
retention-law compliance, actual deletion, grant, scan or retest.</p></header>
<section><h2>What is currently observed</h2><p>
Originally prepared: <strong>""" + str(totals["selected"]) + """</strong> ·
Missing from this supplied CURRENT workroom: <strong>""" + str(totals["not_observed"]) + """</strong> ·
HUMAN-reported closed: <strong>""" + str(totals["closed_human"]) + """</strong> ·
Unclosed: <strong>""" + str(totals["remaining_unclosed"]) + """</strong> ·
Modified HUMAN content: <strong>""" + str(totals.get("human_text_changed",0)) + """</strong></p></section>
<section><h2>Per-request original HUMAN stage</h2>
<table><thead><tr><th>Local #</th><th>Current HUMAN state</th>
<th>Text altered</th><th>Response present</th><th>Assigned</th></tr></thead>
<tbody>""" + tablerows + """</tbody></table></section>
<footer><p>Private local report only. No finding IDs, request IDs, tenant, source
digests, attachment SHA, private HUMAN response text, file paths, passwords or
evidence bytes are exported. Never upload this PRIVATE report or use it as a
grant, legal opinion, audit attestation or verified security result.</p></footer></body></html>"""
    payload = html.encode("utf-8", "strict")
    if len(payload) > MAX_HTML:
        raise ValueError("PRIVATE original HUMAN report exceeds bounded size.")
    return payload
