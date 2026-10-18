"""LightUp offline, human-only escalation board for original authenticated Casebook v1.
Never an approval, grant, consent, at-use revocation check or scan.
"""
from __future__ import annotations

import argparse
import base64
import csv
from datetime import datetime
from hashlib import sha256
import html
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import unicodedata

MAX_BYTES = 512 * 1024
MAX_ROWS = 200
AUTHORITY = (
    "source_authenticated", "client_consent_verified",
    "operator_consent_verified", "authorization_granted",
    "execution_allowed", "release_approved",
)
FAMILIES = {
    "requests": ("request_id", {"request_id", "status", "requested_mode",
                                "requested_risk", "created_at", "decision_recorded"}),
    "engagements": ("engagement_id", {"engagement_id", "status", "created_at"}),
    "grants": ("grant_id", {"grant_id", "engagement_id", "approved_request_id",
                           "request_link_observation", "max_risk", "valid_from",
                           "valid_until", "validity_observation"}),
    "risk_approvals": ("approval_id", {"approval_id", "engagement_id", "status",
                                      "requested_risk", "source_tenant_matches",
                                      "decision_recorded", "decision_provenance_observation"}),
    "case_overview": ("engagement_id", {"engagement_id", "status", "grant_count",
                                      "risk_record_count", "attention", "next_review_action"}),
}
COUNTS = {"requests", "engagements", "grants", "risk_approvals", "grant_link_hold",
          "risk_tenant_hold", "case_attention_hold", "foreign_tenant_row_count",
          "recorded_window_review", "risk_provenance_hold", "pending_risk_review"}
ROOT = {"schema", "status", "source", "as_of", "client_id",
        "declared_counts", *FAMILIES, *AUTHORITY}
ACTIONS = {
    "HOLD_SOURCE_PROVENANCE": "Reconcile original persisted tenant and request provenance",
    "RISK_DECISION_PENDING_SOURCE_REVIEW": "Obtain separate human review of pending risk",
    "HOLD_CLOSED_ENGAGEMENT_WITH_GRANTS": "Review closed engagement and stored grants",
    "EXPIRED_GRANT_SOURCE_REVIEW": "Review historical grant window and ask for fresh authority",
    "FUTURE_GRANT_SOURCE_REVIEW": "Review historical future-dated grant window",
    "REVIEW_ONLY_UNVERIFIED_GRANT_LINK": "Check consent, scope and revocation in original live boundary",
    "NO_GRANT_RECORDED": "Review original client request before any grant",
}
REVIEW_STATUSES = {"unassigned", "investigating", "waiting_on_client",
                   "waiting_on_operator", "needs_source_review", "human_followup_complete"}


class Hold(Exception):
    pass


def _unique_pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise Hold("duplicate JSON member")
        d[k] = v
    return d


def _reject_constant(_):
    raise Hold("non-finite JSON number")


def _str(value, maximum=180):
    return (type(value) is str and 1 <= len(value) <= maximum
            and value.strip() == value and
            not any(ord(c) < 32 or ord(c) == 127 for c in value))


def _rows(obj, family):
    rows = obj.get(family)
    if type(rows) is not list or len(rows) > MAX_ROWS:
        raise Hold("source family invalid")
    identity, fields = FAMILIES[family]
    known = set()
    for row in rows:
        if type(row) is not dict or set(row) != fields or not _str(row[identity]):
            raise Hold("source row invalid")
        if row[identity] in known:
            raise Hold("source identity duplicated")
        known.add(row[identity])
    return rows


def _read_source(path):
    if path.is_symlink():
        raise Hold("symlink source refused")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode)
                or before.st_mode & 0o077 or before.st_size > MAX_BYTES):
            raise Hold("source must be private regular file")
        raw = os.read(fd, MAX_BYTES + 1)
        after = os.fstat(fd)
        if (len(raw) > MAX_BYTES or len(raw) != before.st_size
                or before.st_ino != after.st_ino
                or before.st_mtime_ns != after.st_mtime_ns):
            raise Hold("changed or oversized source")
    finally:
        os.close(fd)
    if raw.startswith(b"\xef\xbb\xbf"):
        raise Hold("BOM refused")
    try:
        data = json.loads(raw.decode("utf-8", "strict"),
                          object_pairs_hook=_unique_pairs,
                          parse_constant=_reject_constant)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise Hold("invalid canonical JSON") from exc
    return admit_source_data(raw, data)


def admit_source_data(raw: bytes, data: dict):
    """Verify an entire original Casebook v1 snapshot (never authority)."""
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES or raw.startswith(b"\xef\xbb\xbf"):
        raise Hold("raw source bytes invalid")
    if type(data) is not dict or set(data) != ROOT:
        raise Hold("unsupported original Casebook source")
    if (data["schema"] != "lightup.auth_casebook.v1"
            or data["status"] != "REVIEW_ONLY"
            or data["source"] != "original_persisted_domain_unverified"
            or not _str(data["client_id"])):
        raise Hold("unknown source family")
    try:
        stamp = datetime.fromisoformat(data["as_of"])
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise Hold("source time without UTC offset")
    except (TypeError, ValueError):
        raise Hold("invalid source time") from None
    for flag in AUTHORITY:
        if data[flag] is not False:
            raise Hold("source claims authority")
    for family in FAMILIES:
        _rows(data, family)
    for row in data["requests"]:
        if (row["status"] not in ("submitted", "under_review", "approved", "rejected")
                or not _str(row["requested_mode"], 80)
                or type(row["requested_risk"]) is not int
                or not 0 <= row["requested_risk"] <= 5
                or type(row["decision_recorded"]) is not bool
                or not _str(row["created_at"], 80)):
            raise Hold("bad source request")
    for row in data["engagements"]:
        if not _str(row["status"], 80) or not _str(row["created_at"], 80):
            raise Hold("bad source engagement")
    for row in data["grants"]:
        if (row["engagement_id"] is not None and
                not _str(row["engagement_id"])):
            raise Hold("bad source grant engagement")
        if (row["approved_request_id"] is not None and
                not _str(row["approved_request_id"])):
            raise Hold("bad source request binding")
        if (not _str(row["request_link_observation"], 100)
                or not _str(row["validity_observation"], 100)
                or type(row["max_risk"]) is not int
                or not 0 <= row["max_risk"] <= 5
                or not _str(row["valid_from"], 80)
                or not _str(row["valid_until"], 80)):
            raise Hold("bad source grant")
    for row in data["risk_approvals"]:
        if (row["engagement_id"] is not None and
                not _str(row["engagement_id"])):
            raise Hold("bad risk engagement")
        if (row["status"] not in ("pending", "approved", "denied")
                or type(row["requested_risk"]) is not int
                or not 0 <= row["requested_risk"] <= 5
                or type(row["source_tenant_matches"]) is not bool
                or type(row["decision_recorded"]) is not bool
                or not _str(row["decision_provenance_observation"], 100)):
            raise Hold("bad source risk")
    engagements = {r["engagement_id"]: r for r in data["engagements"]}
    for row in data["case_overview"]:
        eid = row["engagement_id"]
        if (eid not in engagements or row["status"] != engagements[eid]["status"]
                or not _str(row["attention"], 100)
                or row["attention"] not in ACTIONS
                or not _str(row["next_review_action"], 100)):
            raise Hold("bad case overview")
        expected_action = {
            "HOLD_SOURCE_PROVENANCE": "RECONCILE_PERSISTED_PROVENANCE",
            "RISK_DECISION_PENDING_SOURCE_REVIEW": "REVIEW_OUTSTANDING_ORIGINAL_RISK_REQUEST",
            "HOLD_CLOSED_ENGAGEMENT_WITH_GRANTS": "REVIEW_CLOSED_ENGAGEMENT",
            "EXPIRED_GRANT_SOURCE_REVIEW": "REVIEW_ORIGINAL_GRANT_WINDOW",
            "FUTURE_GRANT_SOURCE_REVIEW": "CHECK_ORIGINAL_GRANT_WINDOW",
            "REVIEW_ONLY_UNVERIFIED_GRANT_LINK": "CONFIRM_SEPARATE_CONSENT_AND_AT_USE_REVOCATION",
            "NO_GRANT_RECORDED": "REVIEW_REQUEST_BEFORE_ANY_GRANT",
        }[row["attention"]]
        if row["next_review_action"] != expected_action:
            raise Hold("source action contradicts attention")
        for field, family in (("grant_count", "grants"),
                              ("risk_record_count", "risk_approvals")):
            expected = sum(g["engagement_id"] == eid for g in data[family])
            if type(row[field]) is not int or row[field] != expected:
                raise Hold("source case count contradictory")
    if set(r["engagement_id"] for r in data["case_overview"]) != set(engagements):
        raise Hold("incomplete case overview")
    counts = data["declared_counts"]
    if type(counts) is not dict or set(counts) != COUNTS:
        raise Hold("unsupported source counts")
    recomputed = {k: len(data[k]) for k in
                  ("requests", "engagements", "grants", "risk_approvals")}
    recomputed.update({
        "grant_link_hold": sum(r["request_link_observation"].startswith("HOLD_")
                               for r in data["grants"]),
        "risk_tenant_hold": sum(not r["source_tenant_matches"]
                                for r in data["risk_approvals"]),
        "case_attention_hold": sum(r["attention"].startswith("HOLD_")
                                   for r in data["case_overview"]),
        "recorded_window_review": sum(
            r["validity_observation"] != "WITHIN_RECORDED_WINDOW_NOT_AUTHORITY"
            for r in data["grants"]),
        "risk_provenance_hold": sum(r["decision_provenance_observation"].startswith("HOLD_")
                                    for r in data["risk_approvals"]),
        "pending_risk_review": sum(r["decision_provenance_observation"] == "RISK_DECISION_PENDING_REVIEW"
                                    for r in data["risk_approvals"]),
    })
    if any(type(v) is not int or v < 0 or v > MAX_ROWS for v in counts.values()):
        raise Hold("invalid count")
    if any(counts[k] != v for k, v in recomputed.items()):
        raise Hold("source declared totals contradictory")
    return raw, data


def _queue(data):
    tasks = []
    for case in data["case_overview"]:
        eid = case["engagement_id"]
        grant_rows = [r for r in data["grants"] if r["engagement_id"] == eid]
        risk_rows = [r for r in data["risk_approvals"] if r["engagement_id"] == eid]
        attention = case["attention"]
        tier = ("HOLD" if attention.startswith("HOLD_") else
                "PENDING" if attention == "RISK_DECISION_PENDING_SOURCE_REVIEW" else "REVIEW")
        flags = [r["request_link_observation"] + " / " + r["validity_observation"]
                 for r in grant_rows]
        flags += [r["decision_provenance_observation"] for r in risk_rows]
        tasks.append({"key": "engagement:" + eid, "family": "engagement",
                      "id": eid, "tier": tier, "attention": attention,
                      "action": ACTIONS[attention], "flags": flags})
    for req in data["requests"]:
        if req["status"] in ("submitted", "under_review", "rejected"):
            tasks.append({"key": "request:" + req["request_id"],
                          "family": "request", "id": req["request_id"],
                          "tier": "PENDING" if req["status"] != "rejected" else "REVIEW",
                          "attention": "RECORDED_REQUEST_" + req["status"].upper(),
                          "action": ("Review original request independently" if req["status"] != "rejected"
                                     else "Record human follow-up without reversing rejection"),
                          "flags": []})
    tasks.sort(key=lambda x: ({"HOLD": 0, "PENDING": 1, "REVIEW": 2}[x["tier"]],
                              x["family"], x["id"]))
    return tasks


def _safe_csv_cell(value):
    """Prevent Unicode-obscured formula interpretation in private CSV viewers."""
    original = str(value)
    normalized = unicodedata.normalize("NFKC", original)
    while normalized and (normalized[0].isspace() or
                          unicodedata.category(normalized[0]) in ("Cf", "Cc", "Zl", "Zp")):
        normalized = normalized[1:]
    if normalized.startswith(("=", "+", "-", "@")):
        return "'" + original
    return original


def _csv(tasks):
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(["Source family", "Original ID (PRIVATE)", "Review tier",
                     "Source observation", "Human next action", "Owner (blank)",
                     "Due date (blank)", "Human stage (blank)"])
    for t in tasks:
        writer.writerow([_safe_csv_cell(v) for v in
                         [t["family"], t["id"], t["tier"], t["attention"],
                          t["action"], "", "", ""]])
    # Source IDs are retained only in this PRIVATE CSV; not intended for spreadsheet execution.
    return output.getvalue().encode("utf-8")


def _page(data, tasks, digest, script):
    esc = lambda s: html.escape(str(s), quote=True)
    groups = []
    for t in tasks:
        flags = "".join("<li>" + esc(f) + "</li>" for f in t["flags"])
        groups.append(
            '<article class="task" data-tier="' + t["tier"] + '" data-key="' + esc(t["key"]) + '">'
            '<header><label class="pick"><input type="checkbox" data-pick="1" aria-label="Select human follow-up for ' + esc(t["id"]) + '"></label><span class="pill ' + t["tier"].lower() + '">' + t["tier"] + '</span>'
            '<small>' + esc(t["family"]) + '</small><strong>' + esc(t["id"]) + '</strong></header>'
            '<p class="observation">' + esc(t["attention"]) + '</p>'
            '<p>' + esc(t["action"]) + '</p>'
            '<details><summary>Recorded source observations (' + str(len(t["flags"])) +
            ')</summary><ul>' + flags + '</ul></details>'
            '<div class="edit"><label>Human reviewer <input maxlength="80" data-field="owner" autocomplete="off"></label>'
            '<label>Proposed UTC follow-up <input type="date" data-field="due"></label>'
            '<label>Human stage <select data-field="stage">' +
            "".join('<option value="' + esc(s) + '"' + (' selected' if s == 'unassigned' else '') + '>' + esc(s.replace("_", " ")) + '</option>'
                    for s in sorted(REVIEW_STATUSES)) + '</select></label>'
            '<label class="wide">Human next step <textarea maxlength="500" data-field="next"></textarea></label>'
            '</div></article>'
        )
    style = """body{margin:0;background:#0b1420;color:#e9eff7;font:15px system-ui,sans-serif}main{max-width:1160px;margin:auto;padding:28px 20px 100px}h1{font-size:2.3rem;margin:.3em 0}p{line-height:1.5}.muted{color:#9fb2c8}.banner{background:#321e26;border:1px solid #db6672;border-radius:14px;padding:16px;margin:18px 0}.controls{position:sticky;top:0;z-index:2;background:#15253a;border:1px solid #33485e;padding:14px;border-radius:14px;display:flex;gap:10px;flex-wrap:wrap;align-items:center}button,input,select,textarea{background:#101e30;color:#f4f6fa;border:1px solid #5b728e;border-radius:8px;padding:9px;font:inherit}button{cursor:pointer;background:#204771}.task{background:#17283b;border:1px solid #314459;border-radius:15px;padding:18px;margin:12px 0;break-inside:avoid}.task header{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.task strong{overflow-wrap:anywhere}.task small{text-transform:uppercase;color:#bbcade}.pill{font-weight:700;font-size:.8rem;border-radius:8px;padding:5px 9px;border:1px solid currentColor}.hold{color:#ff9494}.pending{color:#ffe0a4}.review{color:#a2d5f4}.observation{color:#b9d4f1;font-family:monospace;overflow-wrap:anywhere}.edit{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:14px}.edit label{display:flex;flex-direction:column;gap:5px;color:#c8d9ea}.edit .wide{grid-column:1/-1}.edit textarea{min-height:48px}details{color:#b6c8dc;overflow-wrap:anywhere}#status{font-weight:700}.counts{display:flex;gap:18px;flex-wrap:wrap;padding:8px 0 18px} .counts strong{font-size:1.2em}.bulk{border:1px solid #3e536a;padding:18px;border-radius:14px;background:#14243a;margin:16px 0}.bulkRow{display:flex;gap:12px;flex-wrap:wrap;align-items:end;margin-top:12px}.bulkRow label{display:flex;flex-direction:column;gap:6px}.bulkRow input[type=checkbox]{margin-right:6px}.pick input{min-width:20px;min-height:20px}@media(max-width:690px){.edit{grid-template-columns:1fr}.controls{position:static}}@media print{.controls,.edit,.bulk,.pick,button{display:none!important}body{background:white;color:black}.task{background:white;color:black;border:1px solid #555}.banner{color:black;background:white}details{display:block}}"""
    css_hash = base64.b64encode(sha256(style.encode()).digest()).decode()
    script_hash = base64.b64encode(sha256(script.encode()).digest()).decode()
    csp = ("default-src 'none'; script-src 'sha256-" + script_hash +
           "'; style-src 'sha256-" + css_hash +
           "'; connect-src 'none'; img-src 'none'; form-action 'none'; base-uri 'none'")
    raw_json = json.dumps({"sha256": digest, "client_id": data["client_id"],
                           "as_of": data["as_of"], "tasks": [
                               {k: v for k, v in t.items() if k in
                                ("key", "family", "tier", "attention")}
                               for t in tasks]}, ensure_ascii=True, separators=(",", ":"))
    # A JSON script element is inert and HTML-safe; replace markup delimiters.
    raw_json = raw_json.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="' + esc(csp) + '">'
            '<title>LightUp · Human Scope Escalation</title><style>' + style + '</style></head>'
            '<body><main><p class="muted">LIGHTUP / OFFLINE REVIEW ROOM / DRAFT-HOLD</p>'
            '<h1>Scope Escalation Board</h1><div class="banner"><strong>HUMAN REVIEW ONLY.</strong> '
            'Stored requests, grants, timestamps and risk decisions are historical source observations. '
            'Nothing here authenticates a recipient, verifies separate client/operator consent or revocation '
            'at the moment of use, grants execution rights, approves risk or authorizes a scan.</div>'
            '<p>Private tenant: <strong>' + esc(data["client_id"]) + '</strong> · source observed: ' +
            esc(data["as_of"]) + ' · original SHA-256: <code>' + esc(digest) + '</code></p>'
            '<div class="counts"><span>Original engagements <strong>' +
            str(len(data["engagements"])) + '</strong></span><span>Human follow-ups <strong>' +
            str(len(tasks)) + '</strong></span><span>Source hold cases <strong>' +
            str(sum(t["tier"] == "HOLD" for t in tasks)) + '</strong></span></div>'
            '<div class="controls"><label>Filter <select id="filter"><option value="ALL">All</option>'
            '<option value="HOLD">HOLD</option><option value="PENDING">PENDING</option>'
            '<option value="REVIEW">REVIEW</option></select></label>'
            '<label>Find original ID <input id="search" type="search" autocomplete="off" maxlength="180"></label>'
            '<button id="private">Export PRIVATE human handoff</button>'
            '<button id="restore">Restore PRIVATE human handoff</button>'
            '<input type="file" id="restoreFile" accept=".json,application/json" hidden>'
            '<button id="anon">Export anonymous workload counts</button>'
            '<button id="selectVisible">Select visible</button><button id="clearSelected">Clear selection</button>'
            '<span id="status" role="status" aria-live="polite">Human-only changes stay in this tab.</span>'
            '</div><section class="bulk"><strong>Bulk HUMAN coordination (never authorization)</strong>'
            '<div class="bulkRow"><label>Reviewer <input id="bulkOwner" maxlength="80" autocomplete="off"></label>'
            '<label>Human stage <select id="bulkStage"><option value="">Leave stage unchanged</option>' +
            "".join('<option value="' + esc(st) + '">' + esc(st.replace("_", " ")) + '</option>'
                    for st in sorted(REVIEW_STATUSES)) + '</select></label>'
            '<label>Tentative UTC due <input type="date" id="bulkDue"></label>'
            '<label><input type="checkbox" id="skipExisting" checked> Preserve existing human edits</label>'
            '<button id="applyBulk">Apply selected HUMAN-only fields</button></div>'
            '<p id="workload" class="muted" role="status">No reviewer allocation yet.</p></section>'
            '<section id="tasks">' + "".join(groups) + '</section>'
            '<script type="application/json" id="source">' + raw_json + '</script>'
            '<script>' + script + '</script></main></body></html>').encode("utf-8")


def _recipient_page() -> bytes:
    """Private source-free portable recipient app, pinned self-contained JS/CSS."""
    script_file = Path(__file__).with_name("recipient.js")
    st = script_file.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_size > 48 * 1024
            or st.st_size < 1 or script_file.is_symlink()):
        raise Hold("recipient JS source unavailable")
    script = script_file.read_bytes().decode("utf-8", "strict")
    style = """*{box-sizing:border-box}body{margin:0;background:#0c1622;color:#e7f0fb;font:15px system-ui,sans-serif}main{max-width:940px;margin:auto;padding:24px}h1{font-size:2.1rem}.muted{color:#b7ccde}header{display:flex;gap:12px;flex-wrap:wrap;align-items:center;background:#1d3148;padding:17px;border-radius:12px}input,select,textarea,button{font:inherit;background:#132438;color:#f2f6ff;padding:9px;border:1px solid #68839b;border-radius:8px}input[type=file]{max-width:100%}button{cursor:pointer;background:#21567c}button:disabled{opacity:.45;cursor:not-allowed}textarea{resize:vertical;min-height:90px}.notice{background:#382332;border:1px solid #e48192;border-radius:12px;padding:14px;margin:20px 0;line-height:1.6}.row{border:1px solid #465f78;border-radius:12px;background:#182c42;margin:14px 0;padding:17px}.row h2{font-size:1.2rem;overflow-wrap:anywhere}.form{display:grid;grid-template-columns:1fr 1fr;gap:16px}.form label{display:flex;flex-direction:column;gap:8px}.form label:last-child{grid-column:1/-1}#status{padding:10px;background:#18334b;border-radius:9px}#status[data-hold=true]{background:#4e2635}@media(max-width:650px){.form{grid-template-columns:1fr}.form label:last-child{grid-column:auto}}@media print{header,button,input,select,textarea{display:none!important}body,.row{background:white;color:black}}"""
    css_hash = base64.b64encode(sha256(style.encode()).digest()).decode()
    js_hash = base64.b64encode(sha256(script.encode()).digest()).decode()
    csp = ("default-src 'none'; script-src 'sha256-" + js_hash +
           "'; style-src 'sha256-" + css_hash +
           "'; connect-src 'none'; img-src 'none'; form-action 'none'; base-uri 'none'")
    return ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="%s">
<title>LightUp PRIVATE Recipient Desk</title><style>%s</style></head>
<body><main><p class="muted">LIGHTUP / PRIVATE OFFLINE HUMAN RECEIVER / DRAFT-HOLD</p>
<h1>Recipient Follow-up Desk</h1>
<div class="notice"><strong>HUMAN REVIEW ONLY.</strong> The incoming packet's reviewer label,
source digest, original stored grant/window and any selected risk/status are NOT
authenticated client consent, operator authority, revocation, clearance or permission
to interact with a target. Check the recipient channel separately. Never upload data.</div>
<header><label>Open separately verified PRIVATE reviewer handoff
<input type="file" id="import" accept=".json,application/json"></label>
<button id="export" disabled>Export PRIVATE human reply</button></header>
<p id="identity" class="muted">No source-bound handoff imported.</p>
<p id="status" role="status" aria-live="polite">Only human review fields are editable; no network or persistence.</p>
<section id="cards"></section>
<script>%s</script></main></body></html>""" %
            (html.escape(csp, quote=True), style, script)).encode("utf-8")


def _publish(root, outputs):
    parent = root.parent
    if root.exists() or root.is_symlink() or not parent.is_dir() or parent.is_symlink():
        raise Hold("unsafe or existing output directory")
    pstat = parent.stat()
    if pstat.st_mode & 0o022:
        raise Hold("output parent is group/other writable")
    root.mkdir(mode=0o700)
    try:
        digests = {}
        for name, contents in outputs.items():
            dest = root / name
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(contents)
                stream.flush()
                os.fsync(stream.fileno())
            digests[name] = {"sha256": sha256(contents).hexdigest(),
                             "bytes": len(contents)}
        manifest = json.dumps({"schema": "lightup.scope_escalation_manifest.v1",
                               "status": "REVIEW_ONLY", "authority": False,
                               "files": digests}, sort_keys=True, indent=2).encode()
        fd = os.open(root / "manifest.json", os.O_WRONLY | os.O_CREAT |
                     os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(manifest)
            stream.flush()
            os.fsync(stream.fileno())
        dirfd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except BaseException:
        shutil.rmtree(root)
        raise


def compose_private_outputs(original: bytes, data: dict) -> dict[str, bytes]:
    """Deterministic private room artifacts from exact original snapshot bytes."""
    digest = sha256(original).hexdigest()
    queue = _queue(data)
    app = Path(__file__).with_name("board.js").read_bytes()
    if len(app) > 48 * 1024:
        raise Hold("board JS source too large")
    script = app.decode("utf-8", "strict")
    anonymous = {
        "schema": "lightup.scope_escalation_aggregate.v1",
        "status": "REVIEW_ONLY",
        "authority": False,
        "human_followups": len(queue),
        "tier_counts": {k: sum(t["tier"] == k for t in queue)
                        for k in ("HOLD", "PENDING", "REVIEW")},
        "family_counts": {k: sum(t["family"] == k for t in queue)
                          for k in ("engagement", "request")},
    }
    info = ("LIGHTUP · PRIVATE SCOPE ESCALATION BOARD · DRAFT/HOLD\n"
            "Open PRIVATE-board.html offline. Every file is owner-only.\n"
            "The board is a retrospective human work queue, not consent, at-use STOP,\n"
            "source signature, risk approval, grant, scan instruction or release.\n"
            "PRIVATE-queue.csv includes original record IDs: keep private.\n"
            "Select human tasks and use PRIVATE reviewer handoff for a separate recipient.\n"
            "Open PRIVATE-recipient-desk.html to edit and return selected human tasks.\n"
            "Browser notes are in memory only; separately export PRIVATE handoff.\n"
            "Reopen identical original source to restore; changed bytes HOLD.\n"
            "Absent/missing records are NEVER verified revoked, fixed or cleared.\n"
            "No source files or original domain records are modified.\n")
    outputs = {
        "PRIVATE-board.html": _page(data, queue, digest, script),
        "PRIVATE-recipient-desk.html": _recipient_page(),
        "PRIVATE-queue.csv": _csv(queue),
        "aggregate.json": json.dumps(anonymous, indent=2, sort_keys=True).encode(),
        "START-HERE.txt": info.encode(),
    }
    return outputs


def build_private_workspace(original: bytes, data: dict, root: Path) -> None:
    """Build complete owner-private room, no overwrite or source mutation."""
    _publish(root, compose_private_outputs(original, data))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True,
                        help="Previously authenticated ORIGINAL private Casebook v1 JSON")
    parser.add_argument("--workspace", required=True,
                        help="New private output directory (must not exist)")
    args = parser.parse_args(argv)
    try:
        original, data = _read_source(Path(args.source))
        build_private_workspace(original, data, Path(args.workspace))
        print("REVIEW_ONLY: private offline human board created; never an authority verdict")
        return 2
    except (Hold, ValueError, OSError, UnicodeError, TypeError, KeyError):
        print("HOLD: private original source or workspace not admitted", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
