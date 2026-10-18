"""One-transaction multi-scenario review of original grant-request compatibility.

Standalone companion to request_binding_readiness_cli; never grants authority.
"""
from __future__ import annotations
from contextlib import closing
from html import escape
from pathlib import Path
import csv
import hashlib
import io
import json
import re
import sqlite3
from .request_binding_readiness_cli import AUTHORITY, _assets, _read_only, _source_snapshot

MAX_INPUT = 65536
MAX_SCENARIOS = 8


def _pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate scenario JSON key")
        result[key] = value
    return result


def _fail_constant(value: str):
    raise ValueError("nonfinite JSON not allowed")


def read_scenarios(path: Path) -> list[tuple[str, tuple[str, ...], int]]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT:
        raise ValueError("scenario file unavailable or over limit")
    raw = path.read_bytes()
    if not raw or raw.startswith(b"\xef\xbb\xbf") or len(raw) > MAX_INPUT:
        raise ValueError("scenario file must be nonempty canonical UTF-8")
    doc = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                     parse_constant=_fail_constant)
    if (type(doc) is not dict or set(doc) != {"format", "scenarios"}
            or doc["format"] != "lightup.request_binding_scenarios.v1"
            or type(doc["scenarios"]) is not list
            or not 2 <= len(doc["scenarios"]) <= MAX_SCENARIOS):
        raise ValueError("expected 2–8 exact original risk/scope alternatives")
    scenarios = []
    labels = set()
    definitions = set()
    for entry in doc["scenarios"]:
        if type(entry) is not dict or set(entry) != {"label", "risk", "assets"}:
            raise ValueError("scenario entry schema mismatch")
        label, risk, raw_assets = entry["label"], entry["risk"], entry["assets"]
        if (type(label) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _./()-]{0,63}", label)
                or label in labels or type(risk) is not int or risk not in (1, 2, 3, 4)
                or type(raw_assets) is not list):
            raise ValueError("scenario label, risk or asset shape invalid")
        assets = _assets(raw_assets)
        marker = (assets, risk)
        if marker in definitions:
            raise ValueError("duplicate original scenario")
        labels.add(label)
        definitions.add(marker)
        scenarios.append((label, assets, risk))
    return scenarios


def compare_scenarios(db: Path, *, engagement_id: str, client_id: str | None,
                      operator_user_id: str, include_request_ids: bool,
                      include_labels: bool,
                      scenarios: list[tuple[str, tuple[str, ...], int]]) -> dict:
    """One *read-only SQLite transaction*, not independent mutable snapshots."""
    if not 2 <= len(scenarios) <= MAX_SCENARIOS:
        raise ValueError("bounded scenario list required")
    records = []
    with closing(_read_only(db)) as con:
        for label, assets, risk in scenarios:
            source = _source_snapshot(
                db, engagement_id=engagement_id, client_id=client_id,
                assets=assets, risk=risk,
                include_request_ids=include_request_ids,
                include_labels=include_labels,
                operator_user_id=operator_user_id, connection=con,
            )
            records.append({"label": label, "original_source": source})
    source_fingerprints = {
        entry["original_source"]["source"]["source_revision_sha256_unsigned"]
        for entry in records
    }
    if len(source_fingerprints) != 1:
        raise ValueError("original source rows changed during scenario review")
    record_sets = [
        {item["private_reference"] for item in rec["original_source"]["candidates"]
         if item["request_source_status"] == "candidate_review_only"}
        for rec in records
    ]
    # Source IDs are retained only in private human reports; the aggregate
    # transition counts use original stable tokens, not inferred client consent.
    transitions = []
    for i in range(len(record_sets) - 1):
        first, second = record_sets[i], record_sets[i + 1]
        transitions.append({
            "from_scenario": records[i]["label"],
            "to_scenario": records[i + 1]["label"],
            "still_potential": len(first & second),
            "no_longer_matched_not_revoked": len(first - second),
            "newly_matched_not_authorized": len(second - first),
        })
    return {
        "format": "lightup.request_binding_scenarios_review.v1",
        "disposition": "REVIEW_ONLY_SCENARIOS",
        "authority": dict(AUTHORITY),
        "source_context": "same local query-only SQLite transaction; no live consent or grant",
        "source_revision_sha256_unsigned": next(iter(source_fingerprints)),
        "ordering": "human selected alternatives; NOT chronological grant history",
        "overlap_limits": "same stored requests can match multiple choices; not independent evidence",
        "scenarios": records,
        "adjacent_alternative_changes": transitions,
    }


def format_json(report: dict) -> str:
    return json.dumps(report, ensure_ascii=True, indent=2) + "\n"


def format_csv(report: dict) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(("scenario_slot", "proposed_risk", "asset_count",
                     "recorded_requests", "matching_admin_requests",
                     "nonmatching_approved", "not_approved", "stored_grant_rows",
                     "disposition", "review_only", "client_consent_verified",
                     "operator_consent_verified", "grant_issued", "execution_allowed"))
    for i, record in enumerate(report["scenarios"], 1):
        source = record["original_source"]
        summary, settings = source["summary"], source["source"]
        writer.writerow((
            i, settings["requested_risk"], settings["proposed_asset_count"],
            summary["recorded_requests"], summary["approved_candidate_matches"],
            summary["approved_but_not_compatible"],
            summary["not_administratively_approved"],
            summary["prior_stored_grant_rows"],
            source["disposition"], "REVIEW_ONLY", "false", "false", "false", "false",
        ))
    return output.getvalue()


def format_html(report: dict) -> str:
    import base64
    css = (":root{font:15px/1.55 system-ui;color:#edf4ff;background:#0d1525}"
           "body{max-width:1280px;margin:0 auto;padding:28px}"
           "header{border-bottom:1px solid #52719b;padding-bottom:15px}"
           "h1{font-size:2.3rem;letter-spacing:-.03em}"
           "section{background:#162640;border:1px solid #466082;border-radius:12px;"
           "padding:20px;margin:20px 0;break-inside:avoid}"
           "table{border-collapse:collapse;width:100%;margin:14px 0}"
           "td,th{padding:10px;border-bottom:1px solid #3f5877;text-align:left;"
           "overflow-wrap:anywhere}th{color:#bcdcff}"
           "p{color:#c9d8e9}.status{color:#ffc48f;font-weight:bold}"
           "@media(max-width:800px){body{padding:12px}table{display:block;overflow:auto}}"
           "@media print{body,section{color:black;background:white}p,.status{color:black}}")
    sha = base64.b64encode(hashlib.sha256(css.encode("utf-8")).digest()).decode("ascii")
    blocks = []
    for slot, record in enumerate(report["scenarios"], 1):
        r = record["original_source"]
        summary, settings = r["summary"], r["source"]
        rows = []
        for item in r["candidates"]:
            rows.append("<tr>" + "".join(
                "<td>" + escape(str(v), quote=True) + "</td>"
                for v in (
                    item["ordinal"], item["private_reference"],
                    item["request_id"] or "redacted",
                    item["stored_status"], item["requested_risk"],
                    item["request_source_status"],
                    ", ".join(item["review_flags_non_authorizing"]) or "NO_RECORDED_MISMATCH",
                    item["previously_bound_grant_rows"],
                )
            ) + "</tr>")
        blocks.append(
            "<section><h2>Scenario " + str(slot) + " · " + escape(record["label"]) +
            "</h2><p>Proposed risk " + str(settings["requested_risk"]) +
            " · " + str(settings["proposed_asset_count"]) +
            " exact assets · original requests " + str(summary["recorded_requests"]) +
            " · matching administrative candidates <strong>" +
            str(summary["approved_candidate_matches"]) + "</strong></p>"
            '<p class="status">' + escape(r["disposition"]) +
            '</p><div style="overflow-x:auto"><table><thead><tr><th>#</th>'
            '<th>Private request token</th><th>Original request ID (opt-in)</th>'
            '<th>Stored status</th><th>Requested risk</th><th>Matching</th>'
            '<th>Human mismatch reasons</th><th>Prior stored grant rows ≠ permission</th></tr></thead><tbody>' +
            "".join(rows) + "</tbody></table></div></section>"
        )
    transitions = "".join(
        "<li>" + escape(item["from_scenario"]) + " → " + escape(item["to_scenario"]) +
        ": shared " + str(item["still_potential"]) +
        ", no longer matched " + str(item["no_longer_matched_not_revoked"]) +
        ", newly matched " + str(item["newly_matched_not_authorized"]) +
        " (none implies approval, revocation, permission)</li>"
        for item in report["adjacent_alternative_changes"]
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; '
        'base-uri &#39;none&#39;; form-action &#39;none&#39;; '
        'style-src &#39;sha256-' + sha + '&#39;; script-src &#39;none&#39;; '
        'connect-src &#39;none&#39;; object-src &#39;none&#39;">'
        "<title>LightUp · Multiple original grant-binding alternatives</title>"
        "<style>" + css + "</style></head><body><header>"
        "<p>LIGHTUP / PRIVATE AUTHENTICATED OPERATOR / DRAFT-HOLD</p>"
        "<h1>Original approved-request selection alternatives</h1>"
        "<p>One original query-only SQLite snapshot. Scenarios are human chosen, "
        "not timestamps or real authorizations. All grant/consent/scan/release flags FALSE.</p>"
        "</header>" + "".join(blocks) +
        "<section><h2>Adjacent human-proposed alternatives</h2><ol>" + transitions +
        "</ol><p>Changes represent matching record sets, not chronology or actual "
        "grant narrowing, authorizations, release decisions, STOP or fixes.</p></section>"
        "<footer>DRAFT/HOLD · INCUBATE M3/M7 · PLAN/LAB ONLY. "
        "Source owner CI, security/privacy, two-party authenticated consent, "
        "revocation-at-use and explicit human GO remain mandatory.</footer></body></html>"
    )
