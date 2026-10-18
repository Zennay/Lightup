"""Offline proposal to carry human-only LightUp follow-up across Casebook refresh.

No grant, STOP, target, scanner, authorization or original source mutation.
Requires separate human verification of both private snapshots and sender.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from html import escape
from pathlib import Path
import re
import sys

from board_html import handoff_digest
from window_review import (
    ReviewHold, derive, identity, private_publish, source_file, when,
    ensure_private_destination,
)

STAGES = {"unreviewed", "investigating", "escalated", "documented"}
AUTH = ("authorization_granted", "execution_allowed", "release_approved")
TOP = {"schema", "status", "source_digest", "note", *AUTH, "entries"}
ENTRY = {"grant_id", "engagement_id", "human_stage", "human_owner", "human_next_action"}
MAX_NOTE = 131072
MAX_CASES = 200


def _record_map(rows: list, key: str) -> dict:
    return {record[key]: record for record in rows}


def _source_family(casebook: dict, engagement_id: str) -> dict:
    """Exact original family equality, not simply matching opaque grant IDs."""
    reqs = _record_map(casebook["requests"], "request_id")
    engagement = _record_map(casebook["engagements"], "engagement_id").get(engagement_id)
    overview = _record_map(casebook["case_overview"], "engagement_id").get(engagement_id)
    grants = [item for item in casebook["grants"] if item["engagement_id"] == engagement_id]
    risks = [item for item in casebook["risk_approvals"] if item["engagement_id"] == engagement_id]
    bound = sorted({item.get("approved_request_id") for item in grants if item.get("approved_request_id")})
    return {
        "engagement": engagement,
        "case_overview": overview,
        "linked_grants": sorted(grants, key=lambda r: r["grant_id"]),
        "linked_risks": sorted(risks, key=lambda r: r["approval_id"]),
        "linked_requests": [reqs.get(rid) for rid in bound],
    }


def _read_note(path: Path) -> dict:
    # Original browser-note limit and canonical object, no unsafe symlink.
    from window_review import no_duplicate_keys, reject_constant
    import os
    import stat
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > MAX_NOTE:
            raise ReviewHold("previous human note is not a bounded regular file")
        with os.fdopen(fd, "rb", closefd=False) as source:
            raw = source.read(MAX_NOTE + 1)
        if len(raw) > MAX_NOTE:
            raise ReviewHold("previous human note exceeded limit")
    finally:
        os.close(fd)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicate_keys,
                         parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReviewHold("malformed human follow-up note") from exc
    if (type(doc) is not dict or set(doc) != TOP
            or doc.get("schema") != "lightup.scope_window_human_handoff.v2"
            or doc.get("status") != "REVIEW_ONLY"
            or any(doc.get(flag) is not False for flag in AUTH)
            or type(doc.get("source_digest")) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", doc["source_digest"])
            or type(doc.get("note")) is not str or len(doc["note"]) > 500
            or type(doc.get("entries")) is not list
            or len(doc["entries"]) > MAX_CASES):
        raise ReviewHold("previous human note is not a non-authorizing v2 handoff")
    seen = set()
    for entry in doc["entries"]:
        if type(entry) is not dict or set(entry) != ENTRY:
            raise ReviewHold("unexpected original human handoff fields")
        key = (identity(entry.get("grant_id")), entry.get("engagement_id"))
        if key[1] is not None:
            identity(key[1])
        if key in seen:
            raise ReviewHold("duplicate human handoff grant")
        seen.add(key)
        if (entry.get("human_stage") not in STAGES
                or any(type(entry.get(field)) is not str
                       or len(entry[field]) > length
                       or any(ord(ch) < 32 or ord(ch) == 127
                              or ch in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
                              for ch in entry[field])
                       for field, length in (("human_owner", 60),
                                             ("human_next_action", 280)))):
            raise ReviewHold("unsafe original human-stage or note text")
    return doc


def rebase(old: dict, fresh: dict, note: dict, *, previous_now: datetime,
           current_now: datetime, lead_days: int, future_days: int,
           daily_capacity: int) -> tuple[dict, dict, list[dict]]:
    if old["client_id"] != fresh["client_id"]:
        raise ReviewHold("original tenant changed: no human carry-forward")
    if old["_private_original_sha256"] == fresh["_private_original_sha256"]:
        raise ReviewHold("original snapshots identical: use normal handoff import")
    prior = derive(old, now=previous_now, lead_days=lead_days,
                   future_days=future_days, daily_capacity=daily_capacity)
    current = derive(fresh, now=current_now, lead_days=lead_days,
                     future_days=future_days, daily_capacity=daily_capacity)
    if handoff_digest(prior) != note["source_digest"]:
        raise ReviewHold("previous source/policy and private handoff do not match")
    old_items = {(x["grant_id"], x["engagement_id"]) for x in prior["items"]}
    fresh_items = {(x["grant_id"], x["engagement_id"]) for x in current["items"]}
    old_grants = _record_map(old["grants"], "grant_id")
    new_grants = _record_map(fresh["grants"], "grant_id")
    saved = []
    withheld: list[dict] = []
    stats = {"preserved": 0, "changed": 0, "absent": 0,
             "outside_current_planning": 0}
    for item in note["entries"]:
        key = (item["grant_id"], item["engagement_id"])
        if key not in old_items:
            raise ReviewHold("previous human note contains unknown original grant")
        prior_grant = old_grants.get(key[0])
        now_grant = new_grants.get(key[0])
        if now_grant is None:
            reason = "SOURCE_GRANT_ABSENT_NOT_REVOKED"
            stats["absent"] += 1
        elif key not in fresh_items:
            reason = "OUTSIDE_CURRENT_HUMAN_PLANNING"
            stats["outside_current_planning"] += 1
        elif (prior_grant != now_grant
              or _source_family(old, key[1]) != _source_family(fresh, key[1])):
            reason = "ORIGINAL_LINKED_SOURCE_CHANGED"
            stats["changed"] += 1
        else:
            reason = None
            saved.append(item)
            stats["preserved"] += 1
        if reason:
            withheld.append({"grant_id": key[0], "engagement_id": key[1],
                             "reason": reason,
                             "next_human_action": "REOPEN_ORIGINAL_PERSISTED_CASEBOOK"})
    result = {
        "schema": "lightup.scope_window_human_handoff.v2",
        "status": "REVIEW_ONLY",
        "source_digest": handoff_digest(current),
        "note": ("Unsigned candidate human follow-up from changed original source; "
                 "separately verify tenant, issuer and each case. "
                 "Unchanged source family only; no authorization."),
        **dict.fromkeys(AUTH, False),
        "entries": saved,
    }
    return result, stats, withheld


def private_diff_html(*, old: dict, fresh: dict,
                      stats: dict, withheld: list[dict]) -> bytes:
    """No scripts, targets or raw findings. One private human source review."""
    rows = []
    for item in withheld:
        grant_id = escape(item["grant_id"], quote=True)
        engagement = escape(item["engagement_id"] or "(source missing)", quote=True)
        reason = escape(item["reason"], quote=True)
        rows.append("<tr><td>" + grant_id + "</td><td>" + engagement +
                    "</td><td>" + reason + "</td><td>Reopen original "
                    "persisted source with separately authenticated operator; "
                    "no source revocation is proven.</td></tr>")
    metric = " · ".join(f"{escape(key)}: {number}" for key, number in stats.items())
    html = """<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy"
content="default-src 'none'; script-src 'none'; img-src 'none'; connect-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; object-src 'none'">
<title>PRIVATE LightUp original source refresh — HUMAN HOLD</title>
<style>body{font-family:system-ui;max-width:980px;margin:24px auto;padding:0 18px;background:#0f1722;color:#eef4fa}
h1{font-size:1.8rem}p{line-height:1.6}.notice{border-left:5px solid #e9b15a;padding:14px;background:#25313e}
table{border-collapse:collapse;width:100%;overflow-wrap:anywhere}td,th{border-bottom:1px solid #61717f;padding:12px;text-align:left}
@media(max-width:620px){body{margin:10px}td,th{font-size:.8rem;padding:6px}}</style></head><body>
<header><p>LIGHTUP / PRIVATE HUMAN DIFFERENCE DESK</p>
<h1>Original-source change review</h1>
<p class="notice">HOLD — unsigned historical source only. This is NOT current client consent, grant validation,
verified revocation, execution permission, security verdict, or completed STOP. Verify actual
source ownership, client and operator separately before further action.</p></header>
<p>Original source: """ + escape(old["as_of"]) + """ — new source: """ + escape(fresh["as_of"]) + """</p>
<p>Human follow-up counts: """ + metric + """</p>
<h2>Not carried forward: separate human review required</h2>
<table><thead><tr><th>Original grant ID</th><th>Original engagement ID</th><th>Reason</th>
<th>Human-only next action</th></tr></thead><tbody>""" + "".join(rows) + """</tbody></table>
<p>Only unchanged related original source rows appear in the separately exported
unsigned candidate handoff. A disappeared grant is NOT proof of valid revocation,
a missing review is NOT an approval, and no dates or permissions have been modified.</p>
</body></html>"""
    return html.encode("utf-8")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-casebook", type=Path, required=True)
    parser.add_argument("--new-casebook", type=Path, required=True)
    parser.add_argument("--previous-note", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--old-review-at", help="old prepared_at ISO timestamp, default old as_of")
    parser.add_argument("--lead-days", type=int, default=7)
    parser.add_argument("--future-days", type=int, default=45)
    parser.add_argument("--daily-capacity", type=int, default=8)
    parser.add_argument("--acknowledge-same-tenant", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not args.acknowledge_same_tenant:
            raise ReviewHold("operator must independently verify both original tenant sources")
        if not 0 <= args.lead_days <= 30 or not 1 <= args.future_days <= 366 or not 1 <= args.daily_capacity <= 64:
            raise ReviewHold("invalid earlier/current review policy")
        old = source_file(args.old_casebook)
        fresh = source_file(args.new_casebook)
        note = _read_note(args.previous_note)
        earlier = when(args.old_review_at) if args.old_review_at else when(old["as_of"])
        current = datetime.now(timezone.utc)
        if earlier > current:
            raise ReviewHold("previous review date is in the future")
        proposal, stats = rebase(old, fresh, note, previous_now=earlier,
                                 current_now=current, lead_days=args.lead_days,
                                 future_days=args.future_days,
                                 daily_capacity=args.daily_capacity)
        private_publish(args.output, (json.dumps(proposal, ensure_ascii=False,
                                                 indent=2, allow_nan=False) + "\n").encode("utf-8"))
        print("HOLD: private human source-refresh proposal, "
              + ", ".join(f"{k}={v}" for k, v in stats.items())
              + "; separately review proposed entries inside the new offline board. "
                "No original-source or consent writes.")
        return 3
    except (ReviewHold, OSError, ValueError, OverflowError, KeyError) as exc:
        print(f"HOLD: human follow-up rebase refused ({type(exc).__name__}); "
              "no authorization or original-source change.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
