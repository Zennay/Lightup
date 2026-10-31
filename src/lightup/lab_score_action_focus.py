"""Offline source-local HOLD reviewer projection; no authority or grants."""
from __future__ import annotations

import json
from .lab_score_action_admission import admit_human_actions
from .lab_score_portable_html_safety import admit_inert_html

_ACTIONS = {
    "evidence_reused": "Recapture independent first-party synthetic originals",
    "score_drift": "Review isolated synthetic scorer drift",
}
_GATE = ("Qualified independent source/security/privacy review and separately "
         "authenticated permissions remain required.")


def render_action_focus(data: dict, transport: str, previous: str,
                        current: str, fmt: str) -> str:
    """Display one original source-local HOLD pair, with global HOLD intact."""
    rows = admit_human_actions(data)
    if (type(transport) is not str or transport not in ("baseline", "candidate")
            or type(previous) is not str or type(current) is not str
            or not previous.isascii() or not current.isascii()
            or not previous.isdecimal() or not current.isdecimal()
            or len(previous) != 1 or len(current) != 1):
        raise ValueError("invalid source-local HOLD selector")
    p, c = int(previous), int(current)
    if not (1 <= p < c <= 8 and previous == str(p) and current == str(c)):
        raise ValueError("invalid anonymous original pair")
    selected = [row for row in rows[:-1] if row["transport"] == transport
                and (row["anonymous_previous"], row["anonymous_current"]) == (p, c)]
    if not selected or data["review_status"] != "HOLD":
        raise ValueError("no admitted original HOLD pair")
    reasons = [row["reason"] for row in selected]
    if len(set(reasons)) != len(reasons) or any(reason not in _ACTIONS for reason in reasons):
        raise ValueError("invalid original HOLD reasons")
    result = {
        "schema": "lightup.lab-score-human-action-focus.v1",
        "global_review_status": "HOLD", "source": transport,
        "anonymous_previous": p, "anonymous_current": c,
        "original_unsigned_transport_sha256": data["unsigned_transport_sha256"][transport],
        "selected_hold_reasons": reasons,
        "selected_human_actions": [_ACTIONS[reason] for reason in reasons],
        "other_original_pairs_hidden": True,
        "source_identity_authenticated": False, "authorization_granted": False,
        "remediation_verified": False, "deployment": False,
        "mandatory_human_review": True,
    }
    if fmt == "actions-focus-json":
        return json.dumps(result, sort_keys=True, allow_nan=False) + "\n"
    if fmt == "actions-focus-text":
        return ("LightUp offline source-local HUMAN HOLD review\n"
                "GLOBAL STATUS HOLD — NOT VERIFIED / NOT AUTHORIZED\n"
                f"Original {transport} ZIP, anonymous pair {p}-{c}\n"
                + "".join(f"HUMAN action: {_ACTIONS[r]} — NOT_VERIFIED\n" for r in reasons)
                + "Other pairs intentionally hidden; their HOLD status is unchanged.\n"
                + _GATE + "\nNo scans, grants, research or release.\n")
    if fmt != "actions-focus-html":
        raise ValueError("invalid HUMAN focus format")
    tasks = "".join(f"<li>{_ACTIONS[r]} — <strong>NOT_VERIFIED</strong></li>"
                    for r in reasons)
    html = ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            "<meta http-equiv='Content-Security-Policy' "
            "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            "<title>LightUp HUMAN HOLD focus</title>"
            "<style>body{font:1rem/1.5 system-ui;max-width:58rem;margin:2rem auto;"
            "padding:0 1rem}li{margin:.7rem 0}"
            "@media print{body{margin:0}}</style></head><body><main>"
            "<h1>Original synthetic HUMAN HOLD focus</h1>"
            "<p><strong>GLOBAL STATUS HOLD — NOT VERIFIED / NOT AUTHORIZED.</strong></p>"
            f"<p>Original {transport} ZIP, anonymous pair {p}-{c}. Pair ordinals "
            "cannot be matched between different ZIPs.</p>"
            f"<h2>Human follow-up</h2><ul>{tasks}</ul>"
            "<p>All other original pairs intentionally hidden. Their HOLD status "
            "is not cleared by this view.</p>"
            f"<p>{_GATE} No scans, grants, research or release.</p>"
            "</main></body></html>")
    if len(html.encode()) > 65536:
        raise ValueError("oversized HUMAN focus")
    admit_inert_html(html.encode())
    return html
