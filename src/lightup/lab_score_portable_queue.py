"""Bounded source-free original-pair work queue for offline HUMAN triage.

Anonymous source-free ZIP data is not original evidence authentication,
consent, ownership or authority to contact any target.
"""
from __future__ import annotations

from typing import Any
from .lab_score_portable_focus import build_portable_pair


def build_portable_queue(summary: dict[str, Any]) -> dict[str, Any]:
    """Prioritize every already-admitted original pair, no network or writes."""
    pairs = [build_portable_pair(summary, p["previous_index"], p["current_index"])
             for p in summary["pairs"]]
    # Evidence reuse is the first operator concern; score drift is second.
    # Never put PASS ahead of any HOLD, including two-reason HOLDs.
    pairs.sort(key=lambda p: (
        p["review_status"] != "HOLD",
        "evidence_reused" not in p["hold_reasons"],
        "score_drift" not in p["hold_reasons"],
        p["previous_index"], p["current_index"],
    ))
    hold_count = sum(p["review_status"] == "HOLD" for p in pairs)
    return {
        "schema": "lightup.lab-score-human-pair-queue.v1",
        "pairs_checked": len(pairs),
        "hold_pairs": hold_count,
        "pass_pairs": len(pairs) - hold_count,
        # Already checked against the canonical original pair matrix.
        "archive_priorities": [dict(item) for item in summary["archive_review_queue"]],
        "human_review_only": True,
        "source_identity_authenticated": False,
        "pairs": pairs,
    }


def render_portable_queue(queue: dict[str, Any], *,
                          global_status: str, legacy: bool) -> str:
    prefix = "UNTRUSTED CLAIM: " if legacy else "Synthetic-only: "
    state = "HOLD" if legacy else global_status
    lines = [
        f"{prefix}Original pair HUMAN review queue: {queue['pairs_checked']} pairs; "
        f"{queue['hold_pairs']} HOLD, {queue['pass_pairs']} PASS.",
        f"GLOBAL STATUS {state}; local pair PASS never clears global HOLD.",
        "Original evidence not authenticated. HUMAN review only; no external "
        "targets, scans, consent, grants or deployment.",
    ]
    if legacy:
        lines.append("Legacy queue is UNSIGNED and UNTRUSTED; never a clearance or HTML approval.")
    for archive in queue["archive_priorities"]:
        lines.append(f"{prefix}Review archive {archive['index']}: "
                     f"{archive['hold_pairs']} HOLD pairs "
                     f"({archive['reused_evidence_pairs']} replay, "
                     f"{archive['score_drift_pairs']} score drift).")
    for index, pair in enumerate(queue["pairs"], 1):
        reasons = ", ".join(pair["hold_reasons"]) or "none"
        lines.append(f"{prefix}{index}. pair {pair['previous_index']}-{pair['current_index']}: "
                     f"{pair['review_status']}; reasons: {reasons}.")
    return "\n".join(lines)


def render_portable_queue_html(queue: dict[str, Any], *, global_status: str) -> str:
    """Offline inert HTML from an already admitted canonical v3 ZIP only."""
    if global_status not in ("PASS", "HOLD"):
        raise ValueError("invalid global status")
    from .lab_score_portable_html_safety import admit_inert_html
    archives = "".join(
        f"<tr><th scope='row'>Archive {a['index']}</th>"
        f"<td>{a['hold_pairs']}</td><td>{a['reused_evidence_pairs']}</td>"
        f"<td>{a['score_drift_pairs']}</td></tr>"
        for a in queue["archive_priorities"])
    pairs = "".join(
        f"<tr><th scope='row'>Pair {p['previous_index']}-{p['current_index']}</th>"
        f"<td>{p['review_status']}</td><td>{', '.join(p['hold_reasons']) or 'none'}</td></tr>"
        for p in queue["pairs"])
    html = ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            "<meta http-equiv='Content-Security-Policy' "
            "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            "<title>LightUp offline review queue</title>"
            "<style>body{font:1rem/1.5 system-ui;max-width:60rem;margin:2rem auto;"
            "padding:0 1rem}table{width:100%;border-collapse:collapse;margin:1rem 0}"
            "td,th{border:1px solid;padding:.6rem;text-align:left}</style>"
            "</head><body><main id='content'><h1>Synthetic HUMAN review queue</h1>"
            f"<p><strong>GLOBAL STATUS {global_status}</strong>. "
            "One local PASS never clears a global HOLD.</p>"
            f"<p>{queue['pairs_checked']} original pairs, {queue['hold_pairs']} HOLD. "
            "Original source is NOT authenticated. HUMAN review only; "
            "no consent, target contact, grants, scans or deployment.</p>"
            "<section><h2>Archives needing review</h2><table>"
            "<caption>Original archive priorities</caption><thead><tr>"
            "<th scope='col'>Archive</th><th scope='col'>HOLD pairs</th>"
            "<th scope='col'>Replay</th><th scope='col'>Drift</th>"
            f"</tr></thead><tbody>{archives}</tbody></table></section>"
            "<section><h2>Every original pair</h2><table>"
            "<caption>HOLD-first comparison queue</caption><thead><tr>"
            "<th scope='col'>Pair</th><th scope='col'>Status</th>"
            f"<th scope='col'>Reasons</th></tr></thead><tbody>{pairs}</tbody>"
            "</table></section></main></body></html>")
    admit_inert_html(html.encode("utf-8"))
    return html
