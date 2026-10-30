"""Semantic, source-free, scriptless pair history for portable HUMAN review v3.

Render ONLY from the bounded verified anonymous JSON summary. Private original
metric magnitudes and evidence receipts stay in the owner-only original review.
For legacy packages no such binding exists: the receiver must report HOLD.
"""
from __future__ import annotations

from html import escape
from typing import Any


def render_portable_history(summary: dict[str, Any]) -> str:
    """Canonical offline history with deep links for all 2-8 original archives."""
    count = summary["archives_checked"]
    pairs = summary["pairs"]
    if not 2 <= count <= 8 or len(pairs) != count * (count - 1) // 2:
        raise ValueError("invalid anonymous portable history")
    holds = [pair for pair in pairs if not pair["passed"]]
    if summary["passed"] != (len(holds) == 0):
        raise ValueError("contradictory global portable history")
    status = "PASS" if summary["passed"] else "HOLD"

    def pair_name(p: dict[str, Any]) -> str:
        return f"{p['previous_index']} and {p['current_index']}"

    def pair_status(p: dict[str, Any]) -> str:
        return "PASS" if p["passed"] else "HOLD"

    pair_sections = []
    for p in pairs:
        i, j = p["previous_index"], p["current_index"]
        reason = []
        if not p["independent_evaluations"]:
            reason.append("original evidence was reused")
        if not p["score_stable"]:
            reason.append("first-party scores changed")
        if not reason:
            reason.append("no evidence reuse or score drift reported")
        pair_sections.append(
            f"<section id='pair-{i}-{j}' aria-label='Original pair {i} and {j}'>"
            f"<h3>Archive {i} versus {j}: {pair_status(p)}</h3>"
            f"<p>Evidence independent: {'yes' if p['independent_evaluations'] else 'no'}; "
            f"score stable: {'yes' if p['score_stable'] else 'no'}.</p>"
            f"<p>Reason: {escape('; '.join(reason))}.</p>"
            f"<p><a href='#archive-{i}'>Archive {i}</a> · "
            f"<a href='#archive-{j}'>Archive {j}</a></p></section>"
        )
    archive_sections = []
    for index in range(1, count + 1):
        related = [p for p in pairs if index in (p["previous_index"], p["current_index"])]
        if len(related) != count - 1:
            raise ValueError("incomplete original archive list")
        links = "".join(
            f"<li><a href='#pair-{p['previous_index']}-{p['current_index']}'>"
            f"Compare archives {pair_name(p)}: {pair_status(p)}</a></li>"
            for p in related
        )
        local_holds = sum(not p["passed"] for p in related)
        archive_sections.append(
            f"<section id='archive-{index}' aria-label='Archive {index}'>"
            f"<h3>Archive {index}</h3>"
            f"<p>{len(related)} comparisons, {local_holds} HOLD. "
            "This archive label does not authenticate a source.</p>"
            f"<ul>{links}</ul></section>"
        )
    hotspots = "".join(
        f"<li><strong>{escape(item['capability'])}</strong>: "
        f"{item['affected_pairs']} changed pairs; "
        f"{escape(', '.join(item['metrics']))}</li>"
        for item in summary["capability_hotspots"]
    )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' "
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>LightUp | Canonical history {status}</title>"
        "<style>"
        ":root{font:16px/1.5 system-ui,sans-serif;color:#16283e;background:#f4f7fb}"
        "body{max-width:70rem;margin:auto;padding:1rem}"
        "a{color:#194a83}a:focus-visible{outline:3px solid #dd8a12}"
        "header,section{background:#fff;padding:1rem;margin:1rem 0;border-radius:10px}"
        "section{border:1px solid #d3deea}h2,h3{margin:.4rem 0}"
        "li{margin:.4rem 0}.warning{border-left:4px solid #b85812;padding:.8rem}"
        "</style></head><body>"
        "<header><nav aria-label='Review navigation'>"
        "<a href='index.html'>Overview</a> · "
        "<a href='review.csv'>CSV</a> · <a href='review.md'>HUMAN brief</a></nav>"
        f"<h1>Canonical synthetic original history: {status}</h1>"
        f"<p>{count} anonymous originals; {len(pairs)} original comparisons; "
        f"{len(holds)} HOLD pairs.</p>"
        "<p class='warning'>HUMAN only. Neither the original source nor "
        "consent, release or any external assessment is authenticated or granted. "
        "Only anonymous pair flags are admitted in this portable history; "
        "original private metric values remain outside this ZIP.</p></header>"
        "<main><section aria-labelledby='archive-title'>"
        "<h2 id='archive-title'>Browse original archives</h2>"
        "<p>Every original pair stays visible even if a selected archive passes.</p>"
        + "".join(archive_sections) + "</section>"
        "<section aria-labelledby='pairs-title'><h2 id='pairs-title'>"
        "Original pairwise status and HOLD reasons</h2>"
        + "".join(pair_sections) + "</section>"
        "<section aria-labelledby='scorers-title'><h2 id='scorers-title'>"
        "First-party scorer hotspots</h2>"
        + ("<ul>" + hotspots + "</ul>" if hotspots else
           "<p>No first-party score drift hotspots.</p>")
        + "</section></main><footer>Source-free synthetic localhost review; "
        "original evidence not authenticated; no authority or deployment."
        "</footer></body></html>\n"
    )
