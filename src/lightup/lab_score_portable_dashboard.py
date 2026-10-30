"""Readable, source-free, self-contained entrypoint for offline HUMAN review ZIPs.

Only use the verified summary created by the first-party calibration renderer.
Never embed original private receipts, paths, hashes or source identities.
"""
from __future__ import annotations

from html import escape
from typing import Any


def render_portable_dashboard(summary: dict[str, Any]) -> str:
    """Static accessible operator dashboard with anonymous PASS/HOLD prioritization."""
    n = summary["archives_checked"]
    pairs = summary["pairs"]
    if not 2 <= n <= 8 or len(pairs) != n * (n - 1) // 2:
        raise ValueError("invalid source-free history")
    holds = [p for p in pairs if not p["passed"]]
    if summary["passed"] is not (not holds):
        raise ValueError("inconsistent original global review status")
    state = "PASS" if summary["passed"] else "HOLD"

    def pair_link(p: dict[str, Any]) -> str:
        i, j = p["previous_index"], p["current_index"]
        status = "PASS" if p["passed"] else "HOLD"
        details = (f"<a href='history.html#pair-{i}-{j}'>Open HOLD details"
                   f"<span class='sr-only'> for archives {i} and {j}</span></a>"
                   if not p["passed"] else "No follow-up")
        reuse = "Yes" if not p["independent_evaluations"] else "No"
        drift = "Yes" if not p["score_stable"] else "No"
        return (f"<tr><th scope='row'>{i} versus {j}</th>"
                f"<td><strong class='state {status.lower()}'>{status}</strong></td>"
                f"<td>{reuse}</td><td>{drift}</td><td>{details}</td></tr>")

    pair_rows = "".join(pair_link(p) for p in [*holds, *(p for p in pairs if p["passed"])])
    archive_rows = "".join(
        "<tr><th scope='row'>Archive " + str(item["index"]) + "</th>"
        + "<td>" + str(item["hold_pairs"]) + "</td>"
        + "<td>" + str(item["reused_evidence_pairs"]) + "</td>"
        + "<td>" + str(item["score_drift_pairs"]) + "</td>"
        + "<td><a href='history.html#archive-" + str(item["index"])
        + "'>Browse archive</a></td></tr>"
        for item in summary["archive_review_queue"]
    )
    hotspots = "".join(
        "<tr><th scope='row'>" + escape(item["capability"]) + "</th>"
        + "<td>" + str(item["affected_pairs"]) + "</td>"
        + "<td>" + escape(", ".join(item["metrics"])) + "</td></tr>"
        for item in summary["capability_hotspots"]
    )
    archive_panel = (
        "<table><caption>Most affected anonymous archives first</caption>"
        "<thead><tr><th scope='col'>Archive</th><th scope='col'>HOLD pairs</th>"
        "<th scope='col'>Evidence reused</th><th scope='col'>Score drift</th>"
        "<th scope='col'>Next action</th></tr></thead><tbody>"
        + archive_rows + "</tbody></table>"
        if archive_rows else "<p>No anonymous archives currently need comparison review.</p>"
    )
    hotspots_panel = (
        "<table><caption>Verified first-party scorer hotspots only</caption>"
        "<thead><tr><th scope='col'>Scorer</th><th scope='col'>Affected pairs</th>"
        "<th scope='col'>Changed metric types</th></tr></thead><tbody>"
        + hotspots + "</tbody></table>"
        if hotspots else "<p>No detected first-party score drift hotspots.</p>"
    )
    attention = (
        "<p class='warning'><strong>HOLD is global.</strong> Evidence reuse or "
        "score drift requires HUMAN inspection; checking one PASS pair does "
        "not clear another HOLD.</p>"
        if holds else
        "<p class='warning'><strong>Synthetic PASS only.</strong> The original "
        "private source is not authenticated and no external activity is authorized.</p>"
    )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' "
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<title>LightUp | Offline HUMAN review — " + state + "</title>"
        "<style>"
        ":root{color-scheme:light;font:16px/1.55 system-ui,sans-serif;"
        "background:#f5f7fa;color:#17263c}"
        "*{box-sizing:border-box}body{margin:0}a{color:#184b90}"
        "a:focus-visible{outline:3px solid #d97706;outline-offset:3px}"
        ".skip{position:absolute;top:-6rem}.skip:focus{top:.5rem;background:white}"
        "header{background:#123251;color:#fff;padding:2rem max(1rem,calc((100vw - 66rem)/2))}"
        "header p{max-width:65ch}main{max-width:68rem;margin:auto;padding:1rem}"
        "h1{font-size:2rem;margin:0 0 .6rem}h2{margin:0 0 1rem}"
        "section{background:white;border:1px solid #d7e0e9;border-radius:12px;"
        "padding:1.25rem;margin:1rem 0}"
        ".eyebrow{letter-spacing:.09em;text-transform:uppercase;font-size:.85rem}"
        ".metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(11rem,1fr));gap:1rem}"
        ".metric{border:1px solid #d7e0e9;border-radius:8px;padding:1rem}"
        ".metric strong{font-size:1.8rem;display:block}.metric span{font-size:.9rem}"
        ".warning{border-left:4px solid #ca8500;padding:.8rem 1rem;background:#fff8e7}"
        ".state{display:inline-block;padding:.1rem .7rem;border-radius:999px}"
        ".hold{color:#7b230c;background:#fce4d9}.pass{color:#115c34;background:#d7f2e1}"
        ".scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:38rem}"
        "th,td{text-align:left;border-bottom:1px solid #e2e8f0;padding:.65rem}"
        "thead{background:#edf3f9}tbody tr:hover{background:#f5f8ff}"
        ".links{display:flex;flex-wrap:wrap;gap:1rem}.links a{font-weight:650}"
        "footer{max-width:68rem;margin:auto;padding:2rem 1rem;color:#45566b}"
        ".sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;"
        "overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}"
        "@media print{header{background:white;color:black}section{break-inside:avoid}"
        ".skip{display:none}a{color:black}}"
        "</style></head><body><a class='skip' href='#content'>Skip to review</a>"
        "<header><p class='eyebrow'>LightUp · Synthetic lab only · No network</p>"
        "<h1>Offline HUMAN review</h1>"
        "<p>Source-free archive comparison. All original evidence, receipt IDs,"
        " target information and private paths stay outside this package. "
        "Never treat these files as approval, consent or an external scan grant.</p>"
        "</header><main id='content'>"
        "<section aria-labelledby='overall'><h2 id='overall'>Review at a glance</h2>"
        "<div class='metrics'>"
        "<div class='metric'><strong class='state " + state.lower() + "'>" + state
        + "</strong><span>Global synthetic result</span></div>"
        f"<div class='metric'><strong>{n}</strong><span>Anonymous archives</span></div>"
        f"<div class='metric'><strong>{len(pairs)}</strong><span>Original comparisons</span></div>"
        f"<div class='metric'><strong>{len(holds)}</strong><span>HOLD pairs</span></div>"
        "</div>" + attention + "</section>"
        "<section aria-labelledby='priorities'><h2 id='priorities'>Review priorities</h2>"
        "<p>Start with archives affected by the most HOLD pairs. Ordinals are"
        " local labels, not authenticated identities.</p>"
        "<div class='scroll' role='region' tabindex='0' aria-label='Archive review priorities'>"
        + archive_panel + "</div></section>"
        "<section aria-labelledby='pairs-title'><h2 id='pairs-title'>Every original comparison</h2>"
        "<p>HOLD pairs first; links open the complete, independently saved"
        " offline matrix. An unrelated PASS does not clear a global HOLD.</p>"
        "<div class='scroll' role='region' tabindex='0' aria-label='Pairwise score review'>"
        "<table><caption>All original pairwise verification flags</caption>"
        "<thead><tr><th scope='col'>Original pair</th><th scope='col'>Status</th>"
        "<th scope='col'>Evidence reused</th><th scope='col'>Score drift</th>"
        "<th scope='col'>Details</th></tr></thead><tbody>" + pair_rows
        + "</tbody></table></div></section>"
        "<section aria-labelledby='hotspots'><h2 id='hotspots'>Scorer hotspots</h2>"
        "<p>Anonymous first-party scorer and metric names only, no raw original scores.</p>"
        "<div class='scroll' role='region' tabindex='0' aria-label='First-party scorer hotspots'>"
        + hotspots_panel + "</div></section>"
        "<section aria-labelledby='files'><h2 id='files'>Offline documents</h2>"
        "<nav class='links' aria-label='Verified review exports'>"
        "<a href='history.html'>Full review matrix</a>"
        "<a href='review.md'>HUMAN brief</a>"
        "<a href='review.csv'>Pair flags CSV</a>"
        "<a href='review.json'>Summary JSON</a>"
        "<a href='README.txt'>Handling instructions</a></nav></section>"
        "</main><footer>Synthetic localhost only · No original authentication · "
        "No release, target access, permission, consent, review approval or deployment."
        "</footer></body></html>\n"
    )
