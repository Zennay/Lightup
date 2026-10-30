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
    validate_portable_queue(queue, "HOLD" if legacy else global_status)
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


def render_portable_queue_html(queue: dict[str, Any], *, global_status: str,
                               navigation: bool = False) -> str:
    """Offline inert HTML from an already admitted canonical v3 ZIP only."""
    validate_portable_queue(queue, global_status)
    from .lab_score_portable_html_safety import admit_inert_html
    if navigation:
        archive_rows = []
        for a in queue["archive_priorities"]:
            related = [p for p in queue["pairs"]
                       if (p["review_status"] == "HOLD" and
                           a["index"] in (p["previous_index"], p["current_index"]))]
            links = ", ".join(
                f"<a href='#pair-{p['previous_index']}-{p['current_index']}'>"
                f"{p['previous_index']}-{p['current_index']}</a>" for p in related)
            archive_rows.append(
                f"<tr><th scope='row' id='archive-{a['index']}'>Archive {a['index']}</th>"
                f"<td>{a['hold_pairs']}</td><td>{a['reused_evidence_pairs']}</td>"
                f"<td>{a['score_drift_pairs']}</td><td>{links}</td></tr>")
        archives = "".join(archive_rows)
        pairs = "".join(
            f"<tr><th scope='row' id='pair-{p['previous_index']}-{p['current_index']}'>"
            f"Pair {p['previous_index']}-{p['current_index']}</th>"
            f"<td>{p['review_status']}</td><td>{', '.join(p['hold_reasons']) or 'none'}</td></tr>"
            for p in queue["pairs"])
    else:
        archives = "".join(
            f"<tr><th scope='row'>Archive {a['index']}</th>"
            f"<td>{a['hold_pairs']}</td><td>{a['reused_evidence_pairs']}</td>"
            f"<td>{a['score_drift_pairs']}</td></tr>"
            for a in queue["archive_priorities"])
        pairs = "".join(
            f"<tr><th scope='row'>Pair {p['previous_index']}-{p['current_index']}</th>"
            f"<td>{p['review_status']}</td><td>{', '.join(p['hold_reasons']) or 'none'}</td></tr>"
            for p in queue["pairs"])
    archive_link_header = "<th scope='col'>Jump to HOLD comparisons</th>" if navigation else ""
    quick_link = ""
    if navigation and queue["hold_pairs"]:
        first = queue["pairs"][0]
        quick_link = (f"<nav aria-label='HOLD-first review navigation'>"
                      f"<a href='#pair-{first['previous_index']}-{first['current_index']}'>"
                      "Jump to highest-priority HOLD pair</a></nav>")
    elif navigation:
        quick_link = "<nav aria-label='Review navigation'><a href='#content'>All comparisons PASS; review the global summary</a></nav>"
    html = ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            "<meta http-equiv='Content-Security-Policy' "
            "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            "<title>LightUp offline review queue</title>"
            "<style>body{font:1rem/1.5 system-ui;max-width:60rem;margin:2rem auto;"
            "padding:0 1rem}table{width:100%;border-collapse:collapse;margin:1rem 0}"
            "td,th{border:1px solid;padding:.6rem;text-align:left}"
            "a:focus-visible{outline:3px solid currentColor;outline-offset:2px}"
            "@media print{body{margin:0}a{color:inherit;text-decoration:underline}}"
            "</style>"
            "</head><body><main id='content'><h1>Synthetic HUMAN review queue</h1>"
            f"<p><strong>GLOBAL STATUS {global_status}</strong>. "
            "One local PASS never clears a global HOLD.</p>"
            f"{quick_link}"
            f"<p>{queue['pairs_checked']} original pairs, {queue['hold_pairs']} HOLD. "
            "Original source is NOT authenticated. HUMAN review only; "
            "no consent, target contact, grants, scans or deployment.</p>"
            "<section><h2>Archives needing review</h2><table>"
            "<caption>Original archive priorities</caption><thead><tr>"
            "<th scope='col'>Archive</th><th scope='col'>HOLD pairs</th>"
            "<th scope='col'>Replay</th><th scope='col'>Drift</th>"
            f"{archive_link_header}</tr></thead><tbody>{archives}</tbody></table></section>"
            "<section><h2>Every original pair</h2><table>"
            "<caption>HOLD-first comparison queue</caption><thead><tr>"
            "<th scope='col'>Pair</th><th scope='col'>Status</th>"
            f"<th scope='col'>Reasons</th></tr></thead><tbody>{pairs}</tbody>"
            "</table></section></main></body></html>")
    admit_inert_html(html.encode("utf-8"))
    return html


def validate_portable_queue(queue: dict[str, Any], global_status: str) -> None:
    """Fail closed on contradictory source-free display claims.

    Not an origin/consent verifier. Original ZIP admission remains mandatory.
    """
    if global_status not in ('PASS', 'HOLD'):
        raise ValueError('invalid global review claim')
    pairs = queue['pairs']
    priorities = queue['archive_priorities']
    if (type(queue['pairs_checked']) is not int or not 1 <= len(pairs) <= 28
            or len(pairs) != queue['pairs_checked']
            or type(queue['hold_pairs']) is not int
            or type(queue['pass_pairs']) is not int
            or queue['human_review_only'] is not True
            or queue['source_identity_authenticated'] is not False
            or not isinstance(priorities, list) or len(priorities) > 8):
        raise ValueError('invalid HUMAN queue identity or bounds')
    seen: set[tuple[int, int]] = set()
    holds = 0
    for pair in pairs:
        a, b = pair['previous_index'], pair['current_index']
        if (type(a) is not int or type(b) is not int
                or not 1 <= a < b <= 8 or (a, b) in seen
                or type(pair['independent_evaluations']) is not bool
                or type(pair['score_stable']) is not bool):
            raise ValueError('invalid anonymous pair identity')
        seen.add((a, b))
        reasons = (['evidence_reused'] if not pair['independent_evaluations'] else [])
        if not pair['score_stable']:
            reasons.append('score_drift')
        expected = 'HOLD' if reasons else 'PASS'
        if pair['review_status'] != expected or pair['hold_reasons'] != reasons:
            raise ValueError('contradictory pair outcome')
        holds += expected == 'HOLD'
    # A sender could hide an original HOLD by dropping that pair and updating
    # the unauthenticated counters. Require the COMPLETE n*(n-1)/2 comparison
    # matrix for exactly 2..8 ordinal archives before any renderer displays it.
    archive_count = max(max(a, b) for a, b in seen)
    complete = {(a, b) for a in range(1, archive_count + 1)
                for b in range(a + 1, archive_count + 1)}
    if archive_count < 2 or seen != complete:
        raise ValueError('missing or duplicate original archive comparison')
    ordered = sorted(pairs, key=lambda p: (
        p['review_status'] != 'HOLD',
        'evidence_reused' not in p['hold_reasons'],
        'score_drift' not in p['hold_reasons'],
        p['previous_index'], p['current_index']))
    if pairs != ordered:
        raise ValueError('HUMAN queue is not HOLD-first canonical order')
    if (holds != queue['hold_pairs'] or len(pairs)-holds != queue['pass_pairs']
            or (global_status == 'PASS' and holds)):
        raise ValueError('local HOLD cannot be promoted to global PASS')
    for entry in priorities:
        if (any(type(entry[key]) is not int for key in
                ('index', 'hold_pairs', 'reused_evidence_pairs', 'score_drift_pairs'))
                or not 1 <= entry['index'] <= 8
                or not 1 <= entry['hold_pairs'] <= 7
                or not 0 <= entry['reused_evidence_pairs'] <= entry['hold_pairs']
                or not 0 <= entry['score_drift_pairs'] <= entry['hold_pairs']):
            raise ValueError('invalid anonymous archive priority')
    # Recompute priorities from the same checked original pair outcomes.
    # An altered unsigned count must not become trusted operator guidance.
    by_archive = {i: {'index': i, 'hold_pairs': 0,
                      'reused_evidence_pairs': 0, 'score_drift_pairs': 0}
                  for i in range(1, 9)}
    for pair in pairs:
        if pair['review_status'] != 'HOLD':
            continue
        for index in (pair['previous_index'], pair['current_index']):
            counts = by_archive[index]
            counts['hold_pairs'] += 1
            counts['reused_evidence_pairs'] += not pair['independent_evaluations']
            counts['score_drift_pairs'] += not pair['score_stable']
    expected_priorities = sorted(
        (row for row in by_archive.values() if row['hold_pairs']),
        key=lambda row: (-row['hold_pairs'], row['index']),
    )
    if priorities != expected_priorities:
        raise ValueError('archive priorities contradict original HOLD pairs')
