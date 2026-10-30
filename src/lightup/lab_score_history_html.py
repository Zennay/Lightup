"""Offline, source-free and accessible review of original lab score history.

The exporter accepts only already-verified history summaries. Never embeds
paths, evidence, original hashes, run identities or executable scripts.
"""
from __future__ import annotations

from html import escape
from math import isfinite
from typing import Any

from .lab_score_compare import _SCORE_FIELDS
from .lab_score_suite import _EXPECTED_FINDINGS


def _number(value: Any) -> str:
    if type(value) not in (int, float) or not isfinite(value):
        return "unknown"
    return escape(str(value))


def render_history_html(report: dict[str, Any]) -> str:
    """Render a static 2–8 archive PASS/HOLD matrix, without original evidence."""
    n = report.get("archives_checked")
    if (report.get("schema") != "lightup.lab-score-calibration-history.v1"
            or type(n) is not int or not 2 <= n <= 8):
        raise ValueError("invalid verified history")
    pairs = report.get("pairs")
    if not isinstance(pairs, list) or len(pairs) != n * (n - 1) // 2:
        raise ValueError("invalid pairwise history")
    lookup: dict[tuple[int, int], bool] = {}
    flags: dict[tuple[int, int], tuple[bool, bool]] = {}
    for item in pairs:
        if not isinstance(item, dict):
            raise ValueError("invalid history pair")
        i, j, passed = (item.get("previous_index"),
                        item.get("current_index"), item.get("passed"))
        if (type(i) is not int or type(j) is not int
                or not 1 <= i < j <= n or type(passed) is not bool
                or (i, j) in lookup):
            raise ValueError("invalid pairwise index")
        independent = item.get("independent_evaluations")
        stable = item.get("score_stable")
        if (type(independent) is not bool or type(stable) is not bool
                or passed is not (independent and stable)):
            raise ValueError("contradictory original pair status")
        lookup[i, j] = passed
        flags[i, j] = (independent, stable)
    rows = []
    rows.append("<tr><th scope='col'>Archive</th>"
                + "".join(f"<th scope='col'>{i}</th>" for i in range(1, n + 1))
                + "</tr>")
    for i in range(1, n + 1):
        cells = [f"<th scope='row'>{i}</th>"]
        for j in range(1, n + 1):
            if j <= i:
                cells.append("<td class='unused' aria-label='not compared'>—</td>")
            else:
                ok = lookup[i, j]
                status = "PASS" if ok else "HOLD"
                badge = f"<span class='status {'pass' if ok else 'hold'}'>{status}</span>"
                if not ok:
                    badge = f"<a href='#pair-{i}-{j}' aria-label='Archive {i} versus {j}: HOLD'>{badge}</a>"
                cells.append(f"<td>{badge}</td>")
        rows.append("<tr>" + "".join(cells) + "</tr>")
    problems = []
    seen_holds: set[tuple[int, int]] = set()
    hotspots: dict[str, dict[str, set[Any]]] = {
        capability: {"pairs": set(), "metrics": set()}
        for capability in _EXPECTED_FINDINGS
    }
    reused_pairs, drift_pairs = 0, 0
    for item in report.get("pairwise_holds", []):
        if not isinstance(item, dict):
            raise ValueError("invalid hold")
        i, j = item.get("previous_index"), item.get("current_index")
        if (type(i) is not int or type(j) is not int
                or not 1 <= i < j <= n or lookup.get((i, j)) is not False
                or (i, j) in seen_holds
                or type(item.get("independent_evaluations")) is not bool
                or type(item.get("score_stable")) is not bool
                or flags[i, j] != (item["independent_evaluations"], item["score_stable"])):
            raise ValueError("invalid hold position")
        seen_holds.add((i, j))
        reused_pairs += item.get("independent_evaluations") is False
        drift_pairs += item.get("score_stable") is False
        reasons = []
        if item.get("independent_evaluations") is False:
            reasons.append("Original evidence reused")
        if item.get("score_stable") is False:
            reasons.append("Score drift")
        if not reasons:
            reasons.append("Calibration verification HOLD")
        details = []
        for delta in item.get("metric_deltas", []):
            if not isinstance(delta, dict):
                continue
            capability, metric = delta.get("capability"), delta.get("metric")
            if capability not in _EXPECTED_FINDINGS or metric not in _SCORE_FIELDS:
                continue
            hotspots[capability]["pairs"].add((i, j))
            hotspots[capability]["metrics"].add(metric)
            details.append("<li><strong>" + escape(capability) + " / "
                           + escape(metric) + "</strong>: "
                           + _number(delta.get("previous")) + " → "
                           + _number(delta.get("current")) + "</li>")
        problems.append(f"<section id='pair-{i}-{j}'><h3>Archive {i} versus {j}: HOLD</h3>"
                        + "<p>" + "; ".join(reasons) + "</p>"
                        + ("<ul>" + "".join(details) + "</ul>" if details else "")
                        + "</section>")
    # Human review order is based only on anonymous archive indices and
    # verified pair flags; no path, receipt, hash or original identity escapes.
    archive_issues = {index: {"pairs": set(), "reused": 0, "drift": 0}
                      for index in range(1, n + 1)}
    for item in report.get("pairwise_holds", []):
        i, j = item["previous_index"], item["current_index"]
        for index in (i, j):
            state = archive_issues[index]
            state["pairs"].add((i, j))
            state["reused"] += item.get("independent_evaluations") is False
            state["drift"] += item.get("score_stable") is False
    if seen_holds != {pair for pair, passed in lookup.items() if not passed}:
        raise ValueError("incomplete or mismatched HOLD details")
    if type(report.get("passed")) is not bool or report["passed"] != all(lookup.values()):
        raise ValueError("inconsistent overall calibration status")
    if (type(report.get("independent_evaluations")) is not bool
            or report["independent_evaluations"] != all(ind for ind, _ in flags.values())
            or type(report.get("score_stable")) is not bool
            or report["score_stable"] != all(stable for _, stable in flags.values())
            or report.get("pairs_checked") != len(lookup)):
        raise ValueError("inconsistent summary of original evidence")
    hotspot_rows = []
    for capability, info in sorted(hotspots.items(),
                                   key=lambda pair: (-len(pair[1]["pairs"]), pair[0])):
        if not info["pairs"]:
            continue
        first_i, first_j = min(info["pairs"])
        metrics = ", ".join(sorted(info["metrics"]))
        hotspot_rows.append(
            "<tr><th scope='row'>" + escape(capability) + "</th>"
            + f"<td>{len(info['pairs'])}</td><td>{escape(metrics)}</td>"
            + f"<td><a href='#pair-{first_i}-{first_j}'>Review {first_i} versus {first_j}</a></td></tr>"
        )
    archive_rows = []
    ordered_archives = sorted(archive_issues.items(),
                              key=lambda pair: (-len(pair[1]["pairs"]), pair[0]))
    for index, issue in ordered_archives:
        if not issue["pairs"]:
            continue
        first_i, first_j = min(issue["pairs"])
        archive_rows.append(
            f"<tr><th scope='row'>Archive {index}</th>"
            + f"<td>{len(issue['pairs'])}</td>"
            + f"<td>{issue['reused']}</td><td>{issue['drift']}</td>"
            + f"<td><a href='#pair-{first_i}-{first_j}'>First HOLD pair {first_i} versus {first_j}</a></td></tr>"
        )
    archive_queue = (
        "<h3>Archive review queue</h3>"
        + ("<table><caption>Most affected anonymous archives first</caption>"
           "<thead><tr><th scope='col'>Archive</th><th scope='col'>HOLD pairs</th>"
           "<th scope='col'>Evidence reuse</th><th scope='col'>Score drift</th>"
           "<th scope='col'>First issue</th></tr></thead><tbody>"
           + "".join(archive_rows) + "</tbody></table>"
           if archive_rows else "<p>No archives require review.</p>")
    )
    attention = (
        "<h2>Review priorities</h2>"
        + f"<p>{len(seen_holds)} HOLD pairs; {reused_pairs} with original evidence reuse; "
        + f"{drift_pairs} with score drift.</p>"
        + archive_queue
        + ("<table><caption>First-party score-drift hotspots</caption><thead><tr>"
           "<th scope='col'>Capability</th><th scope='col'>Affected pairs</th>"
           "<th scope='col'>Changed metrics</th><th scope='col'>First review</th>"
           "</tr></thead><tbody>" + "".join(hotspot_rows) + "</tbody></table>"
           if hotspot_rows else "<p>No first-party score-drift hotspots.</p>")
    )
    status = "PASS" if report.get("passed") is True else "HOLD"
    css = """body{font:16px/1.55 system-ui,sans-serif;max-width:880px;margin:2rem auto;padding:0 1rem;color:#152332;background:#fff}
h1,h2,h3{line-height:1.25}table{width:100%;border-collapse:collapse;margin:1.5rem 0}
th,td{padding:.6rem;border:1px solid #9ba9b8;text-align:center}
th{background:#edf2f7}a{color:#064f9e}a:focus-visible{outline:3px solid #0758b5}
.status{display:inline-block;padding:.15rem .5rem;border:2px solid;border-radius:.3rem;font-weight:750}
.pass{color:#155b31;border-color:#155b31}.hold{color:#992a19;border-color:#992a19}
.unused{color:#566575}section{padding:.5rem 1rem;border-left:4px solid #992a19;margin:1rem 0}
footer{border-top:1px solid #9ba9b8;margin-top:2rem;padding-top:1rem;font-size:.9rem}
.table-scroll{max-width:100%;overflow-x:auto;overscroll-behavior-inline:contain}
.table-scroll:focus-visible{outline:3px solid #0758b5}
@media(prefers-color-scheme:dark){body{background:#131b24;color:#f1f5fa}th{background:#293746}
a{color:#a3d0ff}.pass{color:#8ee9aa;border-color:#8ee9aa}.hold{color:#ffb7a7;border-color:#ffb7a7}
.unused{color:#a8b4c0}}"""
    return ("<!doctype html>\n<html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
            "style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; "
            "object-src 'none'; base-uri 'none'; form-action 'none'\">"
            "<title>LightUp synthetic calibration history</title><style>" + css
            + "</style></head><body><main><h1>LightUp synthetic calibration history</h1>"
            + f"<p><strong>Overall: {status}</strong> — {n} verified archives, "
            + f"{len(pairs)} original archive pairs.</p>"
            + "<p>All sources are private fixed-loopback lab fixtures. "
            + "PASS does not authorize external assessment or deployment.</p>"
            + attention
            + "<h2>All-pairs review</h2><div class='table-scroll' role='region' tabindex='0' aria-label='Original archive comparison matrix'><table><caption>Original synthetic "
            + "calibration comparisons</caption><thead>" + rows[0] + "</thead>"
            + "<tbody>" + "".join(rows[1:]) + "</tbody></table></div>"
            + ("<h2>Pairs requiring attention</h2>" + "".join(problems)
               if problems else "<p>All original archive pairs passed.</p>")
            + "</main><footer>Authority: none; fixed localhost fixtures only. "
            + "No external targets, grants, dispatch, scans or releases.</footer>"
            + "</body></html>\n")
