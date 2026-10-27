#!/usr/bin/env python3
"""Private, read-only lab benchmark -> findings handoff. No execution authority."""
from __future__ import annotations

import argparse
import csv
from collections import Counter
from hashlib import sha256
from html import escape
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
# Keep our product-local packet.py ahead of the original owner's
# unrelated assessment-archive/packet.py. The archive is only imported
# by its unambiguous module name "archive".
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(1, str(ROOT / "assessment-archive"))
from archive import Hold, decode_json, encode, publish, read_regular

FLAGS = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")
COMPARE_KEYS = {"status", "regressed_scenarios", "comparisons", *FLAGS}
COMPARE_ROW = {"scenario_id", "status", "regressions", "changes"}
CHANGE_KEYS = {"name", "baseline", "candidate", "delta", "regression"}
METRICS = (
    "valid_findings", "invalid_findings", "missed_findings",
    "coverage_assessed", "coverage_unknown", "scope_violations",
    "policy_violations", "human_interventions", "tool_calls",
    "evidence_quality", "reproducibility", "remediation_quality",
    "retest_correctness", "runtime_seconds", "compute_cost_usd",
)
COUNTERS = set(METRICS[:9])
SCORES = set(METRICS[9:13])
HIGHER = {"valid_findings", "coverage_assessed", *SCORES}
LOWER = {"invalid_findings", "missed_findings", "scope_violations", "policy_violations"}
COLUMNS = ("finding_id", "title", "severity", "retest_status", "remediation")
SEVERITIES = ("critical", "high", "medium", "low", "info")
RETEST = ("not_tested", "fix_pending", "fixed", "regression")
LINK_SCHEMA = "lightup.assessment_remediation_links.v1"
PRIVATE_SCHEMA = "lightup.assessment_remediation_private.v1"
AGG_SCHEMA = "lightup.assessment_remediation_aggregate.v1"
STAGES = ("needs_review", "investigating", "documented")
MAX_COMPARE = 262144
MAX_FINDINGS = 1048576
MAX_LINKS = 262144

def fail_if(condition, reason):
    if condition:
        raise Hold(reason)

def label(text, maximum=256):
    return (type(text) is str and 0 < len(text) <= maximum
            and text == text.strip() and all(32 <= ord(c) <= 126 for c in text))

def bounded_text(text, maximum=500):
    return (type(text) is str and len(text) <= maximum and
            all(c >= " " or c == "\n" for c in text) and
            all(ord(c) not in (0x202a, 0x202b, 0x202d, 0x202e, 0x202c,
                               0x2066, 0x2067, 0x2068, 0x2069) for c in text))

def number(value, metric):
    fail_if(type(value) not in (int, float) or not math.isfinite(value),
            "invalid original metric")
    if metric in COUNTERS:
        fail_if(type(value) is not int or not 0 <= value <= 1000000000,
                "invalid original counter")
    elif metric in SCORES:
        fail_if(not 0 <= value <= 1, "invalid original quality value")
    else:
        fail_if(value < 0 or value > 1000000000000,
                "invalid original operations metric")

def original_comparison(data):
    doc = decode_json(data)
    fail_if(type(doc) is not dict or set(doc) != COMPARE_KEYS,
            "not an original comparator envelope")
    fail_if(any(doc[k] is not False for k in FLAGS), "authority assertion")
    rows, regressions = doc["comparisons"], doc["regressed_scenarios"]
    fail_if(type(rows) is not list or not 1 <= len(rows) <= 64 or
            type(regressions) is not list, "incomplete original comparison")
    scenario_ids, adverse_ids = set(), []
    for row in rows:
        fail_if(type(row) is not dict or set(row) != COMPARE_ROW,
                "invalid scenario comparison")
        ident = row["scenario_id"]
        fail_if(not label(ident) or ident in scenario_ids,
                "ambiguous scenario identity")
        scenario_ids.add(ident)
        changes, reported = row["changes"], row["regressions"]
        fail_if(type(changes) is not list or len(changes) != len(METRICS) or
                type(reported) is not list, "incomplete original metrics")
        names, observed = set(), []
        for change in changes:
            fail_if(type(change) is not dict or set(change) != CHANGE_KEYS,
                    "invalid original metric row")
            metric = change["name"]
            fail_if(type(metric) is not str or metric not in METRICS or
                    metric in names, "unknown or duplicate original metric")
            names.add(metric)
            old, new, delta = (change[k] for k in ("baseline", "candidate", "delta"))
            number(old, metric)
            number(new, metric)
            fail_if(type(delta) not in (int, float) or not math.isfinite(delta) or
                    not math.isclose(new - old, delta, rel_tol=1e-12, abs_tol=1e-9),
                    "mismatched original delta")
            adverse = (metric in HIGHER and new < old) or (metric in LOWER and new > old)
            fail_if(change["regression"] is not adverse,
                    "contradictory original regression classification")
            if adverse:
                observed.append(metric)
        fail_if(names != set(METRICS) or reported != observed or
                row["status"] != ("HOLD" if observed else "REVIEW_ONLY"),
                "contradictory original scenario status")
        if observed:
            adverse_ids.append(ident)
    fail_if(regressions != adverse_ids or
            doc["status"] != ("HOLD" if adverse_ids else "REVIEW_ONLY"),
            "contradictory original cohort HOLD")
    return doc

def original_findings(data):
    try:
        text = data.decode("utf-8-sig")
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        header = next(reader)
        fail_if(tuple(header) != COLUMNS, "noncanonical original findings columns")
        rows = list(reader)
    except (UnicodeError, csv.Error, StopIteration) as exc:
        raise Hold("unreadable original findings CSV") from exc
    fail_if(not 1 <= len(rows) <= 350, "findings outside original export bound")
    accepted = {}
    for row in rows:
        fail_if(len(row) != 5, "malformed original finding")
        ident, title, severity, retest, remediation = row
        fail_if(not label(ident) or ident in accepted or
                not bounded_text(title, 2048) or not title.strip() or
                severity not in SEVERITIES or retest not in RETEST or
                not bounded_text(remediation, 8192) or not remediation.strip(),
                "invalid original finding data")
        accepted[ident] = dict(zip(COLUMNS, row))
    return accepted

def links_document(raw, compare_digest, finding_digest, scenarios, findings):
    if raw is None:
        return []
    doc = decode_json(raw)
    fail_if(type(doc) is not dict or set(doc) != {
        "schema", "comparison_sha256", "findings_sha256", "links", *FLAGS
    } or doc["schema"] != LINK_SCHEMA or
            doc["comparison_sha256"] != compare_digest or
            doc["findings_sha256"] != finding_digest or
            any(doc[k] is not False for k in FLAGS),
            "manual mapping does not bind the exact original inputs")
    links = doc["links"]
    fail_if(type(links) is not list or len(links) > 512, "invalid mapping length")
    observed = set()
    for link in links:
        fail_if(type(link) is not dict or set(link) != {
            "scenario_id", "finding_id", "stage", "reviewer", "next_action", "note"
        }, "invalid manual link")
        scenario, finding = link["scenario_id"], link["finding_id"]
        fail_if(type(scenario) is not str or type(finding) is not str or
                scenario not in scenarios or finding not in findings or
                (scenario, finding) in observed or
                link["stage"] not in STAGES or
                not bounded_text(link["reviewer"], 100) or
                not bounded_text(link["next_action"], 300) or
                not bounded_text(link["note"], 500),
                "invalid or repeated original mapping")
        observed.add((scenario, finding))
    return links

def private_dir(path):
    folder = Path(path).absolute()
    info = os.lstat(folder)
    fail_if(not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
            stat.S_IMODE(info.st_mode) & 0o077, "requires owned private output directory")
    return folder

def csv_cell(value):
    start = value.lstrip()
    return ("'" + value) if start[:1] in ("=", "+", "-", "@") or value[:1] in ("\n", "\r", "\t") else value

def as_csv(rows):
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\r\n", quoting=csv.QUOTE_ALL)
    writer.writerow(("scenario_id", "source_status", "finding_id", "severity",
                     "source_retest_status", "human_stage", "reviewer", "next_action"))
    for row in rows:
        writer.writerow([csv_cell(str(v)) for v in row])
    return out.getvalue().encode("utf-8")

def html_report(comparison, findings, links, digests):
    by_scenario = {}
    for link in links:
        by_scenario.setdefault(link["scenario_id"], []).append(link)
    sections = []
    for index, item in enumerate(comparison["comparisons"], 1):
        identifier = item["scenario_id"]
        mapped = by_scenario.get(identifier, [])
        finding_lines = []
        for link in mapped:
            finding = findings[link["finding_id"]]
            finding_lines.append(
                "<li><strong>" + escape(finding["title"]) + "</strong> · "
                + escape(finding["severity"]) + " · source retest: "
                + escape(finding["retest_status"]) + "<br>Original finding ID: <code>"
                + escape(link["finding_id"]) + "</code><br>Manual follow-up: "
                + escape(link["stage"]) + " / " + escape(link["reviewer"])
                + "<br>Next action: " + escape(link["next_action"])
                + "<br>Human note (unverified): " + escape(link["note"])
                + "<details><summary>Original remediation text (not proof)</summary><p>"
                + escape(finding["remediation"]) + "</p></details></li>"
            )
        adverse = item["regressions"]
        metrics = "".join(
            "<tr><th scope='row'>" + escape(change["name"]) + "</th>"
            "<td>" + escape(str(change["baseline"])) + "</td><td>" +
            escape(str(change["candidate"])) + "</td><td>" +
            escape(str(change["delta"])) + "</td><td>" +
            ("ADVERSE" if change["regression"] else "informational") +
            "</td></tr>"
            for change in item["changes"]
        )
        sections.append(
            '<section id="s' + str(index) + '"><h2>' + str(index) + ". "
            + escape(identifier) + "</h2><p><b>Original comparison:</b> "
            + escape(item["status"]) + " · "
            + str(len(adverse)) + " source-reported adverse metrics</p>"
            + "<p>Source adverse metrics: " + escape(", ".join(adverse) or "none declared")
            + "</p><details><summary>View all 15 original metric values"
              " and their source-reported interpretation</summary>"
              "<div class='scroll'><table><thead><tr><th>Metric</th><th>Baseline</th>"
              "<th>Candidate</th><th>Delta</th><th>Source interpretation</th>"
              "</tr></thead><tbody>" + metrics + "</tbody></table></div></details>"
            + "<h3>Manual finding links (" + str(len(mapped)) + ")</h3>"
            + ("<ul>" + "".join(finding_lines) + "</ul>" if mapped else
               "<p>No human link recorded. This does not mean no finding exists.</p>")
            + "</section>"
        )
    linked_findings = {link["finding_id"] for link in links}
    unmatched = sorted(
        ((key, f) for key, f in findings.items() if key not in linked_findings),
        key=lambda item: (SEVERITIES.index(item[1]["severity"]), item[0])
    )
    unmatched_section = (
        "<section><h2>Unlinked original findings — human mapping required</h2>"
        "<p>These independently exported source findings currently have NO manual"
        " lab-case link. Absence of a link is not clearance or fixed status.</p><ul>"
        + "".join(
            "<li><b>" + escape(f["severity"].upper()) + "</b> · "
            + escape(f["title"]) + " · Original ID <code>" + escape(key)
            + "</code> · source-reported retest " + escape(f["retest_status"])
            + "</li>" for key, f in unmatched
        ) + "</ul></section>"
    )
    stylesheet = (
        "body{font:16px system-ui,sans-serif;max-width:1050px;margin:2rem auto;"
        "padding:0 1.25rem;color:#172136;background:#fafbfd}h1{font-size:2rem}"
        "section{background:white;padding:1.2rem 1.5rem;border:1px solid #cad2e2;"
        "border-radius:.7rem;margin:1rem 0}p,li{line-height:1.6}code{overflow-wrap:anywhere}"
        "header{border-bottom:3px solid #b35625;padding-bottom:1.2rem}"
        ".scroll{max-width:100%;overflow-x:auto}table{width:100%;border-collapse:collapse;"
        "min-width:550px;font-size:.82rem}td,th{padding:.4rem;text-align:left;"
        "border-bottom:1px solid #cad2e2}details{margin:1rem 0}"
        "nav a{display:inline-block;padding:.4rem;margin:.2rem;border:1px solid #abc;"
        "border-radius:.3rem}a{color:#16468f}details{margin:.5rem 0}footer{padding:2rem 0}"
        "@media print{nav{display:none}section{break-inside:avoid}}"
    )
    style_hash = __import__("base64").b64encode(sha256(stylesheet.encode()).digest()).decode()
    csp = "default-src 'none'; style-src 'sha256-" + style_hash + "'; base-uri 'none'; form-action 'none'; img-src 'none'; connect-src 'none'"
    contents = "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    contents += '<meta http-equiv="Content-Security-Policy" content="' + csp + '">'
    contents += "<title>LightUp · private human assessment-to-remediation map</title><style>" + stylesheet + "</style>"
    contents += "<header><h1>LightUp · lab → finding follow-up</h1><p><b>PRIVATE · HUMAN REVIEW · "
    contents += escape(comparison["status"]) + " · NEVER AUTHORIZED</b></p>"
    contents += "<p>Offline original lab comparison + separate original client findings export. Links are manual unverified analyst notes, not ground truth, evidence, consent, proof of same engagement, validated fixes or approval to retest. Verify client and scope separately before any handoff.</p>"
    contents += "<p>Original files are not independently authenticated. Their SHA-256 values below bind exact local bytes only.</p>"
    contents += "<p>Comparison SHA-256: <code>" + digests[0] + "</code><br>Findings SHA-256: <code>" + digests[1] + "</code></p></header>"
    contents += "<nav aria-label='Scenarios'>" + "".join(
        '<a href="#s' + str(i) + '">Case ' + str(i) + '</a>'
        for i in range(1, len(sections) + 1)) + "</nav>"
    contents += "".join(sections) + unmatched_section + "<footer>PLAN/LAB ONLY · DRAFT/HOLD · all four authority flags false · no target work.</footer></html>"
    return contents.encode("utf-8")

def run(args):
    fail_if(not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,39}", args.prefix),
            "invalid private output prefix")
    folder = private_dir(args.output_dir)
    raw_cmp = read_regular(args.comparison, MAX_COMPARE)
    raw_csv = read_regular(args.findings_csv, MAX_FINDINGS)
    digests = (sha256(raw_cmp).hexdigest(), sha256(raw_csv).hexdigest())
    compare = original_comparison(raw_cmp)
    findings = original_findings(raw_csv)
    scenarios = {row["scenario_id"] for row in compare["comparisons"]}
    raw_links = read_regular(args.links, MAX_LINKS) if args.links else None
    links = links_document(raw_links, *digests, scenarios, findings)
    mapped = {link["finding_id"] for link in links}
    linked_scenarios = {link["scenario_id"] for link in links}
    no_links = len(links) == 0
    aggregate = {
        "schema": AGG_SCHEMA, "status": compare["status"],
        "original_scenario_count": len(scenarios),
        "original_findings_count": len(findings),
        "source_regressed_scenario_count": len(compare["regressed_scenarios"]),
        "human_link_count": len(links), "human_linked_scenario_count": len(linked_scenarios),
        "human_unlinked_scenario_count": len(scenarios - linked_scenarios),
        "human_unlinked_finding_count": len(findings.keys() - mapped),
        "original_severity_counts": {x: sum(f["severity"] == x for f in findings.values()) for x in SEVERITIES},
        "human_stage_counts": {x: sum(link["stage"] == x for link in links) for x in STAGES},
        **{flag: False for flag in FLAGS}
    }
    template = {
        "schema": LINK_SCHEMA,
        "comparison_sha256": digests[0], "findings_sha256": digests[1],
        "links": [] if no_links else links,
        **{flag: False for flag in FLAGS}
    }
    agenda = []
    for item in compare["comparisons"]:
        for link in links:
            if link["scenario_id"] == item["scenario_id"]:
                f = findings[link["finding_id"]]
                agenda.append((link["scenario_id"], item["status"], link["finding_id"],
                               f["severity"], f["retest_status"], link["stage"],
                               link["reviewer"], link["next_action"]))
    # The action backlog must surface *all* original findings, including
    # those not yet manually associated with a source lab scenario.
    # No source finding ever silently disappears from human attention.
    for finding_id, finding in sorted(
        findings.items(), key=lambda entry: (
            SEVERITIES.index(entry[1]["severity"]), entry[0])
    ):
        if finding_id not in mapped:
            agenda.append((
                "", "UNLINKED_SOURCE", finding_id, finding["severity"],
                finding["retest_status"], "needs_review", "",
                "Operator: confirm source/client provenance and select a real scenario, if applicable",
            ))
    # Original lab scenarios without associated findings also require human
    # attention, especially those with adverse original comparison metrics.
    for item in sorted(
        compare["comparisons"],
        key=lambda row: (row["status"] != "HOLD", row["scenario_id"])
    ):
        if item["scenario_id"] not in linked_scenarios:
            agenda.append((
                item["scenario_id"], item["status"], "", "", "",
                "needs_review", "",
                "Review original lab scenario and independently establish whether any client finding is related",
            ))
    outputs = {
        "private.html": html_report(compare, findings, links, digests),
        "links.json": encode(template),
        "aggregate.json": encode(aggregate),
        "private-agenda.csv": as_csv(agenda),
    }
    destinations = [(folder / (args.prefix + "-" + name), payload)
                    for name, payload in outputs.items()]
    fail_if(any(os.path.lexists(path) for path, _ in destinations) or
            (args.bundle and
             os.path.lexists(folder / (args.prefix + "-private-room.zip"))),
            "private destination or room already exists; do not overwrite")
    # Recheck exact original source bytes before publishing anything.
    fail_if(sha256(read_regular(args.comparison, MAX_COMPARE)).hexdigest() != digests[0]
            or sha256(read_regular(args.findings_csv, MAX_FINDINGS)).hexdigest() != digests[1]
            or (raw_links is not None and
                read_regular(args.links, MAX_LINKS) != raw_links),
            "original source changed during review")
    published = []
    try:
        for path, payload in destinations:
            publish(path, payload)
            published.append((path, sha256(payload).digest(), len(payload)))
    except Exception:
        for path, expected, size in published:
            try:
                if sha256(read_regular(str(path), size)).digest() == expected:
                    path.unlink()
            except (OSError, Hold):
                pass
        raise
    print("PRIVATE_ASSESSMENT_REMEDIATION_" + compare["status"])
    print("Human-only offline dossier; original scenario and finding sources never modified.")
    print("Private HTML + exact-byte-bound manual links + anonymized aggregate + private CSV created.")
    return 3 if compare["status"] == "HOLD" else 2

def main(argv=None):
    parser = argparse.ArgumentParser(description=(
        "Join an existing original lab cohort comparison to an independently exported original "
        "five-column findings CSV using human-only links. Never grants execution or release."
    ))
    parser.add_argument("--comparison", required=True)
    parser.add_argument("--findings-csv", required=True)
    parser.add_argument("--links", help="Optional existing exact-source-bound human links JSON")
    parser.add_argument("--output-dir", required=True, help="Existing owned private 0700 directory")
    parser.add_argument("--prefix", default="lightup-followup")
    parser.add_argument("--bundle", action="store_true",
                        help="Also create a private portable 0600 room ZIP from completed outputs")
    args = parser.parse_args(argv)
    try:
        status = run(args)
        if args.bundle:
            # Only after native source admission/publication: package the exact
            # private outputs. Both states remain non-authorizing 2/3.
            from packet import create_room
            create_room(args)
        return status
    except (Hold, OSError, ValueError, TypeError, KeyError,
            OverflowError, UnicodeError, RecursionError) as exc:
        print("PRIVATE_ASSESSMENT_REMEDIATION_HOLD — invalid, unsafe, or changed local source/output", file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
