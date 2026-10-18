"""Offline private, printable human handoff for two completed lab benchmark exports.

This reads local JSON only. It cannot plan, dispatch, authorize, score untrusted
ground truth, or elevate REVIEW_ONLY into permission. Exit 2 is expected for an
admissible comparison; exit 3 is a generic HOLD.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
from html import escape
import json
import os
from pathlib import Path
import stat

from assessment_runtime_compare_cli_1513 import (
    _dict_no_duplicates,
    _parse_case_document,
    _reject_nonfinite,
)
from lightup.ai.assessment_runtime_diff_1513 import compare_lab_evaluations
from lightup.ai.assessment_runtime_cohort_1513 import compare_lab_cohorts

SINGLE_LIMIT = 65_536
COHORT_LIMIT = 262_144
REPORT_LIMIT = 1_048_576
FLAGS = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")


def _snapshot(path: str, limit: int):
    """Read exactly one bounded regular file snapshot without following symlinks."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("not a regular input")
            payload = stream.read(limit + 1)
    except BaseException:
        # fdopen owns the descriptor once it enters its context.
        raise
    if not payload or len(payload) > limit:
        raise ValueError("out of bounds")
    data = json.loads(
        payload.decode("utf-8"),
        object_pairs_hook=_dict_no_duplicates,
        parse_constant=_reject_nonfinite,
    )
    return data, sha256(payload).hexdigest()


def _load(path: str, cohort: bool):
    document, digest = _snapshot(path, COHORT_LIMIT if cohort else SINGLE_LIMIT)
    if not cohort:
        return _parse_case_document(document), digest
    if type(document) is not list or not 1 <= len(document) <= 64:
        raise ValueError("invalid cohort")
    return tuple(_parse_case_document(item) for item in document), digest


def _str(value):
    if value is None:
        return "—"
    if type(value) is bool:
        return "true" if value else "false"
    return str(value)


def _e(value):
    return escape(_str(value), quote=True)


def _metrics(changes):
    rows = []
    for item in changes:
        rows.append(
            "<tr><th scope='row'>" + _e(item.name) + "</th><td>" +
            _e(item.baseline) + "</td><td>" + _e(item.candidate) +
            "</td><td>" + _e(item.delta) + "</td><td>" +
            ("REGRESSION" if item.regression else "informational / no regression") +
            "</td></tr>"
        )
    return (
        "<table><thead><tr><th>Metric</th><th>Baseline</th><th>Candidate</th>"
        "<th>Change</th><th>Interpretation</th></tr></thead><tbody>" +
        "".join(rows) + "</tbody></table>"
    )


def _build_report(result, baseline_sha: str, candidate_sha: str, cohort: bool):
    sections = []
    regressions = []
    if cohort:
        for scenario, comparison in result.comparisons:
            regressions.extend((str(scenario), str(name)) for name in comparison.regressions)
            sections.append(
                "<section><h2>Lab scenario: " + _e(scenario) + "</h2>" +
                "<p>Local comparison: " + _e(comparison.status) + "</p>" +
                _metrics(comparison.changes) + "</section>"
            )
    else:
        regressions.extend(("", str(name)) for name in result.regressions)
        sections.append("<section><h2>Lab metric changes</h2>" +
                        _metrics(result.changes) + "</section>")
    concern = (
        "<li>" + (_e(scenario) + ": " if scenario else "") + _e(name) + "</li>"
        for scenario, name in regressions
    )
    issue_section = (
        "<h2>Regression signals</h2><ul>" + "".join(concern) + "</ul>"
        if regressions else
        "<h2>Regression signals</h2><p>No metric regression signaled by this"
        " local comparator. This is not a security, quality or release verdict.</p>"
    )
    authority = "".join("<li><code>" + escape(flag) +
                        " = false</code></li>" for flag in FLAGS)
    body = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; "
        "form-action 'none'; base-uri 'none'\">"
        "<title>LightUp offline lab review — human triage only</title>"
        "<style>body{font:16px/1.5 system-ui,sans-serif;max-width:1100px;"
        "margin:2rem auto;padding:0 1rem;color:#17202c}h1,h2{line-height:1.2}"
        ".notice{border:2px solid #343f53;padding:1rem;margin:1rem 0}"
        "table{border-collapse:collapse;width:100%;font-size:.9rem}"
        "td,th{padding:.5rem;border:1px solid #8993a2;text-align:left;"
        "overflow-wrap:anywhere}tr:nth-child(even){background:#f3f5f8}"
        "section{margin:2rem 0;break-inside:avoid}code{overflow-wrap:anywhere}"
        "@media print{body{max-width:none;font-size:11pt}section{break-inside:auto}"
        "tr{break-inside:avoid}}</style></head><body>"
        "<h1>LightUp · private offline lab comparison</h1>"
        "<div class='notice'><strong>Offline metric review only — HOLD for activation/release.</strong>"
        "<p>This is a comparison of caller-supplied local lab records, not verified"
        " provenance, independent ground truth, security assurance, client consent,"
        " operator authorization or permission to contact any target.</p>"
        "<ul>" + authority + "</ul></div>"
        "<p>Comparison type: " + ("cohort" if cohort else "single case") +
        " · Result: <strong>" + _e(result.status) + "</strong></p>"
        "<h2>Input snapshots (SHA-256, not signatures)</h2>"
        "<p>Baseline bytes: <code>" + escape(baseline_sha) + "</code><br>"
        "Candidate bytes: <code>" + escape(candidate_sha) + "</code></p>"
        "<p>No source paths, raw evidence, credentials or finding payloads are"
        " embedded in this report. Preserve both originals privately.</p>" +
        issue_section + "".join(sections) +
        "<section><h2>Human handoff — not completed by this document</h2>"
        "<p>Reviewer: ___________________  Date: ________________</p>"
        "<p>Investigation / follow-up: __________________________________</p>"
        "<p>Any active assessment, approval or release requires independent"
        " original source-owner, scope/consent, security/privacy, CI/VPS and"
        " explicit HUMAN GO gates outside this tool.</p></section>"
        "</body></html>"
    )
    encoded = body.encode("utf-8")
    if len(encoded) > REPORT_LIMIT:
        raise ValueError("report too large")
    return encoded


def _write_exclusive(path: str, payload: bytes):
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", help="Private JSON baseline export")
    parser.add_argument("candidate", help="Private JSON candidate export")
    parser.add_argument("--cohort", action="store_true",
                        help="Input files contain arrays of 1–64 case exports")
    parser.add_argument("--output", required=True,
                        help="New private HTML report (existing files are refused)")
    args = parser.parse_args(argv)
    try:
        before, first_sha = _load(args.baseline, args.cohort)
        after, second_sha = _load(args.candidate, args.cohort)
        if args.cohort:
            result = compare_lab_cohorts(before, after)
        else:
            result = compare_lab_evaluations(
                before[0], after[0], before[1], after[1])
        metrics_ready = (bool(result.comparisons) and all(
            bool(comparison.changes) for _, comparison in result.comparisons
        )) if args.cohort else bool(result.changes)
        # A *real metric regression* is HOLD, but must still be reviewable.
        # Invalid/replayed records produce an empty comparison and no document.
        if result.status not in ("REVIEW_ONLY", "HOLD") or not metrics_ready:
            print("LAB_REVIEW_HOLD")
            return 3
        document = _build_report(result, first_sha, second_sha, args.cohort)
        _write_exclusive(args.output, document)
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            UnicodeError, RecursionError, AttributeError):
        print("LAB_REVIEW_HOLD")
        return 3
    print("PRIVATE_LAB_REVIEW_WRITTEN — " + result.status + "; NOT AUTHORIZED")
    return 2 if result.status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
