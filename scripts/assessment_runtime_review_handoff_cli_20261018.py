"""Offline private, printable human handoff for two completed lab benchmark exports.

This reads local JSON only. It cannot plan, dispatch, authorize, score untrusted
ground truth, or elevate REVIEW_ONLY into permission. Exit 2 is expected for an
admissible comparison; exit 3 is a generic HOLD.
"""
from __future__ import annotations

import argparse
import csv
from hashlib import sha256
from html import escape
from io import BytesIO, StringIO
import json
import os
from pathlib import Path
import stat
import tempfile
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

from assessment_runtime_compare_cli_1513 import (
    _output as _original_single_result,
    _dict_no_duplicates,
    _parse_case_document,
    _reject_nonfinite,
)
from assessment_runtime_compare_cohort_cli_1513 import _display as _original_cohort_result
from lightup.ai.assessment_runtime_diff_1513 import compare_lab_evaluations
from lightup.ai.assessment_runtime_cohort_1513 import _index, compare_lab_cohorts

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


def _load_case_set(paths):
    """Build a bounded original-format cohort from explicit local case files."""
    if type(paths) is not list or not 1 <= len(paths) <= 64:
        raise ValueError("invalid case selection")
    documents, pairs = [], []
    for path in paths:
        document, _ = _snapshot(path, SINGLE_LIMIT)
        pairs.append(_parse_case_document(document))
        documents.append(document)
    if _index(tuple(pairs)) is None or not _source_ids_unique(tuple(pairs)):
        raise ValueError("invalid lab cohort")
    payload = json.dumps(documents, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(payload) > COHORT_LIMIT:
        raise ValueError("cohort over limit")
    return tuple(pairs), sha256(payload).hexdigest()


def _source_ids_unique(baselines, candidates=()):
    """One original run and one original record can belong to only one case.

    Require disjoint original identities across the baseline/candidate sets,
    even when each scenario by itself would compare cleanly. This rejects a
    run copied to another scenario under a new claimed scenario identity.
    """
    runs, records = set(), set()
    for pair in (*baselines, *candidates):
        record, context = pair
        if (record.run_id in runs or record.record_id in records
                or record.run_id != context.run_id):
            return False
        runs.add(record.run_id)
        records.add(record.record_id)
    return True


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


def _build_report(result, baseline_sha: str, candidate_sha: str, cohort: bool,
                  selected_cases: bool = False, include_source_hashes: bool = True):
    sections = []
    regressions = []
    if cohort:
        for number, (_scenario, comparison) in enumerate(result.comparisons, 1):
            # Printable reports use ordinal labels only; original source scenario
            # identities belong exclusively in the private desk JSON.
            scenario_label = f"Case {number}"
            regressions.extend((scenario_label, str(name)) for name in comparison.regressions)
            sections.append(
                "<section><h2>Lab scenario: " + _e(scenario_label) + "</h2>" +
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
    fingerprint_section = (
        "<h2>Input snapshots (SHA-256, not signatures)</h2>"
        "<p>" + ("Canonical cohort-byte digests." if selected_cases
                  else "Original input-file byte digests.") + "</p>"
        "<p>Baseline: <code>" + escape(baseline_sha) + "</code><br>"
        "Candidate: <code>" + escape(candidate_sha) + "</code></p>"
    ) if include_source_hashes else (
        "<p>Privacy-minimal handoff: original source fingerprint values "
        "and original scenario identities intentionally omitted.</p>"
    )
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
        + fingerprint_section +
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


REVIEW_DESK_SOURCE_COMMIT = "bb5c2299d3697781db7093aaea79ed418f1cc07c"
REVIEW_DESK_SHA256 = "3f578faae06b40dea47cfac8e8318fa8db5dd117b5f3f7e0d5a7853e426fbe29"


LANDING_SHA256 = "d9f8aa4787615bccb9ed5b1eaf222c11ae2e67aed631fd56246db580328dabef"


def _pinned_pack_asset(name: str, digest: str, cap: int):
    """Admit only hash-pinned, local regular HTML assets, without symlinks."""
    path = Path(__file__).resolve().parent.parent / "assessment-review-pack" / name
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("invalid bundled application")
        source = stream.read(cap + 1)
    if not source or len(source) > cap or sha256(source).hexdigest() != digest:
        raise ValueError("pinned application changed")
    return source


def _original_review_desk_snapshot():
    return _pinned_pack_asset("review-desk.html", REVIEW_DESK_SHA256, 65_536)


def _human_worklist(result, cohort: bool):
    """Privacy-minimal, ordinal-only human triage CSV with zero authority."""
    stream = StringIO(newline="")
    rows = csv.writer(stream, lineterminator="\r\n")
    rows.writerow(("case", "priority", "workstream", "metric", "suggested_follow_up",
                   "review_stage", "authorized", "consent_verified", "release_allowed"))
    cases = (result.comparisons if cohort else (("single", result),))
    for ordinal, (_, comparison) in enumerate(cases, 1):
        for name in comparison.regressions:
            if name in ("scope_violations", "policy_violations"):
                priority, team, instruction = ("P1", "scope/policy",
                    "Human review of lab scope/policy evidence; do not execute")
            elif name in ("valid_findings", "invalid_findings", "missed_findings",
                          "coverage_assessed"):
                priority, team, instruction = ("P2", "lab runtime",
                    "Human review of measured lab finding/coverage changes")
            else:
                priority, team, instruction = ("P3", "evidence review",
                    "Human review of evidence or lab quality score changes")
            rows.writerow((f"Case {ordinal}", priority, team, name,
                           instruction, "PENDING_HUMAN_REVIEW", "false", "false", "false"))
    output = stream.getvalue().encode("utf-8")
    if len(output) > 131_072:
        raise ValueError("review worklist exceeds bound")
    return output


def _review_pack(result, first_sha: str, second_sha: str,
                 cohort: bool, selected_cases: bool):
    """One atomic private archive: printable brief + original Review Desk JSON.

    Fixed archive member names; no executable assets or unsafe source paths.
    The private JSON *does* contain original scenario identities and must not
    be confused with the ordinal-only printable human brief.
    """
    report = _build_report(result, first_sha, second_sha, cohort,
                           selected_cases=selected_cases)
    source = (_original_cohort_result(result) if cohort
              else _original_single_result(result))
    desk = json.dumps(source, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(desk) > COHORT_LIMIT:
        raise ValueError("comparison output exceeds bound")
    triage = _human_worklist(result, cohort)
    manifest = json.dumps({
        "format": "lightup.private_lab_review_pack.v1",
        "comparison_type": "cohort" if cohort else "single_case",
        "source_fingerprint_kind": ("canonical_case_set" if selected_cases
                                    else "original_input_file_bytes"),
        "baseline_sha256": first_sha,
        "candidate_sha256": second_sha,
        "status": result.status,
        "authorized": False,
        "consent_verified": False,
        "dispatch_allowed": False,
        "release_allowed": False,
        "source_authenticated": False,
        "approval_granted": False,
        "review_desk_source_commit": REVIEW_DESK_SOURCE_COMMIT,
        "review_desk_sha256": REVIEW_DESK_SHA256,
        "landing_sha256": LANDING_SHA256,
        "printable_review_sha256": sha256(report).hexdigest(),
        "review_desk_json_sha256": sha256(desk).hexdigest(),
        "human_worklist_sha256": sha256(triage).hexdigest(),
    }, sort_keys=True, separators=(",", ":")).encode("ascii")
    # Fixed original #1576 single-file browser is shipped *unchanged*.
    browser = _original_review_desk_snapshot()
    landing = _pinned_pack_asset("index.html", LANDING_SHA256, 16_384)
    instructions = ("LIGHTUP PRIVATE OFFLINE LAB REVIEW — NOT AUTHORIZED\n"
        "1. Extract this sensitive ZIP into a private local folder.\n"
        "2. Open index.html for the local start screen and links.\n"
        "3. Open review-desk.html locally and choose review-desk.json in its file picker.\n"
        "4. Review human-worklist.csv for pending metric follow-ups (not tasks or grants).\n"
        "5. Save any desired local human follow-up from the browser explicitly.\n"
        "The source-rich JSON/ZIP contains original scenario identities.\n"
        "Neither REVIEW_ONLY nor HOLD permits scans, grants or release.\n"
    ).encode("utf-8")
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        for name, content in (("index.html", landing),
                              ("START-HERE.txt", instructions),
                              ("review.html", report),
                              ("review-desk.html", browser),
                              ("review-desk.json", desk),
                              ("human-worklist.csv", triage),
                              ("manifest.json", manifest)):
            info = ZipInfo(name, date_time=(2026, 10, 18, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, content)
    payload = buffer.getvalue()
    if len(payload) > REPORT_LIMIT + COHORT_LIMIT + 32_768:
        raise ValueError("review package exceeds bound")
    return payload


def _redacted_pack(result, first_sha: str, second_sha: str,
                   cohort: bool, selected_cases: bool):
    """Share-minimal human packet: no source IDs, source hashes or browser input."""
    report = _build_report(result, first_sha, second_sha, cohort,
                           selected_cases=selected_cases, include_source_hashes=False)
    worklist = _human_worklist(result, cohort)
    manifest = json.dumps({
        "format": "lightup.ordinal_review_brief.v1",
        "status": result.status,
        "case_count": len(result.comparisons) if cohort else 1,
        "reported_regressions": (sum(len(c.regressions) for _, c in result.comparisons)
                                 if cohort else len(result.regressions)),
        "printable_review_sha256": sha256(report).hexdigest(),
        "human_worklist_sha256": sha256(worklist).hexdigest(),
        "source_authenticated": False,
        "authorized": False,
        "consent_verified": False,
        "dispatch_allowed": False,
        "release_allowed": False,
    }, sort_keys=True, separators=(",", ":")).encode("ascii")
    instructions = (
        "LIGHTUP ORDINAL HUMAN BRIEF — HOLD FOR ANY ACTIVE WORK\n"
        "Open review.html to read the printable metric brief.\n"
        "Open human-worklist.csv for suggested human-only follow-up.\n"
        "Source identifiers, original file fingerprints and interactive raw JSON "
        "are intentionally omitted. Numeric metrics may remain sensitive.\n"
        "Not consent, security proof, or permission to scan or release.\n"
    ).encode("utf-8")
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        for name, data in (("READ-ME.txt", instructions),
                           ("review.html", report),
                           ("human-worklist.csv", worklist),
                           ("manifest.json", manifest)):
            info = ZipInfo(name, date_time=(2026, 10, 18, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, data)
    payload = buffer.getvalue()
    if len(payload) > REPORT_LIMIT + 150_000:
        raise ValueError("private brief exceeds bound")
    return payload


def _write_exclusive(path: str, payload: bytes):
    """Publish complete 0600 bytes only; never expose a partial final filename.

    A new private temporary file is fsynced in the *same directory*, then
    hard-linked to the requested absent destination with no overwrite window.
    Link-based publication refuses existing files and symlinks atomically.
    """
    destination = Path(path)
    fd, temporary = tempfile.mkstemp(
        prefix=".lightup-private-", suffix=".partial", dir=destination.parent,
    )
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, destination, follow_symlinks=False)
    finally:
        os.unlink(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", nargs="?", help="Private JSON baseline export")
    parser.add_argument("candidate", nargs="?", help="Private JSON candidate export")
    parser.add_argument("--baseline-case", action="append", default=[], metavar="FILE",
                        help="Completed baseline case, repeated 1–64 times")
    parser.add_argument("--candidate-case", action="append", default=[], metavar="FILE",
                        help="Completed candidate case, repeated 1–64 times")
    parser.add_argument("--cohort", action="store_true",
                        help="Input files contain arrays of 1–64 case exports")
    parser.add_argument("--output", required=True,
                        help="New private output file (existing files are refused)")
    parser.add_argument("--format", choices=("html", "desk-json", "review-pack", "redacted-html", "redacted-pack"), default="html",
                        help="Printable HTML, original Review Desk #1576 JSON, or private combined ZIP")
    args = parser.parse_args(argv)
    try:
        selected_cases = bool(args.baseline_case or args.candidate_case)
        if selected_cases:
            if args.baseline or args.candidate or args.cohort:
                raise ValueError("cannot mix inputs")
            before, first_sha = _load_case_set(args.baseline_case)
            after, second_sha = _load_case_set(args.candidate_case)
        else:
            if not args.baseline or not args.candidate:
                raise ValueError("two source files required")
            before, first_sha = _load(args.baseline, args.cohort)
            after, second_sha = _load(args.candidate, args.cohort)
        cohort = args.cohort or selected_cases
        if cohort and not _source_ids_unique(before, after):
            raise ValueError("replayed source case identity")
        if cohort:
            result = compare_lab_cohorts(before, after)
        else:
            result = compare_lab_evaluations(
                before[0], after[0], before[1], after[1])
        metrics_ready = (bool(result.comparisons) and all(
            bool(comparison.changes) for _, comparison in result.comparisons
        )) if cohort else bool(result.changes)
        # A *real metric regression* is HOLD, but must still be reviewable.
        # Invalid/replayed records produce an empty comparison and no document.
        if result.status not in ("REVIEW_ONLY", "HOLD") or not metrics_ready:
            print("LAB_REVIEW_HOLD")
            return 3
        if args.format == "redacted-pack":
            document = _redacted_pack(result, first_sha, second_sha, cohort,
                                      selected_cases)
        elif args.format == "review-pack":
            document = _review_pack(result, first_sha, second_sha, cohort,
                                    selected_cases)
        elif args.format == "desk-json":
            # Delegate output shape to *unchanged* original #1515 CLI serializers.
            # The separate #1576 browser reads this exact comparison-result format.
            summary = (_original_cohort_result(result) if cohort
                       else _original_single_result(result))
            document = json.dumps(summary, sort_keys=True, separators=(",", ":"),
                                  allow_nan=False).encode("utf-8")
            if len(document) > COHORT_LIMIT:
                raise ValueError("private comparison result over limit")
        else:
            document = _build_report(result, first_sha, second_sha, cohort,
                                     selected_cases=selected_cases,
                                     include_source_hashes=args.format != "redacted-html")
        _write_exclusive(args.output, document)
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            UnicodeError, RecursionError, AttributeError):
        print("LAB_REVIEW_HOLD")
        return 3
    print("PRIVATE_LAB_REVIEW_WRITTEN — " + result.status + "; NOT AUTHORIZED")
    return 2 if result.status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
