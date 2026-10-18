"""Attach a genuine offline Review Desk human follow-up to its exact private lab pack.

Uses the original Review Desk v1/v2 exported planning schema. Does not run
assessments, authenticate source evidence, authorize work or grant consent.
"""
from __future__ import annotations

import argparse
from datetime import date
from hashlib import sha256
from io import BytesIO
import json
import re
from zipfile import BadZipFile, LargeZipFile, ZipFile, ZIP_DEFLATED, ZipInfo

from assessment_runtime_review_handoff_cli_20261018 import (
    _snapshot, _write_exclusive, _e, _pinned_pack_asset,
)
from assessment_runtime_verify_pack_cli_20261018 import inspect_bytes as inspect_pack_bytes
from assessment_runtime_verify_pack_cli_20261018 import _json, CAPS

MAX_REVIEW = 131_072
MAX_PACK = 1_700_000
FOLLOWUP_SHA256 = "7aafc195b3ed5d4f748c61ac6a846925124355db44a36a43c06835eca5295dcb"
MAX_ATTACHED = 1_700_000
STAGES = frozenset(("todo", "investigating", "waiting", "planned", "reviewed"))
ROUTES = frozenset(("unassigned", "lab-runtime", "scope-review",
                    "evidence-review", "independent-review"))
AUTH = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")
BASE_KEYS = frozenset((
    "schema", "source_sha256", "source_kind", "source_status",
    *AUTH, "release_approved", "scan_allowed", "review_only",
    "cases", "warning",
))
CASE_KEYS = frozenset((
    "case", "priority", "source_status", "metric_regressions",
    "human_stage", "follow_up_date",
))
PRIORITY_METRICS = frozenset(("scope_violations", "policy_violations"))
HIGH_METRICS = frozenset(("missed_findings", "invalid_findings", "valid_findings"))


def _priority(regressions):
    if not regressions:
        return "No regression"
    if PRIORITY_METRICS.intersection(regressions):
        return "Critical drift"
    if HIGH_METRICS.intersection(regressions):
        return "High drift"
    return "Review drift"


def _validate_plan(saved, comparison, source_hash):
    if type(saved) is not dict or set(saved) != BASE_KEYS:
        raise ValueError("unexpected saved planning envelope")
    version = saved["schema"]
    if version not in ("lightup-offline-human-triage-v1",
                       "lightup-offline-human-triage-v2"):
        raise ValueError("unknown planning schema")
    if (saved["source_sha256"] != source_hash
            or saved["source_kind"] not in ("single", "cohort")
            or saved["source_status"] != comparison["status"]
            or saved["warning"] != "UNAUTHENTICATED OFFLINE HUMAN PLANNING. NEVER AUTHORIZES ACTIVITY."
            or saved["review_only"] is not True
            or saved["release_approved"] is not False
            or saved["scan_allowed"] is not False
            or any(saved[flag] is not False for flag in AUTH)):
        raise ValueError("saved review does not bind to original source")
    cohort = "comparisons" in comparison
    if (saved["source_kind"] == "cohort") != cohort:
        raise ValueError("comparison kind mismatch")
    source_cases = comparison["comparisons"] if cohort else [comparison]
    rows = saved["cases"]
    if type(rows) is not list or len(rows) != len(source_cases):
        raise ValueError("saved review case count mismatch")
    final = []
    for index, (row, case) in enumerate(zip(rows, source_cases), 1):
        keys = CASE_KEYS | ({"routing_group"} if version.endswith("v2") else set())
        if type(row) is not dict or set(row) != keys:
            raise ValueError("invalid row structure")
        regressions = case["regressions"]
        if (type(regressions) is not list or
                type(row["metric_regressions"]) is not list or
                any(type(name) is not str for name in regressions) or
                row["metric_regressions"] != sorted(regressions)):
            raise ValueError("source comparison does not match saved review")
        if (row["case"] != f"Case {index:02d}"
                or row["source_status"] != case["status"]
                or row["priority"] != _priority(regressions)
                or row["human_stage"] not in STAGES):
            raise ValueError("saved review labels or stages mismatch")
        route = row["routing_group"] if version.endswith("v2") else "unassigned"
        if route not in ROUTES:
            raise ValueError("invalid planning workstream")
        due = row["follow_up_date"]
        if due is not None:
            if type(due) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", due):
                raise ValueError("invalid follow-up date")
            if date.fromisoformat(due).isoformat() != due:
                raise ValueError("non-canonical follow-up date")
        final.append({
            "case": row["case"],
            "source_status": row["source_status"],
            "priority": row["priority"],
            "metric_regressions": list(row["metric_regressions"]),
            "human_stage": row["human_stage"],
            "follow_up_date": due,
            "routing_group": route,
        })
    return final


def _human_report(rows, source_status):
    entries = "".join(
        "<tr>" + "".join("<td>" + _e(item) + "</td>" for item in (
            row["case"], row["priority"], row["source_status"],
            row["routing_group"], row["human_stage"],
            row["follow_up_date"] or "—",
            ", ".join(row["metric_regressions"]) or "—",
        )) + "</tr>" for row in rows
    )
    body = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
        " style-src 'unsafe-inline'; connect-src 'none'; form-action 'none';"
        " base-uri 'none'\"><title>LightUp · Human follow-up snapshot</title>"
        "<style>body{font:16px/1.5 system-ui,sans-serif;max-width:1100px;"
        "margin:2rem auto;padding:0 1rem}table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #8993a2;padding:.5rem;text-align:left}"
        "tr{break-inside:avoid}@media print{body{font-size:11pt}}</style>"
        "</head><body><h1>LightUp · private human follow-up</h1>"
        "<p><strong>" + _e(source_status) + " · HUMAN PLANNING ONLY · NOT AUTHORIZED</strong></p>"
        "<p>These stages were saved by a reviewer in the original local Review Desk."
        " No decision here verifies source authenticity or approves any assessment,"
        " scope, grant, scanner dispatch, risk treatment, remediation or release.</p>"
        "<table><thead><tr><th>Case</th><th>Priority</th><th>Source</th>"
        "<th>Workstream</th><th>Human stage</th><th>Follow-up date</th>"
        "<th>Metric regressions</th></tr></thead><tbody>"
        + entries +
        "</tbody></table><p>Scenario identities, asset paths and original source"
        " fingerprints omitted from this printable page. The private archive"
        " retains the original Review Desk JSON for source-bound restoration."
        "</p></body></html>"
    )
    data = body.encode("utf-8")
    if len(data) > 131_072:
        raise ValueError("human report over limit")
    return data


def _read_members(input_path):
    # This original source inspector checks fixed private packaging and hashes.
    # Verify and subsequently parse the SAME original source-byte snapshot.
    # Never re-open a user-controlled pathname after source admission.
    raw, _ = _read_raw_archive(input_path)
    source_status = inspect_pack_bytes(raw)
    if source_status not in ("REVIEW_ONLY", "HOLD"):
        raise ValueError("unsupported original review")
    with ZipFile(BytesIO(raw), "r") as source:
        content = {name: source.read(name) for name in CAPS}
    return content, source_status


def _read_raw_archive(path):
    import os
    import stat
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("non-regular package")
        raw = source.read(MAX_PACK + 1)
    if not raw or len(raw) > MAX_PACK:
        raise ValueError("oversized private package")
    return raw, sha256(raw).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", help="Original intact seven-member private review ZIP")
    parser.add_argument("saved_review", help="Browser-exported original v1/v2 human review JSON")
    parser.add_argument("--output", required=True, help="New private annotated ZIP; never overwrite")
    args = parser.parse_args(argv)
    try:
        content, status = _read_members(args.package)
        saved, _ = _snapshot(args.saved_review, MAX_REVIEW)
        if type(saved) is not dict:
            raise ValueError("invalid saved human review")
        source_hash = sha256(content["review-desk.json"]).hexdigest()
        comparison = _json(content["review-desk.json"])
        rows = _validate_plan(saved, comparison, source_hash)
        plan = json.dumps(saved, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
        if len(plan) > MAX_REVIEW:
            raise ValueError("review too large")
        summary = _human_report(rows, status)
        followup_landing = _pinned_pack_asset("followup.html", FOLLOWUP_SHA256, 16_384)
        manifest = _json(content["manifest.json"])
        manifest["format"] = "lightup.private_lab_review_pack.v2"
        manifest["saved_human_review_sha256"] = sha256(plan).hexdigest()
        manifest["human_summary_sha256"] = sha256(summary).hexdigest()
        manifest["followup_landing_sha256"] = FOLLOWUP_SHA256
        manifest["saved_human_review_source_sha256"] = source_hash
        content["manifest.json"] = json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        content["saved-human-review.json"] = plan
        content["human-summary.html"] = summary
        content["review-followup.html"] = followup_landing
        buffer = BytesIO()
        with ZipFile(buffer, "w") as target:
            for name, data in content.items():
                member = ZipInfo(name, date_time=(2026, 10, 18, 0, 0, 0))
                member.compress_type = ZIP_DEFLATED
                member.external_attr = 0o600 << 16
                target.writestr(member, data)
        if len(buffer.getvalue()) > MAX_ATTACHED:
            raise ValueError("annotated package exceeds bound")
        _write_exclusive(args.output, buffer.getvalue())
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            UnicodeError, RecursionError, AttributeError, RuntimeError,
            EOFError, NotImplementedError, BadZipFile, LargeZipFile):
        print("PRIVATE_HUMAN_REVIEW_HOLD")
        return 3
    print("PRIVATE_HUMAN_REVIEW_ATTACHED — " + status +
          "; UNSIGNED; NOT AUTHORIZED")
    return 2 if status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
