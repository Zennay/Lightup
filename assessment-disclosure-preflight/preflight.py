"""Private offline preflight before sharing LightUp original lab artifacts.

Read-only integration with the original held lightup.lab_inspect validator.
No scan, model, network, consent inference, raw source export, or verification.
"""
from __future__ import annotations

import argparse
import csv
import html
import io
import json
import os
from pathlib import Path
import stat
import sys

KINDS = ("isolated_lab_input_preview", "offline_lab_benchmark_source", "isolated_lab_assessment")
SEVERITIES = ("critical", "high", "medium", "low", "info")
FALSE_FLAGS = ("source_authenticated", "ground_truth_verified", "client_consent_verified",
               "operator_consent_verified", "authorization_granted", "dispatch_allowed", "release_allowed")
FILES = ("PRIVATE-review.html", "PRIVATE-receipt.json", "PRIVATE-counts.csv")
MAX_SOURCES = 12


class Hold(Exception):
    """A generic refusal: source details should not escape in exceptions."""


def require(ok: bool) -> None:
    if not ok:
        raise Hold("HOLD: private source or output is not admitted")


def nonnegative(value: object, ceiling: int = 1_000_000_000) -> int:
    require(type(value) is int and 0 <= value <= ceiling)
    return value


def admitted_counts(source: dict) -> dict:
    """Allowlist only original validated, source-free fields; no arbitrary keys."""
    require(type(source) is dict)
    require(source.get("schema") == "lightup.lab_artifact_inspection.v1")
    require(source.get("status") == "REVIEW_ONLY")
    require(all(source.get(flag) is False for flag in FALSE_FLAGS))
    kind = source.get("artifact_kind")
    require(type(kind) is str and kind in KINDS)
    # The original preview deliberately has no comparison_performed field;
    # benchmark and assessment summaries must expose literal false.
    if kind == KINDS[0]:
        require("comparison_performed" not in source)
    else:
        require(source.get("comparison_performed") is False)
    row = {"kind": kind}
    if kind == KINDS[0]:
        require(source.get("assessment_executed") is False)
        row["endpoints"] = nonnegative(source.get("declared_endpoint_count"), 16)
        require(row["endpoints"] >= 1)
    elif kind == KINDS[1]:
        require(source.get("assessment_executed") == "caller_declares_lab_record")
        metrics = source.get("declared_metrics")
        require(type(metrics) is dict)
        keys = ("valid_findings", "invalid_findings", "missed_findings",
                "coverage_assessed", "coverage_unknown")
        row["metrics"] = {key: nonnegative(metrics.get("declared_" + key)) for key in keys}
    else:
        require(source.get("assessment_executed") == "caller_declares_lab_result")
        row["endpoints"] = nonnegative(source.get("declared_target_count"), 16)
        require(1 <= row["endpoints"] <= 16)
        row["findings"] = nonnegative(source.get("declared_finding_count"), 2048)
        raw = source.get("declared_severity_counts")
        require(type(raw) is dict and set(raw) == set(SEVERITIES))
        row["severity"] = {key: nonnegative(raw[key], 2048) for key in SEVERITIES}
        require(sum(row["severity"].values()) == row["findings"])
        for field, original in (
            ("with_ref", "findings_with_source_reference"),
            ("with_summary", "findings_with_source_summary"),
            ("with_id", "findings_with_unique_identity"),
        ):
            row[field] = nonnegative(source.get(original), 2048)
            require(row[field] <= row["findings"])
        require(type(source.get("model_review_included")) is bool)
        row["review_present"] = source["model_review_included"]
    return row


def inspect_sources(paths: list[str]) -> list[dict]:
    """Import only the original held inspector, never decode private input here."""
    try:
        from lightup.lab_inspect import ArtifactRejected, inspect_artifact
    except (ImportError, AttributeError):
        raise Hold("HOLD: original lab-inspect is not installed") from None
    rows = []
    for name in paths:
        try:
            rows.append(admitted_counts(inspect_artifact(name)))
        except (ArtifactRejected, ValueError, TypeError, OSError, RecursionError):
            raise Hold("HOLD: source refused by original inspector") from None
    return rows


def public_cohort(rows: list[dict], minimum: int) -> dict:
    """Default-deny: no per-source values and no small-cohort breakdown."""
    count = len(rows)
    if count < minimum:
        return {"disclosure": "SUPPRESSED_SMALL_COHORT", "sources": "SUPPRESSED"}
    kinds = {kind: sum(row["kind"] == kind for row in rows) for kind in KINDS}
    # Do not expose any category count if a nonzero group would identify <k sources.
    expose_kinds = all(value == 0 or value >= minimum for value in kinds.values())
    return {
        "disclosure": "HUMAN_REVIEW_ONLY_NOT_ANONYMITY",
        "sources": count,
        "artifact_groups": kinds if expose_kinds else "SUPPRESSED_SMALL_GROUP",
        "source_authenticated": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "authorization_granted": False,
        "release_allowed": False,
    }


def human_attention(row: dict) -> list[str]:
    """Conservative source-declaration gaps: prompts for humans, not a verdict."""
    if row["kind"] == KINDS[0]:
        return ["preview_only_no_assessment_has_run"]
    if row["kind"] == KINDS[1]:
        return ["benchmark_metrics_are_unverified_source_claims"]
    count = row["findings"]
    if count == 0:
        return ["no_findings_declared_not_proof_of_safety"]
    flags = []
    if row["with_ref"] < count:
        flags.append("some_findings_lack_evidence_references")
    if row["with_summary"] < count:
        flags.append("some_findings_lack_evidence_summaries")
    if row["with_id"] < count:
        flags.append("some_findings_lack_unique_record_identity")
    if row["review_present"]:
        flags.append("model_review_is_a_claim_not_verification")
    return flags or ["no_count_level_gap_identified_not_a_security_verdict"]


def private_receipt(rows: list[dict]) -> dict:
    """Receipt is private and intentionally not source-byte bound or signed."""
    return {
        "schema": "lightup.assessment_disclosure_preflight.v1",
        "status": "REVIEW_ONLY",
        "source_authenticated": False,
        "source_byte_bound": False,
        "ground_truth_verified": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "authorization_granted": False,
        "dispatch_allowed": False,
        "release_allowed": False,
        "source_count": len(rows),
        "inspected_declarations_only": [
            {"ordinal": index + 1, **row, "human_attention": human_attention(row)}
            for index, row in enumerate(rows)
        ],
    }


def private_html(rows: list[dict]) -> str:
    body = []
    for index, row in enumerate(rows, 1):
        details = []
        if "endpoints" in row:
            details.append("Declared endpoints: " + str(row["endpoints"]))
        if "findings" in row:
            details.append("Declared findings: " + str(row["findings"]))
            details.append("Evidence references: " + str(row["with_ref"]))
            details.append("Evidence summaries: " + str(row["with_summary"]))
            details.append("Unique finding IDs: " + str(row["with_id"]))
            details.append("Declared severities: " + ", ".join(
                key + " " + str(row["severity"][key]) for key in SEVERITIES))
            details.append("Model review present (source claim): " + str(row["review_present"]))
        if "metrics" in row:
            details.append("Declared benchmark metrics: " + ", ".join(
                key + " " + str(value) for key, value in row["metrics"].items()))
        details.append("HUMAN attention (source claim only): " + ", ".join(human_attention(row)))
        safe = "; ".join(details)
        body.append("<tr><th scope='row'>" + str(index) + "</th><td>" +
                    html.escape(row["kind"]) + "</td><td>" + html.escape(safe) + "</td></tr>")
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy"
 content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; form-action 'none'; connect-src 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LightUp PRIVATE disclosure preflight</title>
<style>body{font:16px/1.5 system-ui;max-width:980px;margin:2rem auto;padding:0 1rem;color:#202327}
h1{font-size:1.7rem}p{max-width:80ch}table{border-collapse:collapse;width:100%;overflow-wrap:anywhere}
th,td{padding:.8rem;border:1px solid #999;text-align:left;vertical-align:top}
thead{background:#eee}.warning{border-left:5px solid #944;padding:1rem;background:#f9f3f3}
@media print{body{margin:0}.warning{border:1px solid #444}}</style></head><body>
<h1>PRIVATE assessment disclosure preflight</h1>
<p class="warning"><strong>REVIEW ONLY / HOLD for release.</strong>
These are untrusted declarations from locally selected private laboratory JSON artifacts.
No original artifact names, targets, source paths, finding titles, evidence bodies,
model responses or credentials are reproduced. This report is still PRIVATE;
small groups and declared aggregate values may disclose confidential context.
Neither this tool nor the original inspector verifies origin, tenant, consent,
revocation, findings, remediation, release, or authorization. No scans are run.</p>
<p>Before any recipient handoff: obtain separate genuine source-owner, client and
operator authorization; verify action-time revocation and original release gates;
inspect disclosure risk manually. A source ordinal here is local, not a durable ID.</p>
<table><thead><tr><th>Local ordinal</th><th>Original claimed kind</th>
<th>Source-declared counts only</th></tr></thead><tbody>""" + "".join(body) + """</tbody></table>
<p>No raw private input is included. No JavaScript, external resources, network or
automated publish action. Signed source provenance is NOT supplied.</p></body></html>
"""


def csv_counts(rows: list[dict], minimum: int) -> str:
    cohort = public_cohort(rows, minimum)
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(("field", "value"))
    writer.writerow(("status", "REVIEW_ONLY"))
    writer.writerow(("disclosure", cohort["disclosure"]))
    writer.writerow(("sources", cohort["sources"]))
    groups = cohort.get("artifact_groups", "SUPPRESSED")
    if type(groups) is dict:
        for kind in KINDS:
            writer.writerow(("count_" + kind, groups[kind]))
    else:
        writer.writerow(("artifact_groups", groups))
    writer.writerow(("not_public_anonymization", "TRUE"))
    writer.writerow(("release_allowed", "FALSE"))
    return output.getvalue()


def output_directory(path: str) -> Path:
    directory = Path(path)
    try:
        info = os.lstat(directory)
        require(stat.S_ISDIR(info.st_mode))
        require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0)
        for name in FILES:
            require(not (directory / name).exists() and not (directory / name).is_symlink())
    except (OSError, ValueError):
        raise Hold("HOLD: private 0700 output directory required") from None
    return directory


def publish(directory: Path, files: dict[str, str]) -> None:
    """Prepare full 0600 files in one pinned owner-only directory descriptor.

    Final names appear by exclusive hard-link only after complete fsynced staging.
    On ordinary failure new final names are removed. Sudden process failure may
    leave PRIVATE staging files but cannot publish a partial final file.
    """
    dirfd = -1
    staged: list[str] = []
    created: list[str] = []
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        dirfd = os.open(directory, flags)
        info = os.fstat(dirfd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and info.st_mode & 0o077 == 0)
        require(type(files) is dict and set(files) == set(FILES))
        for name in FILES:
            stage = ".lightup-disclosure-private-" + os.urandom(16).hex()
            fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=dirfd)
            staged.append(stage)
            with os.fdopen(fd, "wb") as stream:
                stream.write(files[name].encode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
        # Every final must be new; no symlink or existing file is overwritten.
        for name, stage in zip(FILES, staged):
            os.link(stage, name, src_dir_fd=dirfd, dst_dir_fd=dirfd,
                    follow_symlinks=False)
            created.append(name)
        os.fsync(dirfd)
    except (OSError, ValueError, TypeError):
        for name in reversed(created):
            if dirfd >= 0:
                try:
                    os.unlink(name, dir_fd=dirfd)
                except OSError:
                    pass
        raise Hold("HOLD: private outputs were not published") from None
    finally:
        if dirfd >= 0:
            for stage in staged:
                try:
                    os.unlink(stage, dir_fd=dirfd)
                except OSError:
                    pass
            os.close(dirfd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline original LightUp assessment disclosure preflight")
    parser.add_argument("private_artifacts", nargs="+", help="1-12 existing original owner-private lab JSON sources")
    parser.add_argument("--private-output-dir", required=True, help="existing owner-only 0700 directory")
    parser.add_argument("--minimum-cohort", type=int, default=5, help="minimum source count for counts-only release (default 5)")
    args = parser.parse_args(argv)
    try:
        require(1 <= len(args.private_artifacts) <= MAX_SOURCES)
        require(type(args.minimum_cohort) is int and 5 <= args.minimum_cohort <= MAX_SOURCES)
        directory = output_directory(args.private_output_dir)
        rows = inspect_sources(args.private_artifacts)
        receipt = json.dumps(private_receipt(rows), ensure_ascii=True, sort_keys=True, indent=2) + "\n"
        files = {
            FILES[0]: private_html(rows),
            FILES[1]: receipt,
            FILES[2]: csv_counts(rows, args.minimum_cohort),
        }
        publish(directory, files)
    except Hold:
        print("HOLD: private assessment disclosure preflight refused; no approval or publication", file=sys.stderr)
        return 3
    print("REVIEW_ONLY: three PRIVATE outputs created; no transfer, scan, or authority granted")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
