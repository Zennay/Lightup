#!/usr/bin/env python3
"""Private original offline lab benchmark workroom; never an execution verdict."""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import json
import math
import os
import stat
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from suite import Hold, ROOT, parent_dir, read_safe, copy_app

ORIGINAL = {
    "single": (ROOT / "scripts/assessment_runtime_compare_cli_1513.py", 65_536),
    "cohort": (ROOT / "scripts/assessment_runtime_compare_cohort_cli_1513.py", 262_144),
    "scored": (ROOT / "scripts/assessment_runtime_ground_truth_cohort_cli_1513.py", 262_144),
}
FALSE = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")
METRICS = (
    "valid_findings", "invalid_findings", "missed_findings",
    "coverage_assessed", "coverage_unknown", "scope_violations",
    "policy_violations", "human_interventions", "tool_calls",
    "evidence_quality", "reproducibility", "remediation_quality",
    "retest_correctness", "runtime_seconds", "compute_cost_usd",
)


def original_input(name: str, cap: int) -> tuple[int, str, str]:
    path = Path(name).absolute()
    read_safe(path, cap)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or not 0 < meta.st_size <= cap:
            raise Hold("HOLD: source is not a bounded regular file")
        raw = bytearray()
        while len(raw) <= cap:
            piece = os.read(fd, min(65_536, cap + 1 - len(raw)))
            if not piece:
                break
            raw.extend(piece)
        if not 0 < len(raw) <= cap or len(raw) != meta.st_size:
            raise Hold("HOLD: source changed during read")
        # Reuse the open original descriptor in the child: path replacement
        # cannot change which bytes the original comparator reads.
        proc = f"/proc/self/fd/{fd}"
        if not Path(proc).exists():
            raise Hold("HOLD: descriptor-bound source access unavailable")
        return fd, proc, hashlib.sha256(raw).hexdigest()
    except BaseException:
        os.close(fd)
        raise


def parse_output(raw: bytes, exit_code: int, kind: str) -> dict:
    if exit_code not in (2, 3) or not 0 < len(raw) <= 2_000_000:
        raise Hold("HOLD: original comparator refused or exceeded bounded output")
    try:
        result = json.loads(raw.decode("utf-8"), parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError):
        raise Hold("HOLD: original comparator returned invalid JSON") from None
    if type(result) is not dict or result.get("status") not in ("HOLD", "REVIEW_ONLY"):
        raise Hold("HOLD: original comparator returned unsupported status")
    if any(result.get(flag) is not False for flag in FALSE):
        raise Hold("HOLD: original comparator reported unexpected authority")
    if exit_code != (2 if result["status"] == "REVIEW_ONLY" else 3):
        raise Hold("HOLD: original comparator exit/status mismatch")

    def admitted_metric(value: object) -> bool:
        return type(value) in (float, int) and math.isfinite(value) and abs(value) <= 1_000_000_000_000

    def changes(obj: object) -> list[dict]:
        if type(obj) is not list or len(obj) != len(METRICS):
            raise Hold("HOLD: original comparison has no complete metrics")
        seen = []
        for row in obj:
            if type(row) is not dict or set(row) != {
                    "name", "baseline", "candidate", "delta", "regression"}:
                raise Hold("HOLD: original metric schema mismatch")
            if row["name"] not in METRICS or type(row["name"]) is not str:
                raise Hold("HOLD: unsupported metric name")
            if (not all(admitted_metric(row[f]) for f in ("baseline", "candidate", "delta"))
                    or type(row["regression"]) is not bool):
                raise Hold("HOLD: invalid metric declaration")
            seen.append(row["name"])
        if set(seen) != set(METRICS):
            raise Hold("HOLD: incomplete or duplicate original metrics")
        return obj

    if kind == "single":
        if set(result) != {"status", *FALSE, "regressions", "changes"}:
            raise Hold("HOLD: invalid single-case comparison")
        metrics = changes(result["changes"])
        if type(result["regressions"]) is not list or any(
            type(x) is not str or x not in METRICS for x in result["regressions"]
        ):
            raise Hold("HOLD: invalid source regression list")
        if set(result["regressions"]) != {
                metric["name"] for metric in metrics if metric["regression"]}:
            raise Hold("HOLD: contradictory original regression flags")
        groups = [{"scenario": "selected original lab case", "status": result["status"],
                   "changes": metrics, "regressions": list(result["regressions"])}]
    else:
        if set(result) != {"status", *FALSE, "regressed_scenarios", "comparisons"}:
            raise Hold("HOLD: invalid cohort comparison schema")
        objects = result["comparisons"]
        if type(objects) is not list or not 1 <= len(objects) <= 64:
            # Native generic HOLD has no comparisons, and must not become a report.
            raise Hold("HOLD: no complete original cohort comparisons were admitted")
        groups = []
        for item in objects:
            if type(item) is not dict or set(item) != {
                    "scenario_id", "status", "changes", "regressions"}:
                raise Hold("HOLD: malformed original scenario comparison")
            scenario = item["scenario_id"]
            if type(scenario) is not str or not 0 < len(scenario) <= 256:
                raise Hold("HOLD: invalid original scenario label")
            metrics = changes(item["changes"])
            if item["status"] not in ("HOLD", "REVIEW_ONLY"):
                raise Hold("HOLD: invalid scenario status")
            regressions = item["regressions"]
            if type(regressions) is not list or set(regressions) != {
                    row["name"] for row in metrics if row["regression"]}:
                raise Hold("HOLD: contradictory cohort metric regressions")
            groups.append({"scenario": scenario, "status": item["status"],
                           "changes": metrics, "regressions": regressions})
        if len({row["scenario"] for row in groups}) != len(groups):
            raise Hold("HOLD: duplicate original scenario identity")
        if type(result["regressed_scenarios"]) is not list or set(result["regressed_scenarios"]) != {
                row["scenario"] for row in groups if row["regressions"]}:
            raise Hold("HOLD: incomplete original adverse scenario list")
    if result["status"] != ("HOLD" if any(item["regressions"] for item in groups)
                            else "REVIEW_ONLY"):
        raise Hold("HOLD: ambiguous original aggregate regression status")
    return {"status": result["status"], "groups": groups, "kind": kind,
            "original_canonical_output": result,
            **{key: False for key in FALSE}}


def original_compare(kind: str, before: str, after: str) -> dict:
    script, cap = ORIGINAL[kind]
    read_safe(script, 500_000)
    first_fd, first, before_sha = original_input(before, cap)
    try:
        second_fd, second, after_sha = original_input(after, cap)
        try:
            if before_sha == after_sha:
                raise Hold("HOLD: baseline and candidate source bytes identical")
            env = dict(os.environ)
            env["PYTHONPATH"] = str(ROOT / "src")
            env["PYTHONNOUSERSITE"] = "1"
            try:
                run = subprocess.run(
                    [sys.executable, "-P", str(script), first, second],
                    cwd=ROOT, env=env, capture_output=True, check=False,
                    pass_fds=(first_fd, second_fd), timeout=120,
                )
            except (OSError, subprocess.TimeoutExpired):
                raise Hold("HOLD: original offline comparator did not finish") from None
            result = parse_output(run.stdout, run.returncode, kind)
            result["original_source_byte_hashes_unsigned"] = {
                "baseline": before_sha, "candidate": after_sha,
            }
            return result
        finally:
            os.close(second_fd)
    finally:
        os.close(first_fd)


def make_html(data: dict) -> bytes:
    blocks = []
    for group in data["groups"]:
        metrics = "".join(
            "<tr class='" + ("regressed" if row["regression"] else "") + "'>"
            "<th scope='row'>" + html.escape(row["name"]) + "</th>"
            "<td>" + html.escape(str(row["baseline"])) + "</td>"
            "<td>" + html.escape(str(row["candidate"])) + "</td>"
            "<td>" + html.escape(str(row["delta"])) + "</td>"
            "<td>" + ("HOLD · adverse declared change" if row["regression"] else "Source-declared") +
            "</td></tr>" for row in group["changes"]
        )
        blocks.append(
            "<section><h2>" + html.escape(group["scenario"]) + "</h2><p>Original declared comparison: <b>" +
            html.escape(group["status"]) + "</b>; adverse primary metrics: " +
            str(len(group["regressions"])) + "</p><div class='scroll'><table>"
            "<thead><tr><th>Metric</th><th>Baseline</th><th>Candidate</th><th>Delta</th>"
            "<th>Interpretation</th></tr></thead><tbody>" + metrics + "</tbody></table></div></section>"
        )
    warning = ("Original comparison observed adverse metrics — HOLD for human assessment."
               if data["status"] == "HOLD" else
               "No adverse primary metric reported — REVIEW_ONLY, never a PASS or release.")
    page = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp PRIVATE lab benchmark review</title>
<style>:root{font:16px/1.55 system-ui;color:#152338;background:#f1f5f9}
*{box-sizing:border-box}body{max-width:1280px;margin:auto;padding:28px}
header,section{background:white;border:1px solid #d2dce5;border-radius:16px;padding:20px;margin:16px 0}
h1{margin:0}h2{font-size:1.15rem}.hold{font-weight:750;color:#853b20}
.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:740px;font-size:.91rem}
th,td{border-bottom:1px solid #d5dfea;text-align:left;padding:9px}
thead{background:#eaf0f6}tr.regressed{background:#fff0e9}
footer{padding:18px 0;color:#354b63}@media print{body{background:white;padding:4px}
section{break-inside:avoid}}</style>
<header><p class="hold">ORIGINAL SOURCE DECLARATIONS / PRIVATE / REVIEW_ONLY OR HOLD</p>
<h1>Offline lab benchmark comparison</h1>
<p>""" + html.escape(warning) + """</p>
<p>Source declarations only. Status: <b>""" + html.escape(data["status"]) + """</b>.
Comparison mode: """ + html.escape(data["kind"]) + """. Source scenarios: """ + str(len(data["groups"])) + """.</p>
<p>Two existing caller-supplied lab benchmark documents were compared locally using the
unchanged original held comparator. This does not prove original producer,
ground truth, valid source ownership, verified exposure, remediation, client/operator
authorization, right to scan or release.</p></header>""" + "".join(blocks) + """
<footer>Original records were not copied. Original source SHA-256 are stored only
in the separate PRIVATE unsigned receipt. Do not publish or externally hand off without
genuine current source-owner/privacy review and separate authenticated client + operator
consent including action-time revocation and explicit HUMAN GO. No scan,
target connection, model, retest, grant or network action occurred.
INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.</footer></html>"""
    return page.encode("utf-8")


def private_file(path: Path, content: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)


def prepare(args: argparse.Namespace) -> int:
    parent = parent_dir(args.private_parent)
    review_studio = ROOT / "assessment-review/standalone.html"
    read_safe(review_studio, 2 * 1024 * 1024)
    data = original_compare(args.kind, args.before, args.after)
    kit = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-benchmark-", dir=parent))
    os.chmod(kit, 0o700)
    completed = False
    try:
        private_file(kit / "PRIVATE-original-benchmark.html", make_html(data))
        private_file(kit / "PRIVATE-original-comparison.json", (
            json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8"))
        private_file(
            kit / "PRIVATE-original-canonical-comparison.json",
            (json.dumps(data["original_canonical_output"], sort_keys=True,
                        separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8"),
        )
        copy_app(review_studio, kit / "PRIVATE-original-benchmark-triage.html")
        # This is the unchanged native owner-compatible comparison JSON, so
        # original assessment-candidates and assessment-trends can import it.
        if args.kind in ("cohort", "scored"):
            private_file(
                kit / "PRIVATE-original-canonical-cohort.json",
                (json.dumps(data["original_canonical_output"], sort_keys=True,
                            separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8"),
            )
        csvio = io.StringIO(newline="")
        writer = csv.writer(csvio)
        writer.writerow(("original_scenario_ordinal", "metric", "baseline", "candidate",
                         "delta", "adverse_declared_change"))
        for ordinal, item in enumerate(data["groups"], 1):
            for row in item["changes"]:
                writer.writerow((ordinal, row["name"], row["baseline"],
                                 row["candidate"], row["delta"],
                                 "HOLD" if row["regression"] else ""))
        private_file(kit / "PRIVATE-numeric-review.csv", csvio.getvalue().encode("utf-8"))
        human = io.StringIO(newline="")
        workflow = csv.writer(human)
        workflow.writerow((
            "original_baseline_sha256_unsigned", "original_candidate_sha256_unsigned",
            "original_scenario_ordinal", "original_metric", "adverse_source_declaration",
            "human_review_stage", "human_owner_group", "human_next_question", "human_blocker",
        ))
        source_ids = data["original_source_byte_hashes_unsigned"]
        for ordinal, item in enumerate(data["groups"], 1):
            for row in item["changes"]:
                if row["regression"]:
                    workflow.writerow((
                        source_ids["baseline"], source_ids["candidate"], ordinal,
                        row["name"], "HOLD", "", "", "", "",
                    ))
        private_file(kit / "PRIVATE-human-benchmark-followup.csv",
                     human.getvalue().encode("utf-8"))
        canonical_link = (
            '<li><a href="PRIVATE-original-canonical-cohort.json">Exact original cohort comparison '
            'for offline trend / candidate studios</a></li>'
            if args.kind in ("cohort", "scored") else ""
        )
        status = data["status"]
        page = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LightUp PRIVATE benchmark handoff</title>
<style>body{font:17px/1.6 system-ui;max-width:800px;margin:3rem auto;padding:1rem}
li{padding:.5rem}a{color:#175e88}.hold{font-weight:700;color:#833a1c}</style>
<h1>PRIVATE offline benchmark handoff</h1>
<p class="hold">""" + html.escape(status) + """ — ALWAYS NON-AUTHORIZING, source claims only.</p>
<ul><li><a href="PRIVATE-original-benchmark.html">Detailed PRIVATE original metric comparison</a></li>
<li><a href="PRIVATE-original-comparison.json">PRIVATE unsigned source-bound result JSON</a></li>
<li><a href="PRIVATE-numeric-review.csv">PRIVATE numeric original metric summary</a></li>
<li><a href="PRIVATE-human-benchmark-followup.csv">Original SHA-bound blank HUMAN follow-up for adverse metrics</a></li>
<li><a href="PRIVATE-original-canonical-comparison.json">Original canonical benchmark JSON for HUMAN triage</a></li>
<li><a href="PRIVATE-original-benchmark-triage.html">Open the complete original offline HUMAN Benchmark Review Desk</a></li>""" + canonical_link + """</ul>
<p>Review on a trusted local computer. No client data was sent to a server,
no scanner/model/target was called, and no consent or release granted.
INCUBATE M3/M7 PLAN/LAB ONLY DRAFT/HOLD.</p></html>""")
        private_file(kit / "OPEN-PRIVATE.html", page.encode("utf-8"))
        completed = True
        print("ORIGINAL DECLARATION: " + status + "; PRIVATE offline comparison locally prepared.")
        print("OPEN LOCALLY: " + str(kit / "OPEN-PRIVATE.html"))
        return 2 if status == "REVIEW_ONLY" else 3
    finally:
        if not completed:
            shutil.rmtree(kit)


def main() -> int:
    p = argparse.ArgumentParser(description="PRIVATE original offline benchmark comparison, no lab execution")
    p.add_argument("--kind", required=True, choices=sorted(ORIGINAL),
                   help="single case, cohort or exact declared-ground-truth cohort")
    p.add_argument("--before", required=True, help="existing original PRIVATE baseline JSON")
    p.add_argument("--after", required=True, help="existing original PRIVATE candidate JSON")
    p.add_argument("--private-parent", required=True, help="existing owner-private 0700 directory")
    args = p.parse_args()
    try:
        return prepare(args)
    except (Hold, ValueError, OSError) as exc:
        print(str(exc) if isinstance(exc, Hold) else "HOLD: original private benchmark admission refused",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
