#!/usr/bin/env python3
"""Opt-in read-only GitHub CI evidence check; NEVER authorizes LightUp execution."""
from __future__ import annotations
import argparse
import json
import os
import re
import sys
from urllib.request import HTTPRedirectHandler, Request, build_opener

API_ROOT = "https://api.github.com/repos/Zennay/Lightup/actions/runs/"
PR_ROOT = "https://api.github.com/repos/Zennay/Lightup/pulls/"
SHA = re.compile(r"[0-9a-f]{40}\Z")
REPO = "Zennay/Lightup"
HOSTED_WORKFLOW = ("LightUp offline preflight", ".github/workflows/lightup-preflight.yml", 375432315)
VPS_WORKFLOW = ("LightUp CI", ".github/workflows/lightup-ci.yml", 373018063)
VPS_RUNNER = "zcloud-vps-1"
VPS_LABELS = frozenset(("self-hosted", "zcloud", "vps"))
HOSTED = frozenset((
    "Offline preflight Python 3.11 (not VPS proof)",
    "Offline preflight Python 3.14 (not VPS proof)",
    "Real producer integration Python 3.11 (not VPS proof)",
    "Real producer integration Python 3.14 (not VPS proof)",
))
PERMANENT = frozenset((
    "LightUp plan-only safety tests (Python 3.11)",
    "LightUp plan-only safety tests (Python 3.14)",
))

def _receipt(holds: list[str]) -> dict:
    return {
        "state": "HOLD" if holds else "EVIDENCE_COMPLETE_NOT_AUTHORIZED",
        "missing_gates": sorted(set(holds)),
        "run_evidence_consistent": not holds,
        "authorization_verified": False,
        "permit_issued": False,
        "execution_enabled": False,
        "release_approved": False,
    }

def evaluate(head: str, hosted_id: int, vps_id: int,
             hosted: object, hosted_jobs: object, vps: object, vps_jobs: object) -> dict:
    """Metadata-only evaluation; fabricated local objects are not GitHub proof."""
    if type(head) is not str or SHA.fullmatch(head) is None:
        return _receipt(["invalid_head"])
    if (type(hosted_id) is not int or type(vps_id) is not int
            or not 0 < hosted_id < 10**17 or not 0 < vps_id < 10**17
            or hosted_id == vps_id):
        return _receipt(["invalid_run_identity"])
    holds: list[str] = []
    for name, run, run_id, listing, required, is_vps in (
        ("hosted", hosted, hosted_id, hosted_jobs, HOSTED, False),
        ("permanent_vps", vps, vps_id, vps_jobs, PERMANENT, True),
    ):
        if not isinstance(run, dict) or not isinstance(listing, dict):
            holds.append(f"{name}_missing_metadata")
            continue
        workflow = VPS_WORKFLOW if is_vps else HOSTED_WORKFLOW
        if ((run.get("name"), run.get("path"), run.get("workflow_id")) != workflow
                or run.get("event") != "pull_request"
                or not isinstance(run.get("repository"), dict)
                or run["repository"].get("full_name") != REPO
                or not isinstance(run.get("head_repository"), dict)
                or run["head_repository"].get("full_name") != REPO):
            holds.append(f"{name}_workflow_identity_mismatch")
        if (type(run.get("id")) is not int or run.get("id") != run_id
                or type(run.get("head_sha")) is not str
                or run.get("head_sha") != head):
            holds.append(f"{name}_head_or_run_mismatch")
        if (run.get("status") != "completed" or run.get("conclusion") != "success"
                or type(run.get("run_attempt")) is not int or run["run_attempt"] < 1):
            holds.append(f"{name}_run_not_successful")
        jobs, total = listing.get("jobs"), listing.get("total_count")
        if (type(jobs) is not list or type(total) is not int
                or total != len(jobs) or not 0 < total <= 100):
            holds.append(f"{name}_incomplete_jobs")
            continue
        if any(not isinstance(job, dict) or type(job.get("name")) is not str for job in jobs):
            holds.append(f"{name}_malformed_jobs")
            continue
        names = [job["name"] for job in jobs]
        if len(names) != len(set(names)) or set(names) != required:
            holds.append(f"{name}_job_set_mismatch")
        for job in jobs:
            if (type(job.get("run_id")) is not int or job.get("run_id") != run_id
                    or type(job.get("run_attempt")) is not int
                    or job.get("run_attempt") != run.get("run_attempt")):
                holds.append(f"{name}_job_run_identity_mismatch")
            if (job.get("head_sha") != head or job.get("status") != "completed"
                    or job.get("conclusion") != "success"):
                holds.append(f"{name}_job_not_successful_on_head")
            labels = job.get("labels")
            if (type(labels) is not list or any(type(s) is not str for s in labels)
                    or (is_vps and (not VPS_LABELS.issubset(labels)
                                    or job.get("runner_name") != VPS_RUNNER))
                    or (not is_vps and ("ubuntu-latest" not in labels
                                         or "self-hosted" in labels
                                         or job.get("runner_name") in (None, "")))):
                holds.append(f"{name}_runner_unverified")
    return _receipt(holds)

class _DenyRedirects(HTTPRedirectHandler):
    """Do not forward an optional API token beyond the fixed GitHub API origin."""

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def verify_pr_head(head: str, pr_number: int, pr: object) -> list[str]:
    """Reject run evidence that belongs to an outdated or unrelated PR revision."""
    if type(pr_number) is not int or not 0 < pr_number < 10**10:
        return ["invalid_pr_identity"]
    if not isinstance(pr, dict):
        return ["pr_metadata_missing"]
    if (pr.get("number") != pr_number or pr.get("state") != "open"
            or pr.get("draft") is not True):
        return ["pr_state_or_identity_mismatch"]
    current = pr.get("head")
    base = pr.get("base")
    if (not isinstance(current, dict) or not isinstance(base, dict)
            or current.get("sha") != head
            or not isinstance(current.get("repo"), dict)
            or current["repo"].get("full_name") != REPO
            or not isinstance(base.get("repo"), dict)
            or base["repo"].get("full_name") != REPO):
        return ["pr_current_head_or_repository_mismatch"]
    return []


def _get_json(url: str, token: str | None) -> object:
    # URLs use a fixed GitHub endpoint, never a user-controlled destination.
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "LightUp-scope-CI-evidence-optin"}
    if token:
        headers["Authorization"] = "Bearer " + token
    with build_opener(_DenyRedirects()).open(Request(url, headers=headers, method="GET"), timeout=8) as response:
        raw = response.read(524289)
    if len(raw) > 524288:
        raise ValueError("too much metadata")
    return json.loads(raw.decode("utf-8"))

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only CI evidence, NEVER authorization")
    parser.add_argument("--head", required=True)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--hosted-run", required=True, type=int)
    parser.add_argument("--vps-run", required=True, type=int)
    args = parser.parse_args(argv)
    if (SHA.fullmatch(args.head) is None or not 0 < args.hosted_run < 10**17
            or not 0 < args.vps_run < 10**17 or args.hosted_run == args.vps_run
            or not 0 < args.pr < 10**10):
        print(json.dumps(_receipt(["invalid_input"]), sort_keys=True))
        return 2
    try:
        token = os.environ.get("GITHUB_TOKEN")
        pr = _get_json(f"{PR_ROOT}{args.pr}", token)
        hosted = _get_json(f"{API_ROOT}{args.hosted_run}", token)
        hj = _get_json(f"{API_ROOT}{args.hosted_run}/jobs?per_page=100", token)
        vps = _get_json(f"{API_ROOT}{args.vps_run}", token)
        vj = _get_json(f"{API_ROOT}{args.vps_run}/jobs?per_page=100", token)
        receipt = evaluate(args.head, args.hosted_run, args.vps_run, hosted, hj, vps, vj)
        receipt = _receipt(receipt["missing_gates"] + verify_pr_head(args.head, args.pr, pr))
    except Exception:
        # Error bodies and credentials must never enter the receipt.
        receipt = _receipt(["metadata_unavailable"])
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["run_evidence_consistent"] else 2

if __name__ == "__main__":
    sys.exit(main())
