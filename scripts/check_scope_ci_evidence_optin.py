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
MAIN_REF = "https://api.github.com/repos/Zennay/Lightup/git/ref/heads/main"
_ALLOWED_API_URL = re.compile(
    r"https://api\.github\.com/repos/Zennay/Lightup/"
    r"(?:git/ref/heads/main"
    r"|pulls/[1-9][0-9]{0,9}(?:/files\?per_page=100)?"
    r"|actions/runs/[1-9][0-9]{0,16}(?:/jobs\?per_page=100)?)\Z"
)
SHA = re.compile(r"[0-9a-f]{40}\Z")
REPO = "Zennay/Lightup"
HOSTED_WORKFLOW = ("LightUp offline preflight", ".github/workflows/lightup-preflight.yml", 375432315)
VPS_WORKFLOW = ("LightUp CI", ".github/workflows/lightup-ci.yml", 373018063)
VPS_RUNNER = "zcloud-vps-1"
CRITICAL_CI_PATHS = frozenset((
    ".github/workflows/lightup-ci.yml",
    ".github/workflows/lightup-preflight.yml",
    "scripts/check_safety_canaries.py",
))
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
HOSTED_PREFLIGHT_ORDER = (
    "Run actions/checkout@v4",
    "Run actions/setup-python@v5",
    "Compile and unit suite",
    "Repeat activation and web canaries with isolated state",
)
HOSTED_INTEGRATION_ORDER = (
    "Run actions/checkout@v4",
    "Run actions/setup-python@v5",
    "Combined unit suite and real producer integration",
    "State verification boundary",
)
VPS_CRITICAL_ORDER = (
    "Guard permanent VPS runner",
    "Checkout",
    "Setup Python",
    "Compile",
    "Unit tests",
    "Real producer integration (requires merged ST2/ST3 predecessors)",
    "Offline activation and web canaries (isolated state)",
)
HOSTED_PREFLIGHT_STEPS = frozenset(HOSTED_PREFLIGHT_ORDER)
HOSTED_INTEGRATION_STEPS = frozenset(HOSTED_INTEGRATION_ORDER)
VPS_CRITICAL_STEPS = frozenset(VPS_CRITICAL_ORDER)


def _verified_required_steps(job: dict, required: tuple[str, ...]) -> bool:
    """Require recorded completion and ordered admission, never just green job."""
    steps = job.get("steps")
    if type(steps) is not list or not 0 < len(steps) <= 40:
        return False
    seen: dict[str, dict] = {}
    last_number = 0
    for step in steps:
        if not isinstance(step, dict) or type(step.get("name")) is not str:
            return False
        name, number = step["name"], step.get("number")
        if (not name or name in seen or type(number) is not int
                or not last_number < number <= 100):
            return False
        last_number = number
        seen[name] = step
    last_number = 0
    for name in required:
        current = seen.get(name)
        if (current is None
                or current.get("status") != "completed"
                or current.get("conclusion") != "success"
                or current["number"] <= last_number):
            return False
        last_number = current["number"]
    return True


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
            required_steps = (VPS_CRITICAL_ORDER if is_vps else
                              HOSTED_INTEGRATION_ORDER if job["name"].startswith("Real producer")
                              else HOSTED_PREFLIGHT_ORDER)
            if not _verified_required_steps(job, required_steps):
                holds.append(f"{name}_critical_steps_unverified")
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


def verify_run_pr_binding(head: str, pr_number: int, pr: object,
                          hosted: object, vps: object) -> list[str]:
    """Bind both CI runs to the same current PR head, branch and base.

    This checks consistency of GitHub API metadata only; it is not a signature
    or a customer authorization. Missing or ambiguous PR links fail closed.
    """
    if not isinstance(pr, dict):
        return ["pr_metadata_missing"]
    current, base = pr.get("head"), pr.get("base")
    if not isinstance(current, dict) or not isinstance(base, dict):
        return ["pr_branch_metadata_missing"]
    head_ref, base_ref, base_sha = current.get("ref"), base.get("ref"), base.get("sha")
    if (type(head_ref) is not str or not head_ref
            or base_ref != "main" or type(base_sha) is not str
            or SHA.fullmatch(base_sha) is None):
        return ["pr_base_or_branch_invalid"]
    holds = []
    for name, run in (("hosted", hosted), ("permanent_vps", vps)):
        if not isinstance(run, dict):
            holds.append(f"{name}_pr_binding_missing")
            continue
        linked = run.get("pull_requests")
        if (run.get("head_branch") != head_ref or type(linked) is not list
                or len(linked) != 1 or not isinstance(linked[0], dict)):
            holds.append(f"{name}_pr_binding_mismatch")
            continue
        linked_pr = linked[0]
        linked_head, linked_base = linked_pr.get("head"), linked_pr.get("base")
        if (type(linked_pr.get("number")) is not int
                or linked_pr.get("number") != pr_number
                or not isinstance(linked_head, dict)
                or linked_head.get("ref") != head_ref
                or linked_head.get("sha") != head
                or not isinstance(linked_base, dict)
                or linked_base.get("ref") != base_ref
                or linked_base.get("sha") != base_sha):
            holds.append(f"{name}_pr_binding_mismatch")
    return holds


def _unique_json_keys(pairs: list[tuple[str, object]]) -> dict:
    """Never resolve conflicting metadata by silently taking its last value."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("ambiguous metadata")
        result[key] = value
    return result


def _reject_nonfinite_json(_value: str) -> None:
    raise ValueError("nonfinite metadata")


def verify_current_main(pr: object, main_ref: object) -> list[str]:
    """Treat changed or unverifiable main as missing latest-main composition."""
    if not isinstance(pr, dict) or not isinstance(pr.get("base"), dict):
        return ["current_main_unverified"]
    if (not isinstance(main_ref, dict)
            or main_ref.get("ref") != "refs/heads/main"
            or not isinstance(main_ref.get("object"), dict)):
        return ["current_main_unverified"]
    base = pr["base"]
    current = main_ref["object"]
    if (base.get("ref") != "main"
            or current.get("type") != "commit"
            or type(current.get("sha")) is not str
            or SHA.fullmatch(current["sha"]) is None
            or base.get("sha") != current["sha"]):
        return ["current_main_unverified"]
    return []


def verify_pr_guard_files(pr: object, changed_files: object) -> list[str]:
    """Refuse self-modified verification workflows and incomplete PR file listings."""
    if not isinstance(pr, dict):
        return ["pr_files_unverified"]
    count = pr.get("changed_files")
    if type(count) is not int or not 0 < count <= 100:
        return ["pr_files_unverified"]
    if type(changed_files) is not list or len(changed_files) != count:
        return ["pr_files_unverified"]
    seen: set[str] = set()
    for item in changed_files:
        if not isinstance(item, dict) or type(item.get("filename")) is not str:
            return ["pr_files_unverified"]
        filename, previous = item["filename"], item.get("previous_filename")
        if (not filename or len(filename) > 4096 or filename in seen
                or item.get("status") not in ("added", "modified", "removed",
                                              "renamed", "copied", "changed")):
            return ["pr_files_unverified"]
        seen.add(filename)
        if previous is not None and (type(previous) is not str
                                     or not previous or len(previous) > 4096):
            return ["pr_files_unverified"]
        paths = (filename, previous) if previous is not None else (filename,)
        if any(path in CRITICAL_CI_PATHS
               or path.startswith(".github/workflows/") for path in paths):
            return ["verification_workflow_or_canary_modified"]
    return []


_STABLE_RUN_FIELDS = (
    "id", "head_sha", "head_branch", "run_attempt", "status",
    "conclusion", "workflow_id", "name", "path", "event",
    "pull_requests", "repository", "head_repository",
)

def verify_run_stability(initial: object, final: object, name: str) -> list[str]:
    """Refuse evidence superseded by an Actions rerun during metadata collection."""
    if not isinstance(initial, dict) or not isinstance(final, dict):
        return [f"{name}_run_changed_during_evidence_read"]
    if any(initial.get(field) != final.get(field) for field in _STABLE_RUN_FIELDS):
        return [f"{name}_run_changed_during_evidence_read"]
    return []


def _get_json(url: str, token: str | None) -> object:
    # Enforce fixed endpoints at the transport boundary, not just the caller.
    # In particular, never forward a GitHub token to a substituted origin.
    if type(url) is not str or _ALLOWED_API_URL.fullmatch(url) is None:
        raise ValueError("unapproved metadata endpoint")
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "LightUp-scope-CI-evidence-optin"}
    if token:
        headers["Authorization"] = "Bearer " + token
    with build_opener(_DenyRedirects()).open(Request(url, headers=headers, method="GET"), timeout=8) as response:
        raw = response.read(524289)
    if len(raw) > 524288:
        raise ValueError("too much metadata")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_keys,
                      parse_constant=_reject_nonfinite_json)

class _OpaqueParser(argparse.ArgumentParser):
    """Suppress argparse echo of untrusted CLI values (and accidental tokens)."""
    def error(self, message: str) -> None:
        raise ValueError("invalid CLI arguments")


def main(argv: list[str] | None = None) -> int:
    parser = _OpaqueParser(description="Read-only CI evidence, NEVER authorization")
    parser.add_argument("--head", required=True)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--hosted-run", required=True, type=int)
    parser.add_argument("--vps-run", required=True, type=int)
    try:
        args = parser.parse_args(argv)
    except ValueError:
        print(json.dumps(_receipt(["invalid_input"]), sort_keys=True, separators=(",", ":")))
        return 2
    if (SHA.fullmatch(args.head) is None or not 0 < args.hosted_run < 10**17
            or not 0 < args.vps_run < 10**17 or args.hosted_run == args.vps_run
            or not 0 < args.pr < 10**10):
        print(json.dumps(_receipt(["invalid_input"]), sort_keys=True))
        return 2
    try:
        token = os.environ.get("GITHUB_TOKEN")
        pr = _get_json(f"{PR_ROOT}{args.pr}", token)
        initial_main = _get_json(MAIN_REF, token)
        changed_files = _get_json(f"{PR_ROOT}{args.pr}/files?per_page=100", token)
        hosted = _get_json(f"{API_ROOT}{args.hosted_run}", token)
        hj = _get_json(f"{API_ROOT}{args.hosted_run}/jobs?per_page=100", token)
        vps = _get_json(f"{API_ROOT}{args.vps_run}", token)
        vj = _get_json(f"{API_ROOT}{args.vps_run}/jobs?per_page=100", token)
        # Re-read the PR last. A retargeted, closed or updated PR cannot
        # borrow successful workflow results collected earlier in this run.
        final_pr = _get_json(f"{PR_ROOT}{args.pr}", token)
        final_main = _get_json(MAIN_REF, token)
        final_hosted = _get_json(f"{API_ROOT}{args.hosted_run}", token)
        final_vps = _get_json(f"{API_ROOT}{args.vps_run}", token)
        receipt = evaluate(args.head, args.hosted_run, args.vps_run, hosted, hj, vps, vj)
        holds = (receipt["missing_gates"]
                 + verify_pr_head(args.head, args.pr, pr)
                 + verify_run_pr_binding(args.head, args.pr, pr, hosted, vps)
                 + verify_pr_head(args.head, args.pr, final_pr)
                 + verify_run_pr_binding(args.head, args.pr, final_pr, hosted, vps)
                 + verify_current_main(pr, initial_main)
                 + verify_current_main(final_pr, final_main)
                 + verify_pr_guard_files(pr, changed_files)
                 + verify_pr_guard_files(final_pr, changed_files)
                 + verify_run_stability(hosted, final_hosted, "hosted")
                 + verify_run_stability(vps, final_vps, "permanent_vps"))
        if (not isinstance(final_pr, dict) or not isinstance(pr, dict)
                or final_pr.get("head") != pr.get("head")
                or final_pr.get("base") != pr.get("base")
                or final_pr.get("state") != pr.get("state")
                or final_pr.get("draft") != pr.get("draft")):
            holds.append("pr_changed_during_evidence_read")
        if initial_main != final_main:
            holds.append("main_changed_during_evidence_read")
        receipt = _receipt(holds)
    except Exception:
        # Error bodies and credentials must never enter the receipt.
        receipt = _receipt(["metadata_unavailable"])
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["run_evidence_consistent"] else 2

if __name__ == "__main__":
    sys.exit(main())
