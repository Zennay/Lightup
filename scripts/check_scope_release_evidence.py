"""Offline, fail-closed LightUp scope authorization release evidence gate.

This *does not* verify authenticity of evidence or authorize target execution.
Use only after an independent owner has verified source/run provenance.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlsplit


def valid_run_url(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    parts = parsed.path.split("/")
    return (parsed.scheme == "https" and parsed.netloc == "github.com"
            and parsed.username is None and parsed.password is None
            and parsed.query == "" and parsed.fragment == ""
            and len(parts) == 7 and parts[:5] == ["", "Zennay", "Lightup", "actions", "runs"]
            and parts[5].isascii() and parts[5].isdecimal() and parts[6] == "") or (parsed.scheme == "https" and parsed.netloc == "github.com"
            and parsed.query == "" and parsed.fragment == ""
            and len(parts) == 6 and parts[:5] == ["", "Zennay", "Lightup", "actions", "runs"]
            and parts[5].isascii() and parts[5].isdecimal())


REQUIRED_JOBS = ("py311_unit", "py314_unit", "py311_producer", "py314_producer", "permanent_vps")


def evaluate(evidence: object) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if type(evidence) is not dict:
        return False, ["evidence must be a JSON object"]
    sha = evidence.get("integration_sha")
    if type(sha) is not str or len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
        reasons.append("missing or malformed full integration SHA")
    if evidence.get("trusted_grant_enforced") is not True:
        reasons.append("trusted pre-I/O grant enforcement not proved")
    if evidence.get("zero_side_effect_denials") is not True:
        reasons.append("zero-side-effect denials not proved")
    if evidence.get("revocation_fence_verified") is not True:
        reasons.append("durable revocation fence not proved")
    if evidence.get("source_owner_reviewed") is not True:
        reasons.append("source-owner review not proved")
    if type(evidence.get("remaining_xfails")) is not int or evidence["remaining_xfails"] != 0:
        reasons.append("unfixed expected failures remain or count missing")
    jobs = evidence.get("jobs")
    if type(jobs) is not dict:
        reasons.append("missing job evidence")
    else:
        for name in REQUIRED_JOBS:
            job = jobs.get(name)
            if type(job) is not dict or job.get("conclusion") != "success" or job.get("head_sha") != sha or not valid_run_url(job.get("run_url")):
                reasons.append(f"{name}: missing success, exact SHA or GitHub run reference")
    return not reasons, reasons


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Usage: python scripts/check_scope_release_evidence.py evidence.json", file=sys.stderr)
        return 2
    try:
        evidence = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"HOLD: unreadable evidence: {exc}", file=sys.stderr)
        return 2
    allowed, reasons = evaluate(evidence)
    print("REVIEW-ELIGIBLE (not authorization)" if allowed else "HOLD: " + "; ".join(reasons))
    return 0 if allowed else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
