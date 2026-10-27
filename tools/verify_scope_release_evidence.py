"""Offline release-evidence gate; never grants operational authorization.

Input is a locally supplied JSON record. This utility does not contact GitHub,
targets, deployment services, or authorization systems.
"""
import argparse
import json
import re
import sys

SHA = re.compile(r"[0-9a-f]{40}\Z")
REQUIRED_CHECKS = frozenset({"hosted", "permanent_vps", "negative_regressions", "positive_controls"})
REQUIRED_GATES = frozenset(f"G{i}" for i in range(1, 11))


def valid(record):
    """Return (allowed_to_review, errors), not permission to execute targets."""
    errors = []
    if type(record) is not dict:
        return False, ["record must be an object"]
    sha = record.get("integration_sha")
    if type(sha) is not str or not SHA.fullmatch(sha):
        errors.append("integration_sha must be a complete lowercase SHA-1")
    checks = record.get("checks")
    if type(checks) is not dict or set(checks) != REQUIRED_CHECKS:
        errors.append("checks must contain exactly the four required entries")
    else:
        for name in sorted(REQUIRED_CHECKS):
            check = checks[name]
            if type(check) is not dict:
                errors.append(f"{name}: expected object")
                continue
            if check.get("conclusion") != "success" or type(check.get("conclusion")) is not str:
                errors.append(f"{name}: conclusion is not success")
            if type(check.get("trigger_sha")) is not str or check["trigger_sha"] != sha:
                errors.append(f"{name}: wrong trigger SHA")
            if type(check.get("run_url")) is not str or not re.fullmatch(
                r"https://github\.com/[^/\s]+/[^/\s]+/actions/runs/[1-9][0-9]*",
                check["run_url"],
            ):
                errors.append(f"{name}: invalid immutable run URL")
            if type(check.get("runner")) is not str or not check["runner"].strip():
                errors.append(f"{name}: missing runner identity")
    gates = record.get("gates")
    if type(gates) is not dict or set(gates) != REQUIRED_GATES:
        errors.append("gates must contain exactly G1 through G10")
    else:
        for gate in sorted(REQUIRED_GATES):
            if type(gates[gate]) is not dict or gates[gate].get("outcome") != "PASS":
                errors.append(f"{gate}: not PASS")
            elif type(gates[gate].get("proof_url")) is not str or not gates[gate]["proof_url"].startswith("https://"):
                errors.append(f"{gate}: missing HTTPS proof")
    reviewer = record.get("reviewer")
    author = record.get("author")
    if not (type(reviewer) is str and reviewer.strip() and
            type(author) is str and author.strip() and reviewer != author):
        errors.append("independent reviewer required")
    if record.get("decision") != "APPROVE" or type(record.get("decision")) is not str:
        errors.append("explicit APPROVE decision required")
    if record.get("deployment_approved") is not True:
        errors.append("explicit deployment approval required")
    return not errors, errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", help="local JSON evidence file")
    args = parser.parse_args(argv)
    try:
        with open(args.record, encoding="utf-8") as source:
            record = json.load(source, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        ok, errors = valid(record)
    except (OSError, ValueError) as exc:
        ok, errors = False, [f"unreadable or invalid evidence: {exc}"]
    for error in errors:
        print(f"DENY: {error}", file=sys.stderr)
    if ok:
        print("REVIEW EVIDENCE COMPLETE — NOT TARGET AUTHORIZATION")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
