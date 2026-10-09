"""Offline structural cross-check of GitHub job metadata against a scope proof.

Does not fetch or authenticate metadata. A trusted reviewer must retrieve
job objects independently from GitHub and check run origin and runner labels.
"""
import json
import os
import stat
import sys

from verify_scope_proof_manifest import verify, reject_duplicate_keys

LANES = (
    ("hosted_py311", "Offline preflight Python 3.11"),
    ("hosted_py314", "Offline preflight Python 3.14"),
    ("permanent_vps", "LightUp plan-only safety tests"),
)


def check(proof, jobs, runs):
    errors = verify(proof)
    if type(jobs) is not list:
        return errors + ["jobs must be a list"]
    if type(runs) is not list:
        return errors + ["runs must be a list"]
    if errors:
        return errors
    expected_runs = {proof["hosted_py311_run_id"], proof["hosted_py314_run_id"], proof["permanent_vps_run_id"]}
    if any(type(run) is not dict for run in runs):
        errors.append("all workflow runs must be objects")
    required_run_keys = {"id", "head_sha", "status", "conclusion"}
    for run in runs:
        if type(run) is dict and not required_run_keys.issubset(run):
            errors.append("workflow run missing required metadata")
    if len(runs) != len(expected_runs):
        errors.append("expected exact workflow run count")
    for run_id in expected_runs:
        matching = [run for run in runs if type(run) is dict and type(run.get("id")) is int and run["id"] == run_id]
        if len(matching) != 1:
            errors.append("missing or duplicate referenced workflow run")
            continue
        run = matching[0]
        if (run.get("head_sha") != proof["implementation_sha"] or
                run.get("status") != "completed" or run.get("conclusion") != "success"):
            errors.append("workflow run SHA or outcome mismatch")
    # Require an exact three-job snapshot; extra entries could conceal a
    # failed or unrelated execution that the index otherwise ignores.
    if len(jobs) != len(LANES):
        errors.append("expected exactly three scoped job records")
    # Fail closed on malformed records, not only on referenced lane entries.
    if any(type(job) is not dict for job in jobs):
        errors.append("all job records must be objects")
    # The selected snapshot should not contain unknown or ambiguous metadata.
    required_job_keys = {"id", "run_id", "name", "status", "conclusion"}
    for job in jobs:
        if type(job) is dict and not required_job_keys.issubset(job):
            errors.append("job record is missing required metadata")
    seen = set()
    for lane, expected_label in LANES:
        job_id = proof[f"{lane}_job_id"]
        run_id = proof[f"{lane}_run_id"]
        matches = [job for job in jobs if type(job) is dict
                   and type(job.get("id")) is int and job["id"] == job_id]
        if len(matches) != 1:
            errors.append(f"{lane}: exactly one matching job required")
            continue
        job = matches[0]
        if job_id in seen:
            errors.append(f"{lane}: job reused")
        seen.add(job_id)
        if type(job.get("run_id")) is not int or job["run_id"] != run_id:
            errors.append(f"{lane}: workflow run mismatch")
        if job.get("status") != "completed" or job.get("conclusion") != "success":
            errors.append(f"{lane}: job not successful")
        name = job.get("name")
        # Permit only the exact job title or a versioned matrix suffix.
        if (type(name) is not str or
                not (name == expected_label or
                     name in (expected_label + " (Python 3.11)",
                              expected_label + " (Python 3.14)"))):
            errors.append(f"{lane}: expected job label missing")
    return errors


def main(argv):
    if len(argv) != 4:
        print("usage: verify_scope_job_provenance.py proof.json jobs.json runs.json", file=sys.stderr)
        return 2
    try:
        # Inputs are reviewer-provided snapshots, not credentials or authority.
        # Refuse oversized snapshots rather than processing unbounded files.
        payloads = []
        if (type(getattr(os, "O_NOFOLLOW", None)) is not int
                or type(getattr(os, "O_NONBLOCK", None)) is not int
                or not os.O_NOFOLLOW or not os.O_NONBLOCK):
            raise ValueError("secure input open unavailable")
        for path in argv[1:]:
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
            descriptor = os.open(path, flags)
            with os.fdopen(descriptor, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError("input is not a regular file")
                raw = stream.read(65537)
            if len(raw) > 65536:
                raise ValueError("oversized input")
            payloads.append(json.loads(raw.decode("utf-8"),
                                       object_pairs_hook=reject_duplicate_keys,
                                       parse_constant=lambda value: (_ for _ in ()).throw(
                                           ValueError("nonstandard JSON constant"))))
        errors = check(*payloads)
    except (OSError, ValueError, UnicodeError, RecursionError):
        print("HOLD: invalid job snapshot input", file=sys.stderr)
        return 2
    if errors:
        print(f"HOLD: job provenance index mismatch ({len(errors)} issue(s))")
        return 1
    print("STRUCTURAL JOB CHECK ONLY: metadata authenticity and authorization not established")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
