"""Bounded, non-authorizing comparison of named test expectations against one unittest log.

All data is caller-supplied (including log and test roster), not CI attestation.
No network, no target, no files, no grants. Always HOLD/exit 2.
"""
from __future__ import annotations

import json
import re
import sys

from scope_unittest_summary_review_20261015 import extract, InvalidLog, FALSE_KEYS

MAX_INPUT = 2 * 1024 * 1024
MAX_LOG_BYTES = 1024 * 1024
MAX_WATCH = 512
ID = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){2,12}")
STAMP = r"(?:20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z )?"
CASE = re.compile(
    r"^" + STAMP + r"(test_[A-Za-z0-9_]{1,126}) \(("
    r"[A-Za-z_][A-Za-z0-9_.]{2,256})\) \.\.\. "
    r"(ok|FAIL|ERROR|expected failure|unexpected success|skipped(?: '[^'\r\n]{0,160}')?)$"
)
MAP = {"ok": "passed", "FAIL": "failed", "ERROR": "error",
       "expected failure": "expected_failure", "unexpected success": "unexpected_success"}
VALID = frozenset((*MAP.values(), "skipped"))


class InvalidRoster(ValueError):
    pass


def unique(pairs):
    data = {}
    for k, v in pairs:
        if k in data:
            raise InvalidRoster("duplicate key")
        data[k] = v
    return data


def no_constant(_):
    raise InvalidRoster("nonfinite")


def positive_int(v):
    return type(v) is int and 0 < v <= 10000000


def decode(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_INPUT:
        raise InvalidRoster("size")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                         parse_constant=no_constant)
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise InvalidRoster("invalid") from exc
    if (type(obj) is not dict
            or set(obj) != {"schema_version", "complete", "raw_log", "watch"}
            or type(obj["schema_version"]) is not int or obj["schema_version"] != 1
            or type(obj["complete"]) is not bool):
        raise InvalidRoster("schema")
    log, entries = obj["raw_log"], obj["watch"]
    if type(log) is not str:
        raise InvalidRoster("body")
    try:
        log_size = len(log.encode("utf-8"))
    except UnicodeError as exc:
        # JSON accepts escaped lone surrogates: never leak a traceback/raw input.
        raise InvalidRoster("invalid UTF-8 log") from exc
    if (not 0 < log_size <= MAX_LOG_BYTES
            or type(entries) is not list or not 1 <= len(entries) <= MAX_WATCH):
        raise InvalidRoster("body")
    expected = {}
    for row in entries:
        if (type(row) is not dict
                or set(row) != {"test", "issue", "owner_pr", "expected_status"}):
            raise InvalidRoster("watch shape")
        name, issue, owner, outcome = (
            row["test"], row["issue"], row["owner_pr"], row["expected_status"])
        if (type(name) is not str or len(name) > 255 or ID.fullmatch(name) is None
                or not name.split(".")[-1].startswith("test_")
                or not positive_int(issue)
                or (owner is not None and not positive_int(owner))
                or type(outcome) is not str or outcome not in VALID):
            raise InvalidRoster("watch value")
        if name in expected:
            raise InvalidRoster("duplicate watch")
        expected[name] = row
    return obj["complete"], log, expected


def inspect(raw):
    complete, log, expected = decode(raw)
    try:
        unittest_summary = extract(log.encode("utf-8"))
    except InvalidLog as exc:
        raise InvalidRoster("missing suite summary") from exc
    observed = {}
    for line in log.splitlines():
        if len(line) > 2048:
            continue
        match = CASE.fullmatch(line)
        if not match:
            continue
        method, fullname, verdict = match.groups()
        if fullname.rsplit(".", 1)[-1] != method or ID.fullmatch(fullname) is None:
            continue
        if fullname in observed:
            # Repeated test rows could be a retry or appended forged output.
            raise InvalidRoster("ambiguous repeated method")
        observed[fullname] = MAP.get(verdict, "skipped")
    # Per-method rows may omit subtests; but they cannot outnumber the declared
    # suite or independently contradict explicit summary counters. This is
    # consistency only, never proof that the supplied job log is authentic.
    if len(observed) > unittest_summary["reported_tests"]:
        raise InvalidRoster("more distinct methods than total tests")
    observed_counts = {kind: sum(result == kind for result in observed.values())
                       for kind in VALID}
    for kind, footer in (("expected_failure", "expected_failures"),
                         ("unexpected_success", "unexpected_successes"),
                         ("failed", "failures"), ("error", "errors"),
                         ("skipped", "skipped")):
        if observed_counts[kind] > unittest_summary[footer]:
            raise InvalidRoster("test cases contradict footer")
    # No claim of exhaustive parsing: unittest may have formatted subtest lines.
    matched = set(expected) & set(observed)
    missing = set(expected) - set(observed)
    changed = sum(observed[name] != expected[name]["expected_status"] for name in matched)
    reds = sum(observed[name] == "expected_failure" for name in matched)
    unexpected = sum(observed[name] == "unexpected_success" for name in matched)
    return {
        "watched": len(expected),
        "matched": len(matched),
        "missing": len(missing),
        "changed_outcome": changed,
        "expected_red_observed": reds,
        "unexpected_success_observed": unexpected,
        "unowned_watched": sum(row["owner_pr"] is None for row in expected.values()),
        "reported_suite_tests": unittest_summary["reported_tests"],
        "reported_suite_failures": unittest_summary["failures"],
        "reported_suite_expected_failures": unittest_summary["expected_failures"],
        "reported_suite_errors": unittest_summary["errors"],
        "reported_suite_result": unittest_summary["reported_result"],
        "coverage": "SELF_ASSERTED_UNVERIFIED" if complete else "INCOMPLETE",
    }


def receipt(summary=None):
    result = {"status": "HOLD", "classification": "UNVERIFIED_CASE_ROSTER",
              "source": "UNAUTHENTICATED_LOCAL_TEXT", "release_evidence": False}
    result.update({key: False for key in FALSE_KEYS})
    if summary is not None:
        result["summary"] = summary
    return result


def main():
    try:
        answer = receipt(inspect(sys.stdin.buffer.read(MAX_INPUT + 1)))
    except (InvalidRoster, OSError, MemoryError, OverflowError):
        answer = receipt()
    sys.stdout.write(json.dumps(answer, separators=(",", ":"), sort_keys=True) + "\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
