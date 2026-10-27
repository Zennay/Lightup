"""Offline CI failure attribution aid; NEVER validates a release or runner.

Consumes only bounded caller-supplied text. A known #301 fingerprint is merely
a review hint, not a waiver for an unexpected failure or security gate.
"""
from __future__ import annotations

import json
import re
import sys

from scope_unittest_summary_review_20261015 import (
    extract, InvalidLog, FALSE_KEYS, MAX_BYTES,
)

STAMP = r"(?:20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z )?"
FAIL = re.compile(r"^" + STAMP + r"(FAIL|ERROR): (test_[A-Za-z0-9_]{1,127}) "
                  r"\(([A-Za-z_][A-Za-z0-9_.]{2,255})\)$")
FILE = re.compile(r"^" + STAMP + r"  File \"([^\r\n\"]{1,1024})\", line ([1-9][0-9]{0,5}), in ([A-Za-z_][A-Za-z0-9_]*)$")
ASSERT = re.compile(r"^" + STAMP + r"AssertionError: False is not true$")
EXPRESSION = re.compile(r"^" + STAMP + r"    self\.assertTrue\(_pure_scope_decision\(a\)\.allowed\)$")
KNOWN_NAME = "test_all_inputs_remain_unchanged_after_pure_scope_decision"
KNOWN_CLASS = "test_scope_legacy_falsy_window_301_red_20261014.LegacyFalsyBoundaryRedTests."
KNOWN_PATH = "/tests/test_scope_legacy_falsy_window_301_red_20261014.py"


def _line_matches_known(line):
    m = FILE.fullmatch(line)
    return bool(m and m.group(1).replace("\\", "/").endswith(KNOWN_PATH)
                and m.group(3) == KNOWN_NAME)


def diagnose(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES:
        raise InvalidLog("size")
    summary = extract(raw)
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise InvalidLog("encoding") from exc
    failures = []
    for i, line in enumerate(lines):
        if len(line) > 4096:
            continue
        m = FAIL.fullmatch(line)
        if m:
            failures.append((i, *m.groups()))
    observed_failures = sum(t == "FAIL" for _, t, _, _ in failures)
    observed_errors = sum(t == "ERROR" for _, t, _, _ in failures)
    # Untrusted logs with fewer/more failure trace headings than the footer
    # are ambiguous, not evidence that this is the only suite breakage.
    if observed_failures != summary["failures"] or observed_errors != summary["errors"]:
        raise InvalidLog("footer/traceback mismatch")
    known = False
    if (summary["reported_result"] == "FAILED"
            and observed_failures == 1 and observed_errors == 0
            and summary["unexpected_successes"] == 0 and len(failures) == 1):
        i, kind, name, fullname = failures[0]
        if (kind == "FAIL" and name == KNOWN_NAME
                and fullname == KNOWN_CLASS + KNOWN_NAME):
            # Only inspect a fully delimited, local traceback. Matching
            # text outside the closing divider is untrusted unrelated data.
            section = lines[i+1:i+24]
            divider = re.compile(r"^" + STAMP + r"-{70}$")
            if section and divider.fullmatch(section[0]):
                end = next((j for j, line in enumerate(section[1:], 1)
                            if divider.fullmatch(line)), None)
                if end is not None and end > 1:
                    body = section[1:end]
                    known = (any(_line_matches_known(l) for l in body)
                             and any(EXPRESSION.fullmatch(l) for l in body)
                             and any(ASSERT.fullmatch(l) for l in body))
    return {
        "reported_tests": summary["reported_tests"],
        "reported_result": summary["reported_result"],
        "reported_failures": summary["failures"],
        "reported_errors": summary["errors"],
        "expected_source_reds": summary["expected_failures"],
        "unverified_failure_class": (
            "KNOWN_301_FIXTURE_SIGNATURE_REVIEW_REQUIRED" if known
            else "UNTRIAGED_OR_NO_FAILURE"),
        "known_issue_hint": 301 if known else None,
        "runner_provenance": "NOT_ATTESTED",
        "source_provenance": "UNAUTHENTICATED_LOCAL_TEXT",
    }


def receipt(result=None):
    output = {"status": "HOLD", "classification": "UNVERIFIED_CI_FAILURE",
              "release_evidence": False}
    output.update({key: False for key in FALSE_KEYS})
    if result is not None:
        output["summary"] = result
    return output


def main():
    try:
        response = receipt(diagnose(sys.stdin.buffer.read(MAX_BYTES + 1)))
    except (InvalidLog, OSError, OverflowError, MemoryError):
        response = receipt()
    sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
