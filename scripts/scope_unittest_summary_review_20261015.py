"""Strict offline unittest result-summary reviewer (not a CI attestation).

Reads one caller-supplied raw local log from stdin, emits aggregate only,
ALWAYS HOLD/exit 2. Does not open files, invoke network or inspect targets.
"""
from __future__ import annotations

import json
import re
import sys

MAX_BYTES = 1024 * 1024
PREFIX = r"(?:20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z )?"
TOTAL = re.compile(r"^" + PREFIX + r"Ran ([1-9][0-9]{0,6}) tests? in ([0-9]{1,7}(?:\.[0-9]{1,6})?)s$")
FINISH = re.compile(r"^" + PREFIX + r"(OK|FAILED)(?: \(([^()]*)\))?$")
PART = re.compile(r"^(failures|errors|skipped|expected failures|unexpected successes)=([0-9]{1,7})$")
KEYS = {
    "failures": "failures", "errors": "errors", "skipped": "skipped",
    "expected failures": "expected_failures",
    "unexpected successes": "unexpected_successes",
}
FALSE_KEYS = ("authorization_verified", "permit_issued", "execution_enabled",
              "merge_approved", "release_approved", "scan_allowed")


class InvalidLog(ValueError):
    pass


def extract(raw):
    if type(raw) is not bytes or not (0 < len(raw) <= MAX_BYTES):
        raise InvalidLog("size")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise InvalidLog("encoding") from exc
    totals, finishes = [], []
    for line in lines:
        if len(line) > 8192:
            continue
        matched = TOTAL.fullmatch(line)
        if matched:
            totals.append(int(matched.group(1)))
        matched = FINISH.fullmatch(line)
        if matched:
            finishes.append((matched.group(1), matched.group(2)))
    if len(totals) != 1 or len(finishes) != 1:
        raise InvalidLog("ambiguous test suite")
    tests, (state, body) = totals[0], finishes[0]
    counts = dict.fromkeys(KEYS.values(), 0)
    if body:
        for part in body.split(", "):
            match = PART.fullmatch(part)
            if match is None or counts[KEYS[match.group(1)]] != 0:
                raise InvalidLog("result")
            counts[KEYS[match.group(1)]] = int(match.group(2))
    elif body is not None:
        raise InvalidLog("empty result")
    if state == "OK" and any((counts["failures"], counts["errors"], counts["unexpected_successes"])):
        raise InvalidLog("contradiction")
    if state == "FAILED" and not any((counts["failures"], counts["errors"], counts["unexpected_successes"])):
        raise InvalidLog("missing failure")
    if sum(counts.values()) > tests:
        raise InvalidLog("impossible totals")
    return {"reported_tests": tests, "reported_result": state,
            **counts, "provenance": "UNAUTHENTICATED_LOCAL_TEXT"}


def receipt(summary=None):
    data = {"status": "HOLD", "classification": "UNVERIFIED_UNITTEST_LOG",
            "release_evidence": False}
    data.update({key: False for key in FALSE_KEYS})
    if summary is not None:
        data["summary"] = summary
    return data


def main():
    try:
        data = receipt(extract(sys.stdin.buffer.read(MAX_BYTES + 1)))
    except (OSError, InvalidLog, OverflowError, MemoryError):
        data = receipt()
    sys.stdout.write(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
