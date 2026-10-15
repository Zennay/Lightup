"""Pairwise offline stdlib unittest summary consistency, never CI attestation.

Input contains TWO self-claimed Python-version logs, not authenticated GitHub
job evidence. ALWAYS HOLD / exit 2; no filesystem, network, targets or grants.
"""
from __future__ import annotations

import json
import sys

from scope_unittest_summary_review_20261015 import (
    FALSE_KEYS, InvalidLog, extract, MAX_BYTES,
)
from scope_unittest_case_roster_review_20261015 import CASE, ID, MAP, VALID

MAX_ENVELOPE = 2 * MAX_BYTES + 32768
COMPARE = ("reported_tests", "reported_result", "failures", "errors",
           "skipped", "expected_failures", "unexpected_successes")


class PairError(ValueError):
    pass


def _pairs(pairs):
    value = {}
    for key, val in pairs:
        if key in value:
            raise PairError("duplicate key")
        value[key] = val
    return value


def _nonfinite(_):
    raise PairError("nonfinite")


def _observed_methods(log, reported_total, summary):
    """Conservative parsed unittest verbose rows; not authenticated test source."""
    methods = {}
    for line in log.splitlines():
        if len(line) > 2048:
            continue
        match = CASE.fullmatch(line)
        if match is None:
            continue
        method, fullname, raw_verdict = match.groups()
        if ID.fullmatch(fullname) is None or fullname.rsplit(".", 1)[-1] != method:
            continue
        if fullname in methods:
            raise PairError("duplicate method in claimed log")
        methods[fullname] = MAP.get(raw_verdict, "skipped")
    if len(methods) > reported_total:
        raise PairError("method rows exceed reported test count")
    for status, field in (("failed", "failures"), ("error", "errors"),
                          ("expected_failure", "expected_failures"),
                          ("unexpected_success", "unexpected_successes"),
                          ("skipped", "skipped")):
        if sum(v == status for v in methods.values()) > summary[field]:
            raise PairError("method statuses contradict unittest footer")
    return methods


def check(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_ENVELOPE:
        raise PairError("size")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise PairError("format") from exc
    if (type(data) is not dict
            or set(data) != {"schema_version", "complete", "python_311_log", "python_314_log"}
            or type(data["schema_version"]) is not int
            or data["schema_version"] != 1
            or type(data["complete"]) is not bool):
        raise PairError("shape")
    summaries = {}
    observed = {}
    for tag in ("python_311_log", "python_314_log"):
        text = data[tag]
        if type(text) is not str:
            raise PairError("log type")
        try:
            encoded = text.encode("utf-8")
        except UnicodeError as exc:
            raise PairError("invalid string") from exc
        if not 0 < len(encoded) <= MAX_BYTES:
            raise PairError("log bound")
        try:
            summaries[tag] = extract(encoded)
        except InvalidLog as exc:
            raise PairError("unparseable log") from exc
        observed[tag] = _observed_methods(text, summaries[tag]["reported_tests"], summaries[tag])
    left, right = summaries.values()
    methods311, methods314 = observed.values()
    different_names = len(methods311.keys() ^ methods314.keys())
    changed_results = sum(methods311[key] != methods314[key]
                          for key in methods311.keys() & methods314.keys())
    differences = sum(left[name] != right[name] for name in COMPARE)
    return {
        "claimed_interpreters": 2,
        "reported_tests_311": left["reported_tests"],
        "reported_tests_314": right["reported_tests"],
        "reported_failures_311": left["failures"],
        "reported_failures_314": right["failures"],
        "reported_expected_red_311": left["expected_failures"],
        "reported_expected_red_314": right["expected_failures"],
        "reported_result_311": left["reported_result"],
        "reported_result_314": right["reported_result"],
        "different_summary_fields": differences,
        "different_method_names": different_names,
        "changed_method_results": changed_results,
        "reported_method_rows_311": len(methods311),
        "reported_method_rows_314": len(methods314),
        "method_listing": (
            "SELF_REPORTED_FULL" if len(methods311) == left["reported_tests"]
            and len(methods314) == right["reported_tests"]
            else "PARTIAL_OR_MISSING"),
        "classification": ("MISMATCH" if differences or different_names or changed_results
                           else "UNAUTHENTICATED_EQUALITY"),
        "coverage": "SELF_ASSERTED_UNVERIFIED" if data["complete"] else "INCOMPLETE",
        "source_provenance": "UNTRUSTED_LOG_TEXT",
    }


def receipt(result=None):
    output = {"status": "HOLD", "release_evidence": False,
              "classification": "UNVERIFIED_PYTHON_PAIR"}
    output.update({key: False for key in FALSE_KEYS})
    if result is not None:
        output["summary"] = result
    return output


def main():
    try:
        data = receipt(check(sys.stdin.buffer.read(MAX_ENVELOPE + 1)))
    except (PairError, OSError, OverflowError, MemoryError):
        data = receipt()
    sys.stdout.write(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
