"""Reconcile a synthetic expected-RED debt roster with two unittest logs.

All inputs are caller-supplied unauthenticated text. This tool NEVER proves
source/runner identity or grants authority. No network, files or target actions.
Always HOLD, exit 2 and six explicit false authority flags.
"""
from __future__ import annotations

import json
import sys

from scope_unittest_summary_review_20261015 import (
    FALSE_KEYS, InvalidLog, MAX_BYTES, extract,
)
from scope_python_pair_summary_review_20261015 import PairError, _observed_methods
from scope_xfail_debt_review_20261015 import (
    SnapshotError, _reject_constant, _unique_pairs, _validate,
)

MAX_INPUT = 2 * MAX_BYTES + 131072
LOG_NAMES = ("python_311_log", "python_314_log")


class ChainError(ValueError):
    pass


def parse(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_INPUT:
        raise ChainError("input bound")
    try:
        envelope = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                              parse_constant=_reject_constant)
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise ChainError("invalid JSON") from exc
    if (type(envelope) is not dict
            or set(envelope) != {"schema_version", "complete", "debt_snapshot", *LOG_NAMES}
            or type(envelope["schema_version"]) is not int
            or envelope["schema_version"] != 1
            or type(envelope["complete"]) is not bool):
        raise ChainError("envelope")
    snapshot = envelope["debt_snapshot"]
    debt = _validate(snapshot)
    summaries = {}
    observed = {}
    for name in LOG_NAMES:
        value = envelope[name]
        if type(value) is not str:
            raise ChainError("log type")
        try:
            encoded = value.encode("utf-8")
        except UnicodeError as exc:
            raise ChainError("invalid log encoding") from exc
        if not 0 < len(encoded) <= MAX_BYTES:
            raise ChainError("log size")
        summaries[name] = extract(encoded)
        observed[name] = _observed_methods(value, summaries[name]["reported_tests"],
                                           summaries[name])
    return envelope, debt, summaries, observed


def review(raw):
    envelope, debt, summaries, observed = parse(raw)
    wanted = {row["test"]: row for row in envelope["debt_snapshot"]["cases"]}
    left, right = (observed[name] for name in LOG_NAMES)
    lsum, rsum = (summaries[name] for name in LOG_NAMES)
    missing_l = wanted.keys() - left.keys()
    missing_r = wanted.keys() - right.keys()
    shared_l, shared_r = wanted.keys() & left.keys(), wanted.keys() & right.keys()
    diverged = sum(left[key] != right[key] for key in wanted.keys() & left.keys() & right.keys())
    mismatched_l = sum(wanted[key]["outcome"] != left[key] for key in shared_l)
    mismatched_r = sum(wanted[key]["outcome"] != right[key] for key in shared_r)
    matched_red = sum(wanted[key]["outcome"] == left[key] == right[key] == "expected_failure"
                      for key in wanted.keys() & left.keys() & right.keys())
    # Actual method sets can be disjoint although summary counters match.
    different_method_set = len(left.keys() ^ right.keys())
    footer_diff = sum(lsum[k] != rsum[k] for k in (
        "reported_tests", "reported_result", "failures", "errors", "skipped",
        "expected_failures", "unexpected_successes"))
    risk = (len(missing_l) + len(missing_r) + diverged + mismatched_l + mismatched_r
            + different_method_set + footer_diff + debt["unowned_issues"])
    return {
        "watched_tests": len(wanted),
        "watched_issues": debt["issues"],
        "missing_owner_issues": debt["unowned_issues"],
        "debt_expected_red_claimed": debt["expected_red"],
        "paired_expected_red_reported": matched_red,
        "watched_missing_311": len(missing_l),
        "watched_missing_314": len(missing_r),
        "watched_outcome_mismatch_311": mismatched_l,
        "watched_outcome_mismatch_314": mismatched_r,
        "watched_cross_python_disagreements": diverged,
        "total_different_named_methods": different_method_set,
        "different_suite_footer_fields": footer_diff,
        "unittest_tests_311": lsum["reported_tests"],
        "unittest_tests_314": rsum["reported_tests"],
        "unittest_result_311": lsum["reported_result"],
        "unittest_result_314": rsum["reported_result"],
        "unittest_failures_311": lsum["failures"],
        "unittest_failures_314": rsum["failures"],
        "unittest_expected_reds_311": lsum["expected_failures"],
        "unittest_expected_reds_314": rsum["expected_failures"],
        "listing": ("SELF_REPORTED_FULL"
                    if len(left) == lsum["reported_tests"]
                    and len(right) == rsum["reported_tests"]
                    else "PARTIAL_OR_MISSING"),
        "coverage": ("SELF_ASSERTED_UNVERIFIED"
                     if envelope["complete"] and debt["coverage"] == "SELF_ASSERTED_UNVERIFIED"
                     else "INCOMPLETE"),
        "classification": ("DISAGREEMENT_IN_UNVERIFIED_EVIDENCE" if risk
                           else "NO_DISAGREEMENT_REPORTED_NOT_AUTHORITY"),
        "provenance": "UNAUTHENTICATED_CALLER_INPUT",
    }


def receipt(summary=None):
    result = {"status": "HOLD", "release_evidence": False,
              "classification": "UNVERIFIED_SCOPE_RED_EVIDENCE_CHAIN"}
    result.update({key: False for key in FALSE_KEYS})
    if summary is not None:
        result["summary"] = summary
    return result


def main():
    try:
        response = receipt(review(sys.stdin.buffer.read(MAX_INPUT + 1)))
    except (ChainError, SnapshotError, InvalidLog, PairError, OSError, OverflowError, MemoryError):
        response = receipt()
    sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
