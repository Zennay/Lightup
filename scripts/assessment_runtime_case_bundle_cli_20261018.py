"""Package previously completed private lab cases for the original #1515 cohort comparator.

Use only local bounded file snapshots; never runs tools, models, scanners,
assessment plans or authorization workflows. Exit 2 for packaged, 3 for HOLD.
"""
from __future__ import annotations

import argparse
import json

from assessment_runtime_compare_cli_1513 import _parse_case_document
from assessment_runtime_review_handoff_cli_20261018 import (
    _snapshot, _write_exclusive, _source_ids_unique, SINGLE_LIMIT, COHORT_LIMIT,
)
from lightup.ai.assessment_runtime_cohort_1513 import _index


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", nargs="+", help="1–64 independent original case JSON files")
    parser.add_argument("--output", required=True,
                        help="New private cohort JSON; existing paths are refused")
    args = parser.parse_args(argv)
    if len(args.cases) > 64:
        print("LAB_COHORT_HOLD")
        return 3
    try:
        documents = []
        pairs = []
        for case_path in args.cases:
            document, _ = _snapshot(case_path, SINGLE_LIMIT)
            pairs.append(_parse_case_document(document))
            documents.append(document)
        # Use the same canonical lab-only scenario and record checks that the
        # original read-only comparator uses. Reject duplicates atomically.
        if _index(tuple(pairs)) is None or not _source_ids_unique(tuple(pairs)):
            raise ValueError("invalid cohort")
        payload = json.dumps(
            documents, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
        if len(payload) > COHORT_LIMIT:
            raise ValueError("cohort over the original bound")
        _write_exclusive(args.output, payload)
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            UnicodeError, RecursionError, AttributeError):
        print("LAB_COHORT_HOLD")
        return 3
    print("PRIVATE_LAB_COHORT_WRITTEN — UNVERIFIED; NOT AUTHORIZED")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
