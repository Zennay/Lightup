#!/usr/bin/env python3
"""Opt-in, non-authorizing exact lab IP-literal review CLI (#1424).

No live grants, networks, target I/O, authority, or successful exit code.
Exit 2: HOLD. Exit 3: REVIEW_ONLY. Both are deliberately nonzero.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from lightup.scope_lab_literal_review_1424 import LabLiteralReview, review_lab_literal


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    result = LabLiteralReview()
    # No argparse diagnostics: unknown, malformed or duplicate inputs must not
    # appear on stderr or be echoed in a usage message.
    if (type(arguments) is list and len(arguments) == 2
            and type(arguments[0]) is str and arguments[0] == "--literal"
            and type(arguments[1]) is str):
        result = review_lab_literal(arguments[1])

    receipt = {
        "status": result.status,
        "classification": result.classification,
        "authorization_verified": result.authorization_verified,
        "permit_issued": result.permit_issued,
        "execution_enabled": result.execution_enabled,
        "merge_approved": result.merge_approved,
        "release_approved": result.release_approved,
    }
    try:
        sys.stdout.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    except (OSError, UnicodeError):
        # A closed pipe or damaged text sink must fail closed with no
        # traceback. Never mistake missing/truncated review output for assent.
        return 2
    return 3 if result.status == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
