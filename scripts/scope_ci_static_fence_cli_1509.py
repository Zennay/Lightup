"""Optional stdin-only CLI for the non-authorizing static CI safety fence (#1509).

No file paths, GitHub API, YAML execution, scanning or grants.
Exit 2 = review-only, exit 3 = hold; never exit 0.
"""
from __future__ import annotations

import sys

from scope_ci_static_fence_1509 import MAX_BYTES, review_workflow

HOLD_JSON = '{"state":"HOLD","authorized":false,"consent_verified":false,"dispatch_allowed":false,"release_allowed":false}\n'
REVIEW_JSON = '{"state":"REVIEW_ONLY","authorized":false,"consent_verified":false,"dispatch_allowed":false,"release_allowed":false}\n'


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        state = review_workflow(raw).state
    except (OSError, ValueError, AttributeError, TypeError):
        state = "HOLD"
    result = REVIEW_JSON if state == "REVIEW_ONLY" else HOLD_JSON
    try:
        sys.stdout.write(result)
        sys.stdout.flush()
    except (OSError, ValueError, TypeError):
        return 3
    return 2 if state == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    sys.exit(main())
