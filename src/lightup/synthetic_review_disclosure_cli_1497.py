"""Opt-in stdin-only fictional review-text quarantine; never returns exit status 0."""
from __future__ import annotations

from dataclasses import asdict
import json
import sys

from .synthetic_review_disclosure_1497 import _hold, review_fictional_handoff_notes


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    verdict = _hold()
    if args == ["--synthetic-only"]:
        try:
            raw = sys.stdin.buffer.read(32769)
            if len(raw) <= 32768:
                parsed = json.loads(raw.decode("utf-8", "strict"))
                if type(parsed) is list:
                    verdict = review_fictional_handoff_notes(tuple(parsed))
        except (UnicodeError, ValueError, TypeError, OverflowError, RecursionError):
            pass
    print(json.dumps(asdict(verdict), sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return 2 if verdict.status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
