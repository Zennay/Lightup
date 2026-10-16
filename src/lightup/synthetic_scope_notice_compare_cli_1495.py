"""Offline-only fictional before/after scope comparison stdin->HTML.

No filesystem paths or target addresses. NO consent, grants, revocation or
execution rights are ever issued. Exit 2=REVIEW_ONLY, 3=HOLD, never 0.
"""
from __future__ import annotations

import sys

from .synthetic_scope_notice_compare_1495 import compare_fictional_scope_envelopes

_MAX_PAIR_BYTES = 131072
_EXACT_ARGS = ("--synthetic-pair-to-html",)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    valid_flags = {
        _EXACT_ARGS: "en",
        ("--synthetic-pair-to-html", "--lang", "en"): "en",
        ("--synthetic-pair-to-html", "--lang", "nl"): "nl",
    }
    language = valid_flags.get(tuple(args)) if type(args) is list and all(
        type(arg) is str for arg in args
    ) else None
    if language is None:
        # Never echo untrusted CLI parameters or parse stdin for bad flags.
        result = compare_fictional_scope_envelopes(b"")
        sys.stdout.buffer.write(result.html.encode("utf-8"))
        return 3
    try:
        raw = sys.stdin.buffer.read(_MAX_PAIR_BYTES + 1)
        result = compare_fictional_scope_envelopes(raw, language=language)
    except (OSError, ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        result = compare_fictional_scope_envelopes(b"", language=language)
    sys.stdout.buffer.write(result.html.encode("utf-8"))
    return 2 if result.status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    sys.exit(main())
