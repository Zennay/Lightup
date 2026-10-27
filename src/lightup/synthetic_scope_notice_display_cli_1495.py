"""Explicit offline-only JSON -> inert HTML stdout for fictional review #1495.

This is a display utility. Exit code 2 is REVIEW_ONLY and is NEVER
consent, approval, dispatch permission, a grant or a successful release.
Exit code 3 is generic HOLD. The tool NEVER exits zero.
"""
from __future__ import annotations

import sys

from .synthetic_scope_notice_consumer_1495 import decode_fictional_notice_for_display
from .synthetic_scope_notice_display_1495 import render_fictional_envelope_html

_MAX_STDIN_BYTES = 65536
_ALLOWED_ARGS = ("--synthetic-json-to-html",)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if type(args) is not list or tuple(args) != _ALLOWED_ARGS:
        # Invalid arguments may contain secrets and must never be echoed.
        sys.stdout.buffer.write(render_fictional_envelope_html(b"").encode("utf-8"))
        return 3
    try:
        # One bounded read. No file paths, target arguments, shell, scan, DB
        # connectivity, service requests or runtime authorization lookups.
        raw = sys.stdin.buffer.read(_MAX_STDIN_BYTES + 1)
        view = decode_fictional_notice_for_display(raw)
        page = render_fictional_envelope_html(raw)
    except (OSError, ValueError, UnicodeError, RecursionError, OverflowError, TypeError):
        view = None
        page = render_fictional_envelope_html(b"")
    sys.stdout.buffer.write(page.encode("utf-8"))
    return 2 if view is not None and view.status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    sys.exit(main())
