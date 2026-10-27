"""Dedicated synthetic pinned-only stdin CLI; never an authorization surface.

Unlike the backwards-compatible demo CLI, this executable refuses legacy
unpinned v1 envelopes rather than permitting silent schema downgrades.
There are no command-line options, file operations, scans or real targets.
Always exits nonzero: 2 REVIEW_ONLY, 3 HOLD.
"""
from __future__ import annotations

from .fictional_packet_cli_1503 import main_pinned


if __name__ == "__main__":
    raise SystemExit(main_pinned())
