"""Opt-in strictly fictional pinned review with a second-channel digest.

This offline executable requires LIGHTUP_FICTIONAL_EXPECTED_SHA256_1503 to
contain an independently maintained exact lowercase SHA-256 reference. It
denies missing, changed, malformed or spoofed-in-packet hashes, and legacy
unpinned schemas. A local environment variable is not a trust anchor against
an attacker with access to the calling process. NO runtime authorization.
Exit 2 = REVIEW_ONLY, exit 3 = HOLD. Never exit 0.
"""
from __future__ import annotations

from .fictional_packet_cli_1503 import main_anchored


if __name__ == "__main__":
    raise SystemExit(main_anchored())
