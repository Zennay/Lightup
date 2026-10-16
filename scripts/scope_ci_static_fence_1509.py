"""Non-authorizing offline snapshot reviewer for canonical LightUp CI (#1509).

A byte-for-byte reviewer aid, not actual runner or release evidence.
No filesystem, network, subprocess or LightUp runtime access.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256

# Pinned developer-selected original main e73b7445c87ad239bdb03c50a99078ef93163b02.
# ANY change, including comments, must receive manual review/re-pinning.
# This digest is not authenticated provenance.
EXPECTED_SHA256 = "961a5e6356598ae258a5cff605b634c92be7ac177297f210432641e418076750"
MAX_BYTES = 16384

REQUIRED_LINES = (
    "permissions:",
    "  contents: read",
    "jobs:",
    "  test:",
    "    runs-on: [self-hosted, zcloud, vps]",
    "    timeout-minutes: 10",
    '        python-version: ["3.11", "3.14"]',
    "      - name: Guard permanent VPS runner",
    '          test "$(hostname)" = "vps-bb300bba"',
    "      - name: Checkout",
    "        uses: actions/checkout@v4",
    "          ref: ${{ github.event.pull_request.head.sha || github.sha }}",
    "          persist-credentials: false",
    "      - name: Setup Python",
    "        uses: actions/setup-python@v5",
    "          python-version: ${{ matrix.python-version }}",
    "        run: python -m compileall -q src tests",
    "        run: python -m unittest discover -s tests -v",
    "        run: python -m unittest discover -s tests/integration -v",
    "        run: python scripts/check_safety_canaries.py",
)


@dataclass(frozen=True, slots=True)
class Review:
    state: str
    authorized: bool = field(default=False, init=False)
    consent_verified: bool = field(default=False, init=False)
    dispatch_allowed: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)


_HOLD = Review("HOLD")
_REVIEW = Review("REVIEW_ONLY")


def review_workflow(raw: object) -> Review:
    """Check a caller-supplied workflow copy without reading or executing it.

    REVIEW_ONLY states only that bytes match a developer-selected snapshot;
    it cannot establish CI execution, registered runner identity or consent.
    """
    if type(raw) is not bytes or not (1 <= len(raw) <= MAX_BYTES):
        return _HOLD
    try:
        source = raw.decode("ascii", errors="strict")
    except UnicodeError:
        return _HOLD
    if "\r" in source or "\x00" in source or not source.endswith("\n"):
        return _HOLD
    lines = source.splitlines()
    positions = []
    for line in REQUIRED_LINES:
        if lines.count(line) != 1:
            return _HOLD
        positions.append(lines.index(line))
    if positions != sorted(positions) or len(set(positions)) != len(positions):
        return _HOLD
    # Exact digest also denies injected extra jobs and ambiguous YAML structures.
    if sha256(raw).hexdigest() != EXPECTED_SHA256:
        return _HOLD
    return _REVIEW
