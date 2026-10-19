#!/usr/bin/env python3
"""Single-command local PRIVATE HUMAN Evidence Relationship Desk.

No network, grants, scans, native HUMAN Apply, CI or activation.
"""
from __future__ import annotations

import sys

USAGE = """LightUp PRIVATE Evidence Relationship Desk · HUMAN ONLY · DRAFT/HOLD

Choose one offline operator workflow:

    python3 remediation-evidence-reuse/desk.py review --help
        Original v1/unified v2 local-fingerprint reuse, two-snapshot drift,
        privacy-minimal count export, PRIVATE HTML or advisory action packet.

    python3 remediation-evidence-reuse/desk.py inbox --help
        Durable source-byte-bound HUMAN question inbox, local state,
        offline review HTML, counts-only progress and PRIVATE handoff.

    python3 remediation-evidence-reuse/desk.py bulk --help\n        PRIVATE HUMAN bulk edit worksheet, no-write preview and explicit\n        atomic same-source session update (never native Apply).\n\n    python3 remediation-evidence-reuse/desk.py carry --help\n        HUMAN-only explicit continuity into a NEW private session for exact\n        unchanged original-source follow-up identities; no lost old actions.\n\n    python3 remediation-evidence-reuse/desk.py timeline --help
        Ordered 2–12 same-source PRIVATE snapshot drift matrix,
        scriptless HTML, aggregate counts or HUMAN-only questions.

Safe operator flow:
    desk.py review PRIVATE.json
    desk.py inbox start --current PRIVATE.json --session PRIVATE-inbox.json
    desk.py inbox status --current PRIVATE.json --session PRIVATE-inbox.json

PRIVATE source inputs must be 0600 inside a real owner-only 0700 directory,
and paths must be absolute. Existing native LightUp owner/auth/grant/scan paths
remain unchanged. Stage INCUBATE M3/M7 PLAN/LAB ONLY. No authorization inferred.
"""


def main() -> int:
    if len(sys.argv) == 1 or sys.argv[1] in ("-h", "--help", "help"):
        print(USAGE)
        return 0  # CLI usage only: no import, operation or security verdict.
    kind = sys.argv[1]
    if kind not in ("review", "inbox", "timeline", "bulk", "carry"):
        print("HOLD: Unknown PRIVATE workflow. Use --help.", file=sys.stderr)
        return 3
    if kind == "review":
        import review as implementation
    elif kind == "bulk":
        import bulk as implementation
    elif kind == "carry":
        import carry as implementation
    elif kind == "inbox":
        import triage as implementation
    else:
        import timeline as implementation
    old_args = sys.argv
    try:
        sys.argv = [old_args[0] + " " + kind, *old_args[2:]]
        return implementation.main()
    finally:
        sys.argv = old_args


if __name__ == "__main__":
    sys.exit(main())
