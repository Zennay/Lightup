#!/usr/bin/env python3
"""Deterministic OFFLINE two-app handoff bundle for operator and team reviewers."""
from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import os
import zipfile

from package import build as build_operator
from package_team_reply import build as build_reply

DIRECTORY = Path(__file__).resolve().parent
OUTPUT = DIRECTORY / "LightUp-Evidence-Collaboration.zip"
WELCOME = """LIGHTUP HUMAN EVIDENCE COLLABORATION - OFFLINE DRAFT/HOLD

1. Original operator independently authenticates to original LightUp and exports
   the exact client/engagement findings summary. Open operator-evidence-review.html
   locally to import that original exported five-column CSV; or use the separate
   existing authenticated evidence_review_handoff_cli to generate a private
   preloaded operator HTML. This public ZIP contains NO client data.
2. Original operator reviews the human findings and selects exactly one locally
   declared team. Export one PRIVATE single-team JSON handoff.
3. Transfer that JSON only through an independently approved confidential channel.
   Recipient opens team-reply.html and imports the received private JSON.
4. Recipient edits only local human references and follow-ups and exports a new
   PRIVATE returned JSON. Send that file to the verified original operator.
5. Operator imports the return into original operator-evidence-review.html only
   after loading the same original source, confirms the independently verified
   client/engagement/team, and reviews the explicit atomic reconciliation.

Nothing in this ZIP authenticates a client, grant, consent, scan, retest or actual
patch. All evidence references are self-reported local notes; source finding
status never changes. INCUBATE M3/M7, PLAN/LAB ONLY, DRAFT/HOLD.
"""


def contents() -> bytes:
    from io import BytesIO
    buf = BytesIO()
    files = (
        ("operator-evidence-review.html", build_operator()),
        ("team-reply.html", build_reply()),
        ("START-HERE.txt", WELCOME.encode("utf-8")),
    )
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, content in files:
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.create_system = 3
            entry.external_attr = (0o100644 << 16)
            archive.writestr(entry, content)
    return buf.getvalue()


def main() -> None:
    zipped = contents()
    if OUTPUT.is_symlink():
        raise ValueError("Will not write through a ZIP symlink.")
    fd, temporary = tempfile.mkstemp(prefix=".lightup-collaboration-", dir=str(DIRECTORY))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(zipped)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, OUTPUT)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print("Offline collaboration ZIP: {} bytes SHA-256 {}".format(
        len(zipped), hashlib.sha256(zipped).hexdigest()
    ))


if __name__ == "__main__":
    main()
