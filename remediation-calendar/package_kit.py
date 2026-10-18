#!/usr/bin/env python3
"""Publish an offline, non-authorizing two-app Casework + Calendar kit.

All original Casework bytes are pinned. No credentials, client data or scanner.
"""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import zipfile

import package as calendar_package

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT = HERE / "LightUp-Remediation-Calendar-Kit.zip"

ORIGINAL_CASEWORK = {
    "index.html": "e063038701a9c7bab94434b697de387b8cf6cf68078c9d1d9588fa1b838f23fd",
    "remediation-engine.js": "c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225",
    "remediation-schedule.js": "4ec9f7ae396cad504ab122072b5c78dec5158a1def360adff3085dcd78ecaa0d",
    "remediation-app.js": "51ed77103946bc3582b0cb9bc0a321fae2135e2c58f5365793a15f8afc2ec3ee",
}

README = """LIGHTUP REMEDIATION CASEWORK + CALENDAR — PRIVATE HUMAN WORKSPACE
INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD

1. Obtain the exact original five-column LightUp findings CSV via the
   existing separate authenticated, tenant/engagement-authorized operator
   export; never source it from an unknown party or treat this kit as login.
2. Open casework/index.html LOCALLY with its neighboring three unchanged
   original Casework files. Import your authorized CSV and edit HUMAN-ONLY
   casework. Save the PRIVATE original Casework v1 JSON.
3. Open calendar/index.html LOCALLY. Independently confirm the same actual
   client and exact engagement. Import the PRIVATE Casework v1 JSON.
4. View deadlines, select exact human owner, allocate human-only work,
   preview proposed severity dates, compare a NEW separately authenticated
   original CSV source, and export PRIVATE revised Casework JSON.
5. Transfer revised private source/notes only through an independently
   approved secure channel. Optional .ics calendar events are TENTATIVE
   human follow-ups, NOT scan/retest authority or verified remediation.

The ZIP contains only public original code and public offline UI, NO client
CSV, notes, credentials, tokens, targets, raw evidence or secrets.
All outputs are unsigned human planning drafts. Original source is included
byte-for-byte and pinned in package_kit.py. SHA256SUMS is a convenience
integrity list, NOT a trusted attestation of provenance or consent.

NO main merge, deploy, live assessment, login, grant, scanner, automatic
remediation, original database write, verified retest or real consent.
Existing exact-head CI, original owner, independent security/privacy,
#177/#182/#829, actual separate client/operator consent, action-time
revocation and explicit HUMAN GO remain prerequisites for release.
"""

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def build() -> bytes:
    files: dict[str, bytes] = {"START-HERE.txt": README.encode("utf-8")}
    for filename, expected in ORIGINAL_CASEWORK.items():
        item = ROOT / "casework" / filename
        if item.is_symlink() or not item.is_file():
            raise ValueError("Original Casework resource is missing or a symlink.")
        content = item.read_bytes()
        if sha(content) != expected:
            raise ValueError("Original owner source changed: " + filename)
        files["casework/" + filename] = content
    files["calendar/index.html"] = calendar_package.build()
    manifest = "\n".join(
        f"{sha(data)}  {name}" for name, data in sorted(files.items())
    ) + "\n"
    files["SHA256SUMS.txt"] = manifest.encode("ascii")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as out:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o644 & 0xFFFF) << 16
            out.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return buffer.getvalue()

def main() -> None:
    artifact = build()
    if OUT.is_symlink():
        raise ValueError("Existing output is a symlink.")
    tmp = HERE / ".lightup-calendar-kit.tmp"
    if tmp.exists() or tmp.is_symlink():
        raise ValueError("Pending archive output must be reviewed.")
    try:
        with tmp.open("xb") as fd:
            fd.write(artifact)
            fd.flush()
            os.fsync(fd.fileno())
        os.replace(tmp, OUT)
    finally:
        tmp.unlink(missing_ok=True)
    print(OUT.name, len(artifact), "bytes", sha(artifact))

if __name__ == "__main__":
    main()
