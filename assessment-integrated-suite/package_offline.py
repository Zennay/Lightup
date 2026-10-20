#!/usr/bin/env python3
"""Software-only portable offline LightUp studio bundle. No source or scan."""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import stat
import sys
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

from suite import APPS, Hold, ROOT, read_safe

MAX_APP = 4 * 1024 * 1024
FALSE_FLAGS = ("authorization_granted", "consent_verified", "source_authenticated",
               "finding_verified", "dispatch_allowed", "release_allowed")
README = """LightUp PRIVATE Offline Assessment Toolkit
-------------------------------------------
SOFTWARE ONLY; NO CUSTOMER OR ASSESSMENT SOURCE DATA INCLUDED.

Extract this ZIP into a new private directory on an approved local computer.
Open START-HERE.html from disk. Do not publish/serve the files over HTTP.
All studios are complete original offline HTML assets from independently held
DRAFT/HOLD PR source snapshots. Use local file choosers manually.
Nothing in this ZIP grants client/operator consent, source authenticity,
authority to scan, vulnerability verification, release or deployment.

These source files are unsigned. manifest.json hashes are only local file-byte
integrity references; they do not authenticate source provenance.
Individual studios independently re-admit any PRIVATE local HUMAN/source data.
Avoid uploading private sources, reviewer notes or generated receipts.
Some studios need previously generated original LightUp artifacts.
Native checkout users can additionally prepare an original-source PRIVATE
casebook and source-byte ledger with assessment-integrated-suite/console.py
options 21/22. This ZIP is browser software only and intentionally does
NOT embed or execute the native Python casebook or client sources.
A missing required original input means HOLD; never fabricate findings.

LightUp: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.
Original source-owner, security/privacy/browser reviews, exact-head hosted &
permanently registered VPS CI, #177/#182/#829, true separately authenticated
current client and operator consent including at-use revocation, and explicit
HUMAN GO remain mandatory before release or real target activity.
"""

def zip_info(filename: str) -> ZipInfo:
    z = ZipInfo(filename, date_time=(1980, 1, 1, 0, 0, 0))
    z.compress_type = ZIP_DEFLATED
    z.create_system = 3
    z.external_attr = 0o100644 << 16
    z.flag_bits = 0x800
    return z

def front_page(files: list[tuple[str, str]]) -> bytes:
    sections = {
        "01  PRIVATE source & human review": [],
        "02  Prepare isolated, fictional lab work": [],
        "03  Examine already-produced benchmark declarations": [],
        "04  Coordinate multiple humans locally": [],
    }
    for name, destination in files:
        if name in ("lab-launchpad.html", "lab-scenario-studio.html"):
            key = "02  Prepare isolated, fictional lab work"
        elif name in ("benchmark-lineage.html", "benchmark-candidates.html",
                      "lab-longitudinal-trends.html"):
            key = "03  Examine already-produced benchmark declarations"
        elif name in ("multi-reviewer-consensus.html", "human-followup-calendar.html",
                      "human-workspace-ledger.html", "human-remediation-team-room.html",
                      "human-lab-to-remediation.html"):
            key = "04  Coordinate multiple humans locally"
        else:
            key = "01  PRIVATE source & human review"
        title = name.replace(".html", "").replace("-", " ").title()
        sections[key].append((title, destination))
    groups = ""
    for heading, items in sections.items():
        entries = "".join(
            '<li><a href="' + html.escape(path, quote=True) + '">' +
            html.escape(label) + '</a><span>Original offline local tool · no auto-import</span></li>'
            for label, path in items
        )
        groups += "<section><h2>" + html.escape(heading) + "</h2><ul>" + entries + "</ul></section>"
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp · Offline PRIVATE Assessment Studio</title>
<style>
:root{color-scheme:dark;font:16px/1.55 system-ui,sans-serif;background:#0b1421;color:#eaf2fb}
*{box-sizing:border-box}body{max-width:1180px;margin:auto;padding:24px}
header{border:1px solid #35516a;border-radius:22px;background:linear-gradient(125deg,#15334b,#112237);padding:34px}
h1{font-size:clamp(2rem,5vw,3.5rem);line-height:1.15;margin:0 0 14px}
p{color:#c7d8e9}.flag{font-weight:750;color:#f7d6a1}
main{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:18px;margin-top:20px}
section{background:#14273b;border:1px solid #38536d;border-radius:15px;padding:18px}
h2{font-size:1.1rem;margin:4px 0 16px;color:#b7f4dd}
ul{margin:0;padding:0;list-style:none}li{border-top:1px solid #354c64;padding:12px 0}
a{display:block;color:#a6dfff;font-size:1.05rem;font-weight:700;text-decoration:underline}
a:focus-visible{outline:3px solid #f2cf87;outline-offset:4px}
span{display:block;color:#a2bfd0;font-size:.85rem;margin-top:3px}
footer{margin:22px 0;padding:18px;border-left:4px solid #efcd91;background:#192739}
@media(max-width:680px){body{padding:12px}main{display:block}section{margin:15px 0}}
</style>
<header><p class="flag">LIGHTUP / SOFTWARE-ONLY / REVIEW_ONLY</p>
<h1>Private Assessment Studio</h1>
<p>""" + str(len(files)) + """ independent original offline HUMAN and lab planning workrooms, delivered together.
Every original source remains DRAFT/HOLD. All files open locally with no server.</p>
<p class="flag">No scan, security approval, verified finding, original source authentication,
client or operator consent, grant, deployment, or automatic task execution.</p></header>
<main>""" + groups + """</main><footer><b>Keep all imported sources and HUMAN decisions PRIVATE.</b>
These studios accept only separately obtained local files. A hash or encrypted
document is not proof of authentic origin or current authorization. Before any
external release, independently establish source ownership, privacy constraints,
current authenticated client/operator consent and revocation at use.
INCUBATE M3/M7 PLAN/LAB ONLY · DRAFT/HOLD. Open README.txt for requirements.</footer>
</html>""").encode("utf-8")

def build(destination: Path) -> int:
    parent = destination.parent
    st = parent.lstat()
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise Hold("HOLD: software destination parent must be an ordinary directory")
    if destination.exists() or destination.is_symlink():
        raise Hold("HOLD: existing destination will never be replaced")
    originals = []
    manifest = []
    total = 0
    for name, source in sorted(APPS.items()):
        read_safe(source, MAX_APP)
        raw = source.read_bytes()
        total += len(raw)
        if total > 20 * 1024 * 1024:
            raise Hold("HOLD: bundled product source is over size limit")
        destination_name = "studios/" + name
        originals.append((name, destination_name, raw))
        manifest.append({
            "filename": destination_name, "source_path": str(source.relative_to(ROOT)),
            "bytes": len(raw), "sha256_unsigned": hashlib.sha256(raw).hexdigest(),
        })
    files = [(name, target) for name, target, _ in originals]
    opening = front_page(files)
    inventory = json.dumps({
        "schema": "lightup.assessment_offline_software_kit.v1",
        "status": "REVIEW_ONLY",
        "software_only": True, "sources_or_client_data_included": False,
        "original_app_count": len(files), "files": manifest,
        **{flag: False for flag in FALSE_FLAGS},
    }, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    completed = False
    try:
        with os.fdopen(fd, "wb") as output:
            with ZipFile(output, mode="w", compression=ZIP_DEFLATED, compresslevel=9) as package:
                package.writestr(zip_info("START-HERE.html"), opening)
                package.writestr(zip_info("README.txt"), README.encode("utf-8"))
                package.writestr(zip_info("manifest.json"), inventory)
                for _, name, raw in originals:
                    package.writestr(zip_info(name), raw)
            output.flush()
            os.fsync(output.fileno())
        completed = True
        print(f"SOFTWARE-ONLY / REVIEW_ONLY: portable offline kit contains {len(originals)} unchanged original apps.")
        print("LOCAL ZIP: " + str(destination))
        print("Unsigned SHA-256: " + hashlib.sha256(destination.read_bytes()).hexdigest())
        return 2
    finally:
        if not completed:
            destination.unlink(missing_ok=True)

def main() -> int:
    p = argparse.ArgumentParser(description="Create software-only offline PRIVATE LightUp product ZIP")
    p.add_argument("--output", required=True, help="new software-only ZIP path; never overwrite")
    args = p.parse_args()
    try:
        return build(Path(args.output).absolute())
    except (Hold, OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, Hold) else "HOLD: cannot prepare offline kit",
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
