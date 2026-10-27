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
from verify_offline import Hold as VerifyHold, verify as verify_package
from build_route_standalone import build as build_standalone_route
from build_attention_standalone import build as build_standalone_attention

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
The portable manifest uses schema v2 and lists exact byte lengths and
SHA-256 digests for every studio, support asset, START-HERE.html, this
README.txt and the operator guide. It does not hash itself. Use verify_offline.py from the original native checkout
to check the archive inventory without extracting any files. Add
`--source-root /path/to/trusted-checkout` to compare every packaged software
entry with the exact source-bound file bytes in that explicit local checkout.
This catches a stale but internally consistent ZIP. A successful verification
establishes local byte integrity/parity only, not authenticity, trusted origin,
consent, security findings, permission or release. The native ZIP builder emits
an adjacent `.sha256` sidecar; pass `--sha256-file /path/to/package.zip.sha256`
to the verifier for convenient byte matching. A sidecar delivered with the ZIP
is not an independent trust anchor.
Individual studios independently re-admit any PRIVATE local HUMAN/source data.
Avoid uploading private sources, reviewer notes or generated receipts.
Some studios need previously generated original LightUp artifacts.
The benchmark-candidates studio includes aggregate-only selected-pair metric
deltas and original adverse-flag crossover. When compatible original source
bytes and private unsigned HUMAN drafts are locally admitted, its scriptless
brief and aggregate JSON schema v5 include the anonymous 2–8-round proposal
 timeline, and its changed-only CSV carries every manually selected round. The
human_review_round_history JSON field is null unless compatible source-byte-bound
PRIVATE HUMAN drafts are loaded. No source identifiers,
reviewer identity, chronology, consent, remediation or release are inferred.
A local HUMAN Lab Route Desk with 20 original review options (52–71) now\nships as human-lab-route.html plus adjacent human-lab-route.js, with memory-only\ndiscussion states, private JSON/CSV export and bounded JSON reimport. The\nportable browser app never opens original assessment sources, validates\ncompletion, accesses a network or grants authority. It is NOT an executor.
For devices where the adjacent JS asset could be lost, the same original UI
also ships as studios/human-lab-route-standalone.html: ONE file with the
same local features, embedded exact-source script and SHA-256-pinned CSP.
The original two-file variant remains available. The standalone is
source-only and UNSIGNED, not a software authenticity proof or consent.
It also supports no-overwrite source-free HUMAN report comparisons,
a full local old→proposed change preview and changed-only CSV export, plus a
pending HUMAN follow-up queue CSV and a scriptless current-plan HTML brief.
These additional exports contain only fixed action captions and local marker
labels; queue ordering is a discussion aid, never an urgency or risk rating.
A distinct local HUMAN Attention Workboard is available as
studios/human-lab-attention.html with adjacent human-lab-attention.js.
It admits one to eight complete source-free original self-reports in
manual order, rejects ambiguous duplicate keys and claimed authority,
shows last-declared state and change counts for all twenty original
actions, and lets a human propose a fixed role and follow-up category.
All 20 rows remain in JSON, CSV and scriptless printable HTML.
No real task assignment, reviewer identity, original evidence, client
contact, scan, consent, grant, verification or recipient dispatch exists.
The source-free exported workboard is UNSIGNED, not a source receipt.
Both local files must stay adjacent; no network or storage is used.
Alternatively open studios/human-lab-attention-standalone.html without
an adjacent JS file; it embeds the same original script with a SHA-256
pinned CSP. The packager refuses mismatch with native original files.
Imported 24 KiB-bounded JSON rejects duplicate object properties even
when escaped or nested, unexpected fields and authority claims.
Local search/status filters and confirmation-only bulk NEEDS_INPUT
or IN_PROGRESS affect matching HUMAN markers; a bulk approval action
does not exist. Hidden status rows remain in complete JSON/CSV export.
The source-free HUMAN Lab Route Desk now also provides a multi-round
comparison view for 2-8 operator-ordered local self-report JSON files,
per-stage marker transition summaries, local changed/repeated/needs-input
filters, and a fixed-status-only private CSV covering all 20 original
actions. The browser never infers actor identity or chronological truth
from chooser order, and invalid files clear stale comparisons.
The multi-round HUMAN comparison can also export a completely
scriptless CSP-pinned printable HTML briefing, with all 20 original
status rows and five anonymous stage transition summaries. No input
file names, hashes, sources, notes, targets or identity are included.
The brief is unsigned, private, and never proof of an authentic review.
The same browser now offers a NEW next-round HUMAN discussion proposal:
manually pick one of the selected round markers for EACH of the original
20 action ordinals, with no default choices, no incomplete export and
an explicit final confirmation. The generated JSON is untrusted and has
the exact original false-authority self-report shape for separate native
HUMAN custody; no old round or active local marker changes. Clearing
local selections removes only the in-memory proposed new discussion.
This is separate from original native receipt verification and does not
edit active local markers or authenticate a review.
None of these browser-only conveniences proves that any native lab step
executed or that a review, consent, finding or release is authentic.\nThe native-only companion console options 72/73/74/75 RECEIVE, REOPEN,\nCOMPARE 2–8 and EXACTLY REOPEN the resulting PRIVATE HUMAN history from\nstrict local self-report receipts exported by this source-free editor. The operator MUST manually move downloaded self-report JSON into\nan existing owner-only 0700 directory with a 0600 input outside any Git\ncheckout; browser storage is never restored automatically. Signed identity,\ntrue originals, actual review, consent and release are NOT inferred.\nThis native Python receiver is deliberately NOT included in this ZIP.
The source-only HUMAN Attention Workboard also has native original receipt
custody: console 76 receives a saved v2 fixed-role/follow-up HUMAN proposal
only after REOPENING each of 1-8 original 72/73 PRIVATE self-report rooms,
matching all twenty action positions, status transitions, round-marker
profiles, false authority and fixed proposal enumerations.
Console 77 reopens every original receipt and every attention output byte.
Both operate only in owner-private 0700/0600 directories OUTSIDE source
checkout. They never contact targets, recipients or services.
The original native attention_receipt.py code, HUMAN input and generated
private outputs are deliberately NOT bundled in this browser-only ZIP.
The original native console additionally exposes actions 78/79,
which create/reopen an original receipt-bound, local-only HUMAN
Attention proposal revision portfolio from 2–8 saved original native
76/77 attention receipts. They require 1–8 existing original 72/73
Route receipt rooms; all originals and output bytes are admitted.
The new PRIVATE review cockpit includes a full 20-action multi-revision
matrix, role/follow-up change-only CSV, 5-stage overview, original latest
source-free proposal and unsigned source/destination file receipt.
This native-only Python and PRIVATE output are NOT in this ZIP.
The original native portfolio 78 now also provides an editable
source-free HUMAN revision choice CSV: exactly twenty original action
rows, with both role and follow-up selection set to 0 = WITHHOLD.
Copy it outside the saved original 0700/0600 receipt room to a NEW
owner-private 0600 input file, and explicitly enter a declared
revision number 1–8 only for the fixed HUMAN proposal fields to use.
Native console 80 reopens all original route, attention and portfolio
source bytes and strictly admits the edited original worksheet before
creating a NEW HUMAN Attention v2 source-free proposal; native 81
reopens all exact original and output bytes read-only. Default WITHHOLD
means UNASSIGNED/UNCLASSIFIED, never an actual person or task.
Original native attention_decision.py, personal identities, original
client source, private HUMAN inputs and all generated PRIVATE output
are deliberately NOT distributed in this software-only ZIP.

Original HUMAN revision order does NOT prove chronology or real work.

\nNative checkout users can additionally prepare an original-source PRIVATE
casebook and source-byte ledger with assessment-integrated-suite/console.py
options 21/22. The same console now has 81 actions, including original
source-bound PRIVATE HUMAN finding selection, reply and sender triage
(options 23-31), exact-receipt PRIVATE disclosure HUMAN decisions and
suppressed HUMAN counts (32-34), and original HUMAN retention plan timeline
and drift (35-36). Source-specific workrooms still require native original
admission. An operator can now explicitly save and restore owner-only 0600
PATH-ONLY console sessions, view local PRIVATE workspace bookmarks and
compare 2-8 saved session path histories (37-39), and prepare a
source-free PRIVATE route board of existing local workrooms (40), or
read a STRICT saved owner-private session for an isolated route board without
changing the live console paths (41).
The native console also supports a source-PATH-snapshot-bound HUMAN work
queue CSV and offline owner-private HTML (42), strict HUMAN CSV reopen
against the exact unchanged session (43), a minimum-necessary single-team
PRIVATE HUMAN task deck (44) and a redacted 2-8 revision history (45).
An original saved 0600 session may resume the native offline HUMAN
browser workroom without replacing current paths (46), and a source-free
priority/declared-date/team workload board can be created locally (47).
The complete native PRIVATE workpack (48) now composes the original
source-bound interactive HUMAN queue, declared-date priorities, and
assigned-team-only task decks in one new 0700 local folder, using ONE
pinned owner-only 0600 HUMAN CSV snapshot for consistent child views.
For a FIRST workpack, options 48/49 accept an intentionally EMPTY CSV
selector and seed all 21 source-PATH-referenced workflow entries as
UNASSESSED (no HUMAN decision, owner, approval or authorization).
Provided existing original CSV files still require exact strict
source-PATH/session binding. An original strict saved session can
recreate this full workpack without modifying live console paths (49).
Native option 50 and suite.py workpack-progress can produce a separate
owner-private offline HUMAN stage/team/declared-date progression from 2-8
original exact-session workpack snapshots without copying question text.
This remains NATIVE-ONLY and is not bundled in browser-only software.
Original Lab Launchpad console 52-54 invokes ONLY the pre-existing source
owner offline build/reopen/compare; 55 joins 3-8 exact original proposals in
one PRIVATE HUMAN portfolio. 56-57 prepare/finalize strict source-bound
PRIVATE HUMAN lab proposal reviews. 58 re-admits original sources and prior
HUMAN CSV to reopen all choices in a new owner-private offline editor. Full
instructions accompany this kit as GUIDE-LAB-PLANNING.md. None of those
native functions or PRIVATE source files are executable in this browser-only
ZIP, and none conveys active target consent, scanning or release authority.

Native option 51 and suite.py workpack-continue re-admit an existing
original owner-only workpack from a strict unchanged saved session and
generate a fresh completely editable HUMAN workpack with a new explicitly
declared review date; old workpack unchanged. New v2 unsigned workpack
receipts bind the exact pinned 0600 CSV bytes/length; older v1 receipts
remain legacy admission without a digest. Option 50 now publishes a
source-minimal searchable offline Progress Cockpit with CSP-pinned local
JavaScript and an independent scriptless 0600 fallback. The native
console opens with a grouped navigator; ALL shows every
original numeric action, ?keyword searches, HELP shows the manual
37->49->50->51 HUMAN-only flow. These are PRIVATE local workflows and
are never actual risk certification, consent, scan permission or a
production assessment service.

The browser can preview proposed imported HUMAN field changes without
revealing question text and bulk-assign staged visible tasks to a HUMAN
team without contacting recipients or granting any assessment authority.
Its browser-only HUMAN attention dashboard live-updates local HOLD,
unavailable originals, manually selected review date, upcoming declared
dates and team workloads, and can filter the workflow rows without hiding
any rows from full original CSV export. No real calendar is queried or set.
The original source-owned suite.py now also accepts a foreground
human-workpack CLI subcommand to reconstruct PRIVATE local HUMAN workpacks
from a strict original saved 0600 session. It requires an existing 0700
parent outside the checkout, unique folder, a HUMAN declared review date
and the EXACT 'BUILD PRIVATE WORKPACK' confirmation string. The original
HUMAN CSV remains optional, with strict re-admission when supplied.
The original queue editor supports a CSP SHA256-pinned source-bound
interactive PRIVATE browser UI, HUMAN bulk HOLD/NEEDS INPUT, undo/redo and
explicit custody acknowledgement after a requested browser CSV download.
No HUMAN stage ever means PASS or authorization. These owner-private native
functions contain sensitive local file: bookmarks and HUMAN question text,
and are deliberately NOT included in this browser-only software ZIP.
The session JSON may reveal confidential client folder names and must NEVER
be put in this ZIP.
All such PRIVATE outputs are created locally outside the checkout.
This ZIP is browser software only; it intentionally does NOT embed any
native Python programs, generated source-specific studio, or client sources.
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
        if not name.endswith(".html"):
            continue  # Local support scripts are packaged, not offered as standalone pages.
        if name in ("lab-launchpad.html", "lab-scenario-studio.html", "human-lab-route.html",
                    "human-lab-route-standalone.html", "human-lab-attention.html",
                    "human-lab-attention-standalone.html"):
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
INCUBATE M3/M7 PLAN/LAB ONLY · DRAFT/HOLD. Open README.txt for requirements.
<a href="GUIDE-LAB-PLANNING.md">Read the original offline Lab HUMAN workflow guide</a>.</footer>
</html>""").encode("utf-8")

def build(destination: Path) -> int:
    parent = destination.parent
    st = parent.lstat()
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise Hold("HOLD: software destination parent must be an ordinary directory")
    sidecar = destination.with_name(destination.name + ".sha256")
    if "\n" in destination.name or "\r" in destination.name or "\\" in destination.name:
        raise Hold("HOLD: package filename cannot be represented safely in a checksum sidecar")
    if destination.exists() or destination.is_symlink():
        raise Hold("HOLD: existing destination will never be replaced")
    if sidecar.exists() or sidecar.is_symlink():
        raise Hold("HOLD: existing checksum sidecar will never be replaced")
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
    # APPS is the single canonical source for both the private native kit
    # and this portable package. Re-admit the independently derived one-file
    # browser app before writing ANY package bytes (never include duplicates).
    standalone_name = "human-lab-route-standalone.html"
    if standalone_name not in APPS:
        raise Hold("HOLD: missing one-file HUMAN route from native workspace")
    standalone_path = APPS[standalone_name]
    if standalone_path != ROOT / "assessment-integrated-suite/human-lab-route-standalone.html":
        raise Hold("HOLD: unrecognised standalone HUMAN route source")
    if standalone_path.read_bytes() != build_standalone_route():
        raise Hold("HOLD: standalone HUMAN route software does not match original sources")
    attention_name = "human-lab-attention-standalone.html"
    attention_path = ROOT / "assessment-integrated-suite/human-lab-attention-standalone.html"
    if APPS.get(attention_name) != attention_path:
        raise Hold("HOLD: missing original standalone HUMAN attention source")
    if attention_path.read_bytes() != build_standalone_attention():
        raise Hold("HOLD: HUMAN attention standalone differs from original browser sources")
    guide_path = ROOT / "assessment-integrated-suite/LAB-PLANNING.md"
    read_safe(guide_path, 262_144)
    guide = guide_path.read_bytes()
    files = [(name, target) for name, target, _ in originals if name.endswith(".html")]
    opening = front_page(files)
    readme = README.encode("utf-8")
    package_assets = [
        {"filename": "START-HERE.html", "bytes": len(opening),
         "sha256_unsigned": hashlib.sha256(opening).hexdigest()},
        {"filename": "README.txt", "bytes": len(readme),
         "sha256_unsigned": hashlib.sha256(readme).hexdigest()},
        {"filename": "GUIDE-LAB-PLANNING.md", "bytes": len(guide),
         "sha256_unsigned": hashlib.sha256(guide).hexdigest()},
    ]
    inventory = json.dumps({
        "schema": "lightup.assessment_offline_software_kit.v2",
        "status": "REVIEW_ONLY",
        "software_only": True, "sources_or_client_data_included": False,
        "original_app_count": len(files), "support_asset_count": len(originals) - len(files),
        "files": manifest, "package_assets": package_assets,
        "manifest_self_hash_excluded": True,
        "operator_guide": {
            "filename": "GUIDE-LAB-PLANNING.md", "bytes": len(guide),
            "sha256_unsigned": hashlib.sha256(guide).hexdigest(),
        },
        **{flag: False for flag in FALSE_FLAGS},
    }, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    completed = False
    sidecar_created = False
    try:
        with os.fdopen(fd, "wb") as output:
            with ZipFile(output, mode="w", compression=ZIP_DEFLATED, compresslevel=9) as package:
                package.writestr(zip_info("START-HERE.html"), opening)
                package.writestr(zip_info("README.txt"), readme)
                package.writestr(zip_info("GUIDE-LAB-PLANNING.md"), guide)
                package.writestr(zip_info("manifest.json"), inventory)
                for _, name, raw in originals:
                    package.writestr(zip_info(name), raw)
            output.flush()
            os.fsync(output.fileno())
        try:
            # Verify the finished ZIP and source-bound studio bytes before keeping it.
            # This is a build-integrity check, not QA or proof of trusted provenance.
            verify_package(destination, source_root=ROOT)
        except VerifyHold:
            raise Hold("HOLD: generated offline ZIP failed native inventory/source-parity verification") from None
        zip_digest = hashlib.sha256(destination.read_bytes()).hexdigest()
        checksum = (zip_digest + "  " + destination.name + "\n").encode("utf-8")
        sidecar_fd = os.open(sidecar, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
        sidecar_created = True
        with os.fdopen(sidecar_fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(checksum)
            output.flush()
            os.fsync(output.fileno())
        completed = True
        print(f"SOFTWARE-ONLY / REVIEW_ONLY: portable offline kit contains {len(files)} offline HUMAN studios + {len(originals)-len(files)} local support assets.")
        print("LOCAL ZIP: " + str(destination))
        print("Unsigned SHA-256: " + zip_digest)
        print("SHA-256 sidecar: " + str(sidecar))
        print("Sidecar is a convenience copy, not an independent trust anchor.")
        return 2
    finally:
        if not completed:
            destination.unlink(missing_ok=True)
            if sidecar_created:
                sidecar.unlink(missing_ok=True)

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
