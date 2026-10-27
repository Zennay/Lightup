#!/usr/bin/env python3
"""Build/inspect an additive offline LightUp HUMAN scheduler software distribution.

The ORIGINAL #1673 integrated suite is built and verified without modification.
A separately named merged runnable source tree adds only our companion.
Software-only: no operator/client packets, tokens, notes, targets or credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import os
from pathlib import Path
import secrets
import shutil
import stat
import sys
import zipfile

import schedule
sys.path.insert(0, str(schedule.PARENT / "remediation-integrated-workspace"))
import install

KIND = "lightup.private_scheduler_software_distribution"
WARNING = ("PRIVATE software-only, no real evidence/client/source authentication, "
           "consent, grant, verification of a finding, remediation, retest, "
           "release approval or HUMAN GO. INCUBATE M3/M7 DRAFT/HOLD.")
SCHEDULER_FILES = (
    "README.md", "schedule.py", "scheduler.js", "archive_schedule.py",
    "schedule_vault.py", "complete_handoff.py", "carry_native.py", "queue_handoff.py",
    "bundle.py", "bundle_receive.py",
)
MAX_MEMBER = 4_000_000
MAX_TOTAL = 20_000_000
ARCHIVE = "remediation-scheduler-software-only.zip"
DISPOSITION = "REVIEW_ONLY_NO_RELEASE_AUTHORITY"


def require(ok: bool, reason: str) -> None:
    install.require(ok, reason)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def page() -> bytes:
    warning = html.escape(WARNING)
    return ('''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; img-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp · PRIVATE evidence-remediation recipient workspace</title>
<style>body{font:16px/1.6 system-ui,sans-serif;background:#edf2f7;color:#172b44;margin:0}main{max-width:950px;margin:30px auto;padding:20px}section,aside{background:white;padding:18px;margin:15px 0;border:1px solid #d5dfea;border-radius:12px}aside{border-left:6px solid #b27924}a{color:#135aa4}code,pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f0f4f9;padding:4px}</style></head><body>
<main><h1>LightUp · PRIVATE HUMAN recipient planner</h1><aside>''' + warning + '''</aside>
<section><h2>1 · Original held evidence workroom</h2>
<p><a href="original-home.html">Open unchanged original private offline suite</a>. This contains the original Casework, Evidence Ledger, portfolio and encrypted human handoff interfaces. No current customer authority is implied by opening this file.</p></section>
<section><h2>2 · Receive genuine source-free HUMAN packets</h2>
<p>Only use originally produced, separately authorized source-free native Cockpits; the planner cannot fabricate a validated finding or permission. From this offline private software directory:</p>
<h3>Source-free plain .luhz or encrypted .luhx</h3>
<pre>python3 remediation-recipient-scheduler/archive_schedule.py \
  --archive "$HOME/lightup-private/approved-human-01.luhz" \
  --output-dir "$HOME/lightup-private/recipient-plan-01"</pre>
<p>For source-free password encrypted .luhx, use <code>--encrypted-archive</code>. The unchanged original native admission and HUMAN recipient reviewer remain included. No plaintext ZIP intermediate.</p>
<h3>Encrypted native full .luhp Cockpit plus HUMAN journal</h3>
<pre>python3 remediation-recipient-scheduler/complete_handoff.py \
  --review-package "$HOME/lightup-private/approved-full-01.luhp" \
  --output-dir "$HOME/lightup-private/full-human-schedule-01"</pre>
<p>This decrypts the full original source-free Cockpit plus its exact bound original HUMAN journal in memory, then creates a new PRIVATE recipient review and scheduler. Output contains sensitive plaintext HUMAN notes in 0700/0600 directories. No sender/client identity or consent is authenticated by passwords alone.</p></section>
<section><h2>3 · Continue or print private HUMAN planning</h2>
<p>The offline HUMAN board offers owner and due-date planning, filtered backlog, bulk edits, optional encrypted private .lurp checkpoints and carefully bounded anonymous calendar reminders. For offline native reopening and owner-scoped scriptless agendas use <code>schedule_vault.py</code>.</p>
<h3>New or reordered source-free packet selection</h3><p>Use <code>carry_native.py</code> to carry previous HUMAN fields only for exact original packet matches with explicit typed human approval. Changed/absent packets never become automatically resolved.</p>
<pre>python3 remediation-recipient-scheduler/carry_native.py \
  --vault "$HOME/lightup-private/previous-human-plan.lurp" \
  --cockpit "$HOME/lightup-private/current-original-01" \
  --output-dir "$HOME/lightup-private/human-carry-01"</pre>
<p><a href="remediation-recipient-scheduler/README.md">Complete private recipient operator guide</a>. No network, scanner, grant or calendar API is invoked by these tools.</p></section>
<section><h2>4 · Share selected HUMAN follow-up only</h2>
<p>Within the PRIVATE scheduling board choose a filtered HUMAN subset and select <strong>Encrypt selected HUMAN-only handoff</strong>. Owner labels and human notes are independent opt-ins and both are omitted by default. The separate encrypted <code>.luhq</code> never includes original source SHA-256, packets, slot/counts, client IDs or evidence. Source authenticity cannot be reconstructed.</p>
<pre>python3 remediation-recipient-scheduler/queue_handoff.py \
  --handoff "$HOME/lightup-private/approved-selected-followup.luhq" \
  --output-dir "$HOME/lightup-private/received-selected-human-01"</pre>
<p>Recipients need their own legitimate disclosure permission and local password. The new PRIVATE output is a source-redacted, scriptless read-only HUMAN brief, not a finding, proof, consent, grant, scan or remediation.</p></section>
<section><h2>Protect the original held release gates</h2><p>All original source-owner review, exact-head hosted and permanently named VPS CI, independent security/privacy/browser/crypto review, original #177/#182/#829, genuine current separately authenticated client and operator consent with action-time revocation and explicit HUMAN GO remain mandatory. The package is software-only. Local hashes are NOT source signatures or approvals.</p></section>
</main></body></html>''').encode("utf-8")


def read_checked(path: Path) -> bytes:
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1
            and s.st_size <= MAX_MEMBER, "Unsupported/symlinked software source")
    return path.read_bytes()


def files_from_original(original: Path, software: Path) -> dict[str, dict]:
    catalog = {}
    for p in sorted(original.rglob("*")):
        if p.is_dir():
            require(not p.is_symlink(), "Original generated folder linked")
            continue
        relative = p.relative_to(original).as_posix()
        if relative in {"manifest.json", "software-only.zip"}:
            continue
        if relative == "index.html":
            relative = "original-home.html"
        raw = read_checked(p)
        dest = software / relative
        dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        install.write_file(dest, raw)
        catalog[relative] = {"sha256": digest(raw), "bytes": len(raw)}
    return catalog


def build(destination: Path) -> None:
    require(destination.is_absolute() and not destination.exists() and
            not destination.is_symlink() and
            destination.parent == destination.parent.resolve(strict=True),
            "Choose a new literal absolute owner-private folder")
    install.owner_dir(destination.parent)
    require(not (destination == schedule.PARENT or
                 destination in schedule.PARENT.parents or
                 schedule.PARENT in destination.parents),
            "Software output must be separate from checked out sources")
    stage = destination.parent / (".lightup-remediation-distribution-" + secrets.token_hex(12))
    os.mkdir(stage, 0o700)
    try:
        original = stage / "original-native-suite"
        install.build(original)
        install.verify(original)  # Existing native original metadata verification, unchanged.
        original_manifest = read_checked(original / "manifest.json")
        software = stage / "software"
        os.mkdir(software, 0o700)
        catalog = files_from_original(original, software)
        for name in SCHEDULER_FILES:
            relative = "remediation-recipient-scheduler/" + name
            source = schedule.PARENT / relative
            raw = read_checked(source)
            require(0 < len(raw) <= MAX_MEMBER and relative not in catalog,
                    "Unsafe or colliding additive recipient scheduler source")
            target = software / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            install.write_file(target, raw)
            catalog[relative] = {"sha256": digest(raw), "bytes": len(raw)}
        new_home = page()
        install.write_file(software / "index.html", new_home)
        catalog["index.html"] = {"sha256": digest(new_home), "bytes": len(new_home)}
        require(len(catalog) >= 80 and
                sum(x["bytes"] for x in catalog.values()) <= MAX_TOTAL,
                "Incomplete or excessive software-only distribution")
        binary = stage / ARCHIVE
        with zipfile.ZipFile(binary, "w", compression=zipfile.ZIP_DEFLATED,
                             compresslevel=8, allowZip64=False) as z:
            for name in sorted(catalog):
                info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o100600 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, read_checked(software / name),
                           compress_type=zipfile.ZIP_DEFLATED, compresslevel=8)
        os.chmod(binary, 0o600)
        receipt = {
            "kind": KIND, "version": 1, "disposition": DISPOSITION,
            "authority_granted": False, "consent_verified": False,
            "remediation_verified": False, "scan_authorized": False,
            "original_native_manifest_sha256": digest(original_manifest),
            "source_heads": install.catalog()[1]["source_heads"],
            "software_files": catalog,
            "portable_zip_sha256": digest(read_checked(binary)),
            "portable_zip_bytes": binary.stat().st_size,
            "warning": WARNING,
        }
        install.write_file(stage / "bundle-manifest.json", install.canonical(receipt))
        install.write_file(stage / "index.html", new_home.replace(
            b'href="original-home.html"', b'href="software/original-home.html"').replace(
            b'href="remediation-recipient-scheduler/README.md"',
            b'href="software/remediation-recipient-scheduler/README.md"'))
        # Inspect the just-created staged artifact before exclusive publication.
        inspect(stage)
        require(not destination.exists(), "Another operator created the destination")
        install.exclusive_publish(stage, destination)
        print("REVIEW_ONLY: PRIVATE source-only scheduler distribution:", destination)
        print("Open offline:", destination / "index.html")
        print("Portable software-only archive:", destination / ARCHIVE)
        print("Native original held suite preserved byte-for-byte in original-native-suite/")
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def inspect(folder: Path) -> None:
    install.owner_dir(folder)
    require({p.name for p in folder.iterdir()} ==
            {"original-native-suite", "software", ARCHIVE, "bundle-manifest.json", "index.html"},
            "Unexpected private distribution root files")
    install.verify(folder / "original-native-suite")
    doc = install.parse(install.read_owner_file(folder / "bundle-manifest.json"))
    require(set(doc) == {
        "kind", "version", "disposition", "authority_granted",
        "consent_verified", "remediation_verified", "scan_authorized",
        "original_native_manifest_sha256", "source_heads", "software_files",
        "portable_zip_sha256", "portable_zip_bytes", "warning"
    } and doc["kind"] == KIND and type(doc["version"]) is int and doc["version"] == 1
            and doc["disposition"] == DISPOSITION and doc["warning"] == WARNING
            and all(doc[x] is False for x in (
                "authority_granted", "consent_verified",
                "remediation_verified", "scan_authorized")),
            "Not a non-authorizing source-only planner distribution")
    require(doc["source_heads"] == install.catalog()[1]["source_heads"] and
            doc["original_native_manifest_sha256"] ==
            digest(install.read_owner_file(folder / "original-native-suite/manifest.json")),
            "Original pinned source manifest mismatch")
    software = folder / "software"
    install.owner_dir(software)
    catalog = doc["software_files"]
    require(type(catalog) is dict and len(catalog) >= 80,
            "Incomplete merged scheduler software catalog")
    expected = set(catalog)
    observed = set()
    for p in software.rglob("*"):
        if p.is_dir():
            install.owner_dir(p)
            continue
        observed.add(p.relative_to(software).as_posix())
    require(observed == expected, "Unexpected, missing or replaced software files")
    native = install.parse(install.read_owner_file(
        folder / "original-native-suite/manifest.json"))["files"]
    native_names = {("original-home.html" if x == "index.html" else x)
                    for x in native if x not in ("manifest.json", "software-only.zip")}
    companion_names = {"remediation-recipient-scheduler/" + n for n in SCHEDULER_FILES}
    require(set(catalog) == native_names | companion_names | {"index.html"},
            "Merged source must contain ONLY original pinned assets and this companion")
    for name, metadata in catalog.items():
        require(type(name) is str and name in
                native_names | companion_names | {"index.html"}
                and type(metadata) is dict and set(metadata) == {"sha256", "bytes"}
                and type(metadata["bytes"]) is int and 0 <= metadata["bytes"] <= MAX_MEMBER,
                "Unexpected merged asset descriptor")
        raw = install.read_owner_file(software / name)
        require(len(raw) == metadata["bytes"] and digest(raw) == metadata["sha256"],
                "Merged source file differed from recorded local bytes")
    zbytes = install.read_owner_file(folder / ARCHIVE)
    require(len(zbytes) == doc["portable_zip_bytes"] and
            digest(zbytes) == doc["portable_zip_sha256"], "Portable software ZIP changed")
    with zipfile.ZipFile(folder / ARCHIVE) as z:
        require(z.namelist() == sorted(expected), "Portable scheduler software inventory changed")
        for item in z.infolist():
            require(not item.is_dir() and (item.external_attr >> 16) == 0o100600
                    and item.file_size <= MAX_MEMBER and
                    z.read(item.filename) == install.read_owner_file(software / item.filename),
                    "Private software ZIP member deviated from original installed bytes")
    require(install.read_owner_file(software / "index.html") == page(),
            "Scheduler portal differs from locally pinned renderer")
    require(install.read_owner_file(folder / "index.html") == page().replace(
        b'href="original-home.html"', b'href="software/original-home.html"').replace(
        b'href="remediation-recipient-scheduler/README.md"',
        b'href="software/remediation-recipient-scheduler/README.md"'),
        "Outer private software portal changed")
    print("REVIEW_ONLY: original unchanged suite + new runnable scheduler bundle locally consistent")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    p = sub.add_parser("build", help="Build new PRIVATE merged original+scheduler source-only package")
    p.add_argument("--output-dir", required=True, type=Path)
    p = sub.add_parser("inspect", help="Inspect existing pinned PRIVATE scheduler distribution")
    p.add_argument("--workspace", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.action == "build":
            build(args.output_dir)
        else:
            inspect(args.workspace)
        return 2
    except (install.Hold, ValueError, OSError, KeyError, TypeError,
            zipfile.BadZipFile, RuntimeError) as exc:
        print("HOLD: private source-only distribution:", exc, file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
