#!/usr/bin/env python3
"""Original PRIVATE disclosure → HUMAN review, entirely local and non-authorizing.

A foreground composer for already-recorded lab artifacts. The original source
validators and native publisher remain authoritative. No recipient dispatch.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "assessment-disclosure-preflight"
INSPECT = SOURCE / "preflight.py"
HUMAN = SOURCE / "human_review.py"
BROWSER = SOURCE / "standalone.html"
ORIGINAL_PREPARED = ("PRIVATE-review.html", "PRIVATE-receipt.json",
                     "PRIVATE-counts.csv", "PRIVATE-human-template.csv")
RECEIPTS = {
    "inspect": "REVIEW_ONLY: three PRIVATE outputs created; no transfer, scan, or authority granted",
    "human": "REVIEW_ONLY: new PRIVATE HUMAN output created; no assessment authority",
}


def hold(reason: str) -> int:
    print("PRIVATE HOLD: " + reason + "; no disclosure, grant or target action.", file=sys.stderr)
    return 3


def owner_private(path: Path, directory: bool) -> bool:
    try:
        info = path.lstat()
        return (info.st_uid == os.geteuid()
                and not (stat.S_IMODE(info.st_mode) & 0o077)
                and (stat.S_ISDIR(info.st_mode) if directory else
                     stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                     and 0 < info.st_size <= 8 * 1024 * 1024))
    except OSError:
        return False


def native(script: Path, args: list[str], receipt: str) -> None:
    source = script.lstat()
    if not stat.S_ISREG(source.st_mode) or not 0 < source.st_size < 2 * 1024 * 1024:
        raise ValueError("source-owned native CLI unavailable")
    result = subprocess.run(
        [sys.executable, "-P", str(script), *args], cwd=ROOT,
        capture_output=True, check=False, timeout=240,
        env={**os.environ, "PYTHONNOUSERSITE": "1",
             "PYTHONDONTWRITEBYTECODE": "1"},
    )
    if (result.returncode != 2 or len(result.stdout) > 4096 or
            len(result.stderr) > 4096 or
            result.stdout.decode("utf-8", "strict").strip() != receipt):
        raise ValueError("source-owned PRIVATE admission refused")


def publish(source: bytes, destination: Path) -> None:
    if len(source) == 0 or len(source) > 128 * 1024:
        raise ValueError("local-only offline page exceeds bound")
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(source)
        output.flush()
        os.fsync(output.fileno())


def original_studio() -> bytes:
    fd = os.open(BROWSER, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 128 * 1024:
            raise ValueError("original standalone HUMAN reviewer unavailable")
        content = os.read(fd, 128 * 1024 + 1)
        after = os.fstat(fd)
        if (len(content) != before.st_size
                or (before.st_dev, before.st_ino, before.st_mtime_ns) !=
                   (after.st_dev, after.st_ino, after.st_mtime_ns)):
            raise ValueError("original offline reviewer changed during read")
        return content
    finally:
        os.close(fd)


def landing(original_count: int) -> bytes:
    # Never embed input source filenames, hashes, targets, credentials, or notes.
    html = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>LightUp · PRIVATE HUMAN disclosure review</title>
<style>body{font:16px/1.55 system-ui;background:#eff4f8;color:#193349;max-width:850px;margin:3rem auto;padding:0 1rem}
main{background:white;border-radius:16px;border:1px solid #ccd7df;padding:2rem}
h1{line-height:1.2}a{color:#125887}li{margin:1rem 0}
.warn{font-weight:750;color:#8b4825}</style>
<main><h1>LightUp · PRIVATE HUMAN disclosure workspace</h1>
<p class="warn">REVIEW_ONLY — nothing here permits a release, scan, recipient transfer or grant.</p>
<p>Already-produced PRIVATE local sources were admitted by the original source-owned
inspector. The original count summary is suppressed for small cohorts; it is not
an anonymity certificate. Source ordinal is not provenance or durable identity.</p>
<ol>
<li><a href="PRIVATE-review.html">Original private source-free preflight review</a></li>
<li><a href="PRIVATE-counts.csv">Original small-cohort-suppressed PRIVATE counts</a></li>
<li><a href="HUMAN-offline-review.html">Original local HUMAN review editor</a>
 — manually choose both the receipt and HUMAN template inside the editor</li>
<li><a href="PRIVATE-human-template.csv">Original unsigned receipt-bound HUMAN CSV</a></li>
</ol><p>To publish a separate PRIVATE scriptless HUMAN follow-up or suppressed HUMAN
summary, explicitly return the edited CSV and exact unchanged original receipt
to the native LightUp console; it never sends the result.</p>
<p>No authentic owner/recipient, client consent, current operator authorization,
revocation-at-use, privacy/security review or HUMAN GO is established. No original
finding was verified or fixed. Keep all private files within an approved local
environment; do not upload the CSV or results to a public service.</p>
<p>Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.</p></main></html>"""
    return html.encode("utf-8")


def run(args: argparse.Namespace) -> int:
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,39}", args.prefix):
        return hold("invalid unique output prefix")
    parent = Path(args.private_parent).absolute()
    if (parent == ROOT or ROOT in parent.parents or
            not owner_private(parent, True)):
        return hold("owner-only 0700 output parent outside source is required")
    destination = parent / args.prefix
    if os.path.lexists(destination):
        return hold("PRIVATE output already exists; never overwrite")
    if args.minimum_cohort < 5 or args.minimum_cohort > 12:
        return hold("minimum cohort disclosure threshold must be 5–12")
    if args.action == "prepare" and (
            not 1 <= len(args.source) <= 12 or len(set(args.source)) != len(args.source)):
        return hold("1–12 distinct original source inputs required")
    try:
        destination.mkdir(mode=0o700)
        if not owner_private(destination, True):
            raise ValueError("private output permissions")
        if args.action == "prepare":
            if not 1 <= len(args.source) <= 12 or len(set(args.source)) != len(args.source):
                raise ValueError("1–12 distinct original source arguments required")
            # Keep source paths inside original source-owned inspector only.
            native(INSPECT, [*args.source, "--private-output-dir", str(destination),
                             "--minimum-cohort", str(args.minimum_cohort)],
                   RECEIPTS["inspect"])
            if not all(owner_private(destination / name, False) for name in ORIGINAL_PREPARED[:3]):
                raise ValueError("original private inspector output missing")
            native(HUMAN, ["prepare", "--receipt",
                            str(destination / "PRIVATE-receipt.json"),
                            "--private-output-dir", str(destination)],
                   RECEIPTS["human"])
            if not owner_private(destination / ORIGINAL_PREPARED[3], False):
                raise ValueError("original PRIVATE HUMAN CSV missing")
            publish(original_studio(), destination / "HUMAN-offline-review.html")
            publish(landing(len(args.source)), destination / "OPEN-PRIVATE.html")
            entry = destination / "OPEN-PRIVATE.html"
        else:
            flags = [args.action, "--receipt", args.receipt,
                     "--answers", args.answers, "--private-output-dir",
                     str(destination)]
            if args.action == "summarize":
                flags += ["--minimum-cohort", str(args.minimum_cohort)]
            native(HUMAN, flags, RECEIPTS["human"])
            filename = ("PRIVATE-human-followup.html" if args.action == "render"
                        else "PRIVATE-human-summary.csv")
            entry = destination / filename
            if not owner_private(entry, False):
                raise ValueError("original source-free HUMAN output missing")
        if not owner_private(entry, False):
            raise ValueError("private source-owned page missing")
        print("PRIVATE REVIEW_ONLY: source-owned disclosure " + args.action +
              " generated; no external share.")
        print("OPEN LOCALLY: " + str(entry))
        print("Recipient, privacy, security and client/operator consent require independent HUMAN checks.")
        return 2
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        # Keep completed original PRIVATE artifacts for custodian inspection.
        return hold("source-owned PRIVATE disclosure operation refused or partial")


def main() -> int:
    parser = argparse.ArgumentParser(description="Original owner-only disclosure + HUMAN review; NEVER release authority")
    modes = parser.add_subparsers(dest="action", required=True)
    for action in ("prepare", "render", "summarize"):
        cmd = modes.add_parser(action)
        cmd.add_argument("--private-parent", required=True)
        cmd.add_argument("--prefix", required=True)
        cmd.add_argument("--minimum-cohort", type=int, default=5)
        if action == "prepare":
            cmd.add_argument("--source", action="append", required=True,
                             help="already-produced private lab file, repeat 1–12")
        else:
            cmd.add_argument("--receipt", required=True)
            cmd.add_argument("--answers", required=True)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
