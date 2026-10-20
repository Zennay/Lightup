#!/usr/bin/env python3
"""Original PRIVATE assessment → HUMAN follow-up casebook, offline only."""
from __future__ import annotations
import argparse
import html
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
BRIDGE = ROOT / "assessment-integrated-suite/remediation_handoff.py"
LEDGER = ROOT / "assessment-workspace-ledger/ledger.py"
STUDIO = ROOT / "assessment-remediation/standalone.html"


def hold(reason: str) -> int:
    print("PRIVATE HOLD: " + reason + "; nothing approved or shared.", file=sys.stderr)
    return 3


def owner_parent(name: str) -> Path:
    path = Path(name).absolute()
    st = path.lstat()
    if (path == ROOT or ROOT in path.parents or not stat.S_ISDIR(st.st_mode)
            or st.st_uid != os.geteuid() or st.st_mode & 0o077):
        raise ValueError("requires owner-only 0700 directory outside source")
    return path


def private_file(path: Path) -> bool:
    st = path.lstat()
    return (stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid()
            and not st.st_mode & 0o077 and st.st_nlink == 1
            and 0 < st.st_size <= 8 * 1024 * 1024)


def copy_studio(destination: Path) -> None:
    fd = os.open(STUDIO, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 256 * 1024:
            raise ValueError("original offline studio invalid")
        raw = os.read(fd, 256 * 1024 + 1)
        after = os.fstat(fd)
        if (len(raw) != before.st_size
                or (before.st_ino, before.st_size, before.st_mtime_ns) !=
                   (after.st_ino, after.st_size, after.st_mtime_ns)):
            raise ValueError("original offline studio changed")
    finally:
        os.close(fd)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())


def original(script: Path, flags: list[str]) -> tuple[int, list[str]]:
    st = script.lstat()
    if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= 1024 * 1024:
        raise ValueError("original PRIVATE producer unavailable")
    result = subprocess.run([sys.executable, "-P", str(script), *flags], cwd=ROOT,
                            capture_output=True, timeout=240, check=False,
                            env={**os.environ, "PYTHONNOUSERSITE": "1",
                                 "PYTHONDONTWRITEBYTECODE": "1"})
    if (len(result.stdout) > 8192 or len(result.stderr) > 8192
            or result.returncode not in (2, 3)):
        raise ValueError("original source refused")
    return result.returncode, result.stdout.decode("utf-8", "strict").strip().splitlines()


def landing(workspace: Path, name: str, ledger: Path, adverse: bool) -> bytes:
    workspace_name = html.escape(workspace.name, quote=True)
    ledger_name = html.escape(ledger.name, quote=True)
    report_name = html.escape(name, quote=True)
    status = "HOLD — original adverse source requires HUMAN review" if adverse else "REVIEW_ONLY — unverified original source"
    page = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp PRIVATE HUMAN assessment casebook</title>
<style>body{font:16px/1.55 system-ui;color:#213749;background:#edf2f7;margin:3rem auto;max-width:820px;padding:0 1rem}
main{background:white;border:1px solid #cad6e0;border-radius:18px;padding:2rem}a{color:#155d89}
li{padding:.5rem}.warn{font-weight:750;color:#8a4520}</style><main>
<h1>LightUp PRIVATE HUMAN assessment casebook</h1><p class="warn">""" +
            html.escape(status) + """ — NEVER authorization.</p>
<p>Two distinct original offline producer outputs: an unchanged source-bound
finding review and a private exact-byte snapshot for human continuity.</p>
<ol><li><a href="../""" + workspace_name + "/" + report_name +
            """-private.html">Original source-bound HUMAN finding dossier</a></li>
<li><a href="../""" + workspace_name +
            """/MAP-OFFLINE.html">Original offline source-to-finding HUMAN mapping studio</a></li>
<li><a href="../""" + ledger_name +
            """/OPEN-PRIVATE.html">Private original byte inventory + HUMAN review</a></li></ol>
<p>Native source and current owner/client/engagement identity must be independently
verified. A removed finding is NOT a fix. Browser proposals are NOT authenticated
authorization, client or operator consent, a grant, retest or permission to share.
All packets stay PRIVATE. No scan, network, model, target, deletion or dispatch.</p>
<p>Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.</p></main></html>""")
    return page.encode("utf-8")


def build(args: argparse.Namespace) -> int:
    parent = owner_parent(args.private_parent)
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,35}", args.prefix):
        return hold("invalid private output prefix")
    workspace = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-followup-", dir=parent))
    os.chmod(workspace, 0o700)
    try:
        copy_studio(workspace / "MAP-OFFLINE.html")
        flags = ["cohorts" if args.baseline else "bridge"]
        if args.baseline:
            flags += ["--baseline", args.baseline, "--candidate", args.candidate]
        else:
            flags += ["--comparison", args.comparison]
        flags += ["--findings-csv", args.findings_csv, "--output-dir", str(workspace),
                  "--prefix", args.prefix]
        if args.links:
            flags += ["--links", args.links]
        if args.bundle:
            flags += ["--bundle"]
        posture, receipt = original(BRIDGE, flags)
        if (len(receipt) != 3 or not receipt[0].startswith("PRIVATE ")
                or not receipt[1].startswith("OPEN LOCALLY: ")):
            raise ValueError("original source receipt unavailable")
        case = Path(receipt[1][len("OPEN LOCALLY: "):])
        if (case.parent != workspace or case.name != args.prefix + "-private.html"
                or not private_file(case)):
            raise ValueError("original source-bound HUMAN dossier missing")
        ledger_code, inventory = original(LEDGER, [
            "capture", "--kit", str(workspace), "--label",
            "Original PRIVATE source-bound HUMAN follow-up", "--private-parent", str(parent)])
        if ledger_code != 2 or len(inventory) != 2 or inventory[0] != "PRIVATE REVIEW_ONLY":
            raise ValueError("original byte inventory refused")
        page = Path(inventory[1])
        if (page.name != "OPEN-PRIVATE.html" or page.parent.parent != parent
                or not private_file(page)):
            raise ValueError("original private ledger output missing")
        index = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-casebook-", dir=parent))
        os.chmod(index, 0o700)
        complete = False
        try:
            fd = os.open(index / "START-HERE.html", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(landing(workspace, args.prefix, page.parent, posture == 3))
                output.flush()
                os.fsync(output.fileno())
            complete = True
        finally:
            if not complete:
                shutil.rmtree(index)
        print("PRIVATE HUMAN HOLD: original adverse source requires review." if posture == 3
              else "PRIVATE REVIEW_ONLY: exact-source human casebook prepared.")
        print("OPEN LOCALLY: " + str(index / "START-HERE.html"))
        print("No source, client consent or independent review verified.")
        return posture
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        # Preserve any completed original PRIVATE receipts for the custodian.
        return hold("source or index incomplete; inspect new owner-private workroom")


def main() -> int:
    p = argparse.ArgumentParser(description="Original offline HUMAN follow-up and source inventory; no target execution")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--comparison")
    group.add_argument("--baseline")
    p.add_argument("--candidate")
    p.add_argument("--findings-csv", required=True)
    p.add_argument("--links")
    p.add_argument("--private-parent", required=True)
    p.add_argument("--prefix", required=True)
    p.add_argument("--bundle", action="store_true")
    args = p.parse_args()
    if (args.baseline is None) != (args.candidate is None):
        return hold("both original completed cohorts must be specified")
    try:
        return build(args)
    except (OSError, ValueError, UnicodeError):
        return hold("PRIVATE parent or original source unavailable")


if __name__ == "__main__":
    raise SystemExit(main())
