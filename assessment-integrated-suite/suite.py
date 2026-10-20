#!/usr/bin/env python3
"""Compose already-produced PRIVATE lab artifacts; never perform an assessment."""
from __future__ import annotations
import argparse
import html
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
INSPECTOR = ROOT / "src/lightup/lab_inspect.py"
BRIEF = ROOT / "assessment-briefing/briefing.py"
DISCLOSE = ROOT / "assessment-disclosure-preflight/preflight.py"
APPS = {
    "human-worksheet.html": ROOT / "assessment-briefing/worksheet-studio-standalone.html",
    "human-retention.html": ROOT / "assessment-retention-desk/standalone.html",
    "human-disclosure.html": ROOT / "assessment-disclosure-preflight/standalone.html",
}

class Hold(Exception):
    pass

def read_safe(path: Path, ceiling: int) -> None:
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or not 0 < st.st_size <= ceiling:
        raise Hold("HOLD: required original file absent, unsafe or over limit")

def source(name: str) -> str:
    path = Path(name).absolute()
    read_safe(path, 8 * 1024 * 1024)
    return str(path)

def parent_dir(name: str) -> Path:
    path = Path(name).absolute()
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise Hold("HOLD: parent must be an existing private ordinary directory")
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise Hold("HOLD: parent must be owned by this user with no group/other rights")
    if path == ROOT or ROOT in path.parents:
        raise Hold("HOLD: output must remain outside the source checkout")
    return path

def original(script: Path, argv: list[str]) -> None:
    read_safe(script, 2 * 1024 * 1024)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    env["PYTHONNOUSERSITE"] = "1"
    try:
        result = subprocess.run(
            [sys.executable, "-P", str(script), *argv],
            cwd=ROOT, env=env, capture_output=True, timeout=120, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Hold("HOLD: local native component did not complete") from None
    if result.returncode != 2:
        raise Hold("HOLD: original source admission or private output refused")

def copy_app(src: Path, dst: Path) -> None:
    read_safe(src, 2 * 1024 * 1024)
    inp = os.open(src, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            with os.fdopen(inp, "rb", closefd=False) as original_file:
                shutil.copyfileobj(original_file, out)
    finally:
        os.close(inp)

def write_html(destination: Path, detail: bool, count: int) -> None:
    links = [
        ("PRIVATE disclosure review", "disclosure/PRIVATE-review.html"),
        ("PRIVATE suppressed counts", "disclosure/PRIVATE-counts.csv"),
        ("PRIVATE unsigned receipt", "disclosure/PRIVATE-receipt.json"),
        ("Offline disclosure HUMAN studio", "workrooms/human-disclosure.html"),
        ("Offline retention HUMAN studio", "workrooms/human-retention.html"),
    ]
    if detail:
        links = [
            ("Original PRIVATE findings briefing", "briefing/private-briefing.html"),
            ("Original HUMAN worksheet", "briefing/human-followup.csv"),
            ("Original unsigned source manifest", "briefing/manifest.json"),
            ("Offline worksheet HUMAN studio", "workrooms/human-worksheet.html"),
        ] + links
    entries = "".join("<li><a href='" + html.escape(dest, quote=True) + "'>" +
                      html.escape(label) + "</a></li>" for label, dest in links)
    doc = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; connect-src 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LightUp PRIVATE Assessment Kit</title>
<style>body{max-width:800px;margin:3rem auto;padding:0 1.5rem;font:17px/1.6 system-ui;background:#f0f3f7;color:#162435}
main{background:white;border:1px solid #d7e2eb;padding:2rem;border-radius:14px}a{color:#155781}
li{margin:.75rem 0}.hold{font-weight:700;color:#90411e}</style><main>
<h1>LightUp PRIVATE assessment kit</h1><p class="hold">REVIEW_ONLY / HOLD — never a security approval.</p>
<p>Original locally selected source files: """ + str(count) + """. No original source bytes are copied into the package;
detailed briefing, when selected, does reproduce PRIVATE source-declared finding content.</p><ul>""" + entries + """</ul>
<p>All files remain PRIVATE; do not upload this package or open it on a public server. HUMAN edits,
source hashes and encryption do not prove source authenticity, client or operator consent,
revocation-at-use, grant, finding verification or release. Separate current authorization
and independent source, privacy and security reviews are mandatory.</p>
<p>No scan, model, target connection, grant, deletion, retest or external transfer performed.
INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.</p></main></html>""")
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write(doc)

def prepare(args: argparse.Namespace) -> int:
    if len(args.source) > 12:
        raise Hold("HOLD: maximum 12 source files")
    parent = parent_dir(args.private_parent)
    files = [source(s) for s in args.source]
    if len(set(files)) != len(files):
        raise Hold("HOLD: duplicate original source")
    for component in (INSPECTOR, BRIEF, DISCLOSE, *APPS.values()):
        read_safe(component, 2 * 1024 * 1024)
    kit = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-kit-", dir=parent))
    os.chmod(kit, 0o700)
    finished = False
    try:
        disclosure = kit / "disclosure"
        disclosure.mkdir(mode=0o700)
        original(DISCLOSE, [*files, "--private-output-dir", str(disclosure)])
        if args.brief:
            original(BRIEF, ["--source", files[0], "--output-dir", str(kit / "briefing")])
        workrooms = kit / "workrooms"
        workrooms.mkdir(mode=0o700)
        for name, src in APPS.items():
            if name == "human-worksheet.html" and not args.brief:
                continue
            copy_app(src, workrooms / name)
        write_html(kit / "OPEN-PRIVATE.html", args.brief, len(files))
        finished = True
        print("REVIEW_ONLY: private kit prepared; no release or consent authority.")
        print("OPEN LOCALLY: " + str(kit / "OPEN-PRIVATE.html"))
        return 2
    finally:
        if not finished:
            shutil.rmtree(kit)

def main() -> int:
    cli = argparse.ArgumentParser(description="PRIVATE local lab review composition; no scan")
    commands = cli.add_subparsers(dest="command", required=True)
    run = commands.add_parser("prepare", help="source-bound PRIVATE bundle + offline HUMAN workrooms")
    run.add_argument("--source", required=True, action="append", help="1-12 already-produced PRIVATE JSON sources")
    run.add_argument("--private-parent", required=True, help="existing owner-only 0700 folder outside checkout")
    run.add_argument("--brief", action="store_true", help="original detailed briefing of first source")
    commands.add_parser("catalog", help="read-only inventory of installed original source modules")
    args = cli.parse_args()
    if args.command == "catalog":
        for label, component in (("source inspector", INSPECTOR), ("PRIVATE briefing", BRIEF),
                                 ("PRIVATE disclosure", DISCLOSE), *APPS.items()):
            print(label + ": " + ("installed" if component.is_file() else "absent"))
        print("REVIEW_ONLY: no authority to execute, scan or release")
        return 0
    try:
        return prepare(args)
    except (Hold, OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, Hold) else "HOLD: local private preparation refused",
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
