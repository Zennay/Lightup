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
from verify_offline import Hold as VerifyHold, compare_packages, verify as verify_package
from install_offline import install as install_private_kit, inspect as inspect_private_kit

ROOT = Path(__file__).resolve().parent.parent
INSPECTOR = ROOT / "src/lightup/lab_inspect.py"
BRIEF = ROOT / "assessment-briefing/briefing.py"
DISCLOSE = ROOT / "assessment-disclosure-preflight/preflight.py"
APPS = {
    "human-worksheet.html": ROOT / "assessment-briefing/worksheet-studio-standalone.html",
    "human-retention.html": ROOT / "assessment-retention-desk/standalone.html",
    "human-disclosure.html": ROOT / "assessment-disclosure-preflight/standalone.html",
    "human-lab-review.html": ROOT / "assessment-lab-review/standalone.html",
    "human-followup-calendar.html": ROOT / "assessment-followup-calendar/standalone.html",
    "lab-launchpad.html": ROOT / "assessment-launchpad/standalone.html",
    "lab-scenario-studio.html": ROOT / "lab-design/standalone.html",
    "benchmark-lineage.html": ROOT / "assessment-lineage/standalone.html",
    "benchmark-candidates.html": ROOT / "assessment-candidates/standalone.html",
    "multi-reviewer-consensus.html": ROOT / "assessment-reviewer-consensus/reviewer-studio.html",
    "lab-longitudinal-trends.html": ROOT / "assessment-trends/standalone.html",
    "human-benchmark-triage.html": ROOT / "assessment-review/standalone.html",
    "human-workspace-ledger.html": ROOT / "assessment-workspace-ledger/standalone.html",
    "human-lab-to-remediation.html": ROOT / "assessment-remediation/standalone.html",
    "human-lab-route.html": ROOT / "assessment-integrated-suite/human-lab-route.html",
    "human-lab-route.js": ROOT / "assessment-integrated-suite/human-lab-route.js",
    "human-lab-route-standalone.html": ROOT / "assessment-integrated-suite/human-lab-route-standalone.html",
    "human-lab-attention.html": ROOT / "assessment-integrated-suite/human-lab-attention.html",
    "human-lab-attention.js": ROOT / "assessment-integrated-suite/human-lab-attention.js",
    "human-lab-attention-standalone.html": ROOT / "assessment-integrated-suite/human-lab-attention-standalone.html",
    "human-remediation-team-room.html": ROOT / "assessment-remediation/team-room.html",
}

class Hold(Exception):
    pass

def reject_symlink_components(path: Path) -> Path:
    """Refuse path traversal through any existing symlink component."""
    candidate = path.absolute()
    for component in (*reversed(candidate.parents), candidate):
        try:
            info = component.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise Hold("HOLD: symbolic-link path component refused")
    return candidate


def guard_command_paths(args: argparse.Namespace) -> None:
    """Apply the same path-component rule to every native command input."""
    paths: list[str] = []
    if args.command == "prepare":
        paths.extend(args.source)
        paths.append(args.private_parent)
    elif args.command == "human-workpack":
        paths.extend([args.private_session, args.private_parent])
        if args.human_csv:
            paths.append(args.human_csv)
    elif args.command == "workpack-progress":
        paths.extend([args.private_session, args.private_parent, *args.workpack])
    elif args.command == "workpack-continue":
        paths.extend([args.private_session, args.from_workpack, args.private_parent])
    elif args.command == "install-kit":
        paths.extend([args.package, args.private_parent])
        if args.sha256_file:
            paths.append(args.sha256_file)
        if args.source_root:
            paths.append(args.source_root)
    elif args.command == "inspect-kit":
        paths.append(args.room)
        if args.package:
            paths.append(args.package)
        if args.sha256_file:
            paths.append(args.sha256_file)
        if args.source_root:
            paths.append(args.source_root)
    elif args.command == "verify-kit":
        paths.append(args.package)
        if args.compare_package:
            paths.append(args.compare_package)
        if args.sha256_file:
            paths.append(args.sha256_file)
        if args.source_root:
            paths.append(args.source_root)
    for value in paths:
        reject_symlink_components(Path(value))


def read_safe(path: Path, ceiling: int) -> None:
    path = reject_symlink_components(path)
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or not 0 < st.st_size <= ceiling:
        raise Hold("HOLD: required original file absent, unsafe or over limit")


def source(name: str) -> str:
    path = reject_symlink_components(Path(name))
    read_safe(path, 8 * 1024 * 1024)
    return str(path)


def parent_dir(name: str) -> Path:
    path = reject_symlink_components(Path(name))
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
        ("Offline original lab finding HUMAN review", "workrooms/human-lab-review.html"),
        ("Offline PRIVATE HUMAN follow-up calendar", "workrooms/human-followup-calendar.html"),
        ("Track 20 original HUMAN Lab discussion steps locally (no authority)", "workrooms/human-lab-route.html"),
        ("Open one-file HUMAN Lab Route Desk (no adjacent JS required)", "workrooms/human-lab-route-standalone.html"),
        ("Coordinate source-free HUMAN Lab attention and reviewer proposals (offline)", "workrooms/human-lab-attention.html"),
        ("Open one-file source-free HUMAN Attention Workboard", "workrooms/human-lab-attention-standalone.html"),
        ("Prepare offline isolated lab manifest (never dispatch)", "workrooms/lab-launchpad.html"),
        ("Author offline hypothetical lab scenarios", "workrooms/lab-scenario-studio.html"),
        ("Compare original lab benchmark lineage", "workrooms/benchmark-lineage.html"),
        ("Explore original candidate tradeoffs", "workrooms/benchmark-candidates.html"),
        ("Reconcile separate HUMAN reviewer plans", "workrooms/multi-reviewer-consensus.html"),
        ("Explore 3-12 original benchmark trajectories", "workrooms/lab-longitudinal-trends.html"),
        ("Triage original canonical benchmark findings with HUMAN review", "workrooms/human-benchmark-triage.html"),
        ("Review exact original PRIVATE workspace ledger with HUMAN decisions", "workrooms/human-workspace-ledger.html"),
        ("Map original lab benchmarks to authenticated client findings (HUMAN only)", "workrooms/human-lab-to-remediation.html"),
        ("Coordinate original PRIVATE HUMAN follow-up with separate teams", "workrooms/human-remediation-team-room.html"),
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

def private_human_workpack(args: argparse.Namespace) -> int:
    """Create one local workpack only from original saved PATH-only context."""
    if args.human_confirm != "BUILD PRIVATE WORKPACK":
        raise Hold("HOLD: exact explicit HUMAN workpack confirmation required")
    from dataclasses import replace
    import console
    import human_workpack
    import private_session
    # Nothing here opens client source, invokes a scanner or grants authority.
    # The identical native strict saved-session reader controls all input.
    current = console.Session()
    admitted = private_session.restore(current, args.private_session)
    isolated = replace(current, **admitted)
    isolated.saved_session = args.private_session
    page = human_workpack.build(
        isolated, args.human_csv or "", args.private_parent,
        args.folder, args.review_date)
    print("PRIVATE REVIEW_ONLY: source-PATH-bound HUMAN Workpack prepared.")
    print("OPEN LOCALLY: " + str(page))
    print("No source authenticity, consent, permission or execution is implied.")
    return 2


def private_workpack_progress(args: argparse.Namespace) -> int:
    """Compare original HUMAN workpacks in declared order, offline only."""
    if args.human_confirm != "BUILD PRIVATE PROGRESS":
        raise Hold("HOLD: exact explicit HUMAN progression confirmation required")
    from dataclasses import replace
    import console
    import private_session
    import workpack_progress
    current = console.Session()
    admitted = private_session.restore(current, args.private_session)
    isolated = replace(current, **admitted)
    isolated.saved_session = args.private_session
    page = workpack_progress.build(
        isolated, args.workpack, args.private_parent, args.folder)
    print("PRIVATE REVIEW_ONLY: original HUMAN workpack progress prepared.")
    print("OPEN LOCALLY: " + str(page))
    print("No real chronology, evidence, consent or execution implied.")
    return 2



def private_workpack_continue(args: argparse.Namespace) -> int:
    """Recreate original selected HUMAN workpack with a new declared date."""
    if args.human_confirm != "CONTINUE PRIVATE WORKPACK":
        raise Hold("HOLD: exact continuation confirmation required")
    from dataclasses import replace
    import console
    import private_session
    import workpack_continue
    current = console.Session()
    admitted = private_session.restore(current, args.private_session)
    isolated = replace(current, **admitted)
    isolated.saved_session = args.private_session
    page = workpack_continue.build(
        isolated, args.from_workpack, args.private_parent,
        args.folder, args.review_date)
    print("PRIVATE REVIEW_ONLY: complete continued HUMAN workpack created.")
    print("OPEN LOCALLY: " + str(page))
    print("Every original HUMAN status is still unverified and editable.")
    return 2


def main() -> int:
    cli = argparse.ArgumentParser(description="PRIVATE local lab review composition; no scan")
    commands = cli.add_subparsers(dest="command", required=True)
    run = commands.add_parser("prepare", help="source-bound PRIVATE bundle + offline HUMAN workrooms")
    run.add_argument("--source", required=True, action="append", help="1-12 already-produced PRIVATE JSON sources")
    run.add_argument("--private-parent", required=True, help="existing owner-only 0700 folder outside checkout")
    run.add_argument("--brief", action="store_true", help="original detailed briefing of first source")
    workpack = commands.add_parser(
        "human-workpack", help="PRIVATE offline HUMAN workpack from original saved session")
    workpack.add_argument("--private-session", required=True,
                          help="original owner-only 0600 PRIVATE-SESSION.json")
    workpack.add_argument("--private-parent", required=True,
                          help="existing owner-only 0700 output parent outside checkout")
    workpack.add_argument("--folder", required=True,
                          help="unused output folder with strict native name")
    workpack.add_argument("--review-date", required=True,
                          help="operator-declared YYYY-MM-DD, not a scheduled task")
    workpack.add_argument("--human-csv", default="",
                          help="optional exact-session original 0600 HUMAN CSV; empty seeds UNASSESSED")
    workpack.add_argument("--human-confirm", required=True,
                          help="must equal exactly BUILD PRIVATE WORKPACK")
    progress = commands.add_parser(
        "workpack-progress", help="PRIVATE HUMAN progression across 2–8 original workpacks")
    progress.add_argument("--private-session", required=True,
                          help="owner-only original saved 0600 PATH-only session")
    progress.add_argument("--workpack", action="append", required=True,
                          help="repeat 2–8 owner-private original HUMAN workpack folders")
    progress.add_argument("--private-parent", required=True,
                          help="existing owner-only 0700 output parent outside checkout")
    progress.add_argument("--folder", required=True, help="unused PRIVATE progress room name")
    progress.add_argument("--human-confirm", required=True,
                          help="must equal exactly BUILD PRIVATE PROGRESS")
    following = commands.add_parser(
        "workpack-continue",
        help="continue original owner-private HUMAN workpack without changing decisions")
    following.add_argument("--private-session", required=True,
                           help="original saved owner-only 0600 PATH-only session")
    following.add_argument("--from-workpack", required=True,
                           help="existing original 0700 HUMAN workpack")
    following.add_argument("--private-parent", required=True,
                           help="existing owner-only 0700 PRIVATE parent")
    following.add_argument("--folder", required=True, help="new unused HUMAN folder")
    following.add_argument("--review-date", required=True,
                           help="new explicitly operator-declared YYYY-MM-DD")
    following.add_argument("--human-confirm", required=True,
                           help="must equal CONTINUE PRIVATE WORKPACK")
    commands.add_parser("catalog", help="read-only inventory of installed original source modules")
    verify = commands.add_parser(
        "verify-kit", help="verify a legacy v1 or current v2 software-only ZIP inventory without extracting")
    verify.add_argument("--package", required=True,
                        help="existing offline ZIP; byte integrity only, never authenticity")
    verify.add_argument("--expected-sha256", default="",
                        help="optional expected ZIP digest from a trusted separate channel")
    verify.add_argument("--sha256-file", default="",
                        help="optional standard sha256sum sidecar bound to the package filename")
    verify.add_argument("--source-root", default="",
                        help="optional local checkout root; fail if packaged software bytes are stale")
    verify.add_argument("--compare-package", default="",
                        help="optional second verified ZIP; print software/support inventory differences without extracting")
    installing = commands.add_parser(
        "install-kit", help="verify and privately install a fully inventoried v2 offline software ZIP")
    installing.add_argument("--package", required=True)
    installing.add_argument("--private-parent", required=True, help="owner-only 0700 local folder")
    installing.add_argument("--folder", required=True, help="new exclusive local directory name")
    installing.add_argument("--expected-sha256", default="")
    installing.add_argument("--sha256-file", default="")
    installing.add_argument("--source-root", default="")
    installing.add_argument("--human-confirm", required=True,
                            help="must equal INSTALL PRIVATE OFFLINE KIT")
    inspecting = commands.add_parser(
        "inspect-kit", help="inspect an installed owner-private kit against its receipt")
    inspecting.add_argument("--room", required=True)
    inspecting.add_argument("--package", default="",
                            help="original software ZIP for independent source recheck")
    inspecting.add_argument("--expected-sha256", default="")
    inspecting.add_argument("--sha256-file", default="")
    inspecting.add_argument("--source-root", default="")
    args = cli.parse_args()
    if args.command == "catalog":
        for label, component in (("source inspector", INSPECTOR), ("PRIVATE briefing", BRIEF),
                                 ("PRIVATE disclosure", DISCLOSE),
                                 ("offline package integrity verifier",
                                  ROOT / "assessment-integrated-suite/verify_offline.py"),
                                 *APPS.items()):
            print(label + ": " + ("installed" if component.is_file() else "absent"))
        print("REVIEW_ONLY: no authority to execute, scan or release")
        return 0
    try:
        guard_command_paths(args)
        if args.command == "verify-kit":
            package = Path(args.package).absolute()
            sha256_file = Path(args.sha256_file).absolute() if args.sha256_file else None
            source_root = Path(args.source_root).absolute() if args.source_root else None
            if args.compare_package:
                return compare_packages(
                    package, Path(args.compare_package).absolute(),
                    args.expected_sha256, sha256_file, source_root)
            return verify_package(package, args.expected_sha256, sha256_file, source_root)
        if args.command == "install-kit":
            if args.human_confirm != "INSTALL PRIVATE OFFLINE KIT":
                raise Hold("HOLD: explicit private installation confirmation required")
            return install_private_kit(
                Path(args.package).absolute(), Path(args.private_parent).absolute(),
                args.folder, args.expected_sha256,
                Path(args.sha256_file).absolute() if args.sha256_file else None,
                Path(args.source_root).absolute() if args.source_root else None)
        if args.command == "inspect-kit":
            return inspect_private_kit(
                Path(args.room).absolute(),
                Path(args.package).absolute() if args.package else None,
                args.expected_sha256,
                Path(args.sha256_file).absolute() if args.sha256_file else None,
                Path(args.source_root).absolute() if args.source_root else None)
        if args.command == "human-workpack":
            return private_human_workpack(args)
        if args.command == "workpack-progress":
            return private_workpack_progress(args)
        if args.command == "workpack-continue":
            return private_workpack_continue(args)
        return prepare(args)
    except (Hold, VerifyHold, OSError, ValueError, TypeError) as exc:
        print(str(exc) if isinstance(exc, (Hold, VerifyHold)) else "HOLD: local private preparation refused",
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
