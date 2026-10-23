#!/usr/bin/env python3
"""Owner-private ORIGINAL lab plan handoff: create/reopen/compare ONLY.

Connects original assessment-launchpad's independent source-owning Python
producers to the assessment console. Never calls the lab-assess CLI, a
scanner, a provider, a socket, a grant, or an external recipient.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import subprocess
import sys

import private_session as privacy

REPO = Path(__file__).resolve().parent.parent
SOURCE = REPO / "assessment-launchpad"
PRODUCTS = {
    "prepare": ("build.py", "private-launchpad.html"),
    "reopen": ("reopen.py", "private-launchpad.html"),
    "compare": ("compare.py", "private-change-brief.html"),
}
MAX_TEXT = 4096


def _hold(reason: str) -> None:
    raise privacy.Hold("HOLD: " + reason)


def _private_parent(name: str) -> Path:
    if type(name) is not str or not name or len(name) > MAX_TEXT:
        _hold("original owner-private directory required")
    input_path = Path(name)
    if not input_path.is_absolute() or input_path.is_symlink():
        _hold("absolute non-symlink owner-private directory required")
    path = input_path.resolve(strict=True)
    if path == REPO or REPO in path.parents or not privacy.private(path, True):
        _hold("original owner-only 0700 parent outside checkout required")
    if stat.S_IMODE(path.lstat().st_mode) != 0o700:
        _hold("original parent must be mode exactly 0700")
    return path


def _private_file(name: str, ceiling: int = 16_384) -> Path:
    if type(name) is not str or not name or len(name) > MAX_TEXT:
        _hold("original source file required")
    requested = Path(name)
    if not requested.is_absolute() or requested.is_symlink():
        _hold("original source must be a direct non-symlink absolute file")
    path = requested.resolve(strict=True)
    _private_parent(str(path.parent))
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or not 0 < info.st_size <= ceiling
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        _hold("original source must be mode exactly 0600 and single-linked")
    return path


def _packet(name: str) -> Path:
    path = _private_parent(name)
    if path == path.parent:
        _hold("original owner-private packet path required")
    # Require the exact direct child to remain an original owned entry.
    _private_parent(str(path.parent))
    return path


def _new_path(parent_name: str, folder: str) -> Path:
    parent = _private_parent(parent_name)
    if type(folder) is not str or not privacy.NAME.fullmatch(folder):
        _hold("a new strict simple PRIVATE room name is required")
    output = parent / folder
    if os.path.lexists(output):
        _hold("new PRIVATE room must not replace any existing entry")
    return output


def _entry(folder: Path, name: str) -> Path:
    if not privacy.private(folder, True) or stat.S_IMODE(folder.lstat().st_mode) != 0o700:
        _hold("original PRIVATE output folder admission failed")
    page = folder / name
    if not privacy.private(page, False) or stat.S_IMODE(page.lstat().st_mode) != 0o600:
        _hold("original PRIVATE local entry was not safely published")
    return page


def _run(kind: str, args: list[str]) -> None:
    script = SOURCE / PRODUCTS[kind][0]
    if not script.is_file() or script.is_symlink():
        _hold("original Lab Launchpad source component unavailable")
    env = dict(os.environ)
    # The original lab scope policy and Studio validators live in src.
    env["PYTHONPATH"] = os.pathsep.join((str(SOURCE), str(REPO / "src")))
    try:
        result = subprocess.run(
            [sys.executable, "-P", str(script), *args],
            cwd=str(REPO), env=env, capture_output=True,
            timeout=60, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        _hold("original offline lab producer did not complete")
    if result.returncode != 2:
        _hold("original offline lab admission refused; review locally")
    # No private source text or stderr can reach the console.
    return None


def prepare(parent: str, folder: str, targets_file: str,
            catalog: str = "", scenario: str = "") -> Path:
    """Run only the original non-scanning lab input packet builder."""
    dest = _new_path(parent, folder)
    target = _private_file(targets_file)
    if bool(catalog) != bool(scenario):
        _hold("Studio catalog and original scenario ID must be paired")
    if scenario and (len(scenario) > 128 or any(ord(c) < 33 or ord(c) > 126 for c in scenario)):
        _hold("selected original Studio scenario ID malformed")
    options = ["--targets-file", str(target), "--output-dir", str(dest)]
    if catalog:
        options += ["--catalog-file", str(_private_file(catalog, 262_144)),
                    "--scenario-id", scenario]
    _run("prepare", options)
    return _entry(dest, PRODUCTS["prepare"][1])


def reopen(original_packet: str) -> Path:
    """Delegate to original exact-byte packet reader, never execute target."""
    packet = _packet(original_packet)
    _run("reopen", ["--packet", str(packet)])
    return _entry(packet, PRODUCTS["reopen"][1])


def compare(before: str, after: str, parent: str, folder: str) -> Path:
    """Native source-bound review of two original proposed lab batches."""
    first, second = _packet(before), _packet(after)
    if first == second:
        _hold("two distinct original lab proposal packets required")
    dest = _new_path(parent, folder)
    if dest == first or dest == second or first in dest.parents or second in dest.parents:
        _hold("original lab packets cannot contain comparison output")
    _run("compare", ["--before", str(first), "--after", str(second),
                     "--output-dir", str(dest)])
    return _entry(dest, PRODUCTS["compare"][1])


def main() -> int:
    parser = argparse.ArgumentParser(
        description= "PRIVATE original lab plan preparation/reopen/compare/portfolio; NEVER scan")
    commands = parser.add_subparsers(dest="operation", required=True)
    a = commands.add_parser("prepare")
    a.add_argument("--targets-file", required=True)
    a.add_argument("--private-parent", required=True)
    a.add_argument("--folder", required=True)
    a.add_argument("--catalog-file", default="")
    a.add_argument("--scenario-id", default="")
    b = commands.add_parser("reopen")
    b.add_argument("--packet", required=True)
    c = commands.add_parser("compare")
    c.add_argument("--before", required=True)
    c.add_argument("--after", required=True)
    c.add_argument("--private-parent", required=True)
    c.add_argument("--folder", required=True)
    d = commands.add_parser(
        "portfolio", help="PRIVATE original 3–8 lab proposal source-bound portfolio")
    d.add_argument("--packet", action="append", required=True,
                   help="repeat 3–8 existing 0700 owner-private proposal packets")
    d.add_argument("--private-parent", required=True)
    d.add_argument("--folder", required=True)
    e = commands.add_parser("review-prepare", help="PRIVATE original HUMAN lab proposal editor")
    e.add_argument("--packet", action="append", required=True)
    e.add_argument("--private-parent", required=True)
    e.add_argument("--folder", required=True)
    f = commands.add_parser("review-finalize", help="re-admit source-bound HUMAN lab decisions")
    f.add_argument("--packet", action="append", required=True)
    f.add_argument("--review-room", required=True)
    f.add_argument("--human-csv", required=True)
    f.add_argument("--private-parent", required=True)
    f.add_argument("--folder", required=True)
    g = commands.add_parser("review-resume",
                            help="PRIVATE original source-bound HUMAN lab review draft continuation")
    g.add_argument("--packet", action="append", required=True)
    g.add_argument("--prior-room", required=True)
    g.add_argument("--prior-csv", required=True)
    g.add_argument("--private-parent", required=True)
    g.add_argument("--folder", required=True)
    for sub in (a, b, c, d, e, f, g):
        sub.add_argument("--human-confirm", required=True,
                         help="exactly PREPARE PRIVATE LAB PLAN / REOPEN PRIVATE LAB PLAN / COMPARE PRIVATE LAB PLANS")
    options = parser.parse_args()
    expected = {
        "prepare": "PREPARE PRIVATE LAB PLAN",
        "reopen": "REOPEN PRIVATE LAB PLAN",
        "compare": "COMPARE PRIVATE LAB PLANS",
        "portfolio": "BUILD PRIVATE LAB PORTFOLIO",
        "review-prepare": "PREPARE PRIVATE LAB HUMAN REVIEW",
        "review-finalize": "FINALIZE PRIVATE LAB HUMAN REVIEW",
        "review-resume": "RESUME PRIVATE LAB HUMAN REVIEW",
    }
    try:
        if options.human_confirm != expected[options.operation]:
            _hold("explicit original HUMAN lab planning confirmation required")
        if options.operation == "prepare":
            page = prepare(options.private_parent, options.folder, options.targets_file,
                           options.catalog_file, options.scenario_id)
        elif options.operation == "reopen":
            page = reopen(options.packet)
        elif options.operation == "compare":
            page = compare(options.before, options.after, options.private_parent, options.folder)
        elif options.operation == "portfolio":
            import lab_plan_portfolio
            page = lab_plan_portfolio.build(options.packet, options.private_parent,
                                            options.folder)
        else:
            import lab_plan_review
            if options.operation in ("review-prepare", "review-resume"):
                page = lab_plan_review.prepare(
                    options.packet, options.private_parent, options.folder,
                    prior_room=options.prior_room if options.operation == "review-resume" else "",
                    prior_csv=options.prior_csv if options.operation == "review-resume" else "")
            else:
                page = lab_plan_review.finalize(options.packet, options.review_room,
                                                options.human_csv, options.private_parent,
                                                options.folder)
        print("PRIVATE REVIEW_ONLY: original Lab Launchpad plan admitted. No scan.")
        print("OPEN LOCALLY: " + str(page))
        return 2
    except Exception as exc:
        # Original Launchpad defines Hold(Exception), not ValueError. Fail
        # closed without emitting original private paths or a traceback.
        print(str(exc) if isinstance(exc, privacy.Hold) else
              "HOLD: original PRIVATE lab planning admission failed",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
