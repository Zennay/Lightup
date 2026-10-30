"""Run two isolated fixed-loopback calibrations and verify their saved evidence.

This command is local synthetic scoring, not assessment authorization or a
network target selector. Original evidence remains private on disk.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from .lab_score_compare import compare_score_runs, render_score_review
from .lab_score_inspect import _private_dir_fd
from .lab_score_suite import _private_output_directory, run_lab_score_suite

SCHEMA = "lightup.lab-score-calibration.v1"


def verify_saved_calibration(output_dir: str | Path) -> dict[str, Any]:
    """Reopen both private saved runs without executing any fixture/worker."""
    root = Path(output_dir).expanduser()
    fd = _private_dir_fd(root)  # pinned, owner-private, no-follow ancestors
    try:
        original = os.fstat(fd)
        if set(os.listdir(fd)) != {"baseline", "candidate"}:
            raise ValueError("unexpected saved calibration entries")
        children = {}
        for name in ("baseline", "candidate"):
            entry = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if (not stat.S_ISDIR(entry.st_mode) or entry.st_uid != os.geteuid()
                    or stat.S_IMODE(entry.st_mode) & 0o077):
                raise PermissionError("unsafe saved calibration subdirectory")
            children[name] = (entry.st_dev, entry.st_ino, entry.st_mtime_ns,
                              entry.st_ctime_ns)
        comparison = compare_score_runs(root / "baseline", root / "candidate")
        after = os.fstat(fd)
        if ((original.st_dev, original.st_ino, original.st_mtime_ns,
             original.st_ctime_ns) !=
            (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns)
                or set(os.listdir(fd)) != {"baseline", "candidate"}):
            raise ValueError("saved calibration changed")
        for name in children:
            entry = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if children[name] != (entry.st_dev, entry.st_ino, entry.st_mtime_ns,
                                  entry.st_ctime_ns):
                raise ValueError("saved calibration subdirectory changed")
    finally:
        os.close(fd)
    return {
        "schema": SCHEMA,
        "passed": comparison["passed"],
        "saved_runs": ["baseline", "candidate"],
        "comparison": comparison,
        "authorization_granted": False,
        "external_targets_contacted": False,
        "deployment": False,
    }


def run_lab_score_calibration(output_dir: str | Path) -> dict[str, Any]:
    """Create two *new* private stores and independently re-inspect both."""
    root = _private_output_directory(output_dir)
    # Each producer creates its own exclusive 0700 directory and 0600 stores.
    # Never proceed to the candidate after a failed baseline; and never emit
    # PASS from producer summaries without independently verifying both saves.
    for name in ("baseline", "candidate"):
        saved = run_lab_score_suite(root / name)
        if saved.get("passed") is not True:
            raise ValueError("synthetic calibration failed")
    return verify_saved_calibration(root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lightup-lab-score-calibrate",
        description="Create and verify two fresh private fixed-loopback score runs.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output-dir",
                      help="new private directory (never overwrites existing files)")
    mode.add_argument("--verify-output-dir",
                      help="read-only reinspection of a saved calibration; no scorers")
    parser.add_argument("--format", choices=("json", "text"), default="text")
    args = parser.parse_args(argv)
    try:
        if args.verify_output_dir is not None:
            result = verify_saved_calibration(args.verify_output_dir)
        else:
            result = run_lab_score_calibration(args.output_dir)
    except Exception:
        # Do not reveal the user's original private output path, raw errors,
        # local lab identifiers or potentially confidential evidence payloads.
        if args.format == "text":
            print("LightUp synthetic calibration: HOLD; saved evidence not verified.",
                  file=sys.stderr)
        else:
            print(json.dumps({"schema": SCHEMA, "passed": False}, sort_keys=True),
                  file=sys.stderr)
        return 2
    if args.format == "text":
        print("LightUp saved synthetic calibrations: baseline and candidate")
        print(render_score_review(result["comparison"]))
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
