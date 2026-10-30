"""Run two isolated fixed-loopback calibrations and verify their saved evidence.

This command is local synthetic scoring, not assessment authorization or a
network target selector. Original evidence remains private on disk.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .lab_score_compare import compare_score_runs, render_score_review
from .lab_score_suite import _private_output_directory, run_lab_score_suite

SCHEMA = "lightup.lab-score-calibration.v1"


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
    comparison = compare_score_runs(root / "baseline", root / "candidate")
    return {
        "schema": SCHEMA,
        "passed": comparison["passed"],
        "saved_runs": ["baseline", "candidate"],
        "comparison": comparison,
        "authorization_granted": False,
        "external_targets_contacted": False,
        "deployment": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lightup-lab-score-calibrate",
        description="Create and verify two fresh private fixed-loopback score runs.",
    )
    parser.add_argument("--output-dir", required=True,
                        help="new private directory (never overwrites existing files)")
    parser.add_argument("--format", choices=("json", "text"), default="text")
    args = parser.parse_args(argv)
    try:
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
