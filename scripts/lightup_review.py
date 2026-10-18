"""LightUp: one local entry point for original offline lab comparison and human review.

Run from any directory:
    python /path/to/Lightup/scripts/lightup_review.py compare BASE.json NEXT.json --format review-pack --output NEW.zip
    python /path/to/Lightup/scripts/lightup_review.py bundle CASE1.json CASE2.json --output NEW.json
    python /path/to/Lightup/scripts/lightup_review.py inspect EXISTING.zip
    python /path/to/Lightup/scripts/lightup_review.py attach ORIGINAL.zip HUMAN.json --output NEW.zip
    python /path/to/Lightup/scripts/lightup_review.py handoff ANNOTATED.zip --output NEW.zip

Reads only explicit local files. No model, network, lab execution, scope grants
or approval. Original REVIEW_ONLY/HOLD exit codes are preserved, never 0 on a
completed assessment review.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "src"
if not SOURCE.is_dir():
    raise SystemExit("LAB_REVIEW_HOLD")
sys.path.insert(0, str(SOURCE))

from assessment_runtime_review_handoff_cli_20261018 import main as compare
from assessment_runtime_case_bundle_cli_20261018 import main as bundle
from assessment_runtime_verify_pack_cli_20261018 import main as inspect
from assessment_runtime_attach_triage_cli_20261018 import main as attach
from assessment_runtime_human_handoff_cli_20261018 import main as handoff

def workspace(argv):
    """Print a local-only operator start-screen location; never starts a server."""
    page = ROOT / "assessment-workspace" / "standalone.html"
    if argv in (["--help"], ["-h"]):
        print("Open the offline workspace locally; it has no network or scan controls.")
        print("Usage: python3 scripts/lightup_review.py workspace")
        return 0
    if argv or not page.is_file():
        print("LAB_REVIEW_HOLD")
        return 3
    print("OFFLINE_WORKSPACE_READY — NOT AUTHORIZED")
    print(page.as_uri())
    return 2


OPERATIONS = {
    "workspace": workspace,
    "compare": compare,
    "bundle": bundle,
    "inspect": inspect,
    "attach": attach,
    "handoff": handoff,
}

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="lightup-review",
        description="Offline human review of original completed LightUp lab evidence. "
                    "Always REVIEW_ONLY or HOLD; never an execution permit.",
    )
    parser.add_argument("operation", choices=tuple(OPERATIONS),
                        help="Open local workspace, compare cases, bundle a cohort, inspect a review, "
                             "attach human stages, or share a minimized handoff")
    if argv is None:
        argv = sys.argv[1:]
    if not argv or argv[0] in ("--help", "-h"):
        parser.print_help()
        return 0 if argv else 3
    operation = argv[0]
    if operation not in OPERATIONS:
        parser.print_usage(sys.stderr)
        print("LAB_REVIEW_HOLD")
        return 3
    return OPERATIONS[operation](argv[1:])

if __name__ == "__main__":
    raise SystemExit(main())
