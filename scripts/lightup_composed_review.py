#!/usr/bin/env python3
"""One private, non-authorizing original comparator → archive → human review flow.

Combines EXISTING original review CLI and existing independent archive source
in a collision-free derived checkout. No target/model/network/authorization.
No test execution or CI changes.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import os
from pathlib import Path
import re
import stat
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parent.parent
ARCHIVE = ROOT / "assessment-archive"
sys.path.insert(0, str(ARCHIVE))

from archive import Hold, read_regular, MAX_SOURCE, publish
from archive import capture as archive_capture
from archive_studio import build as build_studio
from followup import draft as build_followup
from packet import package as build_packet
from lightup_review import compare as original_compare
from lightup_composed_admission import admit_original_review

from types import SimpleNamespace

ARTIFACT_SUFFIXES = (
    "-original-review.zip",
    "-original-comparison.json",
    "-source-archive.json",
    "-archive-studio.html",
    "-human-followup.json",
    "-review-room.zip",
)


def _private_output_folder(path: str) -> Path:
    """Existing owner-only directory. Never create/write outside this choice."""
    parent = Path(path)
    info = parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077):
        raise Hold("output directory must be privately owned and non-symlink")
    return parent


def _target_set(parent: Path, prefix: str):
    if type(prefix) is not str or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,39}", prefix):
        raise Hold("invalid output prefix")
    targets = [parent / (prefix + suffix) for suffix in ARTIFACT_SUFFIXES]
    # Never overwrite files, links, FIFOs or directories (including dangling symlinks).
    if any(os.path.lexists(path) for path in targets):
        raise Hold("output already exists")
    return targets


def run(args):
    output_dir = _private_output_folder(args.output_dir)
    targets = _target_set(output_dir, args.prefix)
    first, second = (Path(x).resolve(strict=True) for x in (args.baseline, args.candidate))
    if first == second:
        raise Hold("input sources must differ")
    # Compare unaltered previously-completed lab sources only. Do not run labs.
    source_sizes = (262144 if args.cohort else 65536)
    before = [sha256(read_regular(str(p), source_sizes)).digest() for p in (first, second)]
    # The original source owner is the only authority on comparator metrics.
    with TemporaryDirectory(prefix=".lightup-offline-workflow-", dir=output_dir) as temp:
        stage = Path(temp)
        review_path = stage / "review.zip"
        compared = original_compare([
            str(first), str(second),
            *(["--cohort"] if args.cohort else []),
            "--format", "review-pack", "--output", str(review_path)
        ])
        if compared not in (2, 3) or not review_path.is_file():
            raise Hold("original comparator supplied no reviewable evidence")
        desk_bytes, original_state = admit_original_review(
            read_regular(str(review_path), MAX_SOURCE),
            baseline_sha=before[0].hex(), candidate_sha=before[1].hex(),
            comparator_exit=compared, cohort=args.cohort,
        )
        after = [sha256(read_regular(str(p), source_sizes)).digest() for p in (first, second)]
        if before != after:
            raise Hold("original source bytes changed while comparing")
        comparison_path = stage / "comparison.json"
        publish(comparison_path, desk_bytes)
        archive_path = stage / "archive.json"
        archival = archive_capture(SimpleNamespace(
            sources=[str(first), str(second), str(comparison_path), str(review_path)],
            output=str(archive_path)
        ))
        if archival != compared or not archive_path.is_file():
            raise Hold("original archive status differs from comparator")
        studio_path = stage / "studio.html"
        if build_studio(str(archive_path), str(studio_path)) != compared:
            raise Hold("source-bound browser source admission failed")
        human_path = stage / "human.json"
        if build_followup(SimpleNamespace(
            manifest=str(archive_path), output=str(human_path)
        )) != 2:
            raise Hold("source-bound human form admission failed")
        packet_path = stage / "packet.zip"
        packaged = build_packet(SimpleNamespace(
            manifest=str(archive_path), choices=str(human_path),
            agenda_date=None, previous=None, include_studio=True,
            aggregate_only=False, output=str(packet_path)
        ))
        if packaged != compared:
            raise Hold("private packet status differs from original comparator")
        last = [sha256(read_regular(str(p), source_sizes)).digest() for p in (first, second)]
        if last != before:
            raise Hold("source bytes changed before private publication")
        # Materialize only after the whole private source-bound package is composed.
        # Every final file is new, no-replace and fsynced; failure never
        # overwrites a pre-existing user file. We do not delete partial outputs
        # because other operators may already have opened a newly published path.
        for part, dest in zip(
            (review_path, comparison_path, archive_path, studio_path, human_path, packet_path),
            targets
        ):
            publish(dest, read_regular(str(part), MAX_SOURCE))
    print("ORIGINAL_LAB_HUMAN_REVIEW_PACKAGE_CREATED — " + original_state + "; NO AUTHORITY")
    print("Original comparator report, canonical source-bound comparison, archive,")
    print("private browser Studio, human draft and review room were preserved.")
    print("HOLD indicates original measured regressions requiring human investigation.")
    print("No original record authenticates a client, verifies consent or grants GO.")
    return compared


def main(argv=None):
    p = argparse.ArgumentParser(description=(
        "Original already-completed lab comparison → private archived human workbench; "
        "no target, model, authorization or release authority."
    ))
    p.add_argument("baseline", help="Existing original completed baseline lab case/cohort file")
    p.add_argument("candidate", help="Existing original completed candidate lab case/cohort file")
    p.add_argument("--cohort", action="store_true", help="Use original pre-existing 1–64 case cohort comparison")
    p.add_argument("--output-dir", required=True, help="Existing privately owned directory (mode 0700)")
    p.add_argument("--prefix", default="lightup-review", help="Distinct new artifact prefix (ASCII only)")
    args = p.parse_args(argv)
    try:
        return run(args)
    except (Hold, OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError, RuntimeError):
        print("ORIGINAL_OFFLINE_REVIEW_HOLD — invalid or changed original lab source or private destination",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
