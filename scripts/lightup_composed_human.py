#!/usr/bin/env python3
"""Compose the ORIGINAL Review Desk saved human plan into private offline handoff.

Only original 7-member completed LAB review ZIP and exact bound saved Review
Desk v1/v2 JSON are accepted by original LightUp source-owner APIs. Never
starts a lab, model, scan, grant, network call, or validates consent.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "assessment-archive"))

from archive import Hold, read_regular, decode_json, publish, MAX_SOURCE
from archive import capture as archive_capture
from archive_studio import build as studio_build
from followup import draft as human_draft
from packet import package as room_build
from lightup_review import attach as original_attach
from lightup_review import handoff as original_handoff
from lightup_composed_review import _private_output_folder, _target_set
from assessment_runtime_verify_pack_cli_20261018 import inspect_bytes as original_inspect


SUFFIXES = (
    "-original-comparison.json",
    "-annotated-original-review.zip",
    "-original-minimal-handoff.zip",
    "-human-source-archive.json",
    "-human-studio.html",
    "-human-source-draft.json",
    "-human-review-room.zip",
)


def run(args):
    output = _private_output_folder(args.output_dir)
    # Reuse original strict output-name policy and add-only publication.
    _target_set(output, args.prefix)
    targets = [output / (args.prefix + suffix) for suffix in SUFFIXES]
    import os
    if any(os.path.lexists(path) for path in targets):
        raise Hold("requested original human worklist already exists")
    original_path = Path(args.original_review).absolute()
    plan_path = Path(args.saved_human_review).absolute()
    if original_path == plan_path:
        raise Hold("original report and saved human plan must differ")
    original_raw = read_regular(str(original_path), MAX_SOURCE)
    planning_raw = read_regular(str(plan_path), 131072)
    original_status = original_inspect(original_raw)
    if original_status not in ("REVIEW_ONLY", "HOLD"):
        raise Hold("original review ZIP not valid for human source binding")
    # Read ONLY original source-owned read-only member metadata.
    with ZipFile(BytesIO(original_raw)) as zf:
        if "review-desk.json" not in zf.namelist():
            raise Hold("original source desk missing")
        comparison = zf.read("review-desk.json")
    doc = decode_json(comparison)
    if (type(doc) is not dict or doc.get("status") != original_status or
            not (type(doc.get("comparisons")) is list or type(doc.get("changes")) is list)):
        raise Hold("original comparison status does not match saved review")
    original_digest = sha256(original_raw).digest()
    planning_digest = sha256(planning_raw).digest()
    with TemporaryDirectory(prefix=".lightup-human-composition-", dir=output) as temporary:
        stage = Path(temporary)
        attached = stage / "annotated.zip"
        minimized = stage / "minimized.zip"
        attached_state = original_attach([
            str(original_path), str(plan_path), "--output", str(attached)])
        if attached_state != (2 if original_status == "REVIEW_ONLY" else 3) or not attached.is_file():
            raise Hold("original source-bound human review validation rejected plan")
        minimized_state = original_handoff([str(attached), "--output", str(minimized)])
        if minimized_state != attached_state or not minimized.is_file():
            raise Hold("original human minimization returned incompatible status")
        desk = stage / "comparison.json"
        publish(desk, comparison)
        manifest = stage / "archive.json"
        archival = archive_capture(SimpleNamespace(
            sources=[str(original_path), str(desk), str(attached), str(minimized)],
            output=str(manifest)))
        if archival != attached_state or not manifest.is_file():
            raise Hold("original source-bound human review status mismatch")
        studio = stage / "studio.html"
        if studio_build(str(manifest), str(studio)) != attached_state:
            raise Hold("original private human Studio status mismatch")
        choices = stage / "human.json"
        if human_draft(SimpleNamespace(manifest=str(manifest), output=str(choices))) != 2:
            raise Hold("private human source draft could not be created")
        room = stage / "room.zip"
        if room_build(SimpleNamespace(
            manifest=str(manifest), choices=str(choices), agenda_date=None,
            previous=None, include_studio=True,
            aggregate_only=False, output=str(room))) != attached_state:
            raise Hold("source-bound human room status mismatch")
        if (sha256(read_regular(str(original_path), MAX_SOURCE)).digest() != original_digest
                or sha256(read_regular(str(plan_path), 131072)).digest() != planning_digest):
            raise Hold("original report or human choices changed during the handoff")
        # Only final, new, owner-private artifacts; nothing extracted/executed.
        for item, destination in zip(
            (desk, attached, minimized, manifest, studio, choices, room), targets
        ):
            publish(destination, read_regular(str(item), MAX_SOURCE))
    print("ORIGINAL_HUMAN_REVIEW_HANDOFF_CREATED — " + original_status)
    print("The exact original source-bound human plan was attached and minimized.")
    print("Original source fingerprints and human plans remain non-authorizing.")
    return 2 if original_status == "REVIEW_ONLY" else 3


def main(argv=None):
    parser = argparse.ArgumentParser(description=(
        "Original completed review pack + exact original Review Desk human plan → "
        "private annotated and minimized original source-owner human handoffs."
    ))
    parser.add_argument("original_review", help="Existing original seven-member source-rich lab review ZIP")
    parser.add_argument("saved_human_review", help="Existing original browser-saved human review v1/v2 JSON")
    parser.add_argument("--output-dir", required=True, help="Existing owner-only 0700 directory")
    parser.add_argument("--prefix", default="lightup-human", help="New owner-private artifact prefix")
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (Hold, OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError, RuntimeError):
        print("ORIGINAL_HUMAN_REVIEW_HOLD — incompatible original source or private destination",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
