#!/usr/bin/env python3
"""Prepare original already-completed lab cohort candidates for original Matrix.

One existing canonical baseline vs 2–12 explicit existing canonical candidate
cohort JSONs. Reuses unchanged original LightUp cohort comparator + original
Candidate Matrix standalone. No target, model, scan, consent or GO action.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
from io import BytesIO
import os
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "assessment-archive"))
from archive import Hold, read_regular, decode_json, encode, publish
from packet import _entry
from lightup_review import compare as original_compare
from lightup_composed_review import _private_output_folder


MATRIX_SHA256 = "5e14ac1bffffa46007dfcbff7a31905abeda93f2d4547021daf0565ecc4fc4df"
COHORT_BYTES = 262144
MAX_CANDIDATES = 12
REPORT_KEYS = frozenset({
    "status", "regressed_scenarios", "comparisons", "authorized",
    "consent_verified", "dispatch_allowed", "release_allowed"
})
NO_AUTH = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")


def _source(path: str):
    resolved = Path(path).resolve(strict=True)
    data = read_regular(str(resolved), COHORT_BYTES)
    return resolved, sha256(data).digest()


def _read_candidate_report(path: Path, comparator_return: int):
    payload = read_regular(str(path), COHORT_BYTES)
    document = decode_json(payload)
    if type(document) is not dict or set(document) != REPORT_KEYS:
        raise Hold("original cohort report has an unexpected schema")
    state = "REVIEW_ONLY" if comparator_return == 2 else "HOLD"
    if (document["status"] != state or
            type(document["comparisons"]) is not list or
            not 1 <= len(document["comparisons"]) <= 64 or
            any(document[k] is not False for k in NO_AUTH)):
        raise Hold("original report lost comparator status or authority boundary")
    return payload, state


def prepare(args):
    if not 2 <= len(args.candidate) <= MAX_CANDIDATES:
        raise Hold("candidate batch must select 2–12 original completed cohorts")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,39}", args.prefix):
        raise Hold("invalid private output prefix")
    output = _private_output_folder(args.output_dir)
    baseline, baseline_digest = _source(args.baseline)
    selections = [_source(path) for path in args.candidate]
    candidates, original_digests = zip(*selections)
    if (baseline in candidates or len(set(candidates)) != len(candidates) or
            len(set(original_digests)) != len(original_digests)):
        raise Hold("repeated original candidate source")
    reports = [
        output / f"{args.prefix}-candidate-{i:02d}.json"
        for i in range(1, len(candidates) + 1)
    ]
    zip_path = output / (args.prefix + "-candidate-matrix.zip")
    manifest_path = output / (args.prefix + "-candidate-index.json")
    destinations = [*reports, manifest_path, zip_path]
    if any(os.path.lexists(destination) for destination in destinations):
        raise Hold("private candidate output already exists")
    original_matrix = read_regular(
        str(ROOT / "assessment-candidates" / "standalone.html"), 131072)
    if sha256(original_matrix).hexdigest() != MATRIX_SHA256:
        raise Hold("original Candidate Matrix source owner asset has changed")
    with TemporaryDirectory(prefix=".lightup-candidate-batch-", dir=output) as temp:
        stage = Path(temp)
        report_bytes = []
        records = []
        any_hold = False
        for index, (candidate, original_digest) in enumerate(selections, 1):
            path = stage / f"candidate-{index:02d}.json"
            result = original_compare([
                str(baseline), str(candidate), "--cohort",
                "--format", "desk-json", "--output", str(path)
            ])
            if result not in (2, 3) or not path.is_file():
                raise Hold("original comparator returned no reviewable cohort result")
            payload, status = _read_candidate_report(path, result)
            any_hold |= status == "HOLD"
            if sha256(read_regular(str(baseline), COHORT_BYTES)).digest() != baseline_digest:
                raise Hold("original baseline changed across candidate comparison")
            if sha256(read_regular(str(candidate), COHORT_BYTES)).digest() != original_digest:
                raise Hold("original candidate bytes changed during comparison")
            report_bytes.append(payload)
            records.append({
                "slot": index,
                "source_cohort_sha256": original_digest.hex(),
                "original_comparison_sha256": sha256(payload).hexdigest(),
                "original_status": status,
            })
        if sha256(read_regular(str(baseline), COHORT_BYTES)).digest() != baseline_digest:
            raise Hold("original baseline changed before private publication")
        if any(sha256(read_regular(str(path), COHORT_BYTES)).digest() != digest
               for path, digest in selections):
            raise Hold("original candidate sources changed before private publication")
        index = {
            "schema": "lightup.original_candidate_batch.v1",
            "status": "HOLD" if any_hold else "REVIEW_ONLY",
            "baseline_cohort_sha256": baseline_digest.hex(),
            "candidate_count": len(records),
            "candidates": records,
            "matrix_source_sha256": MATRIX_SHA256,
            **{key: False for key in NO_AUTH},
        }
        canonical_index = encode(index)
        package = BytesIO()
        instructions = (
            "LIGHTUP ORIGINAL CANDIDATE MATRIX / PRIVATE OFFLINE SOURCE\n"
            "Extract into an owner-private directory. Open standalone.html locally.\n"
            "Select the 2–12 numbered candidate JSON files using its file picker.\n"
            "This ZIP contains only original comparator output and the unchanged\n"
            "original matrix application, NOT original target/source cohort files.\n"
            "Baseline SHA and report hashes are unsigned private byte references.\n"
            "Original metric regression HOLD remains HOLD; do not infer GO.\n"
            "No source authenticates a client, grants scope or permits scanning.\n"
        ).encode("utf-8")
        with ZipFile(package, "w") as zf:
            _entry(zf, "README.txt", instructions)
            _entry(zf, "index.json", canonical_index)
            _entry(zf, "standalone.html", original_matrix)
            for slot, payload in enumerate(report_bytes, 1):
                _entry(zf, f"reports/candidate-{slot:02d}.json", payload)
        result_zip = package.getvalue()
        if len(result_zip) > 6 * 1024 * 1024:
            raise Hold("private original comparison set too large")
        for destination, payload in zip(destinations,
                                        (*report_bytes, canonical_index, result_zip)):
            publish(destination, payload)
    print(f"ORIGINAL_CANDIDATE_MATRIX_READY — {'HOLD' if any_hold else 'REVIEW_ONLY'}")
    print(f"Prepared {len(records)} original finished candidate reports and original Matrix.")
    print("Original private reports are unsigned; none grants execution, GO or consent.")
    return 3 if any_hold else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=(
        "Compare original completed baseline cohort against 2–12 existing finished "
        "candidate cohorts and prepare exact unchanged original offline Candidate Matrix."
    ))
    parser.add_argument("baseline", help="Existing original completed baseline cohort JSON array")
    parser.add_argument("--candidate", action="append", default=[], required=True,
                        help="Existing completed candidate cohort file, repeat 2–12 times")
    parser.add_argument("--output-dir", required=True, help="Existing privately owned directory (0700)")
    parser.add_argument("--prefix", default="lightup-candidates", help="Unused ASCII output prefix")
    args = parser.parse_args(argv)
    try:
        return prepare(args)
    except (Hold, OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError, RuntimeError):
        print("ORIGINAL_CANDIDATE_MATRIX_HOLD — invalid or changed original cohort input",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
