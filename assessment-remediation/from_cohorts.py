#!/usr/bin/env python3
"""Existing completed lab cohorts + original findings -> source-bound private dossier.

Uses the original unchanged #1515 comparator as the only source of benchmark
metric decisions. Strictly offline, no model, tool, scanner, authorization,
client authentication or execution side effects.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import os
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
# Explicit module isolation: this workbench has its own packet.py,
# distinct from assessment-archive/packet.py.
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(2, str(ROOT / "assessment-archive"))
from archive import Hold, publish, read_regular

from bridge import MAX_COMPARE, MAX_FINDINGS, fail_if, original_comparison, original_findings, private_dir, run as create_dossier
from packet import create_room
from lightup_review import compare as original_compare

DOC_SUFFIX = "-canonical-comparison.json"
STUDIO_SUFFIX = "-mapping-studio.html"
STUDIO_BOUND = 131072
REPORT_SUFFIXES = (
    "-private.html", "-links.json", "-aggregate.json",
    "-private-agenda.csv",
)

def existing_sources(args, output):
    first = Path(args.baseline).absolute()
    second = Path(args.candidate).absolute()
    findings = Path(args.findings_csv).absolute()
    fail_if(first == second or first == findings or second == findings,
            "original cohort and client export files must be distinct")
    originals = (
        (first, MAX_COMPARE),
        (second, MAX_COMPARE),
        (findings, MAX_FINDINGS),
    )
    capture = []
    for path, bound in originals:
        raw = read_regular(str(path), bound)
        capture.append((path, bound, raw, sha256(raw).digest()))
    # Keep the exact original CSV independently from benchmark claims.
    original_findings(capture[-1][2])
    return capture

def destination_set(folder, prefix, include_room):
    extras = ("-private-room.zip",) if include_room else ()
    paths = [folder / (prefix + DOC_SUFFIX)]
    paths += [folder / (prefix + suffix) for suffix in REPORT_SUFFIXES + extras]
    paths += [folder / (prefix + STUDIO_SUFFIX)]
    fail_if(any(os.path.lexists(path) for path in paths),
            "one or more private outputs already exist; no replacements")
    return paths

def generate(args):
    fail_if(re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,39}", args.prefix) is None,
            "invalid private dossier prefix")
    folder = private_dir(args.output_dir)
    outputs = destination_set(folder, args.prefix, args.bundle)
    capture = existing_sources(args, folder)
    optional_links = (
        read_regular(args.links, 262144) if args.links is not None else None
    )
    # Supply the exact portable authored Studio with this one-command output,
    # not just a CLI result that requires a separate repository checkout.
    studio_source = Path(__file__).resolve().parent / "standalone.html"
    studio_bytes = read_regular(str(studio_source), STUDIO_BOUND)
    studio_digest = sha256(studio_bytes).digest()
    # The original evaluator must see only regular complete immutable private
    # snapshots; it must never contact assets, run models or claim consent.
    with TemporaryDirectory(prefix=".lightup-remediation-cohort-", dir=folder) as temp:
        stage = Path(temp)
        before = stage / "baseline.json"
        after = stage / "candidate.json"
        for path, (_, _, data, _) in zip((before, after), capture):
            publish(path, data)
        compared = stage / "canonical-comparison.json"
        result = original_compare([
            str(before), str(after),
            "--cohort", "--format", "desk-json", "--output", str(compared)
        ])
        fail_if(result not in (2, 3) or not compared.is_file(),
                "original benchmark comparison did not return an offline review")
        canonical = read_regular(str(compared), MAX_COMPARE)
        parsed = original_comparison(canonical)
        fail_if(result != (2 if parsed["status"] == "REVIEW_ONLY" else 3),
                "original benchmark exit code contradicts its canonical report")
        # Optional previously authored manual links must be tied to EXACTLY
        # the new original comparator JSON bytes and same finding CSV bytes.
        if optional_links is not None:
            from bridge import links_document
            links_document(
                optional_links, sha256(canonical).hexdigest(),
                capture[-1][3].hex(),
                {row["scenario_id"] for row in parsed["comparisons"]},
                original_findings(capture[-1][2]),
            )
        for original_path, bound, _, expected in capture:
            fail_if(sha256(read_regular(str(original_path), bound)).digest() != expected,
                    "original source changed before private publication")
        if optional_links is not None:
            fail_if(read_regular(args.links, 262144) != optional_links,
                    "manual human link source changed before private publication")
        fail_if(sha256(read_regular(str(studio_source), STUDIO_BOUND)).digest() != studio_digest,
                "portable offline Studio changed during source admission")
        # Publish the canonical comparator first so the bridge's output
        # hashes remain bound to the actual final private source path.
        # Failures do not overwrite any existing path. Individually completed
        # artifacts might survive a sudden process crash and remain private.
        published = []
        try:
            canonical_path = outputs[0]
            publish(canonical_path, canonical)
            published.append((canonical_path, sha256(canonical).digest(), len(canonical)))
            status = create_dossier(SimpleNamespace(
                comparison=str(canonical_path),
                findings_csv=str(capture[-1][0]),
                links=args.links, output_dir=str(folder),
                prefix=args.prefix, bundle=args.bundle
            ))
            if status != result:
                raise Hold("source outcome diverged after private dossier generation")
            if args.bundle:
                if create_room(SimpleNamespace(
                    output_dir=str(folder), prefix=args.prefix
                )) != result:
                    raise Hold("private portable room did not match original report status")
            fail_if(sha256(read_regular(str(studio_source), STUDIO_BOUND)).digest() != studio_digest,
                    "portable mapping Studio changed before private publication")
            publish(folder / (args.prefix + STUDIO_SUFFIX), studio_bytes)
            print("ORIGINAL_COMPLETE_COHORT_TO_REMEDIATION_" + parsed["status"])
            print("Canonical comparison, private human dossier and portable Mapping Studio published.")
            print("Original lab and client sources remain unchanged; no scan or grant.")
            return result
        except Exception:
            # Never remove or rewrite existing source data. Only remove
            # our own exact identical just-created canonical report. The
            # bridge/packet own their independently non-overwriting files.
            for path, expected, bound in published:
                try:
                    if sha256(read_regular(str(path), bound)).digest() == expected:
                        path.unlink()
                except (OSError, Hold):
                    pass
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Compare TWO existing completed original lab cohorts and "
                    "prepare original benchmark -> findings human-only private "
                    "review artifacts, without any target execution."
    )
    parser.add_argument("--baseline", required=True, help="Existing original completed baseline cohort array")
    parser.add_argument("--candidate", required=True, help="Existing original completed candidate cohort array")
    parser.add_argument("--findings-csv", required=True, help="Original separately authenticated client findings CSV")
    parser.add_argument("--links", help="Optional exact-new-report-bound private manual mapping JSON")
    parser.add_argument("--output-dir", required=True, help="Existing owned owner-only 0700 directory")
    parser.add_argument("--prefix", default="lightup-lab-followup")
    parser.add_argument("--bundle", action="store_true", help="Also publish 0600 private portable review-room ZIP")
    args = parser.parse_args(argv)
    try:
        return generate(args)
    except (Hold, OSError, ValueError, TypeError, KeyError,
            OverflowError, UnicodeError, RecursionError):
        print("ORIGINAL_COMPLETE_COHORT_TO_REMEDIATION_HOLD — "
              "unsafe, incomplete or changed original input/output",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
