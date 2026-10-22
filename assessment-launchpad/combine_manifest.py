#!/usr/bin/env python3
"""Offline private manifest merge/replacement. Never contacts endpoints or executes assessment."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from types import SimpleNamespace

import launchpad

from launchpad import (
    Hold, MAX_ENDPOINTS, MAX_MANIFEST_BYTES, open_output_directory,
    open_private_input, publish_bundle, read_private_bundle_item, report_hold,
    validate_endpoints,
)

MANIFEST = "lightup-lab-targets.txt"
SUMMARY = "lightup-manifest-combine-private.json"
FILES = {MANIFEST: MAX_MANIFEST_BYTES, SUMMARY: 4096}


def canonical_lines(endpoints):
    return ("\n".join(endpoints) + "\n").encode("utf-8")


def prepare(first_path, second_path, mode, ack_normalization, ack_replace):
    if mode not in ("append", "replace"):
        raise Hold("explicit append or replace mode required")
    first_abs, first_raw, first = open_private_input(first_path)
    second_abs, second_raw, second = open_private_input(second_path)
    if first_abs == second_abs:
        raise Hold("original manifest inputs must be distinct")
    normalized = (
        first_raw != canonical_lines(first) or
        second_raw != canonical_lines(second)
    )
    if normalized and not ack_normalization:
        raise Hold("source whitespace or comments would be omitted; acknowledge normalization")
    if mode == "replace" and not ack_replace:
        raise Hold("replacement requires explicit acknowledgement of removed first manifest")
    merged = first + second if mode == "append" else second
    if not 1 <= len(merged) <= MAX_ENDPOINTS:
        raise Hold("combined manifest exceeds 16 endpoint slots")
    if len(set(merged)) != len(merged):
        raise Hold("literal endpoints overlap across the two manifests")
    canonical = canonical_lines(merged)
    if len(canonical) > MAX_MANIFEST_BYTES:
        raise Hold("canonical manifest exceeds native 16 KiB bound")
    # Invoke exactly the original pinned URL/LabScenario scope policy.
    admitted = validate_endpoints(merged)
    if len(admitted) != len(merged):
        raise Hold("original isolated-lab admission failed")
    counts = {
        "first_endpoints": len(first),
        "second_endpoints": len(second),
        "result_endpoints": len(merged),
        "retained_first_endpoints": len(first) if mode == "append" else 0,
        "discarded_first_endpoints": 0 if mode == "append" else len(first),
    }
    receipt = {
        "schema": "lightup.offline-manifest-combine.v1",
        "status": "REVIEW_ONLY",
        "mode": mode,
        "counts": counts,
        "first_input_sha256": sha256(first_raw).hexdigest(),
        "second_input_sha256": sha256(second_raw).hexdigest(),
        "result_manifest_sha256": sha256(canonical).hexdigest(),
        "normalization_acknowledged": bool(ack_normalization),
        "replacement_acknowledged": bool(ack_replace),
        "original_policy_checked": True,
        "authorized": False,
        "consent_verified": False,
        "dispatch_allowed": False,
        "release_allowed": False,
        "human_go": False,
        "client_identity_verified": False,
        "operator_identity_verified": False,
    }
    receipt_bytes = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    return (first_abs, second_abs), {MANIFEST: canonical, SUMMARY: receipt_bytes}, counts


def run(args):
    originals, files, counts = prepare(
        args.first_manifest, args.second_manifest, args.mode,
        args.ack_normalization, args.ack_replace,
    )
    output_fd, output_abs = open_output_directory(args.output_dir)
    if args.handoff_dir:
        try:
            handoff_fd, handoff_abs = open_output_directory(args.handoff_dir)
            try:
                shared = os.path.commonpath((output_abs, handoff_abs))
                if shared in (output_abs, handoff_abs):
                    raise Hold("handoff directory must be separate from combined output directory")
                for original in originals:
                    source_parent = os.path.dirname(original)
                    source_shared = os.path.commonpath((handoff_abs, source_parent))
                    if source_shared in (handoff_abs, source_parent):
                        raise Hold("handoff directory must be separate from private source trees")
                if not args.verify_output and os.listdir(handoff_fd):
                    raise Hold("handoff output directory must be empty before publication")
            finally:
                os.close(handoff_fd)
        except Exception:
            os.close(output_fd)
            raise
    try:
        for original in originals:
            parent = os.path.dirname(original)
            shared = os.path.commonpath((output_abs, parent))
            if shared == output_abs or shared == parent:
                raise Hold("output directory must be separate from both source trees")
        if args.verify_output:
            if set(os.listdir(output_fd)) != set(FILES):
                raise Hold("existing combined output contains missing or extra files")
            for name, limit in FILES.items():
                if read_private_bundle_item(output_fd, name, limit) != files[name]:
                    raise Hold("combined output drifted from exact re-admitted private sources")
        else:
            if os.listdir(output_fd):
                raise Hold("combined output directory must be empty before publication")
            # Re-admit both source files immediately before private publication.
            original_receipt = json.loads(files[SUMMARY])
            for original, expected_digest in (
                (originals[0], original_receipt["first_input_sha256"]),
                (originals[1], original_receipt["second_input_sha256"]),
            ):
                _, raw, _ = open_private_input(original)
                if sha256(raw).hexdigest() != expected_digest:
                    raise Hold("source manifest changed before publication")
            publish_bundle(output_fd, [(name, files[name]) for name in FILES])
    finally:
        os.close(output_fd)
    if args.handoff_dir:
        if args.verify_output:
            launchpad.verify_existing(args.handoff_dir)
            handoff_fd, _ = open_output_directory(args.handoff_dir)
            try:
                if read_private_bundle_item(handoff_fd, MANIFEST, MAX_MANIFEST_BYTES) != files[MANIFEST]:
                    raise Hold("private handoff does not match exact combined source")
            finally:
                os.close(handoff_fd)
        else:
            # This only creates local preview-only artifacts, never runs the displayed command.
            # If this second publication fails, the separate combined source remains owner-private.
            launchpad.run(SimpleNamespace(manifest=os.path.join(output_abs, MANIFEST),
                                           output_dir=args.handoff_dir))
    status = "REOPENED_REVIEW_ONLY" if args.verify_output else "PUBLISHED_REVIEW_ONLY"
    print(status + " · " + str(counts["result_endpoints"]) +
          " isolated-lab endpoint slots · no assessment, consent, target contact or authorization")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Prepare owner-private lab manifests offline. Never execute lab-assess.")
    parser.add_argument("--first-manifest", required=True, help="existing source manifest (0600)")
    parser.add_argument("--second-manifest", required=True, help="incoming source manifest (0600)")
    parser.add_argument("--mode", choices=("append", "replace"), required=True)
    parser.add_argument("--output-dir", required=True, help="separate existing private output directory (0700)")
    parser.add_argument("--handoff-dir", help="optional second separate empty 0700 directory for complete PREVIEW-ONLY launchpad bundle")
    parser.add_argument("--ack-normalization", action="store_true", help="allow source comments/whitespace to be omitted")
    parser.add_argument("--ack-replace", action="store_true", help="explicitly accept discarding first manifest endpoints")
    parser.add_argument("--verify-output", action="store_true", help="read-only strict reopen against both original sources")
    parser.add_argument("--explain-hold", action="store_true", help="print curated reasons; never endpoint/path values")
    args = parser.parse_args(argv)
    try:
        return run(args)
    except Hold as error:
        report_hold("LAB_MANIFEST_COMBINE_HOLD — private source or original lab policy not admitted", error, args.explain_hold)
    except (OSError, ValueError, TypeError, ImportError, UnicodeError, OverflowError, RecursionError) as error:
        report_hold("LAB_MANIFEST_COMBINE_HOLD — filesystem or source parsing rejected", error, args.explain_hold)
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
