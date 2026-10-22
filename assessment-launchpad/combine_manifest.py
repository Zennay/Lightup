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
MAX_SOURCES = 8


def canonical_lines(endpoints):
    return ("\n".join(endpoints) + "\n").encode("utf-8")


def prepare(first_path, second_path, mode, ack_normalization, ack_replace,
            *, preview_only=False, more_paths=()):
    if mode not in ("append", "replace"):
        raise Hold("explicit append or replace mode required")
    source_paths = (first_path, second_path, *more_paths)
    if not 2 <= len(source_paths) <= MAX_SOURCES:
        raise Hold("use between 2 and 8 original PRIVATE manifest files")
    opened = [open_private_input(path) for path in source_paths]
    originals = tuple(item[0] for item in opened)
    if len(set(originals)) != len(originals):
        raise Hold("original PRIVATE manifest paths must be distinct")
    normalized = any(raw != canonical_lines(lines) for _, raw, lines in opened)
    if normalized and not ack_normalization and not preview_only:
        raise Hold("source whitespace or comments would be omitted; acknowledge normalization")
    if mode == "replace" and not ack_replace and not preview_only:
        raise Hold("replacement requires explicit acknowledgement")
    merged = [item for _, _, lines in
              (opened if mode == "append" else opened[1:]) for item in lines]
    if not 1 <= len(merged) <= MAX_ENDPOINTS:
        raise Hold("combined manifest exceeds 16 endpoint slots")
    if len(set(merged)) != len(merged):
        raise Hold("repeated endpoints across original PRIVATE manifests")
    canonical = canonical_lines(merged)
    if len(canonical) > MAX_MANIFEST_BYTES:
        raise Hold("canonical manifest exceeds native 16 KiB limit")
    if len(validate_endpoints(merged)) != len(merged):
        raise Hold("original isolated-lab admission failed")
    counts = {
        "first_endpoints":len(opened[0][2]),
        "second_endpoints":len(opened[1][2]),
        "result_endpoints":len(merged),
        "retained_first_endpoints":len(opened[0][2]) if mode == "append" else 0,
        "discarded_first_endpoints":0 if mode == "append" else len(opened[0][2]),
        "normalization_requires_ack":normalized,
        "replacement_requires_ack":mode == "replace",
    }
    if len(opened) > 2:
        counts.update(source_manifests=len(opened),
                      additional_endpoints=sum(len(row[2]) for row in opened[2:]))
    receipt = dict(schema="lightup.offline-manifest-combine.v1" if len(opened) == 2
                   else "lightup.offline-manifest-combine.v2",
                   status="REVIEW_ONLY", mode=mode, counts=counts,
                   first_input_sha256=sha256(opened[0][1]).hexdigest(),
                   second_input_sha256=sha256(opened[1][1]).hexdigest(),
                   result_manifest_sha256=sha256(canonical).hexdigest(),
                   normalization_acknowledged=bool(ack_normalization),
                   replacement_acknowledged=bool(ack_replace),
                   original_policy_checked=True,
                   authorized=False, consent_verified=False,
                   dispatch_allowed=False, release_allowed=False,
                   human_go=False, client_identity_verified=False,
                   operator_identity_verified=False)
    if len(opened) > 2:
        receipt["sources"] = [
            dict(ordinal=i, endpoints=len(lines), input_sha256=sha256(raw).hexdigest())
            for i, (_, raw, lines) in enumerate(opened, start=1)]
    receipt_bytes = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(receipt_bytes) > FILES[SUMMARY]:
        raise Hold("private source receipt exceeds bound")
    return originals, {MANIFEST:canonical, SUMMARY:receipt_bytes}, counts


def run(args):
    originals, files, counts = prepare(
        args.first_manifest, args.second_manifest, args.mode,
        args.ack_normalization, args.ack_replace, more_paths=args.more_manifest,
    )
    output_fd, output_abs = open_output_directory(args.output_dir)
    extra_directory = args.handoff_dir or args.workspace_dir
    if extra_directory:
        try:
            handoff_fd, handoff_abs = open_output_directory(extra_directory)
            try:
                shared = os.path.commonpath((output_abs, handoff_abs))
                if shared in (output_abs, handoff_abs):
                    raise Hold("secondary private directory must be separate from combined output directory")
                for original in originals:
                    source_parent = os.path.dirname(original)
                    source_shared = os.path.commonpath((handoff_abs, source_parent))
                    if source_shared in (handoff_abs, source_parent):
                        raise Hold("secondary private directory must be separate from private source trees")
                if not args.verify_output and os.listdir(handoff_fd):
                    raise Hold("secondary output directory must be empty before publication")
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
            digests = ([original_receipt["first_input_sha256"],
                        original_receipt["second_input_sha256"]]
                       if len(originals) == 2 else
                       [entry["input_sha256"] for entry in original_receipt["sources"]])
            for original, expected_digest in zip(originals, digests):
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
    if args.workspace_dir:
        # Reuse the existing original-source-bound HUMAN workspace; no subprocess,
        # scanner, model, DNS, grant or command execution is involved.
        import workspace
        workspace_args = (["--verify-workspace-dir", args.workspace_dir]
                          if args.verify_output else
                          ["--workspace-dir", args.workspace_dir,
                           "--manifest", os.path.join(output_abs, MANIFEST)])
        if workspace.main(workspace_args) != 0:
            raise Hold("existing private HUMAN workspace admission failed")
        review_fd, _ = open_output_directory(os.path.join(args.workspace_dir, workspace.BUNDLE_DIR))
        try:
            if read_private_bundle_item(review_fd, MANIFEST, MAX_MANIFEST_BYTES) != files[MANIFEST]:
                raise Hold("HUMAN workspace original lab manifest does not match combined source")
        finally:
            os.close(review_fd)
    status = "REOPENED_REVIEW_ONLY" if args.verify_output else "PUBLISHED_REVIEW_ONLY"
    print(status + " · " + str(counts["result_endpoints"]) +
          " isolated-lab endpoint slots · no assessment, consent, target contact or authorization")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Prepare owner-private lab manifests offline. Never execute lab-assess.")
    parser.add_argument("--first-manifest", required=True, help="existing source manifest (0600)")
    parser.add_argument("--second-manifest", required=True, help="incoming source manifest (0600)")
    parser.add_argument("--more-manifest", action="append", default=[],
                        help="additional owner-private 0600 manifest (repeat up to six times)")
    parser.add_argument("--mode", choices=("append", "replace"), required=True)
    parser.add_argument("--output-dir", help="separate existing private output directory (0700); omit only in dry-run")
    secondary = parser.add_mutually_exclusive_group()
    secondary.add_argument("--handoff-dir", help="optional second private 0700 directory for original preview bundle")
    secondary.add_argument("--workspace-dir", help="optional second private 0700 directory for complete HUMAN-only workspace")
    parser.add_argument("--ack-normalization", action="store_true", help="allow source comments/whitespace to be omitted")
    parser.add_argument("--ack-replace", action="store_true", help="explicitly accept discarding first manifest endpoints")
    parser.add_argument("--verify-output", action="store_true", help="read-only strict reopen against both original sources")
    parser.add_argument("--dry-run", action="store_true", help="show counts only after original scope admission, without creating files")
    parser.add_argument("--explain-hold", action="store_true", help="print curated reasons; never endpoint/path values")
    args = parser.parse_args(argv)
    try:
        if args.dry_run:
            if args.output_dir or args.handoff_dir or args.workspace_dir or args.verify_output:
                raise Hold("dry-run is read-only and cannot select publication or reopen directories")
            _, _, counts = prepare(args.first_manifest, args.second_manifest, args.mode,
                                   args.ack_normalization, args.ack_replace, preview_only=True,
                                   more_paths=args.more_manifest)
            print("MANIFEST_COMBINE_REVIEW_ONLY · mode=" + args.mode +
                  " · first=" + str(counts["first_endpoints"]) +
                  " · incoming=" + str(counts["second_endpoints"]) +
                  " · sources=" + str(counts.get("source_manifests", 2)) +
                  " · extra_endpoints=" + str(counts.get("additional_endpoints", 0)) +
                  " · retained=" + str(counts["retained_first_endpoints"]) +
                  " · discarded=" + str(counts["discarded_first_endpoints"]) +
                  " · result=" + str(counts["result_endpoints"]) +
                  " · normalization_ack_needed=" + str(counts["normalization_requires_ack"]).lower() +
                  " · replacement_ack_needed=" + str(counts["replacement_requires_ack"]).lower() +
                  " · no output, consent, authorization or assessment")
            return 0
        if not args.output_dir:
            raise Hold("private output directory required for publication or reopen")
        return run(args)
    except Hold as error:
        report_hold("LAB_MANIFEST_COMBINE_HOLD — private source or original lab policy not admitted", error, args.explain_hold)
    except Exception:
        # Never leak exception messages, paths, endpoints or stack traces for unexpected failures.
        report_hold("LAB_MANIFEST_COMBINE_HOLD — filesystem or source parsing rejected", None, args.explain_hold)
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
