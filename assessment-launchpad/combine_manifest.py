#!/usr/bin/env python3
"""Offline private manifest merge/replacement. Never contacts endpoints or executes assessment."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from types import SimpleNamespace

import launchpad
from source_board import render_board, slot_map_csv

from launchpad import (
    Hold, MAX_ENDPOINTS, MAX_MANIFEST_BYTES, open_output_directory,
    open_private_input, publish_bundle, read_private_bundle_item, report_hold,
    validate_endpoints,
)

MANIFEST = "lightup-lab-targets.txt"
SUMMARY = "lightup-manifest-combine-private.json"
BOARD = "lightup-manifest-source-board-private.html"
SLOT_MAP = "lightup-manifest-source-slots-private.csv"
FILES = {MANIFEST: MAX_MANIFEST_BYTES, SUMMARY: 4096, BOARD: 16384, SLOT_MAP: 16384}
MAX_SOURCES = 8


def canonical_lines(endpoints):
    return ("\n".join(endpoints) + "\n").encode("utf-8")


def prepare(first_path, second_path, mode, ack_normalization, ack_replace,
            *, preview_only=False, more_paths=(), omit_sources=(), ack_omit=False, include_source_map=False):
    if mode not in ("append", "replace"):
        raise Hold("explicit append or replace mode required")
    source_paths = (first_path, second_path, *more_paths)
    if not 2 <= len(source_paths) <= MAX_SOURCES:
        raise Hold("use between 2 and 8 original PRIVATE manifest files")
    opened = [open_private_input(path) for path in source_paths]
    originals = tuple(item[0] for item in opened)
    if len(set(originals)) != len(originals):
        raise Hold("original PRIVATE manifest paths must be distinct")
    omissions = tuple(omit_sources)
    if len(omissions) != len(set(omissions)) or any(
            ordinal < 1 or ordinal > len(opened) for ordinal in omissions):
        raise Hold("omit-source ordinal is repeated or outside the selected input series")
    if omissions and not ack_omit and not preview_only:
        raise Hold("source omission requires explicit acknowledgement")
    if mode == "replace" and 1 in omissions:
        raise Hold("first source is already discarded in replace mode")
    normalized = any(raw != canonical_lines(lines) for _, raw, lines in opened)
    if normalized and not ack_normalization and not preview_only:
        raise Hold("source whitespace or comments would be omitted; acknowledge normalization")
    if mode == "replace" and not ack_replace and not preview_only:
        raise Hold("replacement requires explicit acknowledgement")
    selected = [(ordinal, lines) for ordinal, (_, _, lines) in
                enumerate(opened, 1)
                if ordinal not in omissions and (mode == "append" or ordinal != 1)]
    merged = [item for _, lines in selected for item in lines]
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
        "retained_first_endpoints":len(opened[0][2]) if mode == "append" and 1 not in omissions else 0,
        "discarded_first_endpoints":0 if mode == "append" and 1 not in omissions else len(opened[0][2]),
        "normalization_requires_ack":normalized,
        "replacement_requires_ack":mode == "replace",
    }
    include_map = len(opened) > 2 or bool(omissions) or include_source_map
    if include_map:
        counts.update(source_manifests=len(opened),
                      additional_endpoints=sum(len(row[2]) for row in opened[2:]))
    if omissions:
        counts.update(omitted_sources=len(omissions),
                      omitted_endpoints=sum(len(opened[i - 1][2]) for i in omissions))
    receipt = dict(schema=("lightup.offline-manifest-combine.v3" if omissions else
                                "lightup.offline-manifest-combine.v2" if include_map else
                                "lightup.offline-manifest-combine.v1"),
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
    if omissions:
        receipt["omitted_source_ordinals"] = sorted(omissions)
        receipt["omission_acknowledged"] = bool(ack_omit)
    if include_map:
        receipt["sources"] = [
            dict(ordinal=i, endpoints=len(lines), input_sha256=sha256(raw).hexdigest())
            for i, (_, raw, lines) in enumerate(opened, start=1)]
    receipt_bytes = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(receipt_bytes) > FILES[SUMMARY]:
        raise Hold("private source receipt exceeds bound")
    artifacts = {MANIFEST:canonical, SUMMARY:receipt_bytes}
    if include_map:
        artifacts[BOARD] = render_board(receipt)
        artifacts[SLOT_MAP] = slot_map_csv(receipt)
    return originals, artifacts, counts


def run(args):
    originals, files, counts = prepare(
        args.first_manifest, args.second_manifest, args.mode,
        args.ack_normalization, args.ack_replace, more_paths=args.more_manifest,
        omit_sources=args.omit_source, ack_omit=args.ack_omit,
        include_source_map=args.source_slot_map,
    )
    if bool(args.change_before_dir) != bool(args.change_output_dir):
        raise Hold("manifest change comparison requires both a saved before bundle and an isolated output directory")
    if bool(args.history_prior_dir) != bool(args.history_output_dir):
        raise Hold("manifest history requires prior bundles and a separate private output directory")
    if len(args.history_prior_dir) > 7:
        raise Hold("history may contain at most seven prior saved source bundles")
    if args.change_before_dir or args.history_prior_dir:
        # Admit all prior saved bundles before writing any combined output.
        # Local source integrity is not independent authority or chronology.
        import manifest_change_desk
        for prior in ([args.change_before_dir] if args.change_before_dir else []) + args.history_prior_dir:
            manifest_change_desk.admit_saved_bundle(prior)
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
        if args.change_output_dir:
            change_fd, change_abs = open_output_directory(args.change_output_dir)
            try:
                protected = [output_abs, os.path.abspath(args.change_before_dir)]
                protected.extend(os.path.abspath(path) for path in args.history_prior_dir)
                if args.history_output_dir:
                    protected.append(os.path.abspath(args.history_output_dir))
                if extra_directory:
                    protected.append(os.path.abspath(extra_directory))
                protected.extend(os.path.dirname(original) for original in originals)
                for source in protected:
                    common = os.path.commonpath((change_abs, source))
                    if common in (change_abs, source):
                        raise Hold("private change output must be separate from source, handoff and combined directories")
                if not args.verify_output and os.listdir(change_fd):
                    raise Hold("private change output directory must be empty before publication")
            finally:
                os.close(change_fd)
        if args.history_output_dir:
            history_fd, history_abs = open_output_directory(args.history_output_dir)
            try:
                protected = [output_abs]
                if args.change_before_dir:
                    protected.append(os.path.abspath(args.change_before_dir))
                if extra_directory:
                    protected.append(os.path.abspath(extra_directory))
                if args.change_output_dir:
                    protected.append(os.path.abspath(args.change_output_dir))
                protected.extend(os.path.abspath(path) for path in args.history_prior_dir)
                protected.extend(os.path.dirname(original) for original in originals)
                for source in protected:
                    common = os.path.commonpath((history_abs, source))
                    if common in (history_abs, source):
                        raise Hold("private history output must be separate from all source and output trees")
                if not args.verify_output and os.listdir(history_fd):
                    raise Hold("private history output directory must be empty before publication")
            finally:
                os.close(history_fd)
        for original in originals:
            parent = os.path.dirname(original)
            shared = os.path.commonpath((output_abs, parent))
            if shared == output_abs or shared == parent:
                raise Hold("output directory must be separate from both source trees")
        if args.verify_output:
            found = set(os.listdir(output_fd))
            expected = set(files)
            original_receipt = json.loads(files[SUMMARY])
            # Historical v2 source-board packets predate the new PRIVATE slot-map CSV.
            # Reopen that exact already-admitted v2 shape read-only; publishing NEW
            # bundles still requires every current file and its exact source bytes.
            legacy_v2 = (original_receipt["schema"] == "lightup.offline-manifest-combine.v2"
                         and found == expected - {SLOT_MAP})
            if found != expected and not legacy_v2:
                raise Hold("existing combined output contains missing or extra files")
            for name in found:
                if read_private_bundle_item(output_fd, name, FILES[name]) != files[name]:
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
            publish_bundle(output_fd, list(files.items()))
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
    if args.change_before_dir:
        # The independent comparison is published to a THIRD private directory.
        # A failure leaves an already published combined/workspace packet private;
        # it never grants authority, rolls back source files, or executes a scan.
        change_args = ["--before-dir", args.change_before_dir,
                       "--after-dir", args.output_dir,
                       "--verify-output-dir" if args.verify_output else "--output-dir",
                       args.change_output_dir]
        if manifest_change_desk.main(change_args) != 0:
            raise Hold("private manifest change comparison or exact reopen failed")
    if args.history_prior_dir:
        # The already-written canonical combined packet is the final history plan.
        # This is a separate isolated PRIVATE transaction, never a live workflow.
        import manifest_history_desk
        history_args = [part for path in (*args.history_prior_dir, args.output_dir)
                        for part in ("--plan-dir", path)]
        history_args.extend([
            "--verify-output-dir" if args.verify_output else "--output-dir",
            args.history_output_dir,
        ])
        if manifest_history_desk.main(history_args) != 0:
            raise Hold("private history publication or read-only reopen failed")
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
    parser.add_argument("--omit-source", type=int, action="append", default=[],
                        help="omit original PRIVATE source ordinal (repeatable, 1-based)")
    parser.add_argument("--ack-omit", action="store_true",
                        help="confirm intentional exclusion of original source files")
    parser.add_argument("--source-slot-map", action="store_true",
                        help="include a PRIVATE source ordinal/slot map even for a two-source bundle; repeat on exact reopen")
    parser.add_argument("--output-dir", help="separate existing private output directory (0700); omit only in dry-run")
    secondary = parser.add_mutually_exclusive_group()
    secondary.add_argument("--handoff-dir", help="optional second private 0700 directory for original preview bundle")
    secondary.add_argument("--workspace-dir", help="optional second private 0700 directory for complete HUMAN-only workspace")
    parser.add_argument("--change-before-dir", help="optional prior saved PRIVATE combined bundle to compare")
    parser.add_argument("--change-output-dir", help="separate empty 0700 PRIVATE change-desk directory; verify with --verify-output")
    parser.add_argument("--history-prior-dir", action="append", default=[],
                        help="prior saved PRIVATE combine bundle (repeat up to 7); current output becomes final plan")
    parser.add_argument("--history-output-dir", help="additional separate empty PRIVATE 0700 history directory")
    parser.add_argument("--ack-normalization", action="store_true", help="allow source comments/whitespace to be omitted")
    parser.add_argument("--ack-replace", action="store_true", help="explicitly accept discarding first manifest endpoints")
    parser.add_argument("--verify-output", action="store_true", help="read-only strict reopen against both original sources")
    parser.add_argument("--dry-run", action="store_true", help="show admitted counts and optional source-slot ordinals without creating files")
    parser.add_argument("--explain-hold", action="store_true", help="print curated reasons; never endpoint/path values")
    args = parser.parse_args(argv)
    try:
        if args.dry_run:
            if (args.output_dir or args.handoff_dir or args.workspace_dir or args.verify_output
                    or args.change_before_dir or args.change_output_dir
                    or args.history_prior_dir or args.history_output_dir):
                raise Hold("dry-run is read-only and cannot select publication or reopen directories")
            _, dry_files, counts = prepare(args.first_manifest, args.second_manifest, args.mode,
                                   args.ack_normalization, args.ack_replace, preview_only=True,
                                   more_paths=args.more_manifest,
                                   omit_sources=args.omit_source, ack_omit=args.ack_omit,
                                   include_source_map=args.source_slot_map)
            print("MANIFEST_COMBINE_REVIEW_ONLY · mode=" + args.mode +
                  " · first=" + str(counts["first_endpoints"]) +
                  " · incoming=" + str(counts["second_endpoints"]) +
                  " · sources=" + str(counts.get("source_manifests", 2)) +
                  " · extra_endpoints=" + str(counts.get("additional_endpoints", 0)) +
                  " · omitted_sources=" + str(counts.get("omitted_sources", 0)) +
                  " · omission_ack_needed=" + str(bool(args.omit_source)).lower() +
                  " · retained=" + str(counts["retained_first_endpoints"]) +
                  " · discarded=" + str(counts["discarded_first_endpoints"]) +
                  " · result=" + str(counts["result_endpoints"]) +
                  " · normalization_ack_needed=" + str(counts["normalization_requires_ack"]).lower() +
                  " · replacement_ack_needed=" + str(counts["replacement_requires_ack"]).lower() +
                  " · source_slot_map_would_publish=" + str(len((args.more_manifest or [])) > 0 or bool(args.omit_source) or args.source_slot_map).lower() +
                  " · no output, consent, authorization or assessment")
            if SLOT_MAP in dry_files:
                # Source-local ordinals only; never print endpoint values or private paths.
                print("SOURCE_SLOT_MAP_REVIEW_ONLY")
                print(dry_files[SLOT_MAP].decode("ascii"), end="")
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
