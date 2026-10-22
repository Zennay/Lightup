#!/usr/bin/env python3
"""Prepare exact PRIVATE HUMAN review queue edits without CSV hand-editing or browser storage."""
from __future__ import annotations

import argparse
import csv
from io import StringIO
import os

import manifest_history_desk as history
from launchpad import Hold, open_output_directory, publish_bundle, read_private_bundle_item, report_hold

LIMIT = 65536
STAGES = ("FOLLOW_UP_REQUIRED", "NEEDS_CONTEXT", "IN_REVIEW",
          "QUESTION_PREPARED", "PARKED", "HUMAN_REVIEWED")
FIELDS = ("from_ordinal", "to_ordinal", "change", "before_slot", "after_slot", "human_stage")


def admit_updates(values, size):
    changes = {}
    for entry in values:
        try:
            ordinal, stage = entry.split(":", 1)
        except ValueError as error:
            raise Hold("stage edit requires ROW:STAGE") from error
        if not ordinal.isascii() or not ordinal.isdecimal() or str(int(ordinal)) != ordinal:
            raise Hold("stage row ordinal must be a canonical positive integer")
        position = int(ordinal)
        if position < 1 or position > size or position in changes:
            raise Hold("HUMAN row ordinal is repeated or outside the source queue")
        if stage not in STAGES:
            raise Hold("HUMAN stage must be a fixed non-authorizing value")
        changes[position] = stage
    return changes


def source_admission(args):
    inputs = [part for path in args.plan_dir for part in ("--plan-dir", path)]
    if history.main(inputs + ["--verify-output-dir", args.history_dir]) != 0:
        raise Hold("original source-bound private manifest history not admitted")
    original, packet = history.prepare(args.plan_dir)
    fd, absolute = open_output_directory(args.history_dir)
    try:
        source_queue = read_private_bundle_item(fd, history.QUEUE, LIMIT)
        if source_queue != history.render_queue_csv(packet):
            raise Hold("original PRIVATE history queue drifted")
    finally:
        os.close(fd)
    return original, absolute, packet


def emit_csv(rows):
    out = StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(FIELDS)
    for row in rows:
        writer.writerow([row[field] if row[field] is not None else "" for field in FIELDS])
    return out.getvalue().encode("utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Author a PRIVATE exact-slot HUMAN queue locally, without any assessment action.")
    parser.add_argument("--plan-dir", action="append", default=[], required=True,
                        help="each original PRIVATE combined-plan bundle in the saved history order")
    parser.add_argument("--history-dir", required=True, help="original PRIVATE history output directory")
    parser.add_argument("--stage", action="append", default=[],
                        help="set 1-based queue row stage, e.g. --stage 2:NEEDS_CONTEXT; repeatable")
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output-dir", help="separate empty owner-private 0700 answers directory")
    destination.add_argument("--verify-output-dir", help="read-only exact reopen using same --stage choices")
    parser.add_argument("--explain-hold", action="store_true", help="curated HOLD without paths/URLs")
    args = parser.parse_args(argv)
    try:
        sources, history_abs, packet = source_admission(args)
        original = packet["human_review_queue"]
        edits = admit_updates(args.stage, len(original))
        rows = [{**row, "human_stage": edits.get(index, row["human_stage"])}
                for index, row in enumerate(original, 1)]
        csv_bytes = emit_csv(rows)
        if not 0 < len(csv_bytes) <= LIMIT:
            raise Hold("PRIVATE HUMAN answer CSV exceeds source bound")
        fd, output_abs = open_output_directory(args.output_dir or args.verify_output_dir)
        try:
            for source in [*(item[0] for item in sources), history_abs]:
                shared = os.path.commonpath((source, output_abs))
                if shared in (source, output_abs):
                    raise Hold("HUMAN answers output must be separate from original source trees")
            if args.verify_output_dir:
                if set(os.listdir(fd)) != {history.QUEUE}:
                    raise Hold("saved PRIVATE HUMAN answers contain extra or missing files")
                if read_private_bundle_item(fd, history.QUEUE, LIMIT) != csv_bytes:
                    raise Hold("saved PRIVATE HUMAN answers drifted from original rows or selected stages")
            else:
                if os.listdir(fd):
                    raise Hold("PRIVATE HUMAN answers output directory must be empty")
                _, confirmed, _ = source_admission(args)
                if confirmed != history_abs:
                    raise Hold("original PRIVATE history source location changed")
                publish_bundle(fd, [(history.QUEUE, csv_bytes)])
        finally:
            os.close(fd)
        print(("HUMAN_QUEUE_REOPENED" if args.verify_output_dir else "HUMAN_QUEUE_CREATED") +
              " · source_rows=" + str(len(original)) +
              " · edited_rows=" + str(len(edits)) +
              " · HUMAN_REVIEW_ONLY · no approval, authorization, scanner or consent")
        return 0
    except Hold as error:
        report_hold("HUMAN_HISTORY_EDITOR_HOLD — original source or stage not admitted",
                    error, args.explain_hold)
    except Exception:
        report_hold("HUMAN_HISTORY_EDITOR_HOLD — private input or output rejected",
                    None, args.explain_hold)
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
