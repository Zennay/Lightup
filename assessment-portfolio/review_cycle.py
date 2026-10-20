#!/usr/bin/env python3
"""Prepare next offline human review workspace from source-bound proposed changes.

Owner-private work only. Never edits originals, submits grants, or executes a lab.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
from io import BytesIO
import sys
from zipfile import ZipFile, ZIP_STORED, ZipInfo

from portfolio import load_one, package, summarize, read_regular
from archive import FLAGS, Hold, decode_json, encode, publish
from followup import CHOICES_SCHEMA, manifest_identity
from agenda import render_bytes, selected_day
from one_command import SCHEMA as ORIGINAL_WORKSPACE_SCHEMA
from multi_return import _page, _zip
from workspace_return import _workspace, build as return_build
from cycle_diff import build as human_change_board

SCHEMA = "lightup.assessment_portfolio_private_revision_cycle.v1"
MAX_WORKSPACE = 16 * 1024 * 1024


def _append(z, name, blob):
    member = ZipInfo(name, (2026, 10, 18, 0, 0, 0))
    member.external_attr = 0o600 << 16
    z.writestr(member, blob)


def build(workspace_path, manifests, choices, proposals, reference_date, proposal_bundle_path=None, previous_capacity_path=None, capacity_reconfirmed=False, *, proposal_bundle_raw=None):
    selected_day(reference_date)
    if (previous_capacity_path is None) != (capacity_reconfirmed is False):
        raise Hold("old capacity assumptions require explicit human reconfirmation")
    previous_map, previous_agendas = _workspace(read_regular(workspace_path, MAX_WORKSPACE))
    source_count = previous_map["source_count"]
    if len(manifests) != source_count or len(choices) != source_count:
        raise Hold("revision requires all original manifests and human choices")
    if proposal_bundle_path is None and proposal_bundle_raw is None:
        if proposals is None or len(proposals) != source_count:
            raise Hold("revision requires one proposal per original source")
    elif proposals is not None or (proposal_bundle_path is not None and proposal_bundle_raw is not None):
        raise Hold("choose exactly one original human proposal input mode")
    # Full original + complete ZIP + proposal checks before starting a new workspace.
    returned, status, change_total = return_build(
        workspace_path, manifests, choices, proposals, proposal_bundle_path,
        proposal_bundle_raw=proposal_bundle_raw)
    with ZipFile(BytesIO(returned), "r") as z:
        updated_bytes = [z.read(f"original-human-choices-{i:02d}.json")
                         for i in range(1, source_count + 1)]
        return_doc = decode_json(z.read("private-manifest.json"))
    revised_sources = []
    revised_bytes = []
    provenance = []
    for ix, (manifest_path, choice_bytes) in enumerate(zip(manifests, updated_bytes), 1):
        original, manifest_hash = manifest_identity(manifest_path)
        old_entry = previous_map["sources"][ix - 1]
        if (manifest_hash != old_entry["original_manifest_sha256"]
                or original["status"] != old_entry["claimed_status"]):
            raise Hold("original manifest changed after private return")
        revised = decode_json(choice_bytes)
        if (type(revised) is not dict
                or set(revised) != {"schema", "manifest_sha256", "items", *FLAGS}
                or revised["schema"] != CHOICES_SCHEMA
                or revised["manifest_sha256"] != manifest_hash
                or any(revised[k] is not False for k in FLAGS)
                or type(revised["items"]) is not list
                or len(revised["items"]) != original["source_count"]):
            raise Hold("invalid new original-schema human source")
        # The original reconcile function already bound every item to original
        # source identity, all unchanged prior values and bounded human choices.
        raw = render_bytes(original, revised["items"], reference_date, False, "json")
        parsed = load_one(None, reference_date, raw=raw)
        if parsed["status"] != original["status"]:
            raise Hold("original HOLD/source state was not preserved")
        revised_sources.append(parsed)
        revised_bytes.append(raw)
        now_digest = sha256(choice_bytes).hexdigest()
        revised_source = {
            "slot": ix, "original_manifest_sha256": manifest_hash,
            "original_choices_sha256": now_digest,
            "derived_original_agenda_sha256": sha256(raw).hexdigest(),
            "original_source_count": original["source_count"],
            "claimed_status": original["status"]
        }
        provenance.append({
            "slot": ix,
            "original_manifest_sha256": manifest_hash,
            "previous_choices_sha256": old_entry["original_choices_sha256"],
            "new_choices_sha256": now_digest,
            "previous_agenda_sha256": sha256(previous_agendas[ix - 1]).hexdigest(),
            "new_agenda_sha256": revised_source["derived_original_agenda_sha256"],
            "human_changed_slots": return_doc["sources"][ix - 1]["human_updates"],
            "claimed_status": original["status"],
        })
    summary = summarize(revised_sources, reference_date)
    if summary["claimed_status"] != status:
        raise Hold("revision attempted to alter original HOLD")
    fresh_map = {
        "schema": ORIGINAL_WORKSPACE_SCHEMA, "reference_date": reference_date,
        "source_count": source_count, "sources": [
            {"slot": row["slot"], "original_manifest_sha256": row["original_manifest_sha256"],
             "original_choices_sha256": row["new_choices_sha256"],
             "derived_original_agenda_sha256": row["new_agenda_sha256"],
             "original_source_count": len(revised_sources[ix]["rows"]),
             "claimed_status": row["claimed_status"]}
            for ix, row in enumerate(provenance)],
        "claimed_status": summary["claimed_status"],
        "planning_not_permission": True,
        **{flag: False for flag in FLAGS}
    }
    next_packet = BytesIO(package(revised_sources, summary))
    with ZipFile(next_packet, mode="a", compression=ZIP_STORED) as zipout:
        for index, raw in enumerate(revised_bytes, 1):
            _append(zipout, f"original-private-agenda-{index:02d}.json", raw)
        _append(zipout, "private-original-source-map.json", encode(fresh_map))
        _append(zipout, "ORIGINAL-HUMAN-START-HERE.txt", (
            "REVISED ORIGINAL HUMAN WORKSPACE / PRIVATE / NO GO\n"
            "Open workspace-home.html to navigate the next complete human review.\n"
            "The original lab sources were NOT changed or approved.\n"
            "To return the next human-only proposal, separately present original manifests\n"
            "and newly generated original-human-choices-NN.json from the outer ZIP.\n"
            "Use workspace_return.py with next-human-workspace.zip and those choices.\n"
            "Original HOLD persists. Fingerprints authenticate nothing.\n"
        ).encode("utf-8"))
    revision = {
        "schema": SCHEMA, "previous_reference_date": previous_map["reference_date"],
        "new_reference_date": reference_date, "source_count": source_count,
        "human_changed_slots": change_total, "claimed_status": status,
        "sources": provenance, "planning_not_permission": True,
        **{flag: False for flag in FLAGS}
    }
    changed_html, changed_json, changed_csv = human_change_board(
        previous_agendas, revised_bytes, previous_map["reference_date"], reference_date)
    outputs = {"next-human-workspace.zip": next_packet.getvalue(),
               "private-human-change-board.html": changed_html,
               "aggregate-human-stage-transitions.json": changed_json,
               "aggregate-human-stage-transitions.csv": changed_csv,
               "private-revision-record.json": encode(revision),
               "index.html": _page(return_doc["sources"], status),
               "START-HERE.txt": (
                   "LIGHTUP HUMAN REVISION CYCLE · NO GO\n"
                   "This contains a NEW standalone next-human-workspace.zip and NEW\n"
                   "original-human-choices-NN.json; do not overwrite or modify originals.\n"
                   "Use private-human-change-board.html for source-slot human change overview.\n"
                   "Aggregate transition JSON/CSV contains only canonical stage/count data.\n"
                   "The private revision record connects unsigned source bytes; not approval.\n"
                   "Use new choices plus the matching ORIGINAL manifests on next review.\n"
                   "No evidence validation, assessment execution, grants or client consent.\n"
                   "INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.\n"
               ).encode("utf-8")}
    if previous_capacity_path is not None:
        from capacity_handoff import rebind as human_capacity_handoff
        outputs.update(human_capacity_handoff(
            previous_capacity_path, [load_one(None, previous_map["reference_date"], raw=raw)
                                     for raw in previous_agendas],
            previous_map["reference_date"], revised_sources, reference_date,
            human_reconfirmed=capacity_reconfirmed))
    for ix, blob in enumerate(updated_bytes, 1):
        outputs[f"original-human-choices-{ix:02d}.json"] = blob
    return _zip(outputs), status, change_total


def main(argv=None):
    p = argparse.ArgumentParser(description="Build NEXT private human workspace from original proposals; NO GO")
    p.add_argument("--workspace", required=True)
    p.add_argument("--original-manifest", action="append", required=True)
    p.add_argument("--original-choices", action="append", required=True)
    human = p.add_mutually_exclusive_group(required=True)
    human.add_argument("--proposal", action="append", help="Private human proposal per original source")
    human.add_argument("--proposal-bundle", help="Single offline all-agenda human proposal bundle")
    p.add_argument("--next-as-of", required=True, help="Explicit date for next human-only agenda")
    p.add_argument("--previous-private-capacity-plan", help="Optional previous ORIGINAL source-bound human capacity plan")
    p.add_argument("--reconfirm-human-capacity", action="store_true",
                   help="Required with previous plan: explicitly carry ONLY hypothetical neutral-role assumptions")
    p.add_argument("--output", required=True, help="NEW private revision ZIP, never overwrite")
    args = p.parse_args(argv)
    try:
        new_zip, status, changed = build(args.workspace, args.original_manifest,
                                         args.original_choices, args.proposal, args.next_as_of,
                                         args.proposal_bundle,
                                         args.previous_private_capacity_plan,
                                         args.reconfirm_human_capacity)
        publish(args.output, new_zip)
        print(f"NEXT_PRIVATE_HUMAN_WORKSPACE_CREATED changed_human_slots={changed} — NO GO")
        return 3 if status == "HOLD" else 2
    except (Hold, OSError, ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError):
        print("HUMAN_REVISION_CYCLE_HOLD — changed or incompatible original sources",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
