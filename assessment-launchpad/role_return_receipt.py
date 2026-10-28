"""Exact offline admission of a PRIVATE role return into a HUMAN workroom.

Unsigned local source consistency only; no identity, authorization or consent.
"""
from __future__ import annotations

from hashlib import sha256
import json
import copy
import os

from launchpad import FLAGS, Hold, open_output_directory, read_private_bundle_item
from review_desk import ROLES, STAGES, load_json, validate_worksheet
from role_handoff import NAMES as HANDOFF_FILES, assemble, select

RESPONSE_FILE = "lightup-lab-human-role-return-private.json"
CONTEXT_FILE = "lightup-lab-human-role-return-context.json"


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       separators=(",", ":")) + "\n").encode("utf-8")


def handoff_digest(rounds, endpoints, role, stage, slots):
    original = dict(assemble(rounds, endpoints, role, stage, slots))
    digest = sha256()
    for name in HANDOFF_FILES:
        value = original[name]
        digest.update(name.encode("ascii") + b"\x00")
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


def receipt(rounds, endpoints, digest, role, stage, slots, worksheet_bytes):
    if type(role) is not str or role not in ROLES or type(stage) is not str or stage not in ("ALL", *STAGES):
        raise Hold("invalid selected HUMAN role or stage")
    if not 2 <= len(rounds) <= 8:
        raise Hold("role return requires 2-8 source-bound HUMAN rounds")
    indices = select(rounds, role, stage, slots)
    if not indices:
        raise Hold("no matching HUMAN role-return slots")
    return canonical({
        "schema": "lightup.assessment_launchpad_role_return_context.v1",
        "status": "REVIEW_ONLY",
        "canonical_manifest_sha256": digest,
        "original_handoff_sha256": handoff_digest(rounds, endpoints, role, stage, slots),
        "selected_human_role": role,
        "selected_latest_stage": stage,
        "selected_original_slots": [i + 1 for i in indices],
        "source_round_sha256": [sha256(canonical(record)).hexdigest() for record in rounds],
        "owner_worksheet_sha256": sha256(worksheet_bytes).hexdigest(),
        **{key: False for key in FLAGS},
    })


def admit_return(directory, rounds, endpoints, digest):
    """Require original ordered rounds, minimal edits, canonical receipt and bytes."""
    fd, absolute = open_output_directory(directory)
    try:
        if set(os.listdir(fd)) != {RESPONSE_FILE, CONTEXT_FILE}:
            raise Hold("source-bound role return requires its exact two private files")
        reply_raw = read_private_bundle_item(fd, RESPONSE_FILE, 65536)
        receipt_raw = read_private_bundle_item(fd, CONTEXT_FILE, 65536)
    finally:
        os.close(fd)
    meta = load_json(receipt_raw)
    role = meta.get("selected_human_role")
    stage = meta.get("selected_latest_stage")
    selected = meta.get("selected_original_slots")
    if (type(role) is not str or role not in ROLES
            or type(stage) is not str or stage not in ("ALL", *STAGES)
            or type(selected) is not list or not selected
            or any(type(slot) is not int for slot in selected)):
        raise Hold("invalid role-return selection metadata")
    indices = select(rounds, role, stage, selected)
    if [index + 1 for index in indices] != selected:
        raise Hold("role-return source slots not in canonical selection order")
    work = load_json(reply_raw)
    validate_worksheet(work, digest, len(endpoints))
    if work.keys() != rounds[-1].keys():
        raise Hold("role return changed source metadata fields")
    if any(work[key] != rounds[-1][key] for key in rounds[-1] if key != "human_rows"):
        raise Hold("role return changed bound source metadata")
    original_rows = rounds[-1]["human_rows"]
    for index, (before, after) in enumerate(zip(original_rows, work["human_rows"])):
        if index not in indices:
            if after != before:
                raise Hold("role return mutated another HUMAN role or unselected slot")
        elif before["slot"] != after["slot"] or before["role"] != after["role"]:
            raise Hold("selected role return altered source slot or suggested role")
    if reply_raw != canonical(work) or receipt_raw != receipt(
            rounds, endpoints, digest, role, stage, selected, reply_raw):
        raise Hold("original role-return receipt or worksheet bytes drifted")
    return absolute, work, tuple(indices)


def combine_returns(directories, rounds, endpoints, digest):
    """Compose disjoint role-only replies without allowing cross-role edits.

    All responses must originate from the same source round manifest. The
    source-bound receipts are unsigned and never constitute identity or consent.
    """
    if not 1 <= len(directories) <= 5:
        raise Hold("one through five original selected-role packets are supported")
    merged = copy.deepcopy(rounds[-1])
    seen_dirs, selected_indices = set(), set()
    for directory in directories:
        absolute, response, indices = admit_return(directory, rounds, endpoints, digest)
        if absolute in seen_dirs:
            raise Hold("duplicate original role return")
        seen_dirs.add(absolute)
        if selected_indices.intersection(indices):
            raise Hold("HUMAN role returns claim overlapping original slots")
        selected_indices.update(indices)
        for index in indices:
            merged["human_rows"][index] = copy.deepcopy(response["human_rows"][index])
    validate_worksheet(merged, digest, len(endpoints))
    return merged
