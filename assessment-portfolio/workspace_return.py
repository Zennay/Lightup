#!/usr/bin/env python3
"""Return a one-command private workspace to original human choices, atomically.

The offline ZIP is untrusted and supplies no grants, consent, source authenticity or GO.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
from io import BytesIO
import sys
from zipfile import BadZipFile, ZipFile, ZIP_STORED

from portfolio import FLAGS, Hold, MAX_BYTES, decode_json, encode, publish, read_regular, load_one
from one_command import SCHEMA as WORKSPACE_SCHEMA
from proposal_return import reconcile
from multi_return import _page, _zip, SCHEMA as RETURN_SCHEMA
from archive import MAX_MANIFEST, reject_authority
from followup import manifest_identity, load_choices
from agenda import render_bytes, selected_day

MAX_PACKAGE = 16 * 1024 * 1024
MAX_MEMBERS = 26
MAP_SCHEMA = WORKSPACE_SCHEMA
MAP_FIELDS = {"schema", "reference_date", "source_count", "sources",
              "claimed_status", "planning_not_permission", *FLAGS}
SOURCE_FIELDS = {"slot", "original_manifest_sha256", "original_choices_sha256",
                 "derived_original_agenda_sha256", "original_source_count",
                 "claimed_status"}
PACKAGE_FILES = {"START-HERE.txt", "index.html", "interactive-capacity-studio.html",
                 "original-human-review-studio.html", "private-source-bindings.json",
                 "aggregate.html", "aggregate.json", "aggregate.csv",
                 "private-original-source-map.json", "ORIGINAL-HUMAN-START-HERE.txt"}


def _workspace(blob):
    try:
        with ZipFile(BytesIO(blob), "r") as z:
            infos = z.infolist()
            names = [i.filename for i in infos]
            if (len(names) != len(set(names)) or not 11 <= len(names) <= MAX_MEMBERS
                    or any(i.is_dir() or i.compress_type != ZIP_STORED
                           or (i.flag_bits & 1) or i.file_size > MAX_PACKAGE
                           or i.compress_size != i.file_size for i in infos)
                    or sum(i.file_size for i in infos) > MAX_PACKAGE):
                raise Hold("workspace ZIP contents not bounded/canonical")
            mapping = decode_json(z.read("private-original-source-map.json"))
            reject_authority(mapping)
            if (type(mapping) is not dict or set(mapping) != MAP_FIELDS
                    or mapping["schema"] != MAP_SCHEMA
                    or mapping["planning_not_permission"] is not True
                    or type(mapping["source_count"]) is not int
                    or not 1 <= mapping["source_count"] <= 12
                    or type(mapping["sources"]) is not list
                    or len(mapping["sources"]) != mapping["source_count"]
                    or mapping["claimed_status"] not in ("HOLD", "REVIEW_ONLY")
                    or any(mapping[k] is not False for k in FLAGS)):
                raise Hold("unknown original source map")
            selected_day(mapping["reference_date"])
            expected = PACKAGE_FILES | {
                f"original-private-agenda-{i:02d}.json"
                for i in range(1, mapping["source_count"] + 1)}
            # Accept original owner-produced older ZIPs with no navigator.
            # Current newly generated workspaces include a scriptless home.
            nameset = set(names)
            new_map = "private-workspace-content-map.json" in nameset
            if nameset not in (expected, expected | {"workspace-home.html"},
                               expected | {"workspace-home.html", "private-workspace-content-map.json"},
                               expected | {"workspace-home.html", "private-workspace-content-map.json",
                                           "collaboration-guide.html"}):
                raise Hold("incomplete or unexpected workspace ZIP members")
            if new_map:
                from content_map import verify as verify_private_content_map
                expected_content = {name for name in expected
                                    if not name.startswith("original-private-agenda-")
                                    and name not in {"private-original-source-map.json",
                                                     "ORIGINAL-HUMAN-START-HERE.txt"}}
                expected_content.add("workspace-home.html")
                if "collaboration-guide.html" in nameset:
                    expected_content.add("collaboration-guide.html")
                verify_private_content_map(z, expected_content,
                                           mapping["source_count"], mapping["reference_date"])
            if any(i.file_size > MAX_BYTES for i in infos
                   if i.filename.startswith("original-private-agenda-")):
                raise Hold("oversized original agenda")
            agendas = []
            digests = set()
            states = []
            for ix, record in enumerate(mapping["sources"], 1):
                if (type(record) is not dict or set(record) != SOURCE_FIELDS
                        or type(record["slot"]) is not int or record["slot"] != ix
                        or type(record["original_source_count"]) is not int
                        or not 1 <= record["original_source_count"] <= 64
                        or record["claimed_status"] not in ("HOLD", "REVIEW_ONLY")
                        or any(type(record[field]) is not str
                               or len(record[field]) != 64
                               or any(c not in "0123456789abcdef"
                                      for c in record[field])
                               for field in ("original_manifest_sha256",
                                             "original_choices_sha256",
                                             "derived_original_agenda_sha256"))):
                    raise Hold("invalid original source map row")
                if record["original_manifest_sha256"] in digests:
                    raise Hold("original manifest duplicated in archive")
                digests.add(record["original_manifest_sha256"])
                agenda_bytes = z.read(f"original-private-agenda-{ix:02d}.json")
                agenda = load_one(None, mapping["reference_date"], raw=agenda_bytes)
                if (sha256(agenda_bytes).hexdigest() != record["derived_original_agenda_sha256"]
                        or len(agenda["rows"]) != record["original_source_count"]
                        or agenda["status"] != record["claimed_status"]):
                    raise Hold("original agenda is inconsistent with source map")
                agendas.append(agenda_bytes)
                states.append(agenda["status"])
            expected_state = "HOLD" if "HOLD" in states else "REVIEW_ONLY"
            if mapping["claimed_status"] != expected_state:
                raise Hold("original HOLD status was lost")
            return mapping, agendas
    except (BadZipFile, KeyError, RuntimeError, EOFError):
        raise Hold("invalid or incomplete workspace ZIP") from None


def build(workspace_path, manifest_paths, choice_paths, proposal_paths=None, proposal_bundle_path=None, *, proposal_bundle_raw=None):
    blob = read_regular(workspace_path, MAX_PACKAGE)
    mapping, agendas = _workspace(blob)
    count = mapping["source_count"]
    if len(manifest_paths) != count or len(choice_paths) != count:
        raise Hold("each original source requires a manifest and prior human choices")
    if proposal_bundle_path is not None or proposal_bundle_raw is not None:
        if proposal_paths is not None or (proposal_bundle_path is not None and proposal_bundle_raw is not None):
            raise Hold("choose exactly one original human proposal input mode")
        from proposal_bundle import load as load_proposal_bundle
        proposal_bytes = load_proposal_bundle(proposal_bundle_path, mapping, agendas,
                                              raw=proposal_bundle_raw)
    else:
        if proposal_paths is None or len(proposal_paths) != count:
            raise Hold("one private human proposal per original agenda is required")
        proposal_bytes = [read_regular(path, MAX_BYTES) for path in proposal_paths]
    documents = {}
    records = []
    changed_total = 0
    for ix, (manifest, choices, proposal_raw) in enumerate(
            zip(manifest_paths, choice_paths, proposal_bytes), 1):
        original, manifest_hash = manifest_identity(manifest)
        original_choices = load_choices(choices, original, manifest_hash)
        record = mapping["sources"][ix - 1]
        choice_raw = read_regular(choices, MAX_MANIFEST)
        if (manifest_hash != record["original_manifest_sha256"]
                or sha256(choice_raw).hexdigest() != record["original_choices_sha256"]
                or len(original_choices) != record["original_source_count"]
                or original["status"] != record["claimed_status"]):
            raise Hold("original manifest or choices changed since workspace creation")
        regenerated = render_bytes(original, original_choices,
                                   mapping["reference_date"], False, "json")
        if regenerated != agendas[ix - 1]:
            raise Hold("workspace agenda differs from ORIGINAL renderer")
        updated, state, changed = reconcile(manifest, choices, None, None,
                                            agenda_raw=agendas[ix - 1],
                                            proposal_raw=proposal_raw)
        name = f"original-human-choices-{ix:02d}.json"
        documents[name] = updated
        records.append({"slot": ix, "output_member": name,
                        "original_manifest_sha256": manifest_hash,
                        "new_choices_sha256": sha256(updated).hexdigest(),
                        "human_updates": changed, "claimed_status": state})
        changed_total += changed
    overall = "HOLD" if any(row["claimed_status"] == "HOLD" for row in records) else "REVIEW_ONLY"
    private = {"schema": RETURN_SCHEMA, "source_count": count,
               "total_human_updates": changed_total, "claimed_status": overall,
               "sources": records, "planning_not_permission": True,
               **{f: False for f in FLAGS}}
    documents["private-manifest.json"] = encode(private)
    documents["index.html"] = _page(records, overall)
    documents["START-HERE.txt"] = (
        "LIGHTUP ORIGINAL HUMAN WORKSPACE RETURN / NO GO\n"
        "One ORIGINAL immutable manifest, choices and proposal per source were checked.\n"
        "Each numbered JSON is a NEW human-only choices document. Nothing was applied.\n"
        "Private source fingerprints are unsigned, not source identity or authority.\n"
        "Re-render original agendas only after the independent human owner confirms context.\n"
        "HOLD persists. No verified evidence, grant, scanner, consent or target action.\n"
        "INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.\n"
    ).encode("utf-8")
    return _zip(documents), overall, changed_total


def main(argv=None):
    p = argparse.ArgumentParser(description="Return complete original human ZIP to new source-bound choices / NO GO")
    p.add_argument("--workspace", required=True, help="Original one_command.py private ZIP")
    p.add_argument("--original-manifest", action="append", required=True)
    p.add_argument("--original-choices", action="append", required=True)
    human = p.add_mutually_exclusive_group(required=True)
    human.add_argument("--proposal", action="append",
                       help="One private human proposal for each source, same order")
    human.add_argument("--proposal-bundle",
                       help="One complete original-bound multi-agenda human proposal JSON bundle")
    p.add_argument("--output", required=True, help="NEW private return ZIP; never overwrite")
    a = p.parse_args(argv)
    try:
        output, state, changed = build(a.workspace, a.original_manifest,
                                       a.original_choices, a.proposal, a.proposal_bundle)
        publish(a.output, output)
        print(f"ORIGINAL_HUMAN_WORKSPACE_RETURN_CREATED changed_human_slots={changed} — NO GO")
        return 3 if state == "HOLD" else 2
    except (Hold, OSError, ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError):
        print("ORIGINAL_HUMAN_WORKSPACE_RETURN_HOLD — incompatible original human sources",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
