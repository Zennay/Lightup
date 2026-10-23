#!/usr/bin/env python3
"""One-command owner-private assessment human workspace from ORIGINAL archive sources.

No evaluation, model, lab runner, tool dispatch, target access, grants or client consent.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
from io import BytesIO
from zipfile import ZipFile, ZipInfo, ZIP_STORED
import sys

from portfolio import (FLAGS, Hold, MAX_BYTES, decode_json,
                       encode, load_one, package, publish, read_regular, summarize)
from followup import load_choices
from archive import MAX_MANIFEST, _manifest
from agenda import render_bytes, selected_day

SCHEMA="lightup.assessment_portfolio_original_source_workspace.v1"
MAX_WORKSPACE_BYTES=32*1024*1024

def source_digests(manifest_paths, choice_paths):
    """Reopen exact ORIGINAL regular files; never infer identity from SHA-256."""
    if not 1<=len(manifest_paths)<=12 or len(choice_paths)!=len(manifest_paths):
        raise Hold("original source/choices count mismatch")
    return [(
        sha256(read_regular(manifest_path,MAX_MANIFEST)).hexdigest(),
        sha256(read_regular(choices_path,MAX_MANIFEST)).hexdigest(),
    ) for manifest_path,choices_path in zip(manifest_paths,choice_paths)]


def require_original_sources(manifest_paths, choice_paths, expected):
    """Fail closed on source drift before a private output is published or reused."""
    if (type(expected) is not list or len(expected)!=len(manifest_paths)
            or any(type(row) is not dict or
                   set(row)!={"slot","original_manifest_sha256",
                              "original_choices_sha256","derived_original_agenda_sha256",
                              "original_source_count","claimed_status"}
                   or row["slot"]!=i+1
                   for i,row in enumerate(expected))):
        raise Hold("invalid original source binding")
    current=source_digests(manifest_paths,choice_paths)
    for i,(manifest_sha,choices_sha) in enumerate(current):
        if (manifest_sha!=expected[i]["original_manifest_sha256"]
                or choices_sha!=expected[i]["original_choices_sha256"]):
            raise Hold("original source bytes changed before private handoff")


def build(manifest_paths,choice_paths,reference):
    selected_day(reference)
    if not 1<=len(manifest_paths)<=12 or len(choice_paths)!=len(manifest_paths):
        raise Hold("original source/choices count mismatch")
    source_entries=[]
    originals=set()
    agendas=[]
    agenda_bytes=[]
    for index,(manifest_path,choices_path) in enumerate(zip(manifest_paths,choice_paths),1):
        # Every ORIGINAL manifest/choices path was explicitly supplied by the operator.
        raw=read_regular(manifest_path,MAX_MANIFEST)
        original=_manifest(decode_json(raw))
        raw_choices=read_regular(choices_path,MAX_MANIFEST)
        manifest_digest=sha256(raw).hexdigest()
        choices_digest=sha256(raw_choices).hexdigest()
        if manifest_digest in originals:
            raise Hold("same original manifest selected twice")
        originals.add(manifest_digest)
        values=load_choices(choices_path,original,manifest_digest)
        if sha256(read_regular(choices_path,MAX_MANIFEST)).hexdigest()!=choices_digest:
            raise Hold("original human choices changed during import")
        original_agenda=render_bytes(original,values,reference,False,"json")
        if not 0<len(original_agenda)<=MAX_BYTES:
            raise Hold("original human agenda exceeds archive bounds")
        parsed=load_one(None,reference,raw=original_agenda)
        if parsed["status"]!=original["status"]:
            raise Hold("original claimed status changed")
        agendas.append(parsed)
        agenda_bytes.append(original_agenda)
        source_entries.append({"slot":index,
           "original_manifest_sha256":manifest_digest,
           "original_choices_sha256":choices_digest,
           "derived_original_agenda_sha256":sha256(original_agenda).hexdigest(),
           "original_source_count":original["source_count"],
           "claimed_status":original["status"]})
    summary=summarize(agendas,reference)
    metadata={"schema":SCHEMA,"reference_date":reference,
              "source_count":len(agendas),"sources":source_entries,
              "claimed_status":summary["claimed_status"],
              "planning_not_permission":True,
              **{flag:False for flag in FLAGS}}
    packet=BytesIO(package(agendas,summary))
    # No original underlying lab case, client finding/evidence payload or target is included.
    with ZipFile(packet,mode="a",compression=ZIP_STORED) as output:
        for index,raw in enumerate(agenda_bytes,1):
            member=ZipInfo(f"original-private-agenda-{index:02d}.json",(2026,10,18,0,0,0))
            member.external_attr=0o600<<16
            output.writestr(member,raw)
        member=ZipInfo("private-original-source-map.json",(2026,10,18,0,0,0))
        member.external_attr=0o600<<16
        output.writestr(member,encode(metadata))
        member=ZipInfo("ORIGINAL-HUMAN-START-HERE.txt",(2026,10,18,0,0,0))
        member.external_attr=0o600<<16
        output.writestr(member,(
            "LIGHTUP SINGLE-COMMAND ORIGINAL HUMAN ASSESSMENT WORKSPACE\n"
            "Open workspace-home.html for the full offline human workflow.\n"
            "Use original-human-review-studio.html for HUMAN planning proposals only.\n"
            "Original PRIVATE human agendas are included as original-private-agenda-NN.json, "
            "fully source-bound to the separately held original manifest/choices.\n"
            "private-original-source-map.json contains sensitive SHA fingerprints, NOT authentic source proof.\n"
            "This ZIP does not contain original raw customer findings/evidence, source manifest, "
            "password, target, scanner or live authorization.\n"
            "For an original-schema human return, the operator must separately present the "
            "matching ORIGINAL manifest/choices, exact ORIGINAL private agenda from this ZIP, "
            "and its newly exported human proposal to proposal_return.py.\n"
            "Do not reuse previous source outputs when original choices change; retained HOLD never authorizes action.\n"
            "INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO GO.\n").encode("utf-8"))
    assembled=packet.getvalue()
    if not 0<len(assembled)<=MAX_WORKSPACE_BYTES:
        raise Hold("original workspace exceeds private size limit")
    require_original_sources(manifest_paths,choice_paths,source_entries)
    return assembled,summary["claimed_status"],len(agendas)

def main(argv=None):
    p=argparse.ArgumentParser(description="Complete OFFLINE ORIGINAL-source human portfolio in one command; no GO")
    p.add_argument("--original-manifest",required=True,action="append",
                   help="One immutable ORIGINAL archive manifest path, repeat 1–12")
    p.add_argument("--original-choices",required=True,action="append",
                   help="Matching ORIGINAL private human choices, same order")
    p.add_argument("--as-of",required=True,help="Explicit original shared human planning YYYY-MM-DD")
    p.add_argument("--output",required=True,help="NEW owner-private complete workbench ZIP, never overwrite")
    a=p.parse_args(argv)
    try:
        blob,status,count=build(a.original_manifest,a.original_choices,a.as_of)
        # Reopen the real ORIGINAL inputs after all potentially expensive rendering,
        # immediately before the exclusive private ZIP publication.
        with ZipFile(BytesIO(blob),"r") as assembled:
            mapping=decode_json(assembled.read("private-original-source-map.json"))
        if (type(mapping) is not dict or mapping.get("schema")!=SCHEMA
                or mapping.get("source_count")!=count
                or mapping.get("reference_date")!=a.as_of
                or mapping.get("planning_not_permission") is not True
                or any(mapping.get(flag) is not False for flag in FLAGS)):
            raise Hold("original private source map is not canonical")
        require_original_sources(a.original_manifest,a.original_choices,mapping.get("sources"))
        publish(a.output,blob)
        print(f"ORIGINAL_OFFLINE_HUMAN_WORKSPACE_CREATED agendas={count} — NO GO")
        return 3 if status=="HOLD" else 2
    except (Hold,OSError,ValueError,TypeError,KeyError,UnicodeError,
            RecursionError,OverflowError):
        print("ORIGINAL_HUMAN_WORKSPACE_HOLD — missing, changed or incompatible original sources",file=sys.stderr)
        return 3

if __name__=="__main__":
    raise SystemExit(main())
