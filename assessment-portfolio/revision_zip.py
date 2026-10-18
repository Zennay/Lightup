#!/usr/bin/env python3
"""Open a complete prior original human revision ZIP for history; no source authority."""
from __future__ import annotations

from hashlib import sha256
from io import BytesIO
from zipfile import BadZipFile, ZipFile, ZIP_STORED

from portfolio import FLAGS, Hold, read_regular, decode_json
from workspace_return import _workspace

MAX_ZIP = 32*1024*1024
MAX_MEMBERS = 28
BASE = {"next-human-workspace.zip", "private-human-change-board.html",
        "aggregate-human-stage-transitions.json",
        "aggregate-human-stage-transitions.csv", "private-revision-record.json",
        "index.html", "START-HERE.txt"}
CAPACITY = {"new-private-human-capacity-plan.json",
            "new-private-human-capacity-outlook.html",
            "new-aggregate-human-capacity.html",
            "new-aggregate-human-capacity.csv",
            "HUMAN-CAPACITY-RECONFIRMATION.txt"}


def read_cycle_zip(path):
    blob=read_regular(path,MAX_ZIP)
    try:
        with ZipFile(BytesIO(blob),"r") as z:
            infos=z.infolist()
            names=[item.filename for item in infos]
            if (len(names)!=len(set(names)) or not 8<=len(names)<=MAX_MEMBERS
                    or any(item.is_dir() or item.compress_type!=ZIP_STORED
                           or item.flag_bits & 1 or item.file_size>MAX_ZIP
                           or item.compress_size!=item.file_size
                           or "/" in item.filename or "\\" in item.filename
                           for item in infos)
                    or sum(item.file_size for item in infos)>MAX_ZIP):
                raise Hold("private human revision ZIP contains unexpected members")
            raw=z.read("private-revision-record.json")
            if not 0<len(raw)<=131072:
                raise Hold("private human revision receipt exceeds source bounds")
            # Late import: revision_history uses this ZIP entry point optionally.
            from revision_history import load_raw
            record,digest=load_raw(raw)
            n=record["source_count"]
            expected=BASE | {f"original-human-choices-{i:02d}.json" for i in range(1,n+1)}
            if set(names) not in (expected,expected|CAPACITY):
                raise Hold("revision ZIP differs from original complete cycle contract")
            next_workspace=z.read("next-human-workspace.zip")
            if not 0<len(next_workspace)<=16*1024*1024:
                raise Hold("nested original human workspace exceeds bounds")
            map_doc,agendas=_workspace(next_workspace)
            if (map_doc["reference_date"]!=record["new_reference_date"]
                    or map_doc["source_count"]!=record["source_count"]
                    or map_doc["claimed_status"]!=record["claimed_status"]):
                raise Hold("new human workspace differs from original revision record")
            for index,(source,meta,agenda_raw) in enumerate(
                    zip(record["sources"],map_doc["sources"],agendas),1):
                raw_choice=z.read(f"original-human-choices-{index:02d}.json")
                if (not 0<len(raw_choice)<=131072
                        or source["original_manifest_sha256"]!=meta["original_manifest_sha256"]
                        or source["new_choices_sha256"]!=meta["original_choices_sha256"]
                        or sha256(raw_choice).hexdigest()!=source["new_choices_sha256"]
                        or sha256(agenda_raw).hexdigest()!=source["new_agenda_sha256"]
                        or source["new_agenda_sha256"]!=meta["derived_original_agenda_sha256"]
                        or source["claimed_status"]!=meta["claimed_status"]):
                    raise Hold("original human ZIP source/choices/agenda history diverges")
            if CAPACITY <= set(names):
                plan=decode_json(z.read("new-private-human-capacity-plan.json"))
                if (type(plan) is not dict
                        or plan.get("schema")!="lightup.assessment_portfolio_capacity_plan.v1"
                        or plan.get("reference_date")!=record["new_reference_date"]
                        or plan.get("source_count")!=n
                        or type(plan.get("sources")) is not list
                        or len(plan["sources"])!=n
                        or any(plan.get(f) is not False for f in FLAGS)):
                    raise Hold("new human capacity is not bound to original source")
                for src,meta in zip(plan["sources"],map_doc["sources"]):
                    if (type(src) is not dict or src.get("slot")!=meta["slot"]
                            or src.get("source_sha256")!=meta["derived_original_agenda_sha256"]
                            or src.get("claimed_status")!=meta["claimed_status"]):
                        raise Hold("optional human capacity source changed")
            return record,digest
    except (BadZipFile,RuntimeError,KeyError,EOFError,OverflowError):
        raise Hold("invalid complete private human revision ZIP") from None
