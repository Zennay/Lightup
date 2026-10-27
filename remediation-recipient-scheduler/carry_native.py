#!/usr/bin/env python3
"""Carry HUMAN-only assignments into a new original source-free packet selection.

Consumes prior encrypted PRIVATE .lurp through unchanged native AES-GCM
reader, binds each previously assigned row to exact original source SHA and
slot/reason/count, never treats unmatched packets as fixed/authorized.
"""
from __future__ import annotations

import argparse
from datetime import date
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sys

import schedule
import schedule_vault
import single_review

sys.path.insert(0, str(schedule.PARENT / "remediation-integrated-workspace"))
import install
import workflow

WARNING = (
    "PRIVATE HUMAN carry-forward of self-declared scheduling only. SHA-256 "
    "equality is unsigned local source consistency, not authentic identity, "
    "consent, security assessment, remediation, retest or granted authority. "
    "Changed/absent/new original packets are NOT fixed. DRAFT/HOLD."
)

def require(ok: bool, explanation: str) -> None:
    single_review.review.require(ok, explanation)


def original_prior(doc: dict) -> dict[str, dict]:
    require(type(doc) is dict and set(doc) == schedule_vault.PLAN_FIELDS
            and doc["kind"] == schedule.KIND and type(doc["version"]) is int
            and doc["version"] == 1
            and doc["disposition"] == "PRIVATE_HUMAN_ONLY_NO_AUTHORITY"
            and doc["authority_granted"] is False
            and doc["consent_verified"] is False
            and doc["remediation_verified"] is False
            and doc["warning"] == schedule.WARNING,
            "Unknown source-bound HUMAN plan or elevated authority")
    sources = doc["sources"]
    tasks = doc["tasks"]
    require(type(sources) is list and 1 <= len(sources) <= schedule.MAX_SOURCES
            and type(tasks) is list and len(tasks) <= schedule.MAX_TASKS,
            "Incomplete prior source-free HUMAN original packet inventory")
    old: dict[str, dict] = {}
    positions: dict[int, dict] = {}
    for position,source in enumerate(sources,1):
        require(type(source) is dict and
                set(source) == {"packet","source_sha256","reason_groups"}
                and type(source["packet"]) is int and source["packet"] == position
                and type(source["reason_groups"]) is int
                and 0 <= source["reason_groups"] <= 72
                and type(source["source_sha256"]) is str
                and bool(re.fullmatch(r"[0-9a-f]{64}",source["source_sha256"]))
                and source["source_sha256"] not in old,
                "Ambiguous old HUMAN source-free packet identity")
        record = {"source":source,"tasks":{}}
        positions[position]=record
        old[source["source_sha256"]] = record
    for task in tasks:
        require(type(task) is dict and set(task) == schedule_vault.TASK_FIELDS
                and type(task["packet"]) is int
                and task["packet"] in positions
                and type(task["slot"]) is int and 0 <= task["slot"] <= 2048
                and type(task["count"]) is int and task["count"] > 0
                and type(task["reason"]) is str and
                task["reason"] in single_review.read_cockpit.triage.REASONS
                and type(task["stage"]) is str and
                task["stage"] in single_review.STAGES
                and schedule_vault.local_text(task["human_note"],240,960,True)
                and schedule_vault.local_text(task["owner"],64,256)
                and schedule_vault.local_text(task["next_action"],240,960,True)
                and (task["due"] == "" or
                     (type(task["due"]) is str and
                      len(task["due"]) == 10 and
                      date.fromisoformat(task["due"]).isoformat() == task["due"])),
                "Invalid previous HUMAN row or source-free original reason")
        packet = positions[task["packet"]]["tasks"]
        key=(task["slot"],task["reason"])
        require(key not in packet, "Duplicate old HUMAN source-free reason")
        packet[key]=task
    require(all(len(record["tasks"])==record["source"]["reason_groups"]
                for record in old.values()),
            "Previous HUMAN plan original group inventory incomplete")
    return old


def carry(encrypted_vault: Path, originals: list[str], destination: Path) -> None:
    require(destination.is_absolute() and
            destination.parent == destination.parent.resolve(strict=True)
            and not destination.exists() and not destination.is_symlink(),
            "Choose a new literal absolute recipient workspace")
    schedule.private_parent(destination.parent)
    require(encrypted_vault != destination and
            destination not in encrypted_vault.parents and
            encrypted_vault not in destination.parents and
            all(Path(s).is_absolute() and Path(s) != destination and
                destination not in Path(s).parents and
                Path(s) not in destination.parents for s in originals),
            "Original HUMAN source, vault and new destination must be separate")
    # Both source-free recipient admission and exact previous encrypted-plan
    # admission precede any mutation. No time ordering or same-client inferred.
    sources, tasks = schedule.source_records(originals, [])
    earlier = original_prior(schedule_vault.open_vault(encrypted_vault))
    selected = [dict(x) for x in tasks]
    unchanged=0
    carried=0
    new=0
    for s in sources:
        old = earlier.get(s["source_sha256"])
        rows = [r for r in selected if r["packet"] == s["packet"]]
        if old is None:
            new += 1
            continue
        require(len(rows) == len(old["tasks"]) == s["reason_groups"],
                "Source digest claimed unchanged but previous HUMAN members differ")
        for task in rows:
            previous = old["tasks"].get((task["slot"],task["reason"]))
            require(previous is not None and previous["count"] == task["count"],
                    "Source-free member identity mismatched previous original HUMAN state")
        for task in rows:
            previous = old["tasks"][(task["slot"],task["reason"])]
            for field in ("stage","human_note","owner","due","next_action"):
                task[field]=previous[field]
        unchanged += 1
        carried += len(rows)
    require(unchanged, "No unchanged original source-free Cockpit to carry; nothing updated")
    require(sys.stdin.isatty(),
            "PRIVATE HUMAN carry requires explicit interactive operator acknowledgement")
    print("HUMAN-only preview:",unchanged,"unchanged original source-free packet(s),",
          carried,"eligible HUMAN entries,",new,"new/changed packet(s) untouched.")
    print("No authenticated sender, consent, verified fix, source chronology or new grant.")
    try:
        choice = input("Type exactly CARRY to publish a NEW private HUMAN draft: ")
    except EOFError as exc:
        raise single_review.review.Hold("No human confirmation") from exc
    require(choice == "CARRY","HUMAN reviewer did not approve source-exact carry")
    stage=destination.parent / (".lightup-human-source-carry-" + secrets.token_hex(12))
    os.mkdir(stage,0o700)
    try:
        workroom=stage / "human-scheduler"
        os.mkdir(workroom,0o700)
        schedule.private_write(workroom,"index.html",schedule.render(sources,selected))
        schedule.private_write(workroom,"README.txt",
            (WARNING+"\nOnly exact unchanged original sources received previous HUMAN "
             "fields. Use NEW browser-encrypted .lurp file to save this new selected order.\n"
            ).encode("utf-8"))
        receipt={
            "kind":"lightup.private_human_exact_source_carry",
            "version":1,"disposition":"PRIVATE_HUMAN_DRAFT_HOLD",
            "authority_granted":False,"consent_verified":False,
            "remediation_verified":False,
            "source_free_selected":len(sources),
            "exact_source_packet_matches":unchanged,
            "human_entries_carried":carried,
            "new_or_changed_packets_untouched":new,
            "missing_previous_packets":len(earlier)-unchanged,
            "warning":WARNING
        }
        schedule.private_write(stage,"private-summary.json",schedule.canonical(receipt))
        index=workflow.page("PRIVATE source-free HUMAN continuity",[
            ("Open new selected original-source-bound HUMAN planner",
             "human-scheduler/index.html",
             "Only exact original source-free bytes receive prior HUMAN notes; "
             "new and changed packets stay unanswered and unverified.")
        ],WARNING)
        install.write_file(stage/"index.html",index)
        require(not destination.exists(),"Another PRIVATE recipient workroom appeared")
        workflow.workspace.exclusive_dir_publish(stage,destination)
    finally:
        if stage.exists(): shutil.rmtree(stage)
    print("REVIEW_ONLY: PRIVATE human carry-forward planner:",destination/"index.html")
    print("All prior ciphertext and native source-free files remained unchanged.")


def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vault",required=True,type=Path,
                        help="Previously browser-encrypted source-bound HUMAN .lurp")
    parser.add_argument("--cockpit",required=True,action="append",
                        help="Actual original native source-free Cockpit, 1–12 real packets")
    parser.add_argument("--output-dir",required=True,type=Path,
                        help="Fresh absolute private owner-only output folder")
    a=parser.parse_args()
    try:
        carry(a.vault,a.cockpit,a.output_dir)
        return 2
    except (single_review.review.Hold,install.Hold,OSError,
            ValueError,TypeError,KeyError,UnicodeError,OverflowError,
            RuntimeError,ImportError,EOFError) as exc:
        print("HOLD: private original-source HUMAN carry-forward:",exc,file=sys.stderr)
        return 3

if __name__=="__main__":
    raise SystemExit(main())
