#!/usr/bin/env python3
"""Five-view PRIVATE LightUp original-source + HUMAN evidence workbench.

Compose unchanged original Casework/Ticket Desk and Engagement Brief builders
with the existing original Evidence Artifact Ledger and optional encrypted HUMAN
notes. Build everything in memory; publish one new 0700 owner-only folder.
This is HUMAN-only offline planning, never security authorization or deployment.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "remediation-engagement-brief"))
sys.path.insert(0, str(ROOT / "remediation-secure-export"))
sys.path.insert(0, str(ROOT / "src"))

from desk import build_desk
from history import review as history_review
from history_desk import build_history_desk
from sealed_browser import _admit_encrypted_source, _original_workspace_apps, _rows, WORKSPACE_MODES
from workspace_release import _admit_folder, _landing
from secure_export import _authorized_summary, _strict_summary, _vault

def _module(name: str, filename: str):
    location=Path(__file__).with_name(filename)
    spec=importlib.util.spec_from_file_location(name,location)
    if spec is None or spec.loader is None:
        raise ValueError("Original source-bound Evidence Bridge module missing.")
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

bridge=_module("_lightup_original_evidence_bridge","bridge.py")
human=_module("_lightup_private_human_workspace","workspace.py")

MAX_TOTAL_OUTPUT = 12 * 1024 * 1024
MAX_FILES = 6

def _evidence_view(
    current_csv: str, client: str, engagement: str,
    private_human: Path | None, vault
) -> bytes:
    raw=current_csv.encode("utf-8","strict")
    if private_human is None:
        return bridge._render(raw,client,engagement)
    if private_human.suffix.lower()!=".ltv":
        raise ValueError("Optional HUMAN workspace must be encrypted .ltv.")
    original=vault._private_input(private_human.expanduser().absolute(),vault.MAX_VAULT)
    password=vault._password("Separate PRIVATE HUMAN workroom passphrase: ",fresh=False)
    payload,mime,_=vault._open(original,password)
    if mime!="application/json":
        raise ValueError("Optional HUMAN workspace not an original JSON payload.")
    metadata,source,human_json=human._admit_workspace(payload)
    sha,count=_strict_summary(current_csv)
    if (source!=raw or metadata["original_csv_sha256"]!=sha
        or metadata["original_finding_count"]!=count
        or metadata["client_reference"]!=client
        or metadata["engagement_reference"]!=engagement):
        raise ValueError("Original PRIVATE HUMAN notes do not match current authenticated source.")
    # The original Evidence Ledger will only stage a user-triggered preview;
    # the HUMAN operator separately clicks original App's explicit Apply.
    return human._restore_html(raw,human_json,client,engagement)

def _landing_five(views: tuple[str,...], count: int) -> bytes:
    first=_landing(views,count).decode("utf-8","strict")
    anchor="</ul></nav>"
    if first.count(anchor)!=1 or "script-src &apos;none&apos;" not in first:
        raise ValueError("Original offline source workbench navigation drift.")
    first=first.replace(anchor,
      '<li><a href="05-evidence-ledger.html">Original HUMAN Evidence Artifact Ledger</a></li>'+anchor)
    html=first.replace(
      "LightUp · PRIVATE HUMAN source-only workspace",
      "LightUp · PRIVATE HUMAN five-view evidence workbench")
    if len(html.encode("utf-8"))>8192:
        raise ValueError("PRIVATE scriptless navigation exceeds original source limit.")
    return html.encode("utf-8")

def _build_all(
    csv_text: str, client: str, engagement: str,
    source: Path, private_human: Path | None
) -> tuple[dict[str,bytes],tuple[str,...]]:
    vault=_vault()
    original=_admit_encrypted_source(csv_text,client,engagement,source)
    if original["mode"] not in WORKSPACE_MODES:
        raise ValueError("Only original encrypted multiview source is supported.")
    now=_rows(csv_text)
    prior=[_rows(csv) for csv in original["historical_original_csv"]]
    originals=_original_workspace_apps(original,csv_text,client,engagement)
    views=("review","ticketdesk","casework")+(("history",) if prior else ())
    contents={
        "01-review.html":build_desk(now,prior[-1] if prior else None),
        "02-ticketdesk.html":originals["ticketdesk"],
        "03-casework.html":originals["casework"],
        "05-evidence-ledger.html":_evidence_view(csv_text,client,engagement,private_human,vault),
    }
    if prior:
        snapshots=[(dict(unverified_historical=True), records) for records in prior]
        snapshots.append((dict(current_authenticated=True),now))
        contents["04-history.html"]=build_history_desk(history_review(snapshots))
    contents["index.html"]=_landing_five(views,len(now))
    if not 5<=len(contents)<=MAX_FILES or sum(len(x) for x in contents.values())>MAX_TOTAL_OUTPUT:
        raise ValueError("PRIVATE source/HUMAN workbench file/size bounds exceeded.")
    for name,source_bytes in contents.items():
        if type(source_bytes) is not bytes or not source_bytes.startswith(b"<!doctype html>"):
            raise ValueError("Original offline view output format changed.")
        if b"connect-src 'none'" not in source_bytes and name!="index.html":
            raise ValueError("Original nonnetwork browser contract missing.")
    return contents,views

def _publish(output_dir: Path, contents: dict[str,bytes]) -> None:
    target=_admit_folder(output_dir)
    os.mkdir(target,0o700)
    created=[]
    try:
        vault=_vault()
        for name,body in contents.items():
            # Same original source-owner exclusive 0600 file publication.
            vault._exclusive_output(target/name,body)
            created.append(name)
    except BaseException:
        for name in created:
            (target/name).unlink(missing_ok=True)
        try:
            target.rmdir()
        except OSError:
            pass
        raise

def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    for flag in ("db","email","client-id","engagement-id"):
        parser.add_argument("--"+flag,required=True)
    parser.add_argument("--source",required=True,type=Path,
        help="Existing owner-private original engagement multiview source .ltv")
    parser.add_argument("--human",type=Path,
        help="Optional existing owner-private encrypted unified HUMAN collaboration .ltv")
    parser.add_argument("--output-dir",required=True,type=Path,
        help="NEW folder under an owner-private 0700 directory")
    parser.add_argument("--ack-private-workspace",action="store_true",required=True,
        help="Explicit acceptance that this creates PRIVATE plaintext 0600 HTML only")
    args=parser.parse_args(argv)
    try:
        if not args.ack_private_workspace:
            raise ValueError("Explicit local PRIVATE HTML publication acknowledgement required.")
        if not sys.stdin.isatty():
            raise ValueError("Private authenticated terminal is required.")
        current=_authorized_summary(db=args.db,email=args.email,
            client_id=args.client_id,engagement_id=args.engagement_id)
        contents,views=_build_all(current,args.client_id,args.engagement_id,
                                 args.source,args.human)
        _publish(args.output_dir,contents)
        print("PRIVATE LightUp five-view offline workbench created in a NEW 0700 directory.")
        print("Views: source findings, original Ticket Desk, original Casework, "
              +("source history, " if "history" in views else "")
              +"original human Evidence Artifact Ledger.")
        print("Every view is a 0600 offline HTML; index.html is the entrypoint.")
        print("Any HUMAN handoff is PREVIEW-ONLY pending separate original App Apply.")
        print("No scan, grant, verified remediation, live target or client/operator consent issued.")
        return 0
    except Exception:
        print("HOLD: no PRIVATE LightUp evidence workbench published; "
              "verify existing owner source, current role and private filesystem.",file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
