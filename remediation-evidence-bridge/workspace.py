#!/usr/bin/env python3
"""Encrypt PRIVATE HUMAN Evidence Ledger collaboration from exact original source.

No scanning, no authorization, no silent workspace restore. The original Ledger
is unchanged; imports are explicitly previewed and confirmed by a human there.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import sqlite3
import sys

SPEC = importlib.util.spec_from_file_location("_lightup_original_evidence_bridge", Path(__file__).with_name("bridge.py"))
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Original source-bound Evidence Ledger bridge missing.")
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)
KIND = "lightup.private_encrypted_original_human_workspace"
FLAGS = tuple(dict.fromkeys((*bridge.original.FALSE, "tenant_verified", "audit_verdict")))
LIMIT = 1536 * 1024
MAX_BOX = 4 * 1024 * 1024
FIELDS = frozenset({
    "kind","schema_version","disposition","source_contract","client_reference",
    "engagement_reference","original_csv_sha256","original_finding_count",
    "original_csv_base64","original_source_digest","workspace_bytes",
    "workspace_sha256","workspace_base64","warning",*FLAGS
})
UNIFIED = frozenset({
    "kind","schema_version","disposition","source_contract","source_sha256",
    "source_count","client_reference","engagement_reference","casework",
    "evidence_review","attachments","human_requests","warning",*FLAGS
})
UNIFIED_V1 = UNIFIED - {"human_requests"}
COLUMNS = bridge.original.COLUMNS


def _canonical(obj: object) -> bytes:
    return json.dumps(obj,sort_keys=True,ensure_ascii=True,separators=(",",":")).encode("ascii")


def _json(data: bytes, max_size: int) -> dict:
    if len(data) < 2 or len(data) > max_size:
        raise ValueError("PRIVATE HUMAN payload invalid size.")
    obj = json.loads(data.decode("utf-8","strict"), object_pairs_hook=bridge.original._unique_pairs,
                     parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON.")))
    if type(obj) is not dict:
        raise ValueError("PRIVATE HUMAN packet must be an object.")
    return obj


def _native_digest(raw: bytes) -> tuple[str,int]:
    """Python admission equivalent of the pinned original Casework sourceFingerprint.

    The original independent browser performs its own full source/row validation,
    and ONLY the original browser may make a human restore after review.
    """
    bridge.original._strict_summary(raw.decode("utf-8","strict"))
    stream = csv.reader(io.StringIO(raw.decode("utf-8","strict"),newline=""),strict=True)
    if tuple(next(stream,())) != COLUMNS:
        raise ValueError("Original source columns have drifted.")
    rows = [dict(zip(COLUMNS,row,strict=True)) for row in stream]
    if not rows or len(rows)>bridge.original.MAX_FINDINGS:
        raise ValueError("Original source is empty or too large.")
    # JS relational comparisons use UTF-16 code units. This preserves that order.
    rows.sort(key=lambda r:r["finding_id"].encode("utf-16-be"))
    canonical = json.dumps(rows,ensure_ascii=False,separators=(",",":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest(),len(rows)


def _packet(raw: bytes, *, source_digest: str, count: int,
            client: str, engagement: str) -> dict:
    packet = _json(raw,LIMIT)
    version=packet.get("schema_version")
    expected=UNIFIED if type(version) is int and version==2 else UNIFIED_V1
    if set(packet)!=expected or packet.get("kind")!="lightup.private_unified_human_evidence_workspace" or (
        type(version) is not int or version not in (1,2)
    ) or packet.get("disposition")!="PRIVATE_HUMAN_REVIEW_ONLY" or (
        packet.get("source_contract")!="lightup.finding_export._COLUMNS_v1"
    ) or packet.get("source_sha256")!=source_digest or packet.get("source_count")!=count or (
        packet.get("client_reference")!=client or packet.get("engagement_reference")!=engagement
    ) or any(packet[k] is not False for k in FLAGS):
        raise ValueError("HOLD: HUMAN packet does not match exact original source, context or authority flags.")
    for field in ("casework","evidence_review"):
        v=packet[field]
        if v is not None and (type(v) is not list or len(v)!=count):
            raise ValueError("HOLD: incomplete private original HUMAN records.")
    att=packet["attachments"]
    if type(att) is not list or len(att)>120:
        raise ValueError("HOLD: malformed PRIVATE attachment inventory.")
    if version==2 and (type(packet["human_requests"]) is not list or len(packet["human_requests"])>200):
        raise ValueError("HOLD: invalid original HUMAN request list.")
    if type(packet.get("warning")) is not str:
        raise ValueError("HOLD: missing PRIVATE original workspace warning.")
    return packet


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(value: str, limit: int) -> bytes:
    if type(value) is not str or len(value)>limit*2:
        raise ValueError("Invalid PRIVATE encoded payload.")
    raw=base64.b64decode(value,validate=True)
    if len(raw)>limit or _b64(raw)!=value:
        raise ValueError("PRIVATE encoded bytes are invalid or noncanonical.")
    return raw


def _make_workspace(csv_raw: bytes, human_raw: bytes, client: str, engagement: str) -> bytes:
    bridge._text_label(client,"client")
    bridge._text_label(engagement,"engagement")
    sha,count=bridge.original._strict_summary(csv_raw.decode("utf-8","strict"))
    digest,num=_native_digest(csv_raw)
    if count!=num:
        raise ValueError("Original source row identity inconsistent.")
    _packet(human_raw,source_digest=digest,count=count,client=client,engagement=engagement)
    obj={
        "kind":KIND,"schema_version":1,"disposition":"PRIVATE_HUMAN_REVIEW_ONLY",
        "source_contract":"lightup.finding_export._COLUMNS_v1",
        "client_reference":client,"engagement_reference":engagement,
        "original_csv_sha256":sha,"original_finding_count":count,
        "original_csv_base64":_b64(csv_raw),"original_source_digest":digest,
        "workspace_bytes":len(human_raw),"workspace_sha256":hashlib.sha256(human_raw).hexdigest(),
        "workspace_base64":_b64(human_raw),
        "warning":"Original source reported claims and HUMAN-only draft notes; NOT consent, grants, verified remediation, scanning authority or release.",
        **{flag:False for flag in FLAGS}
    }
    result=_canonical(obj)
    if len(result)>MAX_BOX:
        raise ValueError("PRIVATE HUMAN encrypted container exceeds original vault bounds.")
    return result


def _admit_workspace(raw: bytes) -> tuple[dict,bytes,bytes]:
    obj=_json(raw,MAX_BOX)
    if set(obj)!=FIELDS or _canonical(obj)!=raw or (
        obj.get("kind")!=KIND or type(obj.get("schema_version")) is not int or obj["schema_version"]!=1
    ) or obj.get("disposition")!="PRIVATE_HUMAN_REVIEW_ONLY" or (
        obj.get("source_contract")!="lightup.finding_export._COLUMNS_v1"
    ) or any(obj[flag] is not False for flag in FLAGS):
        raise ValueError("Noncanonical or authorizing PRIVATE HUMAN container.")
    bridge._text_label(obj.get("client_reference"),"client")
    bridge._text_label(obj.get("engagement_reference"),"engagement")
    original=_unb64(obj["original_csv_base64"],bridge.original.MAX_CSV_BYTES)
    human=_unb64(obj["workspace_base64"],LIMIT)
    if (type(obj["workspace_bytes"]) is not int or obj["workspace_bytes"]!=len(human) or
            obj["workspace_sha256"]!=hashlib.sha256(human).hexdigest()):
        raise ValueError("PRIVATE HUMAN workspace byte identity changed.")
    digest,count=_native_digest(original)
    sha,n=bridge.original._strict_summary(original.decode("utf-8","strict"))
    if (digest!=obj["original_source_digest"] or sha!=obj["original_csv_sha256"] or
            count!=n or type(obj["original_finding_count"]) is not int or
            count!=obj["original_finding_count"] or type(obj.get("warning")) is not str):
        raise ValueError("Original source identity HOLD.")
    _packet(human,source_digest=digest,count=count,
            client=obj["client_reference"],engagement=obj["engagement_reference"])
    return obj,original,human


def _restore_html(csv_raw: bytes, human_raw: bytes, client: str, engagement: str) -> bytes:
    page=bridge._render(csv_raw,client,engagement).decode("utf-8","strict")
    encoded=_b64(human_raw)
    js="""(function(){
"use strict";
const input=document.getElementById("unifiedImport");
const preview=document.getElementById("unifiedPreviewButton");
const host=document.querySelector("main.shell");
if(!input||!preview||!host||typeof File==="undefined"||typeof DataTransfer==="undefined"){
  const notice=document.getElementById("notice");
  if(notice)notice.textContent="HUMAN HOLD: original workspace handoff is unavailable in this browser.";
  return;
}
const area=document.createElement("section");area.className="card";
const heading=document.createElement("h2");heading.textContent="PRIVATE HUMAN handoff: manually review before restoring";
const info=document.createElement("p");
info.textContent="Encrypted source and human workplan were opened by a local operator. No note has been restored. Wait for exact original source to load, then manually preview. The original app requires a separate explicit apply confirmation; source labels are NOT security verdicts, consent or grants.";
const button=document.createElement("button");button.type="button";button.textContent="Preview encrypted HUMAN workspace (no changes)";
button.addEventListener("click",()=>{
  if(input.disabled){const note=document.getElementById("notice");if(note)note.textContent="Wait for original source import before reviewing HUMAN notes.";return;}
  try{
    const decoded=atob(__PACKET__);
    const bytes=Uint8Array.from(decoded,c=>c.charCodeAt(0));
    const items=new DataTransfer();
    items.items.add(new File([bytes],"PRIVATE-original-human-workspace.json",{type:"application/json"}));
    input.files=items.files;
    preview.click(); // invokes original source-bound preview only; NEVER calls applyUnified
  }catch(_error){
    const notice=document.getElementById("notice");
    if(notice)notice.textContent="HUMAN HOLD: original workspace could not be previewed.";
  }
});
area.append(heading,info,button);host.insertBefore(area,host.firstChild);
})();""".replace("__PACKET__",json.dumps(encoded))
    code=js.encode("utf-8")
    if "</script" in js.lower() or "<!--" in js:
        raise ValueError("Unsafe private workspace bootstrap script.")
    token="'sha256-"+_b64(hashlib.sha256(code).digest())+"'"
    page,changes=re.subn(r"(script-src [^;]+)(; style-src )",
                        lambda m:m.group(1)+" "+token+m.group(2),page)
    if changes!=1 or "</body>" not in page:
        raise ValueError("Original offline CSP changed.")
    before,closing,after=page.rpartition("</body>")
    result=(before+"<script>"+js+"</script>"+closing+after).encode("utf-8")
    if len(result)>4*1024*1024:
        raise ValueError("Private HUMAN offline HTML exceeds limit.")
    if b"connect-src 'none'" not in result:
        raise ValueError("Original no-network policy missing.")
    return result


def main(argv: list[str] | None=None) -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    commands=ap.add_subparsers(dest="action",required=True)
    for action in ("seal","open","open-current","inspect","rotate"):
        p=commands.add_parser(action)
        p.add_argument("--source",type=Path,help="Source authenticated Evidence Ledger .ltv for seal")
        p.add_argument("--workspace",type=Path,help="Private existing unified-human workspace JSON for seal")
        p.add_argument("--input",type=Path,help="Private combined human encrypted .ltv for open/inspect/rotate")
        p.add_argument("--output",type=Path,help="New owner-private .ltv or .html")
        if action in ("open","open-current"):
            p.add_argument("--ack-private-html",action="store_true")
        if action in ("seal","open-current"):
            for k in ("db","email","client-id","engagement-id"):
                p.add_argument("--"+k,required=True)
    opts=ap.parse_args(argv)
    try:
        vault=bridge.original._vault()
        if opts.action=="seal":
            if not opts.source or not opts.workspace or not opts.output or opts.output.suffix!=".ltv":
                raise ValueError("Exact encrypted source, private HUMAN JSON and NEW .ltv required.")
            # Authenticated current source BEFORE reading/sending any human artifact.
            csv_current=bridge.original._authorized_summary(db=opts.db,email=opts.email,
                client_id=opts.client_id,engagement_id=opts.engagement_id)
            current_sha,current_count=bridge.original._strict_summary(csv_current)
            saved=vault._private_input(opts.source.expanduser().absolute(),vault.MAX_VAULT)
            secret=vault._password("Original PRIVATE source vault passphrase: ",fresh=False)
            source,mime,_=vault._open(saved,secret)
            if mime!="application/json":
                raise ValueError("Invalid source vault MIME.")
            manifest,_rendered=bridge._read_envelope(source)
            if (manifest["client_reference"]!=opts.client_id or
                    manifest["engagement_reference"]!=opts.engagement_id or
                    manifest["original_csv_sha256"]!=current_sha or
                    manifest["original_finding_count"]!=current_count):
                raise ValueError("Current original authenticated source does not match selected source vault.")
            csv_raw=base64.b64decode(manifest["source_csv_base64"],validate=True)
            human=vault._private_input(opts.workspace.expanduser().absolute(),LIMIT)
            packed=_make_workspace(csv_raw,human,opts.client_id,opts.engagement_id)
            new_secret=vault._password("New PRIVATE HUMAN collaboration passphrase: ",fresh=True)
            vault._exclusive_output(opts.output.expanduser().absolute(),
                vault._seal(vault._inner(packed,"application/json"),new_secret))
            print("Created a NEW private encrypted original-source-bound HUMAN workspace. No plaintext intermediate.")
            return 0
        if not opts.input or opts.input.suffix!=".ltv":
            raise ValueError("PRIVATE source-bound HUMAN .ltv input required.")
        if opts.action!="inspect":
            ext=".ltv" if opts.action=="rotate" else ".html"
            if not opts.output or opts.output.suffix!=ext or opts.output.expanduser().absolute()==opts.input.expanduser().absolute():
                raise ValueError("New non-overwriting private output path with correct extension required.")
        if opts.action in ("open","open-current") and not opts.ack_private_html:
            raise ValueError("Opening plaintext HUMAN review requires --ack-private-html.")
        current=None
        if opts.action=="open-current":
            csv_current=bridge.original._authorized_summary(db=opts.db,email=opts.email,
                client_id=opts.client_id,engagement_id=opts.engagement_id)
            current=bridge.original._strict_summary(csv_current)
        ciphertext=vault._private_input(opts.input.expanduser().absolute(),vault.MAX_VAULT)
        secret=vault._password("Existing PRIVATE HUMAN collaboration passphrase: ",fresh=False)
        raw,mime,inner=vault._open(ciphertext,secret)
        if mime!="application/json":
            raise ValueError("Unexpected encrypted HUMAN workspace.")
        manifest,csv_raw,human=_admit_workspace(raw)
        if opts.action=="inspect":
            print("Original private source findings:",manifest["original_finding_count"])
            print("Private HUMAN collaboration packet present. No source or human identities displayed.")
            return 0
        if opts.action=="open-current" and (
                manifest["client_reference"]!=opts.client_id or
                manifest["engagement_reference"]!=opts.engagement_id or
                (manifest["original_csv_sha256"],manifest["original_finding_count"])!=current):
            raise ValueError("Fresh authenticated source differs: HUMAN HOLD.")
        if opts.action=="rotate":
            replacement=vault._password("New replacement PRIVATE HUMAN passphrase: ",fresh=True)
            if replacement==secret: raise ValueError("Replacement passphrase must be different.")
            vault._exclusive_output(opts.output.expanduser().absolute(),vault._seal(inner,replacement))
            print("PRIVATE HUMAN source-bound collaboration rotated. Original preserved.")
            return 0
        html=_restore_html(csv_raw,human,manifest["client_reference"],manifest["engagement_reference"])
        vault._exclusive_output(opts.output.expanduser().absolute(),html)
        print("New 0600 OFFLINE PRIVATE HUMAN workroom created; workspace NOT applied.")
        print("Click 'Preview encrypted HUMAN workspace' then separately confirm original app Apply.")
        return 0
    except Exception:
        print("HOLD: PRIVATE HUMAN collaboration unavailable; no new output produced.",file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
