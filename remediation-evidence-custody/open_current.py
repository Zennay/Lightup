#!/usr/bin/env python3
"""One-command original-authenticated PRIVATE local custody review, HUMAN-only.

Authenticates the exact current original LightUp tenant/engagement read, then
opens an existing separately encrypted original HUMAN .ltv in memory. No
original owner file, database, client authority, scanner or grant is modified.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "remediation-evidence-bridge"))

import build
import workspace as original_human
import merge as original_admission

source_owner = original_human.bridge.original
MAX_OUTPUT = 5 * 1024 * 1024
FLAGS = original_human.FLAGS

def _current_rows(raw: bytes) -> set[str]:
    source_owner._strict_summary(raw.decode("utf-8", "strict"))
    lines = csv.DictReader(io.StringIO(raw.decode("utf-8", "strict"), newline=""), strict=True)
    if tuple(lines.fieldnames or ()) != tuple(source_owner.COLUMNS):
        raise ValueError("Original source columns changed.")
    ids = set()
    for record in lines:
        if set(record) != set(source_owner.COLUMNS):
            raise ValueError("Invalid original finding row.")
        fid = record["finding_id"]
        if not fid or fid in ids:
            raise ValueError("Duplicate original finding identity.")
        ids.add(fid)
    return ids

def _render(csv_raw: bytes, human_packet: dict) -> bytes:
    """Make a single owner-only HTML, including only source + indexed HUMAN files."""
    original = build.build()
    if original != (HERE / "standalone.html").read_bytes():
        raise ValueError("PRIVATE app source and standalone build differ.")
    original_hash = hashlib.sha256(original).hexdigest()
    if len(original) > 512 * 1024:
        raise ValueError("Original standalone source is unexpectedly large.")
    current_digest, count = original_human._native_digest(csv_raw)
    if human_packet["source_sha256"] != current_digest or human_packet["source_count"] != count:
        raise ValueError("HUMAN source changed before private HTML rendering.")
    view = {
        "kind": "lightup.private_artifact_ledger",
        "schema_version": 1,
        "disposition": "PRIVATE_HUMAN_EVIDENCE_INDEX_ONLY",
        "source_contract": "lightup.finding_export._COLUMNS_v1",
        "source_sha256": current_digest,
        "source_count": count,
        "client_reference": human_packet["client_reference"],
        "engagement_reference": human_packet["engagement_reference"],
        "attachments": human_packet["attachments"],
        "warning": "PRIVATE local human file comparisons. Original authenticated READ at build-time only; no client consent, grants, verified remediation, retest or current authorization.",
        **{flag: False for flag in FLAGS},
    }
    # Bootstrap text contains only ASCII base64; HTML parser delimiters cannot
    # be injected by client-controlled original CSV or HUMAN file labels.
    human_b64 = base64.b64encode(json.dumps(view, ensure_ascii=True,
                        separators=(",", ":")).encode("ascii")).decode("ascii")
    csv_b64 = base64.b64encode(csv_raw).decode("ascii")
    bootstrap = r'''(async function(){
"use strict";
const message=document.getElementById("notice");
const hold=()=>{if(message){message.textContent="HUMAN HOLD: original private source preload unavailable. Use original protected source workflow.";message.className="alert";}};
try {
 if(typeof DataTransfer==="undefined"||typeof File==="undefined")throw Error("No private local File API.");
 const attach=(id,encoded,name,type)=>{
  const raw=atob(encoded),data=Uint8Array.from(raw,c=>c.charCodeAt(0));
  const picker=document.getElementById(id),transfer=new DataTransfer();
  if(!picker)throw Error("Original private input missing.");
  transfer.items.add(new File([data],name,{type}));picker.files=transfer.files;
 };
 const wait=async(id)=>{
  for(let i=0;i<160;i++){
   const button=document.getElementById(id);
   if(button&&!button.disabled)return;
   await new Promise(done=>setTimeout(done,25));
  }
  throw Error("Original private source admission unavailable.");
 };
 attach("manifest","__HUMAN__","original-private-human-custody.json","application/json");
 document.getElementById("import").click();
 await wait("verifySource");
 attach("sourceCSV","__CSV__","original-current-findings.csv","text/csv");
 document.getElementById("verifySource").click();
 await wait("run");
 if(message)message.textContent="Current source was originally read under actual LightUp account/engagement read permissions at PRIVATE file creation; original CSV and HUMAN references match. No action permission, consent, verified findings or current continuing authorization.";
} catch(_e) { hold(); }
})();'''
    bootstrap = bootstrap.replace("__HUMAN__", human_b64).replace("__CSV__", csv_b64)
    if "</script" in bootstrap.lower() or "<!--" in bootstrap:
        raise ValueError("Unsafe private bootstrap script.")
    code = bootstrap.encode("utf-8")
    pin = base64.b64encode(hashlib.sha256(code).digest()).decode("ascii")
    html = original.decode("utf-8", "strict")
    html, matches = re.subn(r"(script-src [^;]+)(; style-src )",
                            lambda m: m.group(1) + " 'sha256-" + pin + "'" + m.group(2),
                            html)
    if matches != 1 or html.count("</body>") != 1:
        raise ValueError("Offline CSP/body structure changed.")
    html = html.replace("</body>", "<script>" + bootstrap + "</script></body>")
    rendered = html.encode("utf-8", "strict")
    if not rendered.startswith(b"<!doctype html>") or len(rendered) > MAX_OUTPUT or (
        b"connect-src 'none'" not in rendered):
        raise ValueError("PRIVATE offline output policy/size changed.")
    return rendered

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("db", "email", "client-id", "engagement-id"):
        ap.add_argument("--" + name, required=True)
    ap.add_argument("--human", type=Path, required=True,
                    help="Existing original encrypted private HUMAN collaboration .ltv")
    ap.add_argument("--output", type=Path, required=True,
                    help="NEW owner-only 0600 .html in an existing 0700 private directory")
    ap.add_argument("--ack-private-html", action="store_true", required=True,
                    help="Acknowledge confidentiality of decrypted local HTML")
    args = ap.parse_args(argv)
    try:
        if not args.ack_private_html or args.human.suffix.lower() != ".ltv" or args.output.suffix.lower() != ".html":
            raise ValueError("Private HUMAN .ltv and acknowledged new HTML required.")
        if args.human.expanduser().absolute() == args.output.expanduser().absolute():
            raise ValueError("Never replace encrypted original HUMAN source.")
        if not sys.stdin.isatty():
            raise ValueError("Private interactive terminal required.")
        # Always obtain the EXACT currently allowed account and engagement read
        # through the unchanged original DomainStore-authorized exporter.
        current = source_owner._authorized_summary(db=args.db, email=args.email,
                     client_id=args.client_id, engagement_id=args.engagement_id)
        csv_raw = current.encode("utf-8", "strict")
        expected_sha, count = source_owner._strict_summary(current)
        vault = source_owner._vault()
        ciphertext = vault._private_input(args.human.expanduser().absolute(), vault.MAX_VAULT)
        key = vault._password("Existing PRIVATE HUMAN source passphrase: ", fresh=False)
        payload, mime, _inner = vault._open(ciphertext, key)
        if mime != "application/json":
            raise ValueError("Original encrypted HUMAN source type changed.")
        manifest, original_csv, human = original_human._admit_workspace(payload)
        if (original_csv != csv_raw or manifest["original_csv_sha256"] != expected_sha
            or manifest["original_finding_count"] != count
            or manifest["client_reference"] != args.client_id
            or manifest["engagement_reference"] != args.engagement_id):
            raise ValueError("Original private HUMAN source no longer matches current authorized client/engagement.")
        digest, canonical_count = original_human._native_digest(csv_raw)
        if canonical_count != count:
            raise ValueError("Original source membership discrepancy.")
        packet = original_human._packet(human, source_digest=digest, count=count,
                                       client=args.client_id, engagement=args.engagement_id)
        original_admission._records(packet, _current_rows(csv_raw))
        rendered = _render(csv_raw, packet)
        vault._exclusive_output(args.output.expanduser().absolute(), rendered)
        print("New 0600 PRIVATE offline custody HTML created from CURRENT original authorized read.")
        print("Opened human-only source is byte-identical to encrypted original; all local fingerprints and finding IDs admitted.")
        print("No scan, target contact, grant, client/operator consent, verified remediation or deployment.")
        return 0
    except Exception:
        print("HUMAN HOLD: No PRIVATE custody HTML published; check original authorized source, private .ltv, source binding and owner-only destination.", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
