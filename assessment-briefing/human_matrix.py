#!/usr/bin/env python3
"""PRIVATE numeric severity × HUMAN follow-up attention matrix.

Consumes already-produced original lab results and an independently human-filled
original worksheet. Does not verify findings, grant permission or contact targets.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import sys

from briefing import CSS, DENIAL_FLAGS, Hold, SEVERITIES, h, json_bytes, open_source, publish_new
from human_return import (MAX_CSV_BYTES, MAX_MANIFEST_BYTES, read_human_csv,
                          read_limited_file, source_manifest)

STAGES = ("needs_review", "discussing", "blocked", "documented")


def matrix(source: dict, notes: list[dict]) -> dict:
    grid = {s: {state: 0 for state in STAGES} for s in SEVERITIES}
    severity_followup = {s: {
        "source_reported": 0,
        "human_missing_group": 0,
        "human_missing_action": 0,
        "human_blocker_present": 0,
        "human_action_proposed": 0,
        "human_documented": 0,
        "source_evidence_reference_present": 0,
    } for s in SEVERITIES}
    for f, n in zip(source["findings"], notes):
        severity=f["severity"]
        grid[severity][n["stage"]]+=1
        bucket=severity_followup[severity]
        bucket["source_reported"]+=1
        bucket["human_missing_group"]+=int(not bool(n["owner"].strip()))
        bucket["human_missing_action"]+=int(not bool(n["action"].strip()))
        bucket["human_blocker_present"]+=int(bool(n["blocker"].strip()))
        bucket["human_action_proposed"]+=int(bool(n["action"].strip()))
        bucket["human_documented"]+=int(n["stage"]=="documented")
        bucket["source_evidence_reference_present"]+=int(bool(f["evidence_ids"]))
    return {"schema": "lightup.private_lab_human_attention_matrix.v1",
            "status": "REVIEW_ONLY",
            "original_declaration_count": len(source["findings"]),
            "original_declared_endpoint_count": len(source["targets"]),
            "human_stage_by_source_severity": grid,
            "human_self_reported_followup_by_source_severity": severity_followup,
            "source_authenticated": False, "finding_validity_verified": False,
            "human_identity_authenticated": False, "human_progress_verified": False,
            "client_consent_verified": False, "operator_consent_verified": False,
            **DENIAL_FLAGS}


def private_human_queue(source: dict, notes: list[dict]) -> str:
    # No source identifiers, target strings, names, notes, evidence or hashes.
    # Rows preserve original ordinals so a human can look up the original
    # protected source separately.
    buf=io.StringIO(newline="")
    writer=csv.writer(buf,lineterminator="\r\n")
    writer.writerow((
        "original_ordinal","source_reported_severity","source_evidence_reference_count",
        "human_self_reported_stage","human_group_missing","human_action_missing",
        "human_blocker_present","human_action_present",
    ))
    order={sev:i for i,sev in enumerate(SEVERITIES)}
    ranking=[]
    for ordinal,(f,n) in enumerate(zip(source["findings"],notes),1):
        blocked=n["stage"]=="blocked" or bool(n["blocker"].strip())
        missing_group=not bool(n["owner"].strip())
        missing_action=not bool(n["action"].strip())
        values=(ordinal,f["severity"],len(f["evidence_ids"]),n["stage"],
                missing_group,missing_action,blocked,not missing_action)
        # This is a review sorting convenience; NOT a risk, SLA, target
        # verification, tested finding or authorization priority.
        ranking.append((order[f["severity"]],not blocked,
                        n["stage"]=="documented",ordinal,values))
    ranking.sort()
    for _,_,_,_,record in ranking:
        ordinal,sev,refs,stage,group_missing,action_missing,blocked,action_present=record
        writer.writerow((ordinal,sev,refs,stage,int(group_missing),
                         int(action_missing),int(blocked),int(action_present)))
    return buf.getvalue()


def render_matrix(data: dict, source_sha: str) -> str:
    grid=data["human_stage_by_source_severity"]
    followup=data["human_self_reported_followup_by_source_severity"]
    header=("Source-reported severity",)+STAGES+(
        "Source-declared total","HUMAN group missing","HUMAN action missing",
        "HUMAN blocker present","Original evidence-reference present")
    headrow="<tr>"+ "".join("<th>" + h(col.replace("_"," ")) + "</th>" for col in header)+"</tr>"
    rows=[]
    for sev in SEVERITIES:
        f=followup[sev]
        nums=[grid[sev][stage] for stage in STAGES]+[
            f["source_reported"],f["human_missing_group"],f["human_missing_action"],
            f["human_blocker_present"],f["source_evidence_reference_present"]
        ]
        rows.append("<tr><th>"+h(sev.upper())+"</th>"+
                    "".join("<td>"+str(n)+"</td>" for n in nums)+"</tr>")
    prefix=(
        "<header><h1>LightUp · PRIVATE HUMAN attention matrix</h1>" +
        "<p class='notice'>REVIEW ONLY — all vulnerabilities, severity and evidence " +
        "presence are source-reported, not independently validated. HUMAN stages, " +
        "actions, blockers and groups are private self-reported proposals. " +
        "This is NOT remediation, current consent, a grant, release or execution.</p>" +
        "<p><strong>Original source SHA-256 (UNSIGNED):</strong> <code>"+
        source_sha+"</code></p>" +
        "<p>Declared original findings: "+str(data["original_declaration_count"])+
        " · Declared endpoints: "+str(data["original_declared_endpoint_count"])+
        "</p><p>This PRIVATE aggregate table contains no original target strings, " +
        "finding titles, evidence or HUMAN notes. Small aggregates can still be " +
        "confidential. All sorting is for HUMAN attention, not verified risk.</p></header>")
    table=("<section class='card'><h2>HUMAN stage × declared severity</h2>" +
           "<div class='scroll-table'><table><thead>"+headrow+"</thead><tbody>"+
           "".join(rows)+"</tbody></table></div></section>")
    guidance=("<section class='card'><h2>HUMAN questions to resolve separately</h2>" +
              "<ol><li>Confirm original producer, context and engagement with actual " +
              "separate authenticated client/operator actors.</li>" +
              "<li>Independently examine original source evidence before suggesting " +
              "real exposure, mitigation or retest conclusions.</li>" +
              "<li>Ask a human for the owner/group, action and uncertainty behind " +
              "the current self-reported stages.</li>" +
              "<li>Use the accompanying ordinal-only PRIVATE CSV to coordinate " +
              "follow-up without exporting target/notes.</li></ol></section>")
    pin=base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode()
    csp=("default-src 'none'; style-src 'sha256-"+pin+
         "'; script-src 'none'; img-src 'none'; connect-src 'none'; " +
         "base-uri 'none'; form-action 'none'; object-src 'none'")
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>" +
            "<meta http-equiv='Content-Security-Policy' content=\""+h(csp)+"\">" +
            "<meta name='viewport' content='width=device-width,initial-scale=1'>" +
            "<title>PRIVATE HUMAN attention matrix</title><style>"+CSS+
            "</style></head><body>"+prefix+table+guidance+"</body></html>\n")


def create(source_path: str, manifest_path: str,
           worksheet_path: str, output_dir: str) -> None:
    source, _, fingerprint=open_source(source_path)
    source_manifest(read_limited_file(manifest_path,MAX_MANIFEST_BYTES),
                    fingerprint,source)
    notes=read_human_csv(read_limited_file(worksheet_path,MAX_CSV_BYTES),source)
    data=matrix(source,notes)
    html=render_matrix(data,fingerprint).encode("utf-8")
    table=private_human_queue(source,notes).encode("utf-8")
    manifest={"schema":"lightup.private_human_attention_manifest.v1",
              "status":"REVIEW_ONLY",
              "original_source_sha256_unsigned":fingerprint,
              "private_html_sha256_unsigned":hashlib.sha256(html).hexdigest(),
              "private_ordinal_queue_sha256_unsigned":hashlib.sha256(table).hexdigest(),
              "source_authenticated":False,"human_progress_verified":False,
              "client_consent_verified":False,"operator_consent_verified":False,
              **DENIAL_FLAGS}
    publish_new(output_dir,{"private-human-matrix.html":html,
                            "private-human-matrix.json":json_bytes(data),
                            "private-ordinal-followup.csv":table,
                            "manifest.json":json_bytes(manifest)})


def main() -> int:
    p=argparse.ArgumentParser(
        description="PRIVATE human severity and follow-up matrix: NO scans/authority")
    p.add_argument("--source",required=True,help="existing PRIVATE original lab result JSON")
    p.add_argument("--manifest",required=True,help="original PRIVATE briefing manifest")
    p.add_argument("--worksheet",required=True,help="original-format HUMAN review CSV")
    p.add_argument("--output-dir",required=True,help="NEW PRIVATE output directory")
    a=p.parse_args()
    try:
        create(a.source,a.manifest,a.worksheet,a.output_dir)
    except Hold as exc:
        print(str(exc),file=sys.stderr)
        return 3
    print("PRIVATE HUMAN severity/attention matrix created; REVIEW ONLY")
    return 2


if __name__=="__main__":
    raise SystemExit(main())
