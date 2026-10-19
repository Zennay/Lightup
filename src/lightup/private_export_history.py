"""Private offline history of separately encrypted HUMAN remediation plans.

This is a local, non-authorizing HUMAN coordination product. It authenticates
the exact original encrypted ZIP, then decrypts and admits every source-bound
encrypted HUMAN plan in memory. It never edits DomainStore or original files,
retests a target, claims a fix, or authenticates a self-declared owner.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import date, datetime, timezone
from html import escape
import json
from pathlib import Path
import sys
from typing import Any

from .private_export_encrypted import _passphrase, _read_encrypted
from .private_export_encrypted_notes import _read_plan
from .private_export_handoff import _atomic_private_publish, _output_path
from .private_export_workdesk import STAGES

MAX_SNAPSHOTS = 12
PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
FIELDS = ("stage", "owner_alias", "due_date", "human_note")
WATCH_STAGES = {"blocked", "waiting_on_owner", "awaiting_evidence"}
KIND = "lightup.private_human_plan_history"


def _as_of(value: str | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).date().isoformat()
    if type(value) is not str or len(value) != 10 or (
        date.fromisoformat(value).isoformat() != value
    ):
        raise ValueError("expected exact YYYY-MM-DD as-of UTC date")
    return value


def _read_history(source: str, plan_paths: list[str]) -> tuple[dict, list[dict], list[dict]]:
    if not 1 <= len(plan_paths) <= MAX_SNAPSHOTS:
        raise ValueError("one to twelve encrypted HUMAN plan revisions required")
    if len({str(Path(p).resolve()) for p in plan_paths}) != len(plan_paths):
        raise ValueError("duplicate HUMAN workplan snapshot path")
    secret = _passphrase("Original encrypted findings source passphrase")
    manifest, source_rows, _ = _read_encrypted(source, secret)
    del secret
    plans: list[dict] = []
    for index, path in enumerate(plan_paths, 1):
        print("Decrypting private HUMAN snapshot " + str(index) + "/" +
              str(len(plan_paths)) + " (chronology is operator-supplied).")
        passphrase = _passphrase("Snapshot " + str(index) + " encrypted HUMAN plan passphrase")
        admitted, _ = _read_plan(path, passphrase, manifest, source_rows)
        del passphrase
        plans.append(admitted)
    return manifest, source_rows, plans


def _priorities(rows: list[dict], plan: dict, as_of: str) -> list[dict]:
    queue = []
    for row in rows:
        source_id = row["finding_id"]
        state = plan[source_id]
        due = state["due_date"]
        overdue = bool(due and due < as_of)
        watch = state["stage"] in WATCH_STAGES
        high_priority = row["severity"] in ("critical", "high")
        if not overdue and not watch and not high_priority:
            continue
        queue.append({
            "finding_id": source_id,
            "title": row["title"],
            "severity": row["severity"],
            "human_stage": state["stage"],
            "owner_alias": state["owner_alias"],
            "proposed_due_date": due,
            "overdue_human_followup": overdue,
            "source_retest_label": row["retest_status"],
        })
    queue.sort(key=lambda item: (
        not item["overdue_human_followup"],
        PRIORITY.get(item["severity"], 99),
        item["human_stage"] not in WATCH_STAGES,
        item["proposed_due_date"] or "9999-12-31",
        item["finding_id"]
    ))
    return queue


def _summarize(manifest: dict, rows: list[dict], plans: list[dict],
               as_of: str) -> dict[str, Any]:
    if not plans:
        raise ValueError("at least one original plan required")
    source_ids = [row["finding_id"] for row in rows]
    severity = {row["finding_id"]: row["severity"] for row in rows}
    snapshots = []
    revisions = []
    for plan in plans:
        statuses = Counter(plan[key]["stage"] for key in source_ids)
        owners = {plan[key]["owner_alias"] for key in source_ids
                  if plan[key]["owner_alias"]}
        overdue = sum(bool(plan[key]["due_date"] and
                           plan[key]["due_date"] < as_of) for key in source_ids)
        high_attention = sum(
            severity[key] in ("critical", "high") and
            plan[key]["stage"] in WATCH_STAGES for key in source_ids
        )
        snapshots.append({
            "index": len(snapshots) + 1,
            "source_records": len(source_ids),
            "human_owner_alias_count": len(owners),
            "proposed_followups_overdue_at_as_of_utc": overdue,
            "high_or_critical_human_attention": high_attention,
            "human_stages": {stage: statuses[stage] for stage in STAGES}
        })
    for i in range(1, len(plans)):
        earlier, later = plans[i - 1], plans[i]
        changed_fields = Counter()
        changes = 0
        stage_edges = Counter()
        critical_attention_added = 0
        critical_attention_left = 0
        for source_id in source_ids:
            old, new = earlier[source_id], later[source_id]
            modified = [field for field in FIELDS if old[field] != new[field]]
            if modified:
                changes += 1
                changed_fields.update(modified)
            if old["stage"] != new["stage"]:
                stage_edges[(old["stage"], new["stage"])] += 1
            if severity[source_id] in ("critical", "high"):
                before, after = old["stage"] in WATCH_STAGES, new["stage"] in WATCH_STAGES
                if not before and after:
                    critical_attention_added += 1
                elif before and not after:
                    critical_attention_left += 1
        revisions.append({
            "from_snapshot": i,
            "to_snapshot": i + 1,
            "original_findings_with_changed_human_fields": changes,
            "human_field_change_counts": {field: changed_fields[field] for field in FIELDS},
            "high_critical_entered_attention_stages": critical_attention_added,
            "high_critical_left_attention_stages": critical_attention_left,
            "human_stage_transitions": [
                {"from": a, "to": b, "original_finding_count": amount}
                for (a, b), amount in sorted(stage_edges.items())
            ],
        })
    attention = _priorities(rows, plans[-1], as_of)
    attention_counts = Counter((item["severity"], item["human_stage"]) for item in attention)
    return {
        "kind": KIND,
        "version": 1,
        "source_record_count": len(source_ids),
        "operator_declared_snapshot_order": True,
        "source_has_changed": False,
        "as_of_date_utc": as_of,
        "authorizes_action": False,
        "certifies_remediation": False,
        "confirms_owner_or_client_identity": False,
        "snapshots": snapshots,
        "revisions": revisions,
        "latest_attention": {
            "original_findings_requiring_human_review": len(attention),
            "high_critical_human_attention": sum(item["severity"] in ("critical", "high")
                for item in attention),
            "source_severity_and_human_state": [
                {"severity": sev, "human_stage": stage, "count": count}
                for (sev, stage), count in sorted(
                    attention_counts.items(), key=lambda x: (PRIORITY.get(x[0][0], 99), x[0][1]))
            ],
        },
    }


def _html(model: dict, actions: list[dict], private_actions: bool) -> bytes:
    def td(*values: str) -> str:
        return "<tr>" + "".join("<td>" + escape(str(v)) + "</td>" for v in values) + "</tr>"
    snapshot_rows = "".join(
        td("Snapshot " + str(s["index"]), s["source_records"],
           s["human_owner_alias_count"], s["proposed_followups_overdue_at_as_of_utc"],
           s["high_or_critical_human_attention"],
           ", ".join(stage.replace("_", " ") + ": " + str(s["human_stages"][stage])
                     for stage in STAGES))
        for s in model["snapshots"]
    )
    revision_rows = "".join(
        td(str(rev["from_snapshot"]) + " → " + str(rev["to_snapshot"]),
           rev["original_findings_with_changed_human_fields"],
           rev["human_field_change_counts"]["stage"],
           rev["human_field_change_counts"]["owner_alias"],
           rev["human_field_change_counts"]["due_date"],
           rev["human_field_change_counts"]["human_note"],
           rev["high_critical_entered_attention_stages"],
           rev["high_critical_left_attention_stages"])
        for rev in model["revisions"]
    )
    latest_attention = "".join(td(
        entry["severity"], entry["human_stage"].replace("_", " "), entry["count"]
    ) for entry in model["latest_attention"]["source_severity_and_human_state"])
    private_html = ""
    if private_actions:
        private_html = (
            "<section><h2>Explicit PRIVATE latest HUMAN attention queue</h2>"
            "<p>Unencrypted original IDs, titles and owner aliases below require "
            "a separately verified local human recipient. No raw remedy, "
            "evidence or HUMAN note text is included.</p><div class=scroll><table>"
            "<thead><tr><th>Source ID</th><th>Original title</th><th>Source severity</th>"
            "<th>Human stage</th><th>Self-declared owner</th>"
            "<th>Proposed follow-up</th><th>Human follow-up overdue?</th></tr></thead>"
            "<tbody>" +
            "".join(td(item["finding_id"], item["title"], item["severity"],
                       item["human_stage"].replace("_", " "), item["owner_alias"],
                       item["proposed_due_date"] or "not scheduled",
                       "YES" if item["overdue_human_followup"] else "no")
                    for item in actions) +
            "</tbody></table></div></section>"
        )
    html = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;;'
        ' style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">'
        '<title>LightUp PRIVATE HUMAN plan history</title>'
        '<style>:root{font:16px system-ui,sans-serif;color:#14253c;background:#f5f7fc}'
        '*{box-sizing:border-box}body{max-width:1120px;margin:4vh auto;padding:20px;line-height:1.5}'
        'h1{font-size:clamp(25px,4vw,38px);margin:0 0 10px}'
        'section{padding:16px 20px;background:white;border:1px solid #d6dfec;border-radius:12px;margin:18px 0}'
        '.warning{border-left:6px solid #ae6d0c;background:#fff3d8}'
        '.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:670px}'
        'th,td{padding:10px 12px;border-bottom:1px solid #dbe2eb;text-align:left;vertical-align:top}'
        'th{background:#e9eef7}.metric{font-weight:700;font-size:23px}'
        '@media print{body{margin:0}.scroll{overflow:visible}section{break-inside:avoid}}'
        '</style></head><body>'
        '<h1>LightUp · PRIVATE HUMAN plan history</h1>'
        '<p>Offline local review of ' + str(len(model["snapshots"])) +
        ' individually decrypted exact-source HUMAN snapshots.</p>'
        '<section class=warning><strong>HUMAN HOLD · No verified remediation.</strong> '
        'The encrypted original source and workplans have been checked for byte and '
        'schema binding; this does NOT authenticate actual recipients, owner aliases, '
        'client identity, consent or fix completion. The order of snapshots is '
        'operator-supplied; timestamps of HUMAN state were not certified. '
        'Every changed field is an unverified coordination change only. '
        'The resulting HTML is PRIVATE and UNENCRYPTED. A small cohort may identify '
        'a client even without IDs. Separate human privacy and recipient review is required.'
        '</section>'
        '<section><h2>Source-bound overview</h2>'
        '<p><span class=metric>' + str(model["source_record_count"]) + '</span> original source records · '
        'Human follow-up as-of UTC <strong>' + escape(model["as_of_date_utc"]) + '</strong>.</p>'
        '<p>“Overdue” compares human-proposed follow-up dates, not technical fix deadlines.</p></section>'
        '<section><h2>HUMAN workplan snapshots</h2><div class=scroll><table>'
        '<thead><tr><th>Operator sequence</th><th>Original records</th><th>Self-declared owner aliases</th>'
        '<th>Proposed follow-ups overdue</th><th>High/critical HUMAN attention</th>'
        '<th>HUMAN stages</th></tr></thead><tbody>' + snapshot_rows +
        '</tbody></table></div></section>'
        '<section><h2>Changes between HUMAN snapshots</h2><div class=scroll><table>'
        '<thead><tr><th>Sequence</th><th>Records with HUMAN changes</th><th>Stage changed</th>'
        '<th>Owner changed</th><th>Due date changed</th><th>Note changed</th>'
        '<th>High/critical entered attention</th><th>Left attention (not fixed)</th></tr></thead>'
        '<tbody>' + revision_rows + '</tbody></table></div></section>'
        '<section><h2>Latest HUMAN attention queue — anonymous counts</h2>'
        '<p><span class=metric>' +
        str(model["latest_attention"]["original_findings_requiring_human_review"]) +
        '</span> original records identified for operator follow-up. '
        'This includes high/critical source claims, HUMAN blocked/waiting stages or overdue '
        'proposed follow-up. It does not reflect a verified security outcome.</p>'
        '<div class=scroll><table><thead><tr><th>Source severity</th>'
        '<th>Latest HUMAN stage</th><th>Records</th></tr></thead>'
        '<tbody>' + latest_attention + '</tbody></table></div></section>' +
        private_html +
        '<p>No scans, remediation actions, grants, retests, Original DomainStore mutations, '
        'background jobs or transport were performed.</p></body></html>'
    )
    return html.encode("utf-8", "strict")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="LightUp PRIVATE encrypted HUMAN workplan timeline; no security verdict"
    )
    parser.add_argument("source", help="original immutable encrypted findings .lue")
    parser.add_argument("plans", nargs="+", help="chronologically operator-ordered encrypted HUMAN .lun")
    parser.add_argument("--output", required=True, help="new private local .html or aggregate .json")
    parser.add_argument("--format", choices=("html", "json"), default="html")
    parser.add_argument("--as-of", help="UTC date YYYY-MM-DD for HUMAN proposed follow-up aging")
    parser.add_argument("--include-private-actions", action="store_true",
                        help="include original IDs, titles and owner aliases in HTML")
    parser.add_argument("--ack-private-original-data", action="store_true")
    parser.add_argument("--ack-plaintext-destination", action="store_true")
    parser.add_argument("--ack-private-attention-ids", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not args.ack_private_original_data or not args.ack_plaintext_destination:
            raise ValueError("private data and unencrypted file acknowledgment required")
        if args.include_private_actions and not args.ack_private_attention_ids:
            raise ValueError("explicit original IDs + owner aliases acknowledgment required")
        if args.include_private_actions and args.format != "html":
            raise ValueError("private ID queue supported only in explicit HTML view")
        output = _output_path(args.output, ".html" if args.format == "html" else ".json")
        as_of = _as_of(args.as_of)
        manifest, source_rows, plans = _read_history(args.source, args.plans)
        summary = _summarize(manifest, source_rows, plans, as_of)
        if args.format == "json":
            content = (json.dumps(summary, ensure_ascii=False, sort_keys=True,
                                  indent=2) + "\n").encode("utf-8")
        else:
            queue = _priorities(source_rows, plans[-1], as_of)
            content = _html(summary, queue, args.include_private_actions)
        _atomic_private_publish(output, content)
        print("PRIVATE non-authorizing exact-source HUMAN history created locally.")
        print("Snapshot count:", len(plans), "· original records:", len(source_rows))
        print("No original source, plan, grant, findings, owner or retest state was changed.")
        return 0
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt):
        print("HUMAN HOLD: source, private workplans, passphrases, chronology or output invalid.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
