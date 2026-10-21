"""PRIVATE source-free HUMAN discussion actions for an original inbox board.

Never target scans, approve grants, authenticate clients or assert fixed risks.
Full original client/HUMAN source and action-time consent remain external gates.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import html
import io
import json
import os
import re
import stat
import sys

import private_inbox_board as board
import private_reopen as original
from human_review import source_bytes, safe_note, Hold
import private_intake as inbox

FIELDS = ("board_sha256", "slot", "human_status", "proposed_discussion_role",
          "human_question", "human_next_action")
STATUSES = ("UNREVIEWED", "NEEDS_INPUT", "IN_PROGRESS",
            "DISCUSSION_COMPLETE_NO_RELEASE")
ROLES = ("UNASSIGNED", "SECURITY", "PRIVACY", "CLIENT_OPERATIONS", "PLATFORM")
TEMPLATE = "PRIVATE-inbox-actions-template.csv"
OUT_HTML = "PRIVATE-inbox-actions.html"
OUT_CSV = "PRIVATE-inbox-actions.csv"
OUT_JSON = "PRIVATE-inbox-actions.json"


def unique(pairs: list[tuple[str, object]]) -> dict:
    ret = {}
    for key, val in pairs:
        if key in ret:
            raise ValueError("duplicate source-free board JSON key")
        ret[key] = val
    return ret


def board_admit(path: str) -> tuple[str, list[dict]]:
    raw = source_bytes(path)
    if len(raw) > 64 * 1024:
        raise ValueError("private board outside source-free bound")
    digest = hashlib.sha256(raw).hexdigest()
    data = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON constant")))
    keys = {"schema", "status", "source_free", "source_authenticated",
            "reviewers_authenticated", "client_consent_verified", "operator_consent_verified",
            "authorization_granted", "release_allowed",
            "original_human_reopening_performed", "signed", "rooms"}
    if (type(data) is not dict or set(data) != keys or
        data["schema"] != "lightup.private_human_inbox_board.v1" or
        data["status"] != "REVIEW_ONLY" or data["source_free"] is not True or
        type(data["original_human_reopening_performed"]) is not bool or
        any(data[k] is not False for k in (
            "source_authenticated", "reviewers_authenticated", "client_consent_verified",
            "operator_consent_verified", "authorization_granted", "release_allowed", "signed"))):
        raise ValueError("board contains unsupported authority claims")
    rows = data["rooms"]
    if type(rows) is not list or not 1 <= len(rows) <= board.MAX_ROOMS:
        raise ValueError("board has invalid source-free membership")
    admitted = []
    for index, row in enumerate(rows, 1):
        if type(row) is not dict or set(row) != set(board.FIELDS):
            raise ValueError("board slot schema differs from exact source-free product")
        count = row["source_declarations"]
        a, b, held = row["human_a_choices"], row["human_b_choices"], row["unselected_hold"]
        if (type(row["slot"]) is not int or row["slot"] != index or
            any(type(v) is not int or v < 0 for v in (count, a, b, held)) or
            not 1 <= count <= 12 or a+b+held != count or
            row["result_transport"] not in ("ENCRYPTED","PRIVATE_PLAINTEXT") or
            row["local_file_custody"] != "EXACT_UNSIGNED_BYTES" or
            row["source_reopening"] not in ("NOT_PERFORMED_BY_BOARD", "ORIGINAL_NATIVE_REVIEW_ONLY") or
            row["authority"] != "NONE" or
            row["human_followup"] != ("CHECK_HOLD_CHOICES" if held else "INDEPENDENT_REVIEW_REQUIRED") or
            (row["source_reopening"] == "ORIGINAL_NATIVE_REVIEW_ONLY") !=
              data["original_human_reopening_performed"]):
            raise ValueError("original source-free slot inconsistent")
        admitted.append(row)
    return digest, admitted


def csv_template(digest: str, rows: list[dict]) -> str:
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(FIELDS)
    for row in rows:
        writer.writerow((digest, row["slot"], "UNREVIEWED", "UNASSIGNED", "", ""))
    return out.getvalue()


def read_human_csv(path: str, digest: str, originals: list[dict]) -> list[dict]:
    raw = source_bytes(path)
    if len(raw) > 128 * 1024:
        raise ValueError("HUMAN actions CSV exceeds source-bound size limit")
    stream = io.StringIO(raw.decode("utf-8-sig", "strict"), newline="")
    reader = csv.DictReader(stream, strict=True)
    if tuple(reader.fieldnames or ()) != FIELDS:
        raise ValueError("original six HUMAN action columns required")
    rows = list(reader)
    if len(rows) != len(originals):
        raise ValueError("HUMAN action row membership changed")
    clean = []
    for source, item in zip(originals, rows):
        if (type(item) is not dict or set(item) != set(FIELDS) or
            item["board_sha256"] != digest or item["slot"] != str(source["slot"]) or
            item["human_status"] not in STATUSES or
            item["proposed_discussion_role"] not in ROLES):
            raise ValueError("HUMAN action not bound to exact original board")
        question = safe_note(item["human_question"])
        next_action = safe_note(item["human_next_action"])
        if (item["human_status"] == "UNREVIEWED" and
            (item["proposed_discussion_role"] != "UNASSIGNED" or question or next_action)):
            raise ValueError("unreviewed must not silently retain HUMAN instructions")
        if (item["human_status"] == "DISCUSSION_COMPLETE_NO_RELEASE" and
            (not question.strip() or not next_action.strip())):
            raise ValueError("completed discussion requires explicit HUMAN follow-up")
        clean.append({
            "slot": source["slot"], "human_status": item["human_status"],
            "proposed_discussion_role": item["proposed_discussion_role"],
            "human_question": question, "human_next_action": next_action,
            "unselected_hold": source["unselected_hold"],
            "result_transport": source["result_transport"]
        })
    return clean


def render(digest: str, actions: list[dict]) -> str:
    headings = ("Slot","Original HOLD choices","Proposed HUMAN status",
                "Suggested discussion role","HUMAN question","HUMAN next action")
    content = []
    for row in actions:
        vals = (str(row["slot"]),str(row["unselected_hold"]),row["human_status"],
                row["proposed_discussion_role"],row["human_question"],
                row["human_next_action"])
        content.append("<tr>"+"".join("<td>"+html.escape(v)+"</td>" for v in vals)+"</tr>")
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LightUp PRIVATE HUMAN follow-up actions</title><style>
body{font:16px/1.55 system-ui;margin:2rem auto;padding:1rem;max-width:1150px}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #abb7c5;padding:.6rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#ebf1f8}.warning{background:#fff0de;border-left:5px solid #956000;padding:1rem}
@media print{body{margin:0}tr{break-inside:avoid}}
</style></head><body><h1>PRIVATE source-bound HUMAN discussion actions</h1>
<p class="warning">INCUBATE M3/M7 PLAN/LAB ONLY · REVIEW_ONLY/HOLD.
Proposed roles are NOT actual staff assignments. HUMAN discussion completion
is NOT finding verification, a fixed vulnerability, consent, client approval,
original source authentication, security clearance or authorization to scan,
dispatch, disclose or release. A locally equal unsigned SHA binds only
source-free board bytes; manual HUMANS must independently verify originals.</p>
<table><thead><tr>"""+"".join("<th scope='col'>"+html.escape(x)+"</th>" for x in headings)+"""</tr></thead>
<tbody>"""+"".join(content)+"""</tbody></table>
<p>Original source slot numbers refer to the operator's explicit source board
ordering, not customer identities or immutable finding IDs. All HUMAN notes
remain PRIVATE. The board and this report contain no original targets or
evidence, and source/free-text removal does NOT establish anonymity.</p>
</body></html>"""


def final_artifacts(digest: str, actions: list[dict]) -> list[tuple[str,bytes]]:
    data = {"schema":"lightup.private_human_inbox_actions.v1",
            "status":"REVIEW_ONLY","board_sha256":digest,
            "source_authenticated":False,"client_consent_verified":False,
            "operator_consent_verified":False,"authorization_granted":False,
            "release_allowed":False,"signed":False,"human_actions":actions}
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(("board_sha256","slot","human_status","proposed_discussion_role",
                     "human_question","human_next_action",
                     "source_unselected_hold","original_result_transport"))
    for row in actions:
        writer.writerow((digest, row["slot"],row["human_status"],
                         row["proposed_discussion_role"],row["human_question"],
                         row["human_next_action"],row["unselected_hold"],
                         row["result_transport"]))
    return [
        (OUT_HTML, render(digest,actions).encode("utf-8")),
        (OUT_CSV, out.getvalue().encode("utf-8")),
        (OUT_JSON, (json.dumps(data,ensure_ascii=True,sort_keys=True,separators=(",",":"))+"\n").encode("utf-8"))
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Original source-free HUMAN inbox discussion, never authorization")
    parser.add_argument("action", choices=("prepare","finalize","reopen"))
    parser.add_argument("--board", required=True, help="original PRIVATE inbox portfolio JSON in 0600 storage")
    parser.add_argument("--human-csv", help="complete original board-bound HUMAN action CSV")
    parser.add_argument("--private-output-dir", required=True, help="existing owner-only 0700 directory")
    args = parser.parse_args()
    try:
        if (args.action == "prepare") != (args.human_csv is None):
            raise ValueError("HUMAN action CSV required only after prepare")
        digest, originals = board_admit(args.board)
        if args.action == "prepare":
            board.atomic_private_publish(args.private_output_dir,
                                         [(TEMPLATE,csv_template(digest,originals).encode("utf-8"))])
        else:
            actions = read_human_csv(args.human_csv,digest,originals)
            artifacts = final_artifacts(digest,actions)
            if args.action == "finalize":
                board.atomic_private_publish(args.private_output_dir,artifacts)
            else:
                for name, content in artifacts:
                    original_bytes = source_bytes(os.path.join(args.private_output_dir,name))
                    if not hmac.compare_digest(original_bytes,content):
                        raise ValueError("PRIVATE human action result changed")
        print("REVIEW_ONLY: original source-free HUMAN discussion", args.action,
              "complete; no consent, scan or release")
        return 2
    except (ValueError, OSError, TypeError, Hold, MemoryError, UnicodeError, csv.Error):
        print("HOLD: PRIVATE HUMAN action source/review/outcome not admitted", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
