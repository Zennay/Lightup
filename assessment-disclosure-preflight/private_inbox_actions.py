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
import unicodedata

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
DELTA_HTML = "PRIVATE-inbox-HUMAN-revision-delta.html"
DELTA_CSV = "PRIVATE-inbox-HUMAN-revision-delta.csv"
DELTA_JSON = "PRIVATE-inbox-HUMAN-revision-delta.json"


def unique(pairs: list[tuple[str, object]]) -> dict:
    ret = {}
    for key, val in pairs:
        if key in ret:
            raise ValueError("duplicate source-free board JSON key")
        ret[key] = val
    return ret


def safe_action_note(value: object) -> str:
    """Fail closed on Unicode-disguised spreadsheet formulas in HUMAN CSV cells."""
    note = safe_note(value)
    if any(unicodedata.category(char).startswith("C") or
           unicodedata.category(char) in ("Zl", "Zp") for char in note):
        raise ValueError("HUMAN note contains unsafe Unicode control/format/separator")
    if unicodedata.normalize("NFKC", note).lstrip().startswith(("=", "+", "-", "@")):
        raise ValueError("HUMAN note resembles a spreadsheet formula after Unicode normalization")
    return note


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
        question = safe_action_note(item["human_question"])
        next_action = safe_action_note(item["human_next_action"])
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


def revision_delta_artifacts(prior: list[dict], current: list[dict]) -> list[tuple[str, bytes]]:
    """Build a private changed-only HUMAN plan delta; never export free-text notes."""
    if len(prior) != len(current) or not 1 <= len(prior) <= board.MAX_ROOMS:
        raise ValueError("complete source-bound HUMAN revision pair required")
    counts = {"stage": 0, "proposed_role": 0, "question_text": 0, "next_action_text": 0}
    changes = []
    for before, after in zip(prior, current):
        if before["slot"] != after["slot"]:
            raise ValueError("original HUMAN slot order differs")
        fields = []
        if before["human_status"] != after["human_status"]:
            fields.append("stage")
            counts["stage"] += 1
        if before["proposed_discussion_role"] != after["proposed_discussion_role"]:
            fields.append("proposed role")
            counts["proposed_role"] += 1
        question_changed = before["human_question"] != after["human_question"]
        next_changed = before["human_next_action"] != after["human_next_action"]
        if question_changed:
            fields.append("question text")
            counts["question_text"] += 1
        if next_changed:
            fields.append("next-action text")
            counts["next_action_text"] += 1
        if fields:
            changes.append({
                "slot": before["slot"], "changed_fields": fields,
                "prior_status": before["human_status"], "current_status": after["human_status"],
                "prior_role": before["proposed_discussion_role"],
                "current_role": after["proposed_discussion_role"],
                "question_text_changed": question_changed,
                "next_action_text_changed": next_changed,
            })
    columns = (
        "slot", "changed_fields", "prior_status", "current_status", "prior_role",
        "current_role", "question_text_changed", "next_action_text_changed",
        "chronology_authenticated", "source_authenticated", "client_consent_verified",
        "operator_consent_verified", "authorization_granted", "release_allowed",
    )
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(columns)
    for row in changes:
        writer.writerow((
            row["slot"], "; ".join(row["changed_fields"]), row["prior_status"],
            row["current_status"], row["prior_role"], row["current_role"],
            str(row["question_text_changed"]).lower(), str(row["next_action_text_changed"]).lower(),
            "false", "false", "false", "false", "false", "false",
        ))
    html_rows = []
    for row in changes:
        values = (
            str(row["slot"]), "; ".join(row["changed_fields"]), row["prior_status"],
            row["current_status"], row["prior_role"], row["current_role"],
            "YES" if row["question_text_changed"] else "NO",
            "YES" if row["next_action_text_changed"] else "NO",
        )
        html_rows.append("<tr>" + "".join("<td>" + html.escape(value) + "</td>" for value in values) + "</tr>")
    table = ("<table><thead><tr>" + "".join("<th>" + html.escape(value) + "</th>" for value in (
        "Slot", "Changed fields", "Prior stage", "Current stage", "Prior role",
        "Current role", "Question changed", "Next action changed")) +
        "</tr></thead><tbody>" + "".join(html_rows) + "</tbody></table>") if changes else (
        "<p>No HUMAN planning-field differences between these two source-bound revisions.</p>")
    page = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PRIVATE HUMAN revision delta</title><style>body{font:16px/1.5 system-ui;max-width:1100px;margin:2rem auto;padding:1rem}table{border-collapse:collapse;width:100%}td,th{border:1px solid #9aa9bc;padding:.5rem;text-align:left;overflow-wrap:anywhere}th{background:#edf3fa}.notice{background:#fff0dd;padding:1rem;border-left:5px solid #965400}</style></head><body>
<h1>PRIVATE HUMAN revision delta</h1>
<p class="notice">REVIEW_ONLY · INCUBATE M3/M7 PLAN/LAB ONLY. Same original board bytes, complete row membership and all HUMAN fields were locally admitted before comparison. The report is unsigned; source, reviewer, chronology and consent are not authenticated. A changed HUMAN stage is not remediation or release.</p>
<p>Changed slots: __CHANGED__ / __SLOTS__. Question and next-action text is intentionally omitted; only whether it changed is shown.</p>
__TABLE__
<p>Prior/current ordering is operator-supplied, not authenticated chronology. Keep this report private. No original input or active HUMAN plan was changed.</p></body></html>"""
    page = page.replace("__CHANGED__", str(len(changes))).replace("__SLOTS__", str(len(prior))).replace("__TABLE__", table)
    data = {
        "schema": "lightup.private_human_inbox_revision_delta.v1",
        "status": "REVIEW_ONLY", "same_original_board_bytes_checked": True,
        "source_authenticated": False, "reviewers_authenticated": False,
        "client_consent_verified": False, "operator_consent_verified": False,
        "authorization_granted": False, "release_allowed": False,
        "chronology_authenticated": False, "signed": False,
        "slot_count": len(prior), "changed_slot_count": len(changes),
        "field_change_counts": counts, "changes": changes,
    }
    return [
        (DELTA_HTML, page.encode("utf-8")),
        (DELTA_CSV, out.getvalue().encode("utf-8")),
        (DELTA_JSON, (json.dumps(data, ensure_ascii=True, sort_keys=True,
                                 separators=(",", ":")) + "\n").encode("utf-8")),
    ]


def publish_private_artifacts(output_dir: str, artifacts: list[tuple[str, bytes]]) -> None:
    """Publish an exact-inventory private report into a fresh empty destination.

    This matches the strict subsequent reopen contract. Do not create a
    'successful' report in a mixed directory that cannot be reopened.
    """
    directory = os.stat(output_dir, follow_symlinks=False)
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid() or
        stat.S_IMODE(directory.st_mode) != 0o700 or os.listdir(output_dir)):
        raise ValueError("PRIVATE HUMAN output needs an empty owner-only 0700 directory")
    board.atomic_private_publish(output_dir, artifacts)


def reopen_private_artifacts(output_dir: str, artifacts: list[tuple[str, bytes]]) -> None:
    """Read-only, fail-closed custody admission shared by all HUMAN outputs.

    Match the entire saved inventory, not just selected report filenames.
    Local custody and byte equality never establish the sender's identity.
    """
    expected = {name for name, _ in artifacts}
    if not expected or len(expected) != len(artifacts):
        raise ValueError("PRIVATE HUMAN report inventory is not canonical")
    directory = os.stat(output_dir, follow_symlinks=False)
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid() or
        stat.S_IMODE(directory.st_mode) != 0o700):
        raise ValueError("saved PRIVATE HUMAN directory must be owner-only 0700")
    if set(os.listdir(output_dir)) != expected:
        raise ValueError("saved PRIVATE HUMAN inventory differs from expected output")
    for name, content in artifacts:
        if not name or name in (".", "..") or os.path.basename(name) != name:
            raise ValueError("PRIVATE HUMAN output filename rejected")
        path = os.path.join(output_dir, name)
        metadata = os.stat(path, follow_symlinks=False)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or
            stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1):
            raise ValueError("saved PRIVATE HUMAN file must be owner-only regular 0600")
        if not hmac.compare_digest(source_bytes(path), content):
            raise ValueError("saved PRIVATE HUMAN report changed")


def main() -> int:
    parser = argparse.ArgumentParser(description="Original source-free HUMAN inbox discussion, never authorization")
    parser.add_argument("action", choices=("prepare","reopen-template","finalize","reopen","compare","reopen-compare"))
    parser.add_argument("--board", required=True, help="original PRIVATE inbox portfolio JSON in 0600 storage")
    parser.add_argument("--human-csv", help="complete original board-bound current HUMAN action CSV")
    parser.add_argument("--prior-human-csv", help="prior complete original board-bound HUMAN action CSV for compare")
    parser.add_argument("--private-output-dir", required=True, help="existing owner-only 0700 directory")
    args = parser.parse_args()
    try:
        if args.action in ("prepare", "reopen-template"):
            if args.human_csv is not None or args.prior_human_csv is not None:
                raise ValueError("template actions do not accept HUMAN result CSV inputs")
        elif args.action in ("compare", "reopen-compare"):
            if args.human_csv is None or args.prior_human_csv is None:
                raise ValueError("compare/reopen-compare require both prior and current HUMAN CSVs")
        elif args.human_csv is None or args.prior_human_csv is not None:
            raise ValueError("finalize/reopen require only the current HUMAN CSV")
        digest, originals = board_admit(args.board)
        if args.action in ("prepare", "reopen-template"):
            artifacts = [(TEMPLATE, csv_template(digest, originals).encode("utf-8"))]
            if args.action == "prepare":
                publish_private_artifacts(args.private_output_dir, artifacts)
            else:
                reopen_private_artifacts(args.private_output_dir, artifacts)
        elif args.action in ("compare", "reopen-compare"):
            prior = read_human_csv(args.prior_human_csv,digest,originals)
            current = read_human_csv(args.human_csv,digest,originals)
            artifacts = revision_delta_artifacts(prior,current)
            if args.action == "compare":
                publish_private_artifacts(args.private_output_dir, artifacts)
            else:
                reopen_private_artifacts(args.private_output_dir,artifacts)
        else:
            actions = read_human_csv(args.human_csv,digest,originals)
            artifacts = final_artifacts(digest,actions)
            if args.action == "finalize":
                publish_private_artifacts(args.private_output_dir, artifacts)
            else:
                reopen_private_artifacts(args.private_output_dir, artifacts)
        print("REVIEW_ONLY: original source-free HUMAN discussion", args.action,
              "complete; no consent, scan or release")
        return 2
    except (ValueError, OSError, TypeError, Hold, MemoryError, UnicodeError, csv.Error):
        print("HOLD: PRIVATE HUMAN action source/review/outcome not admitted", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
