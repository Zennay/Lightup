#!/usr/bin/env python3
"""Offline multi-export HUMAN workload portfolio. No finding validation or authority."""
from __future__ import annotations

import argparse
import ctypes
import errno
import html
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

MAX_FILES = 12
MAX_BYTES = 16384
MAX_TOTAL = 1000000
STAGES = ("unassigned", "assigned", "waiting_human", "locally_answered")
FLAGS = ("authenticated", "tenant_verified", "source_authorized",
         "assessment_authorized", "grant", "client_consent",
         "operator_consent", "execution", "scan", "audit_verdict",
         "retest_verified", "release")
INBOX_KIND = "lightup.anonymous_human_inbox_counts_only"
WORKROOM_KIND = "lightup.private_human_workroom_anonymous_counts"
PLAN_KIND = "lightup.private_anonymous_human_slot_workload"
PORTFOLIO_KIND = "lightup.anonymous_human_portfolio_counts_only"
INBOX_FIELDS = {"kind", "schema_version", "disposition",
                "source_free_workrooms_not_unique_cases",
                "local_pending_human_questions_not_fixes", "warning", *FLAGS}
PLAN_FIELDS = {"kind", "schema_version", "disposition", "slots_not_unique_cases",
               "local_stage_totals", "pending_local_human_attention_slots",
               "due_slots_with_local_dates", "warning", *FLAGS}
WORKROOM_FIELDS = {"kind", "schema_version", "disposition",
                   "source_free_inbox", "local_human_planning", "warning", *FLAGS}
WARNING = ("Independent anonymous exports can refer to the same underlying HUMAN "
           "work. Totals are packet-sums, NOT unique clients, findings, fixed "
           "vulnerabilities, authentic evidence, permission, or verification. "
           "Only a human may decide whether private counts can be shared.")


class Hold(ValueError):
    """Reject all input without publishing partial output."""


def require(ok: bool) -> None:
    if not ok:
        raise Hold("HOLD: invalid, stale, private or incompatible counts-only input")


def nonnegative(value: object, maximum: int = MAX_TOTAL) -> int:
    require(type(value) is int and 0 <= value <= maximum)
    return value


def pairs(values: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in values:
        require(key not in result)
        result[key] = value
    return result


def private_dir(path: Path) -> None:
    require(path.is_absolute() and not path.is_symlink()
            and path == path.resolve(strict=True))
    mode = path.stat(follow_symlinks=False)
    require(stat.S_ISDIR(mode.st_mode) and mode.st_uid == os.getuid()
            and mode.st_mode & 0o077 == 0)


def read_private(path: Path) -> bytes:
    require(path.is_absolute() and not path.is_symlink())
    private_dir(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid()
                and st.st_mode & 0o077 == 0 and 1 <= st.st_size <= MAX_BYTES)
        data = os.read(fd, MAX_BYTES + 1)
        after = os.fstat(fd)
        require(len(data) == st.st_size and st.st_size == after.st_size
                and st.st_mtime_ns == after.st_mtime_ns)
        return data
    finally:
        os.close(fd)


def parse(raw: bytes) -> dict:
    require(1 <= len(raw) <= MAX_BYTES)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _: require(False),
                           parse_float=lambda _: require(False))
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise Hold("HOLD: noncanonical PRIVATE HUMAN counts JSON") from exc
    require(type(value) is dict)
    return value


def header(obj: dict, kind: str, fields: set[str], disposition: str) -> None:
    require(type(obj) is dict and set(obj) == fields
            and obj["kind"] == kind
            and type(obj["schema_version"]) is int
            and obj["schema_version"] == 1
            and obj["disposition"] == disposition
            and type(obj["warning"]) is str
            and 10 <= len(obj["warning"]) <= 4096
            and all(obj[k] is False for k in FLAGS))


def admit_inbox(obj: dict) -> dict:
    header(obj, INBOX_KIND, INBOX_FIELDS, "PRIVATE_HUMAN_COUNTS_ONLY_NO_AUTHORITY")
    slots = nonnegative(obj["source_free_workrooms_not_unique_cases"], 12)
    require(1 <= slots <= 12)
    questions = nonnegative(obj["local_pending_human_questions_not_fixes"])
    return {"slots": slots, "questions": questions}


def admit_plan(obj: dict, slots: int) -> dict:
    header(obj, PLAN_KIND, PLAN_FIELDS,
           "UNVERIFIED_HUMAN_PLANNING_COUNTS_ONLY")
    require(nonnegative(obj["slots_not_unique_cases"], 12) == slots)
    stages = obj["local_stage_totals"]
    require(type(stages) is dict and set(stages) == set(STAGES))
    totals = {stage: nonnegative(stages[stage], slots) for stage in STAGES}
    require(sum(totals.values()) == slots)
    pending = nonnegative(obj["pending_local_human_attention_slots"], slots)
    require(pending == slots - totals["locally_answered"])
    due = nonnegative(obj["due_slots_with_local_dates"], slots)
    return {"stages": totals, "attention": pending, "due": due}


def admit(obj: dict) -> dict:
    if obj.get("kind") == INBOX_KIND:
        inner = admit_inbox(obj)
        return {"source": "inbox", **inner, "planning": None}
    header(obj, WORKROOM_KIND, WORKROOM_FIELDS, "COUNTS_ONLY_NO_AUTHORITY")
    inner = admit_inbox(obj["source_free_inbox"])
    planning = admit_plan(obj["local_human_planning"], inner["slots"])
    return {"source": "workroom", **inner, "planning": planning}


def serialize(payload: object) -> bytes:
    return (json.dumps(payload, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")


def aggregate(inputs: list[dict]) -> dict:
    require(1 <= len(inputs) <= MAX_FILES)
    rows = []
    for index, source in enumerate(inputs, 1):
        row = {"packet": index, "type": source["source"],
               "source_free_slots_not_unique": source["slots"],
               "pending_human_questions_not_fixes": source["questions"],
               "planning": source["planning"]}
        rows.append(row)
    total_slots = sum(x["source_free_slots_not_unique"] for x in rows)
    questions = sum(x["pending_human_questions_not_fixes"] for x in rows)
    planned = [x["planning"] for x in rows if x["planning"] is not None]
    return {"kind": PORTFOLIO_KIND, "schema_version": 1,
            "disposition": "PRIVATE_PACKET_SUMS_ONLY_NO_AUTHORITY",
            "packet_count": len(rows),
            "source_free_slot_appearances_not_unique": total_slots,
            "pending_human_questions_not_fixes": questions,
            "packets_with_local_human_planning": len(planned),
            "pending_local_human_attention_slot_appearances":
                sum(p["attention"] for p in planned),
            "due_slot_appearances_with_local_dates":
                sum(p["due"] for p in planned),
            "stage_slot_appearances":
                {s: sum(p["stages"][s] for p in planned) for s in STAGES},
            "rows": rows, "warning": WARNING, **{f: False for f in FLAGS}}


def human_queue_rows(summary: dict) -> list[dict]:
    """Volume-order PRIVATE anonymous packets, never security-risk priority."""
    return sorted(summary["rows"],
                  key=lambda r: (-r["pending_human_questions_not_fixes"],
                                 -(r["planning"]["attention"]
                                   if r["planning"] is not None else 0),
                                 r["packet"]))


def queue_bytes(summary: dict) -> bytes:
    lines = ["volume_rank,packet,questions_not_fixes,local_human_attention,slot_appearances,ordering"]
    for rank, row in enumerate(human_queue_rows(summary), 1):
        p = row["planning"]
        fields = (rank, row["packet"], row["pending_human_questions_not_fixes"],
                  p["attention"] if p is not None else "",
                  row["source_free_slots_not_unique"], "human_question_volume_only")
        lines.append(",".join(str(v) for v in fields))
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def recommendations(summary: dict) -> list[str]:
    """Human-only coordination suggestions; never source truth or automated action."""
    notes = []
    if summary["pending_human_questions_not_fixes"]:
        notes.append("Ask original source-owning HUMAN reviewers to triage pending "
                     "questions locally; counts do not show whether any fix exists.")
    if summary["stage_slot_appearances"]["unassigned"]:
        notes.append("Assign unassigned HUMAN slot appearances in their ORIGINAL "
                     "encrypted workrooms, not in this anonymous portfolio.")
    if summary["stage_slot_appearances"]["waiting_human"]:
        notes.append("Review waiting_human slot appearances with authorized people "
                     "inside the original private workroom; no automatic escalation.")
    if summary["due_slot_appearances_with_local_dates"]:
        notes.append("Check date-bearing slot appearances only in the original "
                     "PRIVATE local plans; exact dates were intentionally omitted.")
    if summary["packets_with_local_human_planning"] != summary["packet_count"]:
        notes.append("Some inbox-only packets have no HUMAN planning breakdown: "
                     "do not interpret missing fields as zero.")
    if not notes:
        notes.append("No pending counters were declared in these packets; this is "
                     "NOT evidence of completed cases, consent, or verified fixes.")
    notes.append("Review potential overlap between independent source packets "
                 "privately before making staffing or completion claims.")
    return notes


def brief_bytes(summary: dict) -> bytes:
    lines = [
        "LIGHTUP | PRIVATE HUMAN WORKLOAD FOLLOW-UP",
        "INCUBATE / M3-M7 PLAN-LAB ONLY / DRAFT HOLD",
        "No active operation, genuine consent, evidence, fix or security verdict.",
        "",
        f"Packets: {summary['packet_count']}",
        "Slot appearances (not unique): "
        f"{summary['source_free_slot_appearances_not_unique']}",
        "Pending HUMAN questions (not fixes): "
        f"{summary['pending_human_questions_not_fixes']}",
        "Local HUMAN attention appearances (planning packets only): "
        f"{summary['pending_local_human_attention_slot_appearances']}",
        "",
        "HUMAN FOLLOW-UPS (NO AUTOMATIC ACTION)"
    ]
    lines.extend(f"{i}. {note}" for i, note in enumerate(recommendations(summary), 1))
    lines.extend(("", WARNING, ""))
    return "\n".join(lines).encode("ascii")


def csv_bytes(summary: dict) -> bytes:
    names = ("packet", "kind", "slot_appearances", "questions", "human_attention",
             "dated_slots", *STAGES)
    lines = [",".join(names)]
    for row in summary["rows"]:
        plan = row["planning"]
        fields = [str(row["packet"]), row["type"],
                  str(row["source_free_slots_not_unique"]),
                  str(row["pending_human_questions_not_fixes"])]
        if plan is None:
            fields += ["", ""] + [""] * len(STAGES)
        else:
            fields += [str(plan["attention"]), str(plan["due"])]
            fields += [str(plan["stages"][s]) for s in STAGES]
        lines.append(",".join(fields))
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def html_bytes(summary: dict) -> bytes:
    rows = []
    for row in summary["rows"]:
        plan = row["planning"]
        pending = str(plan["attention"]) if plan else "Not provided"
        due = str(plan["due"]) if plan else "Not provided"
        rows.append("<tr><th>Packet %02d</th><td>%s</td><td>%d</td>"
                    "<td>%d</td><td>%s</td><td>%s</td></tr>" %
                    (row["packet"], html.escape(row["type"]),
                     row["source_free_slots_not_unique"],
                     row["pending_human_questions_not_fixes"], pending, due))
    action_rows = "".join("<li><span>%s</span></li>" % html.escape(note)
                          for note in recommendations(summary))
    queue_rows = "".join(
        "<tr><th>%d</th><td>Packet %02d</td><td>%d</td><td>%s</td></tr>" %
        (rank, row["packet"], row["pending_human_questions_not_fixes"],
         str(row["planning"]["attention"]) if row["planning"] else "Not provided")
        for rank, row in enumerate(human_queue_rows(summary), 1))
    bars = "".join("<li><span>%s</span><strong>%d</strong></li>" %
                   (html.escape(k.replace("_", " ")),
                    summary["stage_slot_appearances"][k]) for k in STAGES)
    page = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LightUp | PRIVATE HUMAN workload portfolio</title>
<style>:root{color-scheme:dark}*{box-sizing:border-box}body{background:#0e1624;color:#edf5ff;font:16px system-ui;margin:0;padding:32px}
main{max-width:1060px;margin:auto}h1{font-size:2.2rem}p{line-height:1.65;color:#c3d0e1}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(185px,1fr));gap:12px;margin:24px 0}
article{background:#19283c;border:1px solid #344864;border-radius:14px;padding:18px}
article strong{font-size:2.1rem;display:block;color:#c8f9e0}article span{color:#bad0e5}
table{border-collapse:collapse;width:100%%;min-width:700px}th,td{text-align:left;padding:14px;border-bottom:1px solid #344864}
.scroll{overflow-x:auto}ul{list-style:none;padding:0}li{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #344864}
small{font-size:13px}aside{border-left:3px solid #f5c77b;padding:12px 18px;background:#29303e}
</style></head><body><main>
<p><small>LIGHTUP / PRIVATE OFFLINE / REVIEW ONLY</small></p>
<h1>HUMAN workload portfolio</h1><p>Aggregated source-free packet appearances.
No browser scripts, network access, original evidence, names, dates, or identifiers.</p>
<div class="kpis">
<article><strong>%(packet_count)d</strong><span>Independent imported packets</span></article>
<article><strong>%(source_free_slot_appearances_not_unique)d</strong><span>Slot appearances (not unique cases)</span></article>
<article><strong>%(pending_human_questions_not_fixes)d</strong><span>Local pending questions (not fixes)</span></article>
<article><strong>%(pending_local_human_attention_slot_appearances)d</strong><span>Planned HUMAN attention appearances</span></article>
</div><aside><strong>Non-authorizing / DRAFT HOLD.</strong><p>%(warning)s</p></aside>
<h2>Human follow-ups (no automated action)</h2><article><ul>%(actions)s</ul></article>
<h2>HUMAN question-volume routing (not security severity)</h2><div class="scroll"><table><thead><tr><th>Volume rank</th><th>Private packet ordinal</th><th>Questions</th><th>Planned attention</th></tr></thead><tbody>%(queue)s</tbody></table></div>
<h2>Source packets</h2><div class="scroll"><table><thead><tr>
<th>Packet</th><th>Local export</th><th>Slot appearances</th><th>Questions</th>
<th>Planned attention</th><th>Locally dated slots</th></tr></thead><tbody>%(rows)s</tbody></table></div>
<h2>Work stages (workroom packets only)</h2><article><ul>%(bars)s</ul>
<p>%(packets_with_local_human_planning)d of %(packet_count)d packets include stage totals.
Blank does not mean zero.</p></article>
<p><small>These are locally entered HUMAN workflow states, never evidence, truth,
consent, remediation, severity, a validated retest, or authority to assess targets.</small></p>
</main></body></html>
""" % {**summary, "warning": html.escape(WARNING), "rows": "".join(rows),
       "bars": bars, "actions": action_rows, "queue": queue_rows}
    return page.encode("utf-8")


def exclusive_write(path: Path, payload: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as writer:
            writer.write(payload)
            writer.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def publish(stage: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    require(renameat2 is not None)
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                           ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    rc = renameat2(-100, os.fsencode(stage), -100,
                   os.fsencode(destination), 1)  # RENAME_NOREPLACE
    if rc != 0:
        raise OSError(ctypes.get_errno(), "HOLD: exclusive publication refused")


def packet_directory(folder: Path) -> list[Path]:
    """An explicit owner-private directory: nothing imported by broad globbing."""
    private_dir(folder)
    names = sorted(item.name for item in folder.iterdir())
    require(1 <= len(names) <= MAX_FILES and
            names == [f"packet-{i:02d}.json" for i in range(1, len(names) + 1)])
    # Every member is further checked as owner-only, no-follow, bounded JSON.
    return [folder / name for name in names]


def build(paths: list[Path], destination: Path) -> None:
    require(1 <= len(paths) <= MAX_FILES and destination.is_absolute())
    private_dir(destination.parent)
    require(not destination.exists() and not destination.is_symlink())
    # No partial outputs if any of the original exports fail admission.
    sources = [admit(parse(read_private(p))) for p in paths]
    summary = aggregate(sources)
    stage = Path(tempfile.mkdtemp(prefix=".lightup-private-portfolio-",
                                  dir=destination.parent))
    os.chmod(stage, 0o700)
    try:
        exclusive_write(stage / "index.html", html_bytes(summary))
        exclusive_write(stage / "counts.csv", csv_bytes(summary))
        exclusive_write(stage / "human-volume-queue.csv", queue_bytes(summary))
        exclusive_write(stage / "summary.json", serialize(summary))
        exclusive_write(stage / "human-followup.txt", brief_bytes(summary))
        folder_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(folder_fd)
        finally:
            os.close(folder_fd)
        publish(stage, destination)
        parent_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PRIVATE offline aggregate HUMAN count exports; no authority")
    sources = parser.add_mutually_exclusive_group(required=True)
    sources.add_argument("--input", type=Path, action="append",
                         help="Repeat for 1-12 explicit owner-private 0600 native count JSONs")
    sources.add_argument("--packet-dir", type=Path,
                         help="One private folder with ONLY packet-01.json...packet-NN.json")
    parser.add_argument("--output-dir", required=True, type=Path,
                        help="New absolute 0700 private directory, never overwritten")
    args = parser.parse_args()
    try:
        paths = (packet_directory(args.packet_dir) if args.packet_dir is not None
                 else args.input)
        build(paths, args.output_dir)
    except (Hold, ValueError, OSError) as exc:
        print("HOLD: no complete new HUMAN portfolio published", file=sys.stderr)
        return 2
    print("Private source-free HUMAN portfolio published (not evidence or authority).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
