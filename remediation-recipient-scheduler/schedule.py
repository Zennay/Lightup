#!/usr/bin/env python3
"""Offline PRIVATE HUMAN follow-up scheduler for native LightUp source-free Cockpits.

Source owner and original recipient validators are reused unchanged. This is
non-authorizing scheduling, never actual consent, verification or remediation.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

PARENT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PARENT / "remediation-integrated-workspace"))
import single_review  # Original source-free packet and HUMAN journal admission.

KIND = "lightup.source_free_human_schedule.v1"
WARNING = ("PRIVATE HUMAN scheduling proposal, not authenticated sender/client, "
           "authorized recipient, consent, finding verification, remediation, "
           "successful retest, release approval or grant. DRAFT/HOLD.")
MAX_SOURCES = 12
MAX_TASKS = 864
SCRIPT = Path(__file__).with_name("scheduler.js")
STYLES = """
:root{font-family:system-ui, sans-serif;color:#e5edf8;background:#0b1525}
*{box-sizing:border-box}body{margin:0}header{background:#152438;border-bottom:1px solid #394861;padding:20px 4vw}
h1{margin:0 0 6px;font-size:1.6rem}h2{font-size:1.1rem;margin:0 0 12px}p{line-height:1.5}
.warning{background:#433023;color:#fff1d5;border:1px solid #a67840;padding:12px;border-radius:10px}
main{max-width:1200px;margin:25px auto;padding:0 20px}
.ownerboard{display:flex;gap:10px;flex-wrap:wrap;margin:10px 0 20px}.owner-card{padding:12px;border:1px solid #506787;border-radius:10px;background:#233652;min-width:180px;text-align:left}.owner-card strong{display:block}.owner-card small{color:#d5e4f5}
.controls,.stats{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}
article{background:#17263a;border:1px solid #3b5067;border-radius:12px;padding:17px;margin:12px 0}
input,select,textarea,button{font:inherit;background:#102036;color:#f2f7ff;border:1px solid #657990;border-radius:7px;padding:9px}
button{cursor:pointer;background:#234669}button:hover{background:#305a85}button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:3px solid #f3be6a}
input[type=search]{flex:2;min-width:250px}label{display:block;margin:7px 0}label span{display:block;font-size:.9rem;color:#c8d4e6;margin-bottom:3px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(205px,1fr));gap:10px}
.grid input,.grid select,.grid textarea{width:100%}
.task-title{font-weight:700}.muted{color:#b9cadf}.badge{display:inline-block;border:1px solid #637990;border-radius:12px;padding:3px 8px;margin-right:6px}
#notify{min-height:28px;color:#f5cb7d}#stats{font-size:1.05rem}a{color:#98cdfc}
dialog{width:min(95vw,470px);max-height:90vh;border:1px solid #829dbe;border-radius:14px;
padding:22px;background:#17263a;color:#f2f7ff;box-shadow:0 22px 80px #040913}
dialog::backdrop{background:#02060ce8}dialog form{display:grid;gap:12px}
dialog input[type=password]{display:block;width:100%;min-height:44px;margin-top:5px}
dialog label span{font-weight:600}dialog button{min-height:44px}
dialog [role=alert]{color:#ffd393;min-height:1rem;margin:0}
"""
def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)

def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def canonical(obj: object) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, separators=(",", ":"),
                       sort_keys=True, allow_nan=False) + "\n").encode("utf-8")

def private_parent(path: Path) -> None:
    require(path.is_absolute() and not path.is_symlink() and path.is_dir(),
            "Output parent must be an existing absolute private directory")
    info = path.stat()
    require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
            "Output parent must be owned and exactly 0700")

def private_write(folder: Path, name: str, data: bytes) -> None:
    fd = os.open(folder / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())

def source_records(cockpits: list[str], journals: list[str]) -> tuple[list[dict], list[dict]]:
    require(1 <= len(cockpits) <= MAX_SOURCES, "Require 1–12 real original Cockpit folders")
    require(not journals or len(journals) == len(cockpits),
            "Supply one --journal path or '-' per --cockpit, or none")
    sources: list[dict] = []
    tasks: list[dict] = []
    seen: set[str] = set()
    for index, original_dir in enumerate(cockpits, start=1):
        cockpit = Path(original_dir)
        require(cockpit.is_absolute(), "Original Cockpit paths must be absolute")
        original_rows, source_key, _, _ = single_review.original(cockpit)
        require(source_key not in seen,
                "Identical Cockpit supplied twice: no invented second snapshot")
        seen.add(source_key)
        if journals and journals[index - 1] != "-":
            raw = single_review.review.private_read(Path(journals[index - 1]))
            original_rows = single_review.admit_journal(raw, original_rows, source_key)
        sources.append({"packet": index, "source_sha256": source_key,
                        "reason_groups": len(original_rows)})
        for row in original_rows:
            tasks.append({
                "packet": index, "slot": row["slot"], "reason": row["reason"],
                "count": row["count"], "stage": row["stage"],
                "human_note": row["note"], "owner": "", "due": "", "next_action": ""
            })
    require(len(tasks) <= MAX_TASKS, "Too many original source-free HUMAN groups")
    return sources, tasks

def render(sources: list[dict], tasks: list[dict]) -> bytes:
    js = SCRIPT.read_bytes()
    require(0 < len(js) <= 90000 and b"</script" not in js.lower(),
            "Unsafe or excessive embedded scheduler JavaScript")
    css = STYLES.encode("utf-8")
    csp = ("default-src 'none'; base-uri 'none'; form-action 'none'; "
           "connect-src 'none'; object-src 'none'; frame-ancestors 'none'; "
           "img-src 'none'; style-src 'sha256-" +
           base64.b64encode(hashlib.sha256(css).digest()).decode("ascii") +
           "'; script-src 'sha256-" +
           base64.b64encode(hashlib.sha256(js).digest()).decode("ascii") + "'")
    seed = json.dumps({"kind": KIND, "warning": WARNING, "sources": sources,
                       "tasks": tasks}, ensure_ascii=False, separators=(",", ":"))
    # Never allow original HUMAN text to break its inert application/json element.
    seed = seed.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{html.escape(csp, quote=True)}">
<title>LightUp · PRIVATE HUMAN Scheduler</title>
<style>{STYLES}</style></head><body>
<header><h1>LightUp · PRIVATE HUMAN Scheduler</h1>
<p>Source-free remediation follow-ups across {len(sources)} separate admitted packet(s). No inferred chronology or client joins.</p>
<div class="warning">{html.escape(WARNING)}</div></header>
<main><section class="stats" id="stats" aria-live="polite"></section>
<section aria-label="HUMAN owner workload"><h2>Local HUMAN owner workload</h2><div class="ownerboard" id="ownerBoard"></div></section>
<div class="controls"><input id="search" type="search" placeholder="Search HUMAN reason, owner, action" aria-label="Search tasks">
<select id="filter"><option value="all">All tasks</option><option value="soon">Due within 7 days</option><option value="overdue">Overdue</option><option value="unscheduled">Not scheduled</option><option value="unowned">No owner</option><option value="pending">Still pending</option></select>
<select id="source"><option value="all">All source-free packets</option></select><select id="ownerFilter"><option value="all">All HUMAN owners</option></select></div>
<div class="controls"><label><span>Batch owner (blank means clear)</span><input id="batchOwner" type="text" maxlength="64"></label>
<label><span>Batch due (blank means clear)</span><input id="batchDue" type="date"></label>
<label><span>Batch stage</span><select id="batchStage"><option value="keep">Keep stage</option><option value="open_human">Open HUMAN</option><option value="ask_source_owner">Ask source owner</option><option value="in_discussion_human">In discussion</option><option value="answered_human_only">Answered HUMAN-only</option></select></label>
<label><span>Fields to change</span><label><input id="batchUseOwner" type="checkbox"> Owner</label><label><input id="batchUseDue" type="checkbox"> Due date</label></label>
<button id="bulk">Preview and apply to currently visible tasks</button><button id="undo" disabled>Undo previous batch</button></div>
<div class="controls"><button id="save">Save encrypted PRIVATE plan</button>
<button id="open">Open encrypted plan</button><input id="openfile" type="file" accept=".lurp,application/json" hidden>
<button id="carry">Carry unchanged source-bound HUMAN plan forward</button><input id="carryfile" type="file" accept=".lurp,application/json" hidden>
<button id="agenda">Export printable PRIVATE HUMAN agenda (visible tasks)</button>
<button id="selective">Encrypt selected HUMAN-only handoff (visible tasks)</button>
<button id="calendar">Export tentative PRIVATE calendar (.ics)</button>
<button id="counts">Export anonymous counts</button></div>
<p class="muted">Passwords are entered only in this browser tab. No storage, telemetry, network or calendar API; downloads require protected offline custody. ICS contains only anonymous task labels by default, not private notes or identities. Anonymous counts can still disclose small cohorts.</p>
<div id="notify" role="status" aria-live="polite"></div>
<section id="tasks" aria-label="Private HUMAN tasks"></section></main>
<script type="application/json" id="seed">{seed}</script>
<script>{js.decode("utf-8")}</script></body></html>"""
    return page.encode("utf-8")

def build(args: argparse.Namespace) -> None:
    output = Path(args.output_dir)
    private_parent(output.parent)
    require(output.is_absolute() and not output.exists() and not output.is_symlink(),
            "Output must be a new absolute PRIVATE directory")
    sources, tasks = source_records(args.cockpit, args.journal)
    page = render(sources, tasks)
    os.mkdir(output, 0o700)
    try:
        private_write(output, "index.html", page)
        private_write(output, "README.txt",
                      (WARNING + "\n\nOpen index.html offline on an approved private machine. "
                       "PRIVATE encrypted .lurp may contain HUMAN notes and names. "
                       "Syntactic source admission and hashes are not source-authentication.\n").encode())
    except BaseException:
        shutil.rmtree(output)
        raise
    print(f"REVIEW_ONLY: private scheduler created: {output / 'index.html'}")
    print(f"{len(sources)} source-free original packets; {len(tasks)} HUMAN-only reason groups.")
    print(f"Unsigned software SHA-256: {digest(page)}")

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cockpit", action="append", required=True,
                        help="Absolute PRIVATE original source-free Cockpit directory; repeat 1–12x")
    parser.add_argument("--journal", action="append", default=[],
                        help="Corresponding native source-bound HUMAN JSON or '-' for none")
    parser.add_argument("--output-dir", required=True,
                        help="New absolute folder below existing owned 0700 parent")
    args = parser.parse_args()
    try:
        build(args)
        return 2
    except (ValueError, OSError, single_review.review.Hold, UnicodeError) as exc:
        print(f"HOLD: {exc}", file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
