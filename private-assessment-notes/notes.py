#!/usr/bin/env python3
"""Owner-private original-utility credential-masked HUMAN assessment note workroom.

No claim that pattern-based masking anonymizes text or grants public release.
"""
from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import html
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from private_csv_formula import unsafe_private_csv_note
from private_masking import mask_private_notes  # Core original producer + local defence-in-depth.
from browser_studio import render as render_browser_studio

MAX_FILE = 512 * 1024
MAX_MASKED_FILE = 2 * MAX_FILE
MAX_TOTAL = 2 * 1024 * 1024
MAX_FILES = 12
SCHEMA = "lightup.private_assessment_redacted_human_notes.v1"
FALSE_FLAGS = ("source_authenticated", "client_consent_verified", "operator_consent_verified",
               "approved_to_share", "release_allowed", "dispatch_allowed")
ALLOWED = ("NEEDS_HUMAN_REVIEW", "SOURCE_OWNER_REQUIRED", "WITHHOLD",
           "INTERNAL_REVIEW_ONLY")
STAGES = set(ALLOWED)
CSV_FIELDS = ("source_ordinal", "source_sha256_unsigned", "human_stage", "human_note")
CSS = """
:root{color-scheme:light;font:16px/1.55 system-ui;color:#1a2940;background:#edf2f7}
*{box-sizing:border-box}body{max-width:1120px;margin:auto;padding:20px}
header,.panel{background:white;border:1px solid #d4e1eb;border-radius:17px;padding:22px;margin:18px 0}
h1{font-size:clamp(1.6rem,4vw,2.6rem);margin:.2rem 0}
h2{font-size:1.15rem}p{line-height:1.65}
a{color:#155780}a:focus-visible{outline:3px solid #ac6b13}
.warn{border-left:4px solid #b34e28;padding:15px;background:#fff0e8;color:#72301a;font-weight:650}
pre{white-space:pre-wrap;overflow-wrap:anywhere;tab-size:4;padding:20px;background:#101d30;color:#e6efff;border-radius:8px}
code{font:inherit}small{color:#48576d}
td,th{text-align:left;padding:10px;border-bottom:1px solid #d0dae4}
table{border-collapse:collapse;width:100%}
@media print{body{background:white;padding:0}header,.panel{border:1px solid #999;break-inside:avoid}pre{color:black;background:white;border:1px solid #bbb}}
"""


class Hold(Exception):
    pass


def private_directory(name: str) -> Path:
    directory = Path(name).absolute()
    st = directory.lstat()
    if (not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode)
            or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077):
        raise Hold("HOLD: required owner-private ordinary directory (mode 0700)")
    if directory == ROOT or ROOT in directory.parents:
        raise Hold("HOLD: private output cannot live inside source checkout")
    return directory


def private_input(name: str, limit: int) -> bytes:
    path = Path(name).absolute()
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)
            or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077
            or not 0 < st.st_size <= limit):
        raise Hold("HOLD: original selected input must be ordinary, owner-only and within limit")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        fst = os.fstat(fd)
        if (not stat.S_ISREG(fst.st_mode) or fst.st_ino != st.st_ino
                or fst.st_dev != st.st_dev or fst.st_size != st.st_size):
            raise Hold("HOLD: selected original input changed during admission")
        chunks = bytearray()
        while len(chunks) <= limit:
            block = os.read(fd, min(65536, limit + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        if not 0 < len(chunks) <= limit:
            raise Hold("HOLD: selected input size is invalid")
        return bytes(chunks)
    finally:
        os.close(fd)


def clean_text(raw: bytes) -> str:
    try:
        value = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        raise Hold("HOLD: expected UTF-8 text rather than a binary evidence object") from None
    if not value or any(ord(char) == 0 or (ord(char) < 32 and char not in "\r\n\t")
                        for char in value):
        raise Hold("HOLD: unsupported control characters in PRIVATE source text")
    return value


def file_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def save_json(path: Path, data: dict) -> None:
    file_new(path, (json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)
                    + "\n").encode("utf-8"))


def read_json(path: Path, max_bytes: int) -> dict:
    raw = private_input(str(path), max_bytes)
    try:
        def no_duplicate(pairs):
            data = {}
            for key, value in pairs:
                if key in data:
                    raise ValueError("duplicate")
                data[key] = value
            return data
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicate,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if type(data) is not dict:
            raise ValueError("non object")
        return data
    except (UnicodeError, ValueError):
        raise Hold("HOLD: original PRIVATE manifest is not a canonical object") from None


def landing(count: int, final: bool, stages: list[str] | None = None,
            include_masking_cues: bool = False) -> bytes:
    items = ("<li><a href='PRIVATE-HUMAN-summary.html'>Offline redacted HUMAN review</a></li>"
             "<li><a href='PRIVATE-source-bindings.json'>Original unsigned PRIVATE byte identity</a></li>"
             "<li><a href='PRIVATE-HUMAN-decisions.csv'>PRIVATE original-bound HUMAN decisions CSV</a></li>")
    if not final:
        items += "<li><a href='PRIVATE-HUMAN-editor.html'>PRIVATE offline interactive HUMAN decision editor</a></li>"
    if include_masking_cues and not final:
        items += ("<li><a href='PRIVATE-masking-cues.html'>Optional PRIVATE "
                  "literal masking-cue navigation (never a safety score)</a></li>"
                  "<li><a href='PRIVATE-HAR-HOLD.html'>PRIVATE original "
                  "HAR whole-copy HOLD attention (HUMAN-only)</a></li>"
                  "<li><a href='PRIVATE-HAR-INVENTORY.html'>PRIVATE HAR "
                  "original-ordinal marker-category inventory</a></li>"
                  "<li><a href='PRIVATE-HAR-QUEUE.html'>PRIVATE HAR "
                  "HUMAN category attention queue</a></li>"
                  "<li><a href='PRIVATE-HAR-QUESTIONS.html'>PRIVATE "
                  "source-minimal HUMAN HAR review checklist</a></li>"
                  "<li><a href='PRIVATE-HAR-ACTIONS.html'>PRIVATE HAR "
                  "original-ordinal HUMAN action worksheet</a></li>"
                  "<li><a href='PRIVATE-HAR-ACTIONS.csv'>PRIVATE HAR "
                  "HUMAN action CSV template (non-authorising)</a></li>"
                  "<li><a href='PRIVATE-HAR-STUDIO.html'>PRIVATE HAR "
                  "offline HUMAN action status Studio (source-minimal)</a></li>")
    if final:
        items += "<li><a href='PRIVATE-redacted-notes.txt'>PRIVATE combined HUMAN redacted notes</a></li>"
    for slot in range(1, count + 1):
        filename = f"notes/PRIVATE-redacted-{slot:03d}.txt"
        items += ("<li><a href='" + filename + "'>PRIVATE redacted note #" + str(slot) +
                  "</a></li>")
    verdict = ("HUMAN decision copy only; never consent or release"
               if final else "Unreviewed; edit the PRIVATE CSV locally, then finalize")
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; connect-src 'none'; form-action 'none'">
<title>LightUp PRIVATE HUMAN credential review</title>
<style>""" + CSS + """</style><header>
<p class="warn">PRIVATE / REVIEW_ONLY / HOLD · NOT PUBLIC-SAFE</p>
<h1>Credential-masked original assessment notes</h1>
<p>""" + html.escape(verdict) + """</p>
<p>Original individually selected PRIVATE note sources: """ + str(count) +
""". The original source bytes are not included in this packet. All output
remains confidential: credential masking is pattern-based, not complete secret
detection, personal-data removal or source authentication.</p></header><main class="panel">
<h2>Local HUMAN workroom</h2><ul>""" + items + """</ul>
<p>No live target, scan, model, upload, worker, authorization,
retest or external publication occurred. Separate verified current source
ownership, independent privacy/security review, distinct client/operator
consent with at-use revocation and explicit HUMAN GO remain required before
any external customer use. INCUBATE M3/M7 PLAN/LAB ONLY DRAFT/HOLD.</p>
</main></html>""").encode("utf-8")


def summary(rows: list[dict], stages: list[dict]) -> bytes:
    panels = []
    for row, decision in zip(rows, stages):
        text = html.escape(row["redacted_text"])
        human_note = html.escape(decision["human_note"])
        panels.append("<section class='panel'><h2>Original source position #" +
                      str(row["ordinal"]) + "</h2><p>HUMAN review stage: <b>" +
                      html.escape(decision["human_stage"]) + "</b></p>" +
                      ("<p>HUMAN note: " + human_note + "</p>" if human_note else "") +
                      "<p class='warn'>Pattern-redacted content still PRIVATE. "
                      "Check remaining secrets and personal details manually.</p><pre>" +
                      text + "</pre></section>")
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp PRIVATE HUMAN masked notes</title>
<style>""" + CSS + """</style><header><p class="warn">PRIVATE / NOT ANONYMIZED /
NO AUTHORIZATION OR SECURITY ATTESTATION</p>
<h1>Original LightUp source-bound redacted notes</h1>
<p>Partial pattern-based removal of known credential shapes only. Other secrets,
personal data and client identifiers may remain. Both redacted content and source
hashes are PRIVATE. No verified source provenance, client or operator consent,
scan, release or approval is implied.</p></header><main>""" +
            "".join(panels) +
            """</main><footer class="panel">INCUBATE M3/M7 · PLAN/LAB ONLY ·
DRAFT/HOLD. No model, network, execution, evidence replay or external
delivery.</footer></html>""").encode("utf-8")


def csv_document(rows: list[dict]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, CSV_FIELDS, lineterminator="\r\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: row[key] for key in CSV_FIELDS})
    return stream.getvalue().encode("utf-8")


def prepare(inputs: list[str], parent_string: str,
            include_masking_cues: bool = False,
            created_room: list[Path] | None = None) -> int:
    if not 1 <= len(inputs) <= MAX_FILES:
        raise Hold("HOLD: choose 1-12 existing original PRIVATE text notes")
    parent = private_directory(parent_string)
    paths = [str(Path(value).absolute()) for value in inputs]
    if len(set(paths)) != len(paths):
        raise Hold("HOLD: repeated original PRIVATE file")
    rows = []
    counter = 0
    for index, path in enumerate(paths, start=1):
        raw = private_input(path, MAX_FILE)
        counter += len(raw)
        if counter > MAX_TOTAL:
            raise Hold("HOLD: aggregate PRIVATE input exceeds 2 MiB")
        before = clean_text(raw)
        after = mask_private_notes(before)
        if len(after.encode("utf-8")) > MAX_MASKED_FILE:
            raise Hold("HOLD: original redaction output exceeded PRIVATE size bound")
        row = {
            "ordinal": index,
            "source_sha256_unsigned": sha256(raw).hexdigest(),
            "source_bytes": len(raw),
            "output_sha256_unsigned": sha256(after.encode("utf-8")).hexdigest(),
            "output_bytes": len(after.encode("utf-8")),
            "redacted_text": after,
            "source_ordinal": index,
            # Wholly withheld derived HAR-like copies cannot be inspected
            # without the original private source holder. Surface this as a
            # starting HUMAN discussion state, never as an automatic permit
            # or permanent decision. Existing non-HAR behavior is unchanged.
            "human_stage": ("SOURCE_OWNER_REQUIRED"
                            if after == "[WITHHELD_PRIVATE_HAR_UNREVIEWED]"
                            else "NEEDS_HUMAN_REVIEW"),
            "human_note": "",
        }
        rows.append(row)
    kit = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-notes-", dir=parent))
    os.chmod(kit, 0o700)
    ready = False
    try:
        notes = kit / "notes"
        notes.mkdir(mode=0o700)
        for row in rows:
            file_new(notes / f"PRIVATE-redacted-{row['ordinal']:03d}.txt",
                     row["redacted_text"].encode("utf-8"))
        bindings = {
            "schema": SCHEMA, "claimed_status": "HOLD", "reviewed": False,
            "pattern_redaction_not_anonymization": True,
            "sources": [
                {key: row[key] for key in ("ordinal", "source_sha256_unsigned",
                                           "source_bytes", "output_sha256_unsigned",
                                           "output_bytes")} for row in rows
            ],
            **{flag: False for flag in FALSE_FLAGS},
        }
        save_json(kit / "PRIVATE-source-bindings.json", bindings)
        file_new(kit / "PRIVATE-HUMAN-decisions.csv", csv_document(rows))
        file_new(kit / "PRIVATE-HUMAN-summary.html", summary(rows, rows))
        file_new(kit / "PRIVATE-HUMAN-editor.html", render_browser_studio(rows))
        if include_masking_cues:
            # Optional source-minimal navigator inside a NEW original kit.
            # Existing original canonical source metadata remains unchanged.
            # For independently source-bound custody use native masking-cues.
            from private_masking_cues import cues as cue_rows, cue_page, cue_csv
            mask_rows = cue_rows(rows)
            file_new(kit / "PRIVATE-masking-cues.html", cue_page(mask_rows))
            file_new(kit / "PRIVATE-masking-cues.csv", cue_csv(mask_rows))
            from private_har_hold_board import (
                render as render_har_hold, render_inventory, inventory_csv,
            )
            file_new(kit / "PRIVATE-HAR-HOLD.html", render_har_hold(rows))
            file_new(kit / "PRIVATE-HAR-INVENTORY.html", render_inventory(rows))
            file_new(kit / "PRIVATE-HAR-INVENTORY.csv", inventory_csv(rows))
            from private_har_attention_queue import render as render_har_queue
            file_new(kit / "PRIVATE-HAR-QUEUE.html", render_har_queue(rows))
            from private_har_questions import render as render_questions
            file_new(kit / "PRIVATE-HAR-QUESTIONS.html", render_questions(rows))
            from private_har_worklist import worksheet_html, worksheet_csv
            file_new(kit / "PRIVATE-HAR-ACTIONS.html", worksheet_html(rows))
            file_new(kit / "PRIVATE-HAR-ACTIONS.csv", worksheet_csv(rows))
            from private_har_studio import render as render_har_studio
            file_new(kit / "PRIVATE-HAR-STUDIO.html", render_har_studio(rows))
        file_new(kit / "OPEN-PRIVATE.html",
                 landing(len(rows), False,
                         include_masking_cues=include_masking_cues))
        ready = True
        if created_room is not None:
            created_room.append(kit)
        print("REVIEW_ONLY: local PRIVATE notes workroom created; credential masking is incomplete.")
        print("OPEN LOCALLY: " + str(kit / "OPEN-PRIVATE.html"))
        return 2
    finally:
        if not ready:
            shutil.rmtree(kit)


def load_decisions(raw: bytes, bindings: list[dict]) -> list[dict]:
    try:
        stream = io.StringIO(clean_text(raw), newline="")
        reader = csv.DictReader(stream)
        if reader.fieldnames != list(CSV_FIELDS):
            raise ValueError()
        rows = list(reader)
    except (ValueError, csv.Error):
        raise Hold("HOLD: HUMAN decision CSV has an unsupported schema") from None
    if len(rows) != len(bindings) or not 1 <= len(rows) <= MAX_FILES:
        raise Hold("HOLD: incomplete or extra HUMAN source choices")
    out = []
    for ordinal, (decision, original) in enumerate(zip(rows, bindings), start=1):
        if (None in decision or set(decision) != set(CSV_FIELDS)
                or decision["source_ordinal"] != str(ordinal)
                or decision["source_sha256_unsigned"] != original["source_sha256_unsigned"]
                or decision["human_stage"] not in STAGES):
            raise Hold("HOLD: original PRIVATE identity or HUMAN decision is invalid")
        note = decision["human_note"]
        if (type(note) is not str or len(note) > 500
                or note.lstrip().startswith(("=", "+", "-", "@"))
                or unsafe_private_csv_note(note, 500)
                or any(ord(ch) < 32 and ch not in "\t" for ch in note)):
            raise Hold("HOLD: HUMAN note must be short plain text")
        out.append({"human_stage": decision["human_stage"], "human_note": note,
                    "source_ordinal": ordinal,
                    "source_sha256_unsigned": original["source_sha256_unsigned"]})
    return out


def load_workroom(kit: Path) -> tuple[dict, list[dict], list[dict]]:
    bindings = read_json(kit / "PRIVATE-source-bindings.json", 128 * 1024)
    if (bindings.get("schema") != SCHEMA or bindings.get("claimed_status") != "HOLD"
            or bindings.get("reviewed") is not False
            or bindings.get("pattern_redaction_not_anonymization") is not True
            or any(bindings.get(flag) is not False for flag in FALSE_FLAGS)):
        raise Hold("HOLD: source workroom manifest changed or implies authority")
    sources = bindings.get("sources")
    if type(sources) is not list or not 1 <= len(sources) <= MAX_FILES:
        raise Hold("HOLD: source workroom manifest missing original slots")
    rows = []
    total = 0
    for slot, source in enumerate(sources, start=1):
        if (type(source) is not dict or set(source) != {
                "ordinal", "source_sha256_unsigned", "source_bytes",
                "output_sha256_unsigned", "output_bytes"}
                or type(source["ordinal"]) is not int or source["ordinal"] != slot
                or type(source["source_bytes"]) is not int
                or not 0 < source["source_bytes"] <= MAX_FILE
                or type(source["output_bytes"]) is not int
                or not 0 < source["output_bytes"] <= MAX_MASKED_FILE
                or any(type(source[key]) is not str or len(source[key]) != 64
                       or any(c not in "0123456789abcdef" for c in source[key])
                       for key in ("source_sha256_unsigned", "output_sha256_unsigned"))):
            raise Hold("HOLD: original workroom source byte identity is invalid")
        raw = private_input(str(kit / "notes" / f"PRIVATE-redacted-{slot:03d}.txt"), MAX_MASKED_FILE)
        total += len(raw)
        if total > MAX_TOTAL * 2 or len(raw) != source["output_bytes"]:
            raise Hold("HOLD: original redacted source content size was modified")
        if sha256(raw).hexdigest() != source["output_sha256_unsigned"]:
            raise Hold("HOLD: original redacted note content changed")
        rows.append({"ordinal": slot, "redacted_text": clean_text(raw), **source})
    return bindings, sources, rows


def finalize(kit_string: str, choices: str, parent_string: str) -> int:
    kit = private_directory(kit_string)
    parent = private_directory(parent_string)
    bindings, sources, rows = load_workroom(kit)
    decisions = load_decisions(private_input(choices, 64 * 1024), sources)
    for row, decision in zip(rows, decisions):
        row.update(decision)
    destination = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-human-handoff-", dir=parent))
    os.chmod(destination, 0o700)
    completed = False
    try:
        notes = destination / "notes"
        notes.mkdir(mode=0o700)
        combined = []
        for row in rows:
            name = f"PRIVATE-redacted-{row['ordinal']:03d}.txt"
            value = row["redacted_text"].encode("utf-8")
            file_new(notes / name, value)
            combined.append("===== ORIGINAL SOURCE POSITION #" + str(row["ordinal"]) + " =====\n" +
                            "HUMAN stage: " + row["human_stage"] + "\n" +
                            row["redacted_text"].rstrip("\r\n") + "\n")
        file_new(destination / "PRIVATE-redacted-notes.txt", ("\n".join(combined)).encode("utf-8"))
        new_bindings = dict(bindings)
        new_bindings["human_proposals_recorded"] = True
        new_bindings["claimed_status"] = "HOLD"
        new_bindings["human_stages"] = {
            state: sum(x["human_stage"] == state for x in decisions) for state in ALLOWED
        }
        decision_bytes = csv_document(rows)
        new_bindings["human_decisions_sha256_unsigned"] = sha256(decision_bytes).hexdigest()
        save_json(destination / "PRIVATE-source-bindings.json", new_bindings)
        file_new(destination / "PRIVATE-HUMAN-decisions.csv", decision_bytes)
        file_new(destination / "PRIVATE-HUMAN-summary.html", summary(rows, decisions))
        file_new(destination / "OPEN-PRIVATE.html", landing(len(rows), True))
        completed = True
        print("HOLD: PRIVATE HUMAN decision handoff locally prepared, not an external release.")
        print("OPEN LOCALLY: " + str(destination / "OPEN-PRIVATE.html"))
        return 3
    finally:
        if not completed:
            shutil.rmtree(destination)


def main() -> int:
    p = argparse.ArgumentParser(description="PRIVATE human credential-masking workroom; no release or network")
    commands = p.add_subparsers(dest="action", required=True)
    prepared = commands.add_parser("prepare", help="masked PRIVATE copies + local HUMAN review")
    prepared.add_argument("--source", action="append", required=True,
                          help="1-12 existing owner-private UTF-8 notes")
    prepared.add_argument("--private-parent", required=True, help="owner-only mode 0700 directory")
    prepared.add_argument(
        "--with-mask-cues", action="store_true",
        help="embed additional PRIVATE source-minimal HUMAN masking-cue preview in NEW original kit")
    har_workflow_0 = commands.add_parser("har-review-start", help="offline PRIVATE source-bound HAR HUMAN workflow; HOLD")
    har_workflow_0.add_argument("--source", action="append", required=True)
    har_workflow_0.add_argument("--private-parent", required=True)
    har_workflow_1 = commands.add_parser("har-review-reopen", help="offline PRIVATE source-bound HAR HUMAN workflow; HOLD")
    har_workflow_1.add_argument("--workflow-room", required=True)
    har_workflow_2 = commands.add_parser("har-review-progress", help="offline PRIVATE source-bound HAR HUMAN workflow; HOLD")
    har_workflow_2.add_argument("--workflow-room", required=True)
    har_workflow_2.add_argument("--edited-actions", required=True)
    har_workflow_2.add_argument("--private-parent", required=True)
    har_workflow_2.add_argument("--previous-round", action="append", default=[],
                                help="0–7 existing original-bound HUMAN status packets")
    har_workflow_3 = commands.add_parser("har-review-progress-reopen", help="offline PRIVATE source-bound HAR HUMAN workflow; HOLD")
    har_workflow_3.add_argument("--workflow-room", required=True)
    har_workflow_3.add_argument("--progress-room", required=True)
    har_workflow_4 = commands.add_parser("har-review-history", help="offline PRIVATE source-bound HAR HUMAN workflow; HOLD")
    har_workflow_4.add_argument("--workflow-room", required=True)
    har_workflow_4.add_argument("--round", action="append", required=True)
    har_workflow_4.add_argument("--private-parent", required=True)
    har_workflow_5 = commands.add_parser("har-review-history-reopen", help="offline PRIVATE source-bound HAR HUMAN workflow; HOLD")
    har_workflow_5.add_argument("--workflow-room", required=True)
    har_workflow_5.add_argument("--round", action="append", required=True)
    har_workflow_5.add_argument("--history-room", required=True)
    har_desk = commands.add_parser("har-review-desk", help="owner-private original-bound offline HUMAN next-action desk; HOLD")
    har_desk.add_argument("--workflow-room", required=True)
    har_desk.add_argument("--progress-room", action="append", required=True)
    har_desk.add_argument("--private-parent", required=True)
    har_desk_read = commands.add_parser("har-review-desk-reopen", help="immutable PRIVATE HUMAN next-action desk; HOLD")
    har_desk_read.add_argument("--workflow-room", required=True)
    har_desk_read.add_argument("--progress-room", action="append", required=True)
    har_desk_read.add_argument("--desk-room", required=True)
    har_revision = commands.add_parser(
        "har-review-revision", help="source-bound earlier-to-new PRIVATE HAR HUMAN handoff; HOLD")
    har_revision.add_argument("--older-workflow", required=True)
    har_revision.add_argument("--newer-workflow", required=True)
    har_revision.add_argument("--older-progress-room", required=True)
    har_revision.add_argument("--private-parent", required=True)
    har_revision_reopen = commands.add_parser(
        "har-review-revision-reopen",
        help="read-only original-bound PRIVATE HAR revision handoff; HOLD")
    har_revision_reopen.add_argument("--older-workflow", required=True)
    har_revision_reopen.add_argument("--newer-workflow", required=True)
    har_revision_reopen.add_argument("--older-progress-room", required=True)
    har_revision_reopen.add_argument("--revision-room", required=True)
    cues_command = commands.add_parser(
        "masking-cues",
        help="original-bound PRIVATE HUMAN literal masking-marker navigation; REVIEW_ONLY")
    cues_command.add_argument("--original-kit", required=True,
                              help="unchanged PRIVATE original prepared notes workroom")
    cues_command.add_argument("--private-parent", required=True,
                              help="owner-private output folder")
    cues_reopen = commands.add_parser(
        "masking-cues-reopen",
        help="read-only exact-original PRIVATE HUMAN masking cue receipt; always HOLD")
    cues_reopen.add_argument("--original-kit", required=True)
    cues_reopen.add_argument("--room", required=True,
                             help="unchanged original PRIVATE masking cue room")
    har_progress = commands.add_parser(
        "har-action-progress",
        help="PRIVATE original-bound manual HAR status import, always HOLD")
    har_progress.add_argument("--original-kit", required=True)
    har_progress.add_argument("--cue-room", required=True,
                              help="unchanged source-bound masking-cue packet v18")
    har_progress.add_argument("--edited-actions", required=True,
                              help="separate owner-only manually edited actions CSV")
    har_progress.add_argument("--private-parent", required=True,
                              help="owner-only 0700 destination parent")
    har_progress_reopen = commands.add_parser(
        "har-action-progress-reopen",
        help="read-only source-bound PRIVATE HUMAN HAR progress packet; HOLD")
    har_progress_reopen.add_argument("--original-kit", required=True)
    har_progress_reopen.add_argument("--cue-room", required=True)
    har_progress_reopen.add_argument("--progress-room", required=True)
    har_history = commands.add_parser(
        "har-action-history",
        help="source-bound 2–8 PRIVATE HUMAN task-status rounds; always HOLD")
    har_history.add_argument("--original-kit", required=True)
    har_history.add_argument("--cue-room", required=True)
    har_history.add_argument("--round", action="append", required=True,
                             help="2–8 existing PRIVATE source-bound status packets, oldest first")
    har_history.add_argument("--private-parent", required=True)
    har_history_reopen = commands.add_parser(
        "har-action-history-reopen",
        help="read-only original-source PRIVATE HUMAN round history admission")
    har_history_reopen.add_argument("--original-kit", required=True)
    har_history_reopen.add_argument("--cue-room", required=True)
    har_history_reopen.add_argument("--round", action="append", required=True,
                                    help="the same original human-supplied ordered rounds")
    har_history_reopen.add_argument("--history-room", required=True)
    finished = commands.add_parser("finalize", help="source-bound local PRIVATE HUMAN handoff only")
    finished.add_argument("--original-kit", required=True, help="unchanged PRIVATE workroom")
    finished.add_argument("--decisions", required=True, help="locally completed PRIVATE HUMAN CSV")
    finished.add_argument("--private-parent", required=True, help="owner-only mode 0700 directory")
    selected = commands.add_parser(
        "select", help="explicit selected-only PRIVATE internal HUMAN discussion, never release")
    selected.add_argument("--completed-packet", required=True,
                          help="unchanged completed original HUMAN packet")
    selection = selected.add_mutually_exclusive_group(required=True)
    selection.add_argument("--position", action="append", type=int,
                           help="original source position, individually marked INTERNAL_REVIEW_ONLY")
    selection.add_argument("--plan", help="owner-private 0600 original source-reference-only selection plan")
    selected.add_argument("--private-parent", required=True, help="owner-only 0700 directory")
    changes = commands.add_parser(
        "changes", help="source-bound comparison of two completed direct HUMAN revisions, private only")
    changes.add_argument("--earlier", required=True, help="original completed HUMAN packet")
    changes.add_argument("--later", required=True, help="direct completed HUMAN revision packet")
    changes.add_argument("--private-parent", required=True, help="owner-only 0700 directory")
    history = commands.add_parser(
        "history", help="source-bound PRIVATE HUMAN review history for 2-16 direct revisions")
    history.add_argument("--packet", action="append", required=True,
                         help="completed original HUMAN packet, earliest to latest")
    history.add_argument("--private-parent", required=True, help="owner-only 0700 directory")
    agenda = commands.add_parser("agenda", help="source-bound local HUMAN discussion agenda editor")
    agenda.add_argument("--history-kit", required=True, help="original PRIVATE completed history workroom")
    agenda.add_argument("--latest-packet", required=True, help="actual final completed original HUMAN packet")
    agenda.add_argument("--private-parent", required=True, help="owner-only 0700 directory")
    agenda_end = commands.add_parser(
        "agenda-finalize", help="strict original-bound HUMAN CSV discussion proposal packet only")
    agenda_end.add_argument("--agenda-kit", required=True, help="original PRIVATE agenda workroom")
    agenda_end.add_argument("--history-kit", required=True, help="original PRIVATE history workroom")
    agenda_end.add_argument("--latest-packet", required=True, help="actual final original HUMAN packet")
    agenda_end.add_argument("--completed-csv", required=True, help="complete PRIVATE original HUMAN proposal CSV")
    agenda_end.add_argument("--private-parent", required=True, help="owner-only 0700 directory")
    team = commands.add_parser(
        "agenda-team", help="minimum-necessary PRIVATE HUMAN discussion for one proposed team")
    team.add_argument("--review-kit", required=True, help="original completed PRIVATE HUMAN agenda review")
    team.add_argument("--history-kit", required=True, help="original completed PRIVATE history")
    team.add_argument("--latest-packet", required=True, help="original latest completed HUMAN packet")
    team.add_argument("--team", required=True,
                      choices=("SECURITY", "PRIVACY", "CLIENT_OPERATIONS", "PLATFORM"))
    team.add_argument("--private-parent", required=True, help="owner-only 0700 directory")
    extra = commands.add_parser(
        "mask-copy", help="manual extra PRIVATE masking of selected completed original HUMAN notes")
    extra.add_argument("--completed-packet", required=True, help="completed original owner-private HUMAN packet")
    extra.add_argument("--rules-json", required=True,
                       help="owner-only 0600 secret-containing HUMAN literal masking rules")
    extra.add_argument("--private-parent", required=True, help="owner-only 0700 directory")
    sensitivity = commands.add_parser(
        "sensitivity-prepare", help="source-bound PRIVATE HUMAN privacy concern worksheet")
    sensitivity.add_argument("--completed-packet", required=True)
    sensitivity.add_argument("--private-parent", required=True)
    sensitivity.add_argument("--with-mask-cues", action="store_true",
                             help="embed original PRIVATE masking cue navigation and read-only receipt")
    sensitivity_end = commands.add_parser(
        "sensitivity-finalize", help="source-bound HUMAN sensitivity review; always HOLD")
    sensitivity_end.add_argument("--completed-packet", required=True)
    sensitivity_end.add_argument("--triage-kit", required=True)
    sensitivity_end.add_argument("--completed-csv", required=True)
    sensitivity_end.add_argument("--private-parent", required=True)
    reconcile = commands.add_parser(
        "sensitivity-reconcile", help="original-bound 2-8 HUMAN reviewers and new blank PRIVATE review")
    reconcile.add_argument("--completed-packet", required=True)
    reconcile.add_argument("--review", action="append", required=True,
                           help="separately completed owner-private HUMAN sensitivity packet")
    reconcile.add_argument("--private-parent", required=True)
    workbench = commands.add_parser(
        "sensitivity-workbench", help="one PRIVATE offline HUMAN timeline/reviewer suite and next draft")
    workbench.add_argument("--completed-packet", required=True)
    workbench.add_argument("--mode", required=True, choices=("timeline", "reviewers"))
    workbench.add_argument("--review", action="append", required=True,
                           help="two to eight completed source-bound HUMAN reviews")
    workbench.add_argument("--private-parent", required=True)
    discussion = commands.add_parser(
        "sensitivity-discussion-receive",
        help="strictly receive original-bound selected HUMAN discussion CSV; always HOLD")
    discussion.add_argument("--completed-packet", required=True)
    discussion.add_argument("--review", action="append", required=True,
                            help="two to eight original completed PRIVATE HUMAN reviewer packets")
    discussion.add_argument("--selected-csv", required=True,
                            help="owner-private exact browser selected-discussion CSV")
    discussion.add_argument("--private-parent", required=True)
    reopen_discussion = commands.add_parser(
        "sensitivity-discussion-reopen",
        help="read-only re-admission of previous PRIVATE selected HUMAN discussion room")
    reopen_discussion.add_argument("--completed-packet", required=True)
    reopen_discussion.add_argument("--review", action="append", required=True)
    reopen_discussion.add_argument("--room", required=True,
                                   help="unchanged original owner-private received discussion room")
    actions_plan = commands.add_parser(
        "sensitivity-discussion-actions-prepare",
        help="offline selected HUMAN conversation editor with new owner-private room")
    actions_plan.add_argument("--completed-packet", required=True)
    actions_plan.add_argument("--review", action="append", required=True)
    actions_plan.add_argument("--room", required=True, help="original received selected discussion room")
    actions_plan.add_argument("--private-parent", required=True)
    actions_end = commands.add_parser(
        "sensitivity-discussion-actions-finalize",
        help="strictly finalize all selected PRIVATE HUMAN next actions; always HOLD")
    actions_end.add_argument("--completed-packet", required=True)
    actions_end.add_argument("--review", action="append", required=True)
    actions_end.add_argument("--room", required=True)
    actions_end.add_argument("--draft-room", required=True)
    actions_end.add_argument("--completed-csv", required=True)
    actions_end.add_argument("--private-parent", required=True)
    action_reopen = commands.add_parser(
        "sensitivity-discussion-actions-reopen",
        help="read-only exact-source PRIVATE HUMAN action packet reopening; HOLD")
    action_reopen.add_argument("--completed-packet", required=True)
    action_reopen.add_argument("--review", action="append", required=True)
    action_reopen.add_argument("--room", required=True)
    action_reopen.add_argument("--final-room", required=True)
    action_history = commands.add_parser(
        "sensitivity-discussion-actions-history",
        help="2-8 completed ORIGINAL PRIVATE HUMAN action rounds, never a fix verdict")
    action_history.add_argument("--completed-packet", required=True)
    action_history.add_argument("--review", action="append", required=True)
    action_history.add_argument("--room", required=True)
    action_history.add_argument("--final-room", action="append", required=True,
                                help="completed HUMAN action room in manually declared chronological order")
    action_history.add_argument("--private-parent", required=True)
    history_reopen = commands.add_parser(
        "sensitivity-discussion-actions-history-reopen",
        help="read-only original-bound PRIVATE HUMAN action chronology; HOLD")
    history_reopen.add_argument("--completed-packet", required=True)
    history_reopen.add_argument("--review", action="append", required=True)
    history_reopen.add_argument("--room", required=True)
    history_reopen.add_argument("--final-room", action="append", required=True)
    history_reopen.add_argument("--history-room", required=True)
    history_receive = commands.add_parser(
        "sensitivity-discussion-actions-history-receive",
        help="receive original-bound PRIVATE HUMAN chronology browser selection; HOLD")
    history_receive.add_argument("--completed-packet", required=True)
    history_receive.add_argument("--review", action="append", required=True)
    history_receive.add_argument("--room", required=True)
    history_receive.add_argument("--final-room", action="append", required=True)
    history_receive.add_argument("--history-room", required=True)
    history_receive.add_argument("--selected-csv", required=True)
    history_receive.add_argument("--private-parent", required=True)
    history_receive_reopen = commands.add_parser(
        "sensitivity-discussion-actions-history-receive-reopen",
        help="read-only original-bound selected HUMAN history receipt reopening; HOLD")
    history_receive_reopen.add_argument("--completed-packet", required=True)
    history_receive_reopen.add_argument("--review", action="append", required=True)
    history_receive_reopen.add_argument("--room", required=True)
    history_receive_reopen.add_argument("--final-room", action="append", required=True)
    history_receive_reopen.add_argument("--history-room", required=True)
    history_receive_reopen.add_argument("--selected-room", required=True)
    team_prepare = commands.add_parser(
        "sensitivity-discussion-team-prepare",
        help="source-bound offline PRIVATE HUMAN internal team routing proposals")
    team_prepare.add_argument("--completed-packet", required=True)
    team_prepare.add_argument("--review", action="append", required=True)
    team_prepare.add_argument("--room", required=True)
    team_prepare.add_argument("--final-room", action="append", required=True)
    team_prepare.add_argument("--history-room", required=True)
    team_prepare.add_argument("--private-parent", required=True)
    team_finalize = commands.add_parser(
        "sensitivity-discussion-team-finalize",
        help="write PRIVATE original-bound HUMAN proposed-team packet; always HOLD")
    team_finalize.add_argument("--completed-packet", required=True)
    team_finalize.add_argument("--review", action="append", required=True)
    team_finalize.add_argument("--room", required=True)
    team_finalize.add_argument("--final-room", action="append", required=True)
    team_finalize.add_argument("--history-room", required=True)
    team_finalize.add_argument("--draft-room", required=True)
    team_finalize.add_argument("--completed-csv", required=True)
    team_finalize.add_argument("--private-parent", required=True)
    team_reopen = commands.add_parser(
        "sensitivity-discussion-team-reopen",
        help="read-only original-bound PRIVATE HUMAN proposed-team packet; HOLD")
    team_reopen.add_argument("--completed-packet", required=True)
    team_reopen.add_argument("--review", action="append", required=True)
    team_reopen.add_argument("--room", required=True)
    team_reopen.add_argument("--final-room", action="append", required=True)
    team_reopen.add_argument("--history-room", required=True)
    team_reopen.add_argument("--team-room", required=True)
    sensitivity_attention = commands.add_parser(
        "sensitivity-attention", help="PRIVATE changed/new HUMAN concern handoff from two original reviews")
    sensitivity_attention.add_argument("--completed-packet", required=True)
    sensitivity_attention.add_argument("--earlier-review", required=True)
    sensitivity_attention.add_argument("--later-review", required=True)
    sensitivity_attention.add_argument("--kind", required=True,
                                       choices=("ALL_ATTENTION", "CHANGES_ONLY", "CURRENT_WITHHOLD"))
    sensitivity_attention.add_argument("--topic", choices=(
        "CREDENTIALS", "PERSONAL_DATA", "CLIENT_DATA", "OTHER", "UNKNOWN"))
    sensitivity_attention.add_argument("--private-parent", required=True)
    sensitivity_history = commands.add_parser(
        "sensitivity-history", help="2-8 completed original-bound HUMAN sensitivity rounds and next blank review")
    sensitivity_history.add_argument("--completed-packet", required=True)
    sensitivity_history.add_argument("--review", action="append", required=True,
                                     help="completed PRIVATE sensitivity review, earliest first")
    sensitivity_history.add_argument("--private-parent", required=True)
    sensitivity_focus = commands.add_parser(
        "sensitivity-focus", help="minimum-necessary PRIVATE HUMAN concern agenda; always HOLD")
    sensitivity_focus.add_argument("--completed-packet", required=True)
    sensitivity_focus.add_argument("--triage-review", required=True)
    sensitivity_focus.add_argument("--topic", required=True,
                                   choices=("CREDENTIALS", "PERSONAL_DATA",
                                            "CLIENT_DATA", "OTHER", "UNKNOWN"))
    sensitivity_focus.add_argument("--status", required=True,
                                   choices=("PENDING", "REVIEW_REQUIRED", "WITHHOLD"))
    sensitivity_focus.add_argument("--private-parent", required=True)
    original_mask = commands.add_parser(
        "mask-template", help="prepare original-source-bound HUMAN extra masking request template")
    original_mask.add_argument("--completed-packet", required=True,
                               help="completed original owner-private HUMAN packet")
    original_mask.add_argument("--private-parent", required=True, help="owner-only 0700 directory")
    args = p.parse_args()
    try:
        if args.action == "prepare":
            return prepare(args.source, args.private_parent,
                           include_masking_cues=args.with_mask_cues)
        if args.action in {"har-review-revision",
                            "har-review-revision-reopen"}:
            from private_har_revision import create as create_revision, reopen as reopen_revision
            if args.action == "har-review-revision":
                return create_revision(args.older_workflow,
                                       args.newer_workflow,
                                       args.older_progress_room,
                                       args.private_parent)
            return reopen_revision(args.older_workflow,
                                   args.newer_workflow,
                                   args.older_progress_room,
                                   args.revision_room)
        if args.action.startswith("har-review-"):
            from private_har_workflow import (
                prepare as start_review, reopen as reopen_review,
                progress as import_review, admit as admit_review,
            )
            if args.action in {"har-review-desk", "har-review-desk-reopen"}:
                from private_har_review_desk import create as create_desk, reopen as reopen_desk
                if args.action == "har-review-desk":
                    return create_desk(args.workflow_room, args.progress_room,
                                       args.private_parent)
                return reopen_desk(args.workflow_room, args.progress_room,
                                   args.desk_room)
            if args.action == "har-review-start":
                return start_review(args.source, args.private_parent)
            if args.action == "har-review-reopen":
                return reopen_review(args.workflow_room)
            if args.action == "har-review-progress":
                return import_review(args.workflow_room, args.edited_actions,
                                     args.private_parent, args.previous_round)
            original, cue_room = admit_review(args.workflow_room)
            if args.action == "har-review-progress-reopen":
                from private_har_progress import reopen_progress
                return reopen_progress(str(original), str(cue_room),
                                       args.progress_room)
            from private_har_history import create as start_history, reopen as reopen_history
            if args.action == "har-review-history":
                return start_history(str(original), str(cue_room),
                                     args.round, args.private_parent)
            return reopen_history(str(original), str(cue_room),
                                  args.round, args.history_room)
        if args.action == "masking-cues":
            from private_masking_cues import create as create_masking_cues
            return create_masking_cues(args.original_kit, args.private_parent)
        if args.action == "masking-cues-reopen":
            from private_masking_cues import reopen as reopen_masking_cues
            return reopen_masking_cues(args.original_kit, args.room)
        if args.action == "har-action-progress":
            from private_har_progress import import_progress
            return import_progress(args.original_kit, args.cue_room,
                                   args.edited_actions, args.private_parent)
        if args.action == "har-action-progress-reopen":
            from private_har_progress import reopen_progress
            return reopen_progress(args.original_kit, args.cue_room,
                                   args.progress_room)
        if args.action in {"har-action-history",
                            "har-action-history-reopen"}:
            from private_har_history import create as create_har_history, reopen as reopen_har_history
            if args.action == "har-action-history":
                return create_har_history(args.original_kit, args.cue_room,
                                          args.round, args.private_parent)
            return reopen_har_history(args.original_kit, args.cue_room,
                                      args.round, args.history_room)
        if args.action == "finalize":
            return finalize(args.original_kit, args.decisions, args.private_parent)
        # Offline local PRIVATE operations only, never a scan/target dispatch.
        if args.action == "changes":
            from revision_changes import compare
            return compare(args.earlier, args.later, args.private_parent)
        if args.action == "history":
            from revision_history import build_history
            return build_history(args.packet, args.private_parent)
        if args.action in {"agenda", "agenda-finalize"}:
            from history_agenda import prepare as prepare_agenda, finalize as finalize_agenda
            if args.action == "agenda":
                return prepare_agenda(args.history_kit, args.latest_packet, args.private_parent)
            return finalize_agenda(args.agenda_kit, args.history_kit, args.latest_packet,
                                   args.completed_csv, args.private_parent)
        if args.action == "agenda-team":
            from agenda_team import team_packet
            return team_packet(args.review_kit, args.history_kit, args.latest_packet,
                               args.team, args.private_parent)
        if args.action == "mask-copy":
            from manual_mask import prepare as prepare_extra_mask
            return prepare_extra_mask(args.completed_packet, args.rules_json, args.private_parent)
        if args.action == "mask-template":
            from manual_mask import template as prepare_mask_template
            return prepare_mask_template(args.completed_packet, args.private_parent)
        if args.action == "sensitivity-prepare":
            from privacy_triage import prepare as prepare_sensitivity
            return prepare_sensitivity(args.completed_packet, args.private_parent,
                                       include_masking_cues=args.with_mask_cues)
        if args.action == "sensitivity-finalize":
            from privacy_triage import finalize as finalize_sensitivity
            return finalize_sensitivity(args.completed_packet, args.triage_kit,
                                        args.completed_csv, args.private_parent)
        if args.action == "sensitivity-reconcile":
            from privacy_triage_reconcile import build as build_sensitivity_reconcile
            return build_sensitivity_reconcile(
                args.completed_packet, args.review, args.private_parent)
        if args.action == "sensitivity-workbench":
            from privacy_triage_workbench import build as build_sensitivity_workbench
            return build_sensitivity_workbench(
                args.completed_packet, args.mode, args.review, args.private_parent)
        if args.action == "sensitivity-discussion-receive":
            from privacy_triage_selected_discussion import create as receive_discussion
            return receive_discussion(
                args.completed_packet, args.review, args.selected_csv,
                args.private_parent)
        if args.action == "sensitivity-discussion-reopen":
            from privacy_triage_selected_discussion import reopen as reopen_discussion
            return reopen_discussion(args.completed_packet, args.review, args.room)
        if args.action in {
            "sensitivity-discussion-actions-prepare",
            "sensitivity-discussion-actions-finalize",
        }:
            from privacy_triage_discussion_actions import plan, close
            if args.action == "sensitivity-discussion-actions-prepare":
                return plan(args.completed_packet, args.review, args.room,
                            args.private_parent)
            return close(args.completed_packet, args.review, args.room,
                         args.draft_room, args.completed_csv, args.private_parent)
        if args.action == "sensitivity-discussion-actions-reopen":
            from privacy_triage_discussion_actions import reopen_actions
            return reopen_actions(args.completed_packet, args.review,
                                  args.room, args.final_room)
        if args.action == "sensitivity-discussion-actions-history":
            from privacy_triage_discussion_history import create as action_history
            return action_history(args.completed_packet, args.review,
                                  args.room, args.final_room,
                                  args.private_parent)
        if args.action == "sensitivity-discussion-actions-history-reopen":
            from privacy_triage_discussion_history import reopen_history
            return reopen_history(args.completed_packet, args.review,
                                  args.room, args.final_room,
                                  args.history_room)
        if args.action == "sensitivity-discussion-actions-history-receive":
            from privacy_triage_history_selection import receive
            return receive(args.completed_packet, args.review, args.room,
                           args.final_room, args.history_room,
                           args.selected_csv, args.private_parent)
        if args.action == "sensitivity-discussion-actions-history-receive-reopen":
            from privacy_triage_history_selection import reopen_selected
            return reopen_selected(args.completed_packet, args.review,
                                   args.room, args.final_room,
                                   args.history_room, args.selected_room)
        if args.action in {"sensitivity-discussion-team-prepare",
                           "sensitivity-discussion-team-finalize"}:
            from privacy_triage_discussion_team import prepare, finalize
            if args.action == "sensitivity-discussion-team-prepare":
                return prepare(args.completed_packet, args.review, args.room,
                               args.final_room, args.history_room,
                               args.private_parent)
            return finalize(args.completed_packet, args.review, args.room,
                            args.final_room, args.history_room,
                            args.draft_room, args.completed_csv,
                            args.private_parent)
        if args.action == "sensitivity-discussion-team-reopen":
            from privacy_triage_discussion_team import reopen_team
            return reopen_team(args.completed_packet, args.review,
                               args.room, args.final_room,
                               args.history_room, args.team_room)
        if args.action == "sensitivity-attention":
            from privacy_triage_attention import create as build_sensitivity_attention
            return build_sensitivity_attention(
                args.completed_packet, args.earlier_review, args.later_review,
                args.kind, args.topic, args.private_parent)
        if args.action == "sensitivity-history":
            from privacy_triage_history import build as build_sensitivity_history
            return build_sensitivity_history(
                args.completed_packet, args.review, args.private_parent)
        if args.action == "sensitivity-focus":
            from privacy_triage_focus import focus as sensitivity_focus_workroom
            return sensitivity_focus_workroom(
                args.completed_packet, args.triage_review, args.topic,
                args.status, args.private_parent)
        from selective_handoff import prepare_selected
        return prepare_selected(args.completed_packet, args.position or [],
                                args.private_parent, args.plan)
    except (Hold, OSError, ValueError, KeyError, TypeError) as exc:
        print(str(exc) if isinstance(exc, Hold) else "HOLD: PRIVATE notes workflow refused",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    # CLI companions import 'notes'. Avoid importing this same executable a
    # second time under a distinct module identity: two Hold classes would
    # leak an uncaught traceback (and possibly PRIVATE pathname) on refusal.
    # Keep one canonical import identity before dispatching any companion.
    sys.modules.setdefault("notes", sys.modules[__name__])
    raise SystemExit(main())
