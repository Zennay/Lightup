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
from lightup.redaction import redact_text  # Exact unchanged original #672 source.
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


def landing(count: int, final: bool, stages: list[str] | None = None) -> bytes:
    items = ("<li><a href='PRIVATE-HUMAN-summary.html'>Offline redacted HUMAN review</a></li>"
             "<li><a href='PRIVATE-source-bindings.json'>Original unsigned PRIVATE byte identity</a></li>"
             "<li><a href='PRIVATE-HUMAN-decisions.csv'>PRIVATE original-bound HUMAN decisions CSV</a></li>")
    if not final:
        items += "<li><a href='PRIVATE-HUMAN-editor.html'>PRIVATE offline interactive HUMAN decision editor</a></li>"
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


def prepare(inputs: list[str], parent_string: str) -> int:
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
        after = redact_text(before)
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
            "human_stage": "NEEDS_HUMAN_REVIEW",
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
        file_new(kit / "OPEN-PRIVATE.html", landing(len(rows), False))
        ready = True
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
    finished = commands.add_parser("finalize", help="source-bound local PRIVATE HUMAN handoff only")
    finished.add_argument("--original-kit", required=True, help="unchanged PRIVATE workroom")
    finished.add_argument("--decisions", required=True, help="locally completed PRIVATE HUMAN CSV")
    finished.add_argument("--private-parent", required=True, help="owner-only mode 0700 directory")
    args = p.parse_args()
    try:
        if args.action == "prepare":
            return prepare(args.source, args.private_parent)
        return finalize(args.original_kit, args.decisions, args.private_parent)
    except (Hold, OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, Hold) else "HOLD: PRIVATE notes workflow refused",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
