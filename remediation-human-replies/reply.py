#!/usr/bin/env python3
"""PRIVATE offline source-redacted HUMAN recipient reply round-trip.

Only consumes the held original encrypted .luhq source-free selected HUMAN
handoff via its *unchanged* native decrypt/admit logic. Neither this tool nor
a browser password authenticates a real sender, client, consent or remediation.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import html
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import unicodedata

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "remediation-recipient-scheduler"))
import queue_handoff as original
import schedule
import schedule_vault
import single_review
import encrypted_cockpit
import workflow

KIND = "lightup.private_source_redacted_human_reply.v1"
ENVELOPE_KIND = "lightup.private_source_redacted_human_reply_encrypted.v1"
DISPOSITION = "PRIVATE_HUMAN_RESPONSE_DRAFT_HOLD"
AAD = b"LIGHTUP_PRIVATE_SOURCE_REDACTED_HUMAN_REPLY_V1"
WARNING = ("PRIVATE source-redacted HUMAN replies only. No authenticated sender, "
           "client/operator consent, original finding/evidence, verified fix, "
           "retest, grant, disclosure approval, scan or release. DRAFT/HOLD.")
STAGES = frozenset(("received_human", "working_human",
                    "need_clarification_human", "answered_human_only",
                    "declined_human"))
MAX_REPLY = 262144
MAX_ENCRYPTED = 400000
FIELDS = frozenset(("kind", "version", "disposition", "authority_granted",
                    "consent_verified", "source_authenticated",
                    "remediation_verified", "warning", "source_redacted_sha256",
                    "responses"))
RESPONSE_FIELDS = frozenset(("ordinal", "reason", "status", "answer", "question"))
ENVELOPE_FIELDS = frozenset(("kind", "version", "disposition",
    "authority_granted", "consent_verified", "source_authenticated",
    "remediation_verified", "warning", "kdf", "iterations", "algorithm",
    "salt_b64", "nonce_b64", "ciphertext_b64"))
STYLE = """
body{font:16px/1.5 system-ui,sans-serif;background:#f3f6fb;color:#182c46;margin:0}
main{max-width:1040px;padding:1.5rem;margin:0 auto}
article,aside{background:#fff;padding:1rem 1.2rem;border-radius:10px;border:1px solid #bdccd9;margin:1rem 0}
aside{border-left:6px solid #9b681b}
label{display:block;margin:.8rem 0;font-weight:600}
textarea,select,input{display:block;font:inherit;box-sizing:border-box;width:100%;max-width:800px;padding:.65rem;border:1px solid #69819a;border-radius:6px}
textarea{min-height:5rem}button{border:1px solid #48709d;padding:.8rem 1rem;border-radius:7px;background:#fff;color:#163e6b;cursor:pointer}
button:focus-visible,select:focus-visible,textarea:focus-visible,input:focus-visible{outline:3px solid #bf8d2b}
small{color:#425a75}dd{white-space:pre-wrap;overflow-wrap:anywhere;margin:0 0 .7rem}
dt{font-weight:600}h1{font-size:1.8rem}@media print{button,form{display:none}article{break-inside:avoid}}
"""

def require(value: bool, reason: str) -> None:
    original.require(value, reason)

def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def canonical(obj: dict) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")

def source(archive: Path) -> tuple[dict, str, bytes]:
    packet = original.decrypt(archive)  # original strict encrypted admission + TTY password
    originals, _, _ = original.admit(packet)
    digest = sha(canonical(packet))
    raw = encrypted_cockpit.private_envelope(archive)
    require(len(originals) <= original.MAX_ITEMS, "Original selected HUMAN batch too large")
    return packet, digest, raw

def payload(packet: dict, digest: str, responses: list[dict]) -> dict:
    return {
        "kind": KIND, "version": 1, "disposition": DISPOSITION,
        "authority_granted": False, "consent_verified": False,
        "source_authenticated": False, "remediation_verified": False,
        "warning": WARNING, "source_redacted_sha256": digest,
        "original_items": packet["items"], "responses": responses,
    }

def responses_default(items: list[dict]) -> list[dict]:
    return [{"ordinal": i, "reason": row["reason"], "status": "received_human",
             "answer": "", "question": ""} for i, row in enumerate(items, 1)]

def admit_reply(obj: dict, packet: dict, digest: str) -> list[dict]:
    require(type(obj) is dict and frozenset(obj) == FIELDS
            and obj.get("kind") == KIND and type(obj.get("version")) is int
            and obj["version"] == 1 and obj.get("disposition") == DISPOSITION
            and obj.get("warning") == WARNING
            and original.exactly_false(obj)
            and obj.get("source_redacted_sha256") == digest,
            "HUMAN reply is not bound to exactly this original redacted handoff")
    rows = obj["responses"]
    require(type(rows) is list and len(rows) == len(packet["items"])
            and 1 <= len(rows) <= original.MAX_ITEMS,
            "Incomplete or oversized HUMAN reply membership")
    for i, (row, baseline) in enumerate(zip(rows, packet["items"]), 1):
        require(type(row) is dict and frozenset(row) == RESPONSE_FIELDS
                and type(row.get("ordinal")) is int and row["ordinal"] == i
                and row.get("reason") == baseline["reason"]
                and type(row.get("status")) is str and row["status"] in STAGES
                and schedule_vault.local_text(row.get("answer"), 240, 960, True)
                and schedule_vault.local_text(row.get("question"), 240, 960, True),
                "Invalid or reordered HUMAN reply, control chars or oversized answers")
    return rows

def hash_csp(raw: bytes) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii") + "'"

def editable_page(packet: dict, digest: str, previous: list[dict] | None = None) -> bytes:
    script = (HERE / "reply.js").read_bytes()
    require(len(script) < 32000 and b"</script" not in script.lower(),
            "Unsafe local recipient source script")
    seed = payload(packet, digest, previous if previous is not None else responses_default(packet["items"]))
    seed_json = json.dumps(seed, ensure_ascii=True, separators=(",", ":")).replace(
        "<", "\\u003c")
    policy = ("default-src 'none'; script-src " + hash_csp(script) +
              "; style-src " + hash_csp(STYLE.encode()) +
              "; connect-src 'none'; form-action 'none'; object-src 'none'; "
              "img-src 'none'; base-uri 'none'")
    parts = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width,initial-scale=1">',
             '<meta http-equiv="Content-Security-Policy" content="',
             html.escape(policy, quote=True), '">',
             '<title>LightUp PRIVATE HUMAN recipient replies</title><style>',
             STYLE, '</style></head><body><main><h1>PRIVATE recipient HUMAN replies</h1>',
             '<aside><strong>INCUBATE · DRAFT/HOLD</strong><p>',
             html.escape(WARNING), '</p>',
             '<p>Only the originally selected, source-redacted HUMAN tasks appear here. ',
             'Their order is not authenticated chronology or individual case identity. ',
             'The originating owner must separately authorize any disclosure. ',
             'No data is sent to a server. Browser entries are not autosaved; only ',
             'the deliberately exported encrypted file persists.</p></aside>',
             '<p><strong>', str(len(packet["items"])),
             '</strong> selected PRIVATE HUMAN tasks. A password is NOT ',
             'authenticated consent or sender proof.</p>',
             '<label>Filter recipient HUMAN tasks<input id="filter" type="search" ',
             'maxlength="120" placeholder="HUMAN reason or reply status"></label>',
             '<p id="summary" aria-live="polite"></p><section id="tasks"></section>',
             '<form id="save-form"><h2>Encrypt PRIVATE HUMAN return</h2>',
             '<p>A fresh locally encrypted <code>.luhr</code> contains only the ',
             'same selected redacted HUMAN task descriptions and human replies; ',
             'not original client/target/evidence IDs. Send only through an ',
             'independently authorized secure channel; share password separately.</p>',
             '<label>New unique passphrase (14–256 NFC characters)<input id="password" ',
             'type="password" minlength="14" maxlength="256" autocomplete="new-password" required></label>',
             '<label>Confirm passphrase<input id="confirm" type="password" ',
             'minlength="14" maxlength="256" autocomplete="new-password" required></label>',
             '<button type="submit">Encrypt and save private .luhr return</button>',
             '<button type="button" id="reset">Discard in-memory reply edits</button></form>',
             '<p id="message" role="status" aria-live="polite"></p>',
             '<script id="seed" type="application/json">', seed_json,
             '</script><script>', script.decode("utf-8"), '</script></main></body></html>']
    return "".join(parts).encode("utf-8")

def printable(packet: dict, rows: list[dict]) -> bytes:
    q = lambda x: html.escape(str(x), quote=True)
    parts = ['<!doctype html><html lang="en"><meta charset="utf-8">',
             '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
             'script-src \'none\'; style-src \'unsafe-inline\'; connect-src \'none\'; '
             'img-src \'none\'; object-src \'none\'; base-uri \'none\'">',
             '<title>PRIVATE HUMAN recipient return</title><style>', STYLE,
             '</style><main><h1>PRIVATE source-redacted HUMAN return</h1><aside>',
             q(WARNING), '<p>Recipient answers remain self-declared, never ',
             'source verification, a valid remediation, retest or authorization. ',
             'No original case identity is recoverable from these selected items.</p></aside>']
    for index, (base, row) in enumerate(zip(packet["items"], rows), 1):
        parts.extend(['<article><h2>Selected HUMAN task ', str(index), '</h2><dl>',
                      '<dt>Original redacted HUMAN reason</dt><dd>', q(base["reason"]), '</dd>',
                      '<dt>Originating HUMAN request</dt><dd>',
                      q(base["next_action"] or "Not recorded"), '</dd>',
                      '<dt>Recipient HUMAN status</dt><dd>', q(row["status"]), '</dd>',
                      '<dt>Recipient private answer</dt><dd>', q(row["answer"] or "Not recorded"), '</dd>',
                      '<dt>Further HUMAN question</dt><dd>', q(row["question"] or "None"), '</dd>',
                      '</dl></article>'])
    parts.append('</main>')
    result = "".join(parts).encode("utf-8")
    require(len(result) <= MAX_REPLY, "Scriptless PRIVATE HUMAN reply too large")
    return result

def exclusive_output(output: Path, archives: list[Path], contents: dict[str, bytes]) -> None:
    require(output.is_absolute() and output.parent == output.parent.resolve(strict=True)
            and not output.exists() and not output.is_symlink(),
            "Choose a NEW absolute PRIVATE output directory")
    schedule.private_parent(output.parent)
    for archive in archives:
        require(archive.is_absolute() and archive.parent == archive.parent.resolve(strict=True)
                and archive not in output.parents and output not in archive.parents
                and archive.parent != output and archive != output,
                "PRIVATE inputs cannot overlap output")
    staging = output.parent / (".lightup-human-reply-" + secrets.token_hex(12))
    os.mkdir(staging, 0o700)
    try:
        for filename, body in contents.items():
            schedule.private_write(staging, filename, body)
        require(not output.exists(), "Private output appeared during preparation")
        workflow.workspace.exclusive_dir_publish(staging, output)
    finally:
        if staging.exists():
            shutil.rmtree(staging)

def prepare(archive: Path, output: Path) -> None:
    require(output.is_absolute() and not output.exists()
            and archive.is_absolute() and archive != output
            and archive.parent != output and archive not in output.parents,
            "Separate original encrypted source-redacted input from fresh PRIVATE output")
    packet, digest, exact = source(archive)
    body = editable_page(packet, digest)
    require(encrypted_cockpit.private_envelope(archive) == exact,
            "Original selected HUMAN encrypted handoff changed during publication")
    exclusive_output(output, [archive], {
        "index.html": body,
        "README.txt": (WARNING + "\nPrivate offline HTML can expose originally "
                       "selected HUMAN planning text; do not distribute it.\n"
                       "Edit locally, export password-encrypted .luhr, then use "
                       "reply.py open with original .luhq and received .luhr.\n").encode(),
    })
    print("REVIEW_ONLY: PRIVATE source-redacted HUMAN recipient reply:", output / "index.html")

def open_reply(reply_file: Path, archive: Path, output: Path, editable: bool = False) -> None:
    require(reply_file.is_absolute() and archive.is_absolute() and reply_file != archive,
            "Original .luhq and reply .luhr must be separate private inputs")
    packet, digest, source_bytes = source(archive)
    encrypted = schedule_vault.private_vault(reply_file)
    doc = schedule_vault.strict_json(encrypted, MAX_ENCRYPTED)
    require(frozenset(doc) == ENVELOPE_FIELDS and doc.get("kind") == ENVELOPE_KIND
            and type(doc.get("version")) is int and doc["version"] == 1
            and doc.get("disposition") == DISPOSITION and doc.get("warning") == WARNING
            and original.exactly_false(doc)
            and doc.get("kdf") == "PBKDF2-HMAC-SHA256"
            and type(doc.get("iterations")) is int and doc["iterations"] == 600000
            and doc.get("algorithm") == "AES-256-GCM",
            "Unknown PRIVATE HUMAN reply envelope or elevated authority")
    salt = schedule_vault.decode64(doc["salt_b64"], 16, 16)
    nonce = schedule_vault.decode64(doc["nonce_b64"], 12, 12)
    cipher = schedule_vault.decode64(doc["ciphertext_b64"], 17, MAX_REPLY + 16)
    require(sys.stdin.isatty(), "PRIVATE password needs interactive terminal")
    phrase = getpass.getpass("Separate HUMAN reply passphrase: ")
    require(type(phrase) is str and 14 <= len(phrase) <= 256
            and unicodedata.normalize("NFC", phrase) == phrase
            and phrase == phrase.strip()
            and all(unicodedata.category(c)[0] != "C" for c in phrase),
            "PRIVATE recipient reply password outside NFC/length bound")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    try:
        raw = AESGCM(encrypted_cockpit.aead_key(phrase, salt)).decrypt(nonce, cipher, AAD)
    except InvalidTag as exc:
        raise single_review.review.Hold(
            "Wrong private HUMAN reply password or altered ciphertext") from exc
    body = schedule_vault.strict_json(raw, MAX_REPLY)
    replies = admit_reply(body, packet, digest)
    require(schedule_vault.private_vault(reply_file) == encrypted
            and encrypted_cockpit.private_envelope(archive) == source_bytes,
            "Original PRIVATE encrypted handoff/reply changed during admission")
    counts = {stage: sum(row["status"] == stage for row in replies)
              for stage in sorted(STAGES)}
    counts.update({"kind": "lightup.anonymous_human_reply_counts.v1",
                   "disposition": DISPOSITION,
                   "authority_granted": False, "consent_verified": False,
                   "source_authenticated": False, "remediation_verified": False,
                   "selected_human_tasks": len(replies),
                   "warning": WARNING})
    contents = {
        "index.html": (editable_page(packet, digest, replies) if editable
                       else printable(packet, replies)),
        "anonymous-counts.json": schedule.canonical(counts),
    }
    if editable:
        contents["README.txt"] = (
            "PRIVATE editable resumed HUMAN reply; same exact original redacted "
            "selection and previous encrypted response. This HTML intentionally "
            "contains plaintext PRIVATE self-declared recipient answers. Export "
            "a NEW encrypted .luhr; do not treat HUMAN state as verified.\n"
        ).encode("utf-8")
    exclusive_output(output, [archive, reply_file], contents)
    print("REVIEW_ONLY: PRIVATE source-redacted HUMAN " +
          ("editable resume:" if editable else "response:"), output / "index.html")
    print("No original findings, verified fixes or client/operator consent implied.")

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    options = parser.add_subparsers(dest="action", required=True)
    for name in ("prepare", "open", "resume"):
        p = options.add_parser(name)
        p.add_argument("--handoff", type=Path, required=True,
                       help="Original encrypted source-redacted .luhq HUMAN handoff")
        p.add_argument("--output-dir", type=Path, required=True,
                       help="NEW absolute owner-private 0700 output folder")
        if name in ("open", "resume"):
            p.add_argument("--reply", type=Path, required=True,
                           help="Received browser-encrypted PRIVATE HUMAN .luhr response")
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            prepare(args.handoff, args.output_dir)
        else:
            open_reply(args.reply, args.handoff, args.output_dir,
                       editable=args.action == "resume")
        return 2
    except (single_review.review.Hold, OSError, ValueError, KeyError, TypeError,
            UnicodeError, RuntimeError, ImportError, OverflowError) as exc:
        print("HOLD: source-redacted PRIVATE HUMAN reply: " + str(exc), file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
