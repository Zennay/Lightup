#!/usr/bin/env python3
"""Offline PRIVATE receipt of selectively encrypted HUMAN-only follow-up tasks.

Never accepts original evidence, signed claims or actual authority. Source
context is deliberately REDACTED before this package is created in the
original browser. Password protection is NOT sender authentication/consent.
"""
from __future__ import annotations

import argparse
import base64
from datetime import date
import getpass
import hashlib
import html
import os
from pathlib import Path
import secrets
import shutil
import sys

import schedule
import schedule_vault
import single_review

sys.path.insert(0, str(schedule.PARENT / "remediation-integrated-workspace"))
import encrypted_cockpit
import install
import workflow

KIND="lightup.selected_private_human_followup_encrypted.v1"
INNER="lightup.selected_private_human_followup.v1"
DISPOSITION="SELECTED_HUMAN_DRAFT_HOLD"
WARNING=("PRIVATE selected source-redacted HUMAN follow-up, not sender/client "
         "identity, consent, signed source, finding verification, remediation, "
         "retest, scan, grant or release.")
AAD=b"LIGHTUP_PRIVATE_HUMAN_SELECTED_HANDOFF_V1"
MAX_FILE=360000
MAX_CLEAR=262144
MAX_ITEMS=schedule.MAX_TASKS
ENVELOPE=frozenset(("kind","version","disposition","authority_granted",
                     "consent_verified","source_authenticated","remediation_verified",
                     "kdf","iterations","algorithm","salt_b64","nonce_b64",
                     "ciphertext_b64","warning"))
CONTENT=frozenset(("kind","version","disposition","authority_granted",
                    "consent_verified","source_authenticated","remediation_verified",
                    "warning","includes_owner_labels","includes_private_notes","items"))
ITEM=frozenset(("reason","stage","due","next_action","owner","human_note"))
STYLE="""body{font:15px/1.5 system-ui,sans-serif;max-width:950px;margin:25px auto;padding:20px;color:#132840;background:white}
h1{font-size:1.7rem}aside{background:#fff6e5;border:2px solid #bd8a41;padding:1rem;border-radius:8px}
article{padding:16px;border:1px solid #b6c6d8;margin:12px 0;border-radius:10px;break-inside:avoid}
dt{font-weight:650}dd{white-space:pre-wrap;margin:0 0 .6rem}
small{display:block;color:#50647c}@media print{article{break-inside:avoid}}"""

def require(value: bool, reason: str) -> None:
    single_review.review.require(value,reason)

def exactly_false(obj: dict) -> bool:
    return (obj.get("authority_granted") is False and
            obj.get("consent_verified") is False and
            obj.get("source_authenticated") is False and
            obj.get("remediation_verified") is False)

def decrypt(archive: Path) -> dict:
    encrypted=encrypted_cockpit.private_envelope(archive)
    require(100 <= len(encrypted) <= MAX_FILE,"Encrypted HUMAN-only handoff outside bounded size")
    doc=schedule_vault.strict_json(encrypted, MAX_FILE)
    require(type(doc) is dict and set(doc) == ENVELOPE
            and doc["kind"] == KIND and type(doc["version"]) is int
            and doc["version"] == 1 and doc["disposition"] == DISPOSITION
            and exactly_false(doc)
            and doc["kdf"] == "PBKDF2-HMAC-SHA256"
            and type(doc["iterations"]) is int and doc["iterations"] == 600000
            and doc["algorithm"] == "AES-256-GCM" and doc["warning"] == WARNING,
            "Unknown PRIVATE selected HUMAN envelope or elevated authority")
    salt=schedule_vault.decode64(doc["salt_b64"],16,16)
    iv=schedule_vault.decode64(doc["nonce_b64"],12,12)
    cipher=schedule_vault.decode64(doc["ciphertext_b64"],17,MAX_CLEAR+16)
    require(sys.stdin.isatty(),
            "Private HUMAN handoff password requires an interactive terminal")
    phrase=getpass.getpass("Private selected HUMAN handoff password: ")
    require(type(phrase) is str and 12 <= len(phrase) <= 256,
            "PRIVATE HUMAN password length outside bound")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    try:
        raw=AESGCM(encrypted_cockpit.aead_key(phrase,salt)).decrypt(
            iv,cipher,AAD)
    except InvalidTag as exc:
        raise single_review.review.Hold(
            "Incorrect selected HUMAN password or altered ciphertext") from exc
    doc_clear=schedule_vault.strict_json(raw,MAX_CLEAR)
    require(encrypted_cockpit.private_envelope(archive) == encrypted,
            "Encrypted HUMAN transfer changed during native admission")
    return doc_clear

def admit(doc: dict) -> tuple[list[dict],bool,bool]:
    require(type(doc) is dict and set(doc) == CONTENT
            and doc["kind"] == INNER and type(doc["version"]) is int
            and doc["version"] == 1 and doc["disposition"] == DISPOSITION
            and exactly_false(doc) and doc["warning"] == WARNING
            and type(doc["includes_owner_labels"]) is bool
            and type(doc["includes_private_notes"]) is bool,
            "Unrecognized source-redacted PRIVATE HUMAN follow-up")
    items=doc["items"]
    require(type(items) is list and 1 <= len(items) <= MAX_ITEMS,
            "Source-redacted HUMAN task selection incomplete or too large")
    owners=doc["includes_owner_labels"]
    notes=doc["includes_private_notes"]
    for row in items:
        require(type(row) is dict and set(row) == ITEM
                and type(row["reason"]) is str
                and row["reason"] in single_review.read_cockpit.triage.REASONS
                and type(row["stage"]) is str
                and row["stage"] in single_review.STAGES
                and schedule_vault.local_text(row["next_action"],240,960,True)
                and schedule_vault.local_text(row["owner"],64,256)
                and schedule_vault.local_text(row["human_note"],240,960,True)
                and (owners or row["owner"] == "")
                and (notes or row["human_note"] == "")
                and (row["due"] == "" or (
                    type(row["due"]) is str and len(row["due"]) == 10 and
                    date.fromisoformat(row["due"]).isoformat() == row["due"])),
                "Unsafe HUMAN field in selected PRIVATE follow-up")
    return items,owners,notes

def html_page(items: list[dict], owners: bool, notes: bool) -> bytes:
    q=lambda value:html.escape(str(value),quote=True)
    style_hash=base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode("ascii")
    sections=[
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; base-uri \'none\'; connect-src \'none\'; script-src \'none\'; style-src \'sha256-'+style_hash+'\'">',
        '<title>PRIVATE selected HUMAN follow-up</title><style>',STYLE,
        '</style></head><body><h1>PRIVATE selected HUMAN follow-up</h1>',
        '<aside>',q(WARNING),
        '<p>Recipient task notes and deadlines are self-declared HUMAN planning only; '
        'no original source IDs, packet SHA digests, evidence, case IDs, verified '
        'remediation, authenticated sender or client consent are included. '
        'Do not share without separate real recipient permission.</p></aside>',
        '<p>',str(len(items)),' source-redacted HUMAN tasks chosen by original operator. '
        'Original source history and item identity intentionally cannot be reconstructed.</p>'
    ]
    for i,item in enumerate(items,1):
        sections.extend(['<article><h2>Selected HUMAN task ',str(i),'</h2><dl>',
                         '<dt>Source-redacted HUMAN category</dt><dd>',q(item["reason"]),'</dd>',
                         '<dt>HUMAN self-declared status</dt><dd>',q(item["stage"]),'</dd>',
                         '<dt>Tentative due</dt><dd>',q(item["due"] or "Unscheduled"),'</dd>',
                         '<dt>HUMAN requested next action</dt><dd>',
                         q(item["next_action"] or "Not recorded"),'</dd>'])
        if owners:
            sections.extend(['<dt>HUMAN owner label (self-declared)</dt><dd>',
                             q(item["owner"] or "Unassigned"),'</dd>'])
        if notes:
            sections.extend(['<dt>Confidential PRIVATE HUMAN note</dt><dd>',
                             q(item["human_note"] or "No note"),'</dd>'])
        sections.extend(['</dl><small>Anonymous label, never a confirmed security finding '
                         'or recipient authorization.</small></article>'])
    sections.append('</body></html>')
    rendered="".join(sections).encode("utf-8")
    require(len(rendered) <= MAX_CLEAR,
            "PRIVATE HUMAN printable recipient view exceeds limit")
    return rendered

def receive(archive: Path, destination: Path) -> None:
    require(destination.is_absolute() and
            destination.parent == destination.parent.resolve(strict=True)
            and not destination.exists() and not destination.is_symlink()
            and archive != destination and destination not in archive.parents
            and archive not in destination.parents and archive.parent != destination,
            "Select fresh, non-overlapping PRIVATE recipient folder")
    schedule.private_parent(destination.parent)
    plain=decrypt(archive)
    items,owners,notes=admit(plain)
    stage=destination.parent/(".lightup-selected-human-" + secrets.token_hex(12))
    os.mkdir(stage,0o700)
    try:
        schedule.private_write(stage,"private-followup.html",html_page(items,owners,notes))
        schedule.private_write(stage,"anonymous-summary.json",schedule.canonical({
            "kind":"lightup.selected_private_human_followup_receipt",
            "version":1,"disposition":"HUMAN_ONLY_DRAFT_HOLD",
            "authority_granted":False,"consent_verified":False,
            "source_authenticated":False,"remediation_verified":False,
            "selected_reason_groups":len(items),
            "includes_human_owner_labels":owners,
            "includes_private_human_notes":notes,
            "warning":WARNING,
        }))
        portal=workflow.page(
            "PRIVATE selected source-redacted HUMAN follow-up",
            [("Open selected private HUMAN read-only follow-up",
              "private-followup.html",
              "Local scriptless recipient brief without any original source identity.")],
            WARNING+" Local passphrase secrecy and private files are not actual consent.")
        install.write_file(stage/"index.html",portal)
        require(not destination.exists(),
                "PRIVATE recipient output appeared before exclusive publish")
        workflow.workspace.exclusive_dir_publish(stage,destination)
    finally:
        if stage.exists():shutil.rmtree(stage)
    print("REVIEW_ONLY: selected source-redacted PRIVATE HUMAN handoff:",destination/"index.html")
    print("Items:",len(items),"Private owner labels included:",owners,"Notes included:",notes)
    print("No original evidence, source identity, verified remediation or grant.")

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--handoff",type=Path,required=True,
                   help="Locally transferred encrypted selected PRIVATE .luhq")
    p.add_argument("--output-dir",type=Path,required=True,
                   help="Fresh absolute PRIVATE 0700 recipient folder")
    a=p.parse_args()
    try:
        receive(a.handoff,a.output_dir)
        return 2
    except (single_review.review.Hold,install.Hold,OSError,ValueError,
            TypeError,KeyError,ImportError,RuntimeError,OverflowError,
            EOFError,UnicodeError) as exc:
        print("HOLD: PRIVATE source-redacted HUMAN handoff:",exc,file=sys.stderr)
        return 3

if __name__=="__main__":
    raise SystemExit(main())
