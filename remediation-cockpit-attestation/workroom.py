#!/usr/bin/env python3
"""Encrypted portable HUMAN workroom: original source-free inbox + private plan.

Both inputs are independently admitted before sealed transport. Recipient
rebuilds native cockpits and private coordination board in a NEW atomic 0700
workspace, never applying original remediation or changing authorization.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import html
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import attest
import coordination
import inbox
import portable_inbox
import transport

review = attest.review
native = attest.read_cockpit
MAGIC = b"LIGHTUP-PRIVATE-HUMAN-WORKROOM-1\x00"
DOMAIN = b"LightUp PRIVATE HUMAN portable encrypted workroom v1\x00"
KIND = "lightup.private_human_encrypted_workroom_handoff"
MAX_INNER = portable_inbox.MAX_ENCRYPTED
MAX_CLEAR = 48 * 1024 * 1024
MAX_BLOB = MAX_CLEAR + len(MAGIC) + 12 + 16
WARNING = ("Separate local HUMAN follow-up planning, not original source "
           "authenticity, real operator identity, client consent, remediation, "
           "authorization or verified retest.")


def require(state: bool) -> None:
    attest.require(state)


def derived(secret: bytes) -> bytes:
    return hmac.new(secret, DOMAIN, hashlib.sha256).digest()


def original_encrypted_inbox(folder: Path, key_file: Path) -> bytes:
    plaintext, _ = portable_inbox.extract(folder, key_file)
    secret = attest.key_bytes(key_file)
    nonce = os.urandom(12)
    ciphertext = AESGCM(portable_inbox.group_key(secret)).encrypt(
        nonce, plaintext, portable_inbox.MAGIC)
    result = portable_inbox.MAGIC + nonce + ciphertext
    require(len(result) <= MAX_INNER)
    return result


def seal(inbox_dir: Path, plan_file: Path, key_file: Path, output: Path) -> dict:
    require(output != plan_file and output != key_file and
            output != inbox_dir and inbox_dir not in output.parents and
            not output.exists() and not output.is_symlink())
    source, digest = coordination.admitted_inbox(inbox_dir, key_file)
    plan, raw = coordination.decrypt(plan_file, key_file, source, digest)
    inner = original_encrypted_inbox(inbox_dir, key_file)
    require(coordination.admitted_inbox(inbox_dir, key_file) == (source, digest) and
            attest.private_file(plan_file, coordination.MAX_FILE) == raw)
    document = {"kind": KIND, "schema_version": 1,
                "inbox_ciphertext": transport.b64(inner),
                "encrypted_human_plan": transport.b64(raw),
                "plan_revision": plan["revision"]}
    plaintext = transport.canonical(document)
    require(len(plaintext) <= MAX_CLEAR)
    secret = attest.key_bytes(key_file)
    nonce = os.urandom(12)
    encrypted = AESGCM(derived(secret)).encrypt(nonce, plaintext, MAGIC)
    attest.exclusive_private_write(output, MAGIC + nonce + encrypted)
    return plan


def root_page(revision: int, slots: int) -> bytes:
    require(type(revision) is int and 1 <= revision <= 1000 and
            type(slots) is int and 1 <= slots <= inbox.MAX)
    content = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        'style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\';">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>PRIVATE HUMAN Workroom</title>'
        '<style>body{font:16px system-ui,sans-serif;max-width:800px;margin:3rem auto;'
        'background:#f5f7fb;padding:1rem;color:#18263c}a{display:block;padding:1rem;'
        'background:#fff;border:1px solid #cad4e4;margin:1rem 0;color:#174997}'
        'p{line-height:1.6}small{color:#40536b}</style></head><body>'
        '<h1>PRIVATE HUMAN Workroom</h1><p>Offline local plan revision '+
        str(revision)+' for '+str(slots)+' separately source-free admitted slots.</p>'
        '<a href="board/index.html">Open PRIVATE HUMAN assignments and due dates</a>'
        '<a href="inbox/index.html">Open original source-free HUMAN Evidence Inbox</a>'
        '<p><small>'+html.escape(WARNING)+'</small></p>'
        '</body></html>\n'
    )
    return content.encode("utf-8")


def open_workroom(package: Path, key_file: Path,
                  output_parent: Path) -> tuple[Path, dict]:
    inbox.strict_private_dir(output_parent)
    require(package.is_absolute() and package != key_file and
            package != output_parent and package not in output_parent.parents and
            output_parent not in key_file.parents)
    secret = attest.key_bytes(key_file)
    raw = attest.private_file(package, MAX_BLOB)
    require(raw.startswith(MAGIC) and len(raw) > len(MAGIC) + 12 + 16)
    nonce = raw[len(MAGIC):len(MAGIC)+12]
    plaintext = AESGCM(derived(secret)).decrypt(
        nonce, raw[len(MAGIC)+12:], MAGIC)
    require(len(plaintext) <= MAX_CLEAR)
    obj = json.loads(plaintext.decode("ascii"),
                     object_pairs_hook=transport.no_duplicate_pairs)
    require(type(obj) is dict and set(obj) ==
            {"kind", "schema_version", "inbox_ciphertext",
             "encrypted_human_plan", "plan_revision"} and
            obj["kind"] == KIND and type(obj["schema_version"]) is int and
            obj["schema_version"] == 1 and
            type(obj["plan_revision"]) is int and
            1 <= obj["plan_revision"] <= 1000 and
            plaintext == transport.canonical(obj))
    inner = transport.decode_b64(obj["inbox_ciphertext"], MAX_INNER)
    plan_raw = transport.decode_b64(obj["encrypted_human_plan"], coordination.MAX_FILE)
    # No original source or plan file is modified. All private files remain
    # inside the newly allocated and unpublished staging workspace.
    temporary = Path(tempfile.mkdtemp(prefix=".lightup-human-workroom-", dir=output_parent))
    completed = False
    try:
        private_inner = temporary / ".inner.ltinbox"
        attest.exclusive_private_write(private_inner, inner)
        admitted_path, original = portable_inbox.receive(private_inner, key_file, temporary)
        native.workspace.exclusive_dir_publish(admitted_path, temporary / "inbox")
        private_inner.unlink()
        plan_file = temporary / "plan.ltplan"
        attest.exclusive_private_write(plan_file, plan_raw)
        source, digest = coordination.admitted_inbox(temporary / "inbox", key_file)
        plan, _ = coordination.decrypt(plan_file, key_file, source, digest)
        require(plan["revision"] == obj["plan_revision"] and
                original == source)
        coordination.publish(temporary / "inbox", key_file, plan_file,
                             temporary / "board", linked_workroom=True)
        import workroom_home
        attest.exclusive_private_write(temporary / "index.html",
                                       workroom_home.render(plan))
        # Final admission against all original native source-free members,
        # encrypted plan attachment, and reconstructed coordination HTML.
        require(coordination.admitted_inbox(temporary / "inbox", key_file)
                == (source, digest) and
                coordination.decrypt(plan_file, key_file, source, digest)[0] == plan and
                (temporary / "board" / "index.html").is_file() and
                (temporary / "inbox" / "index.html").is_file() and
                attest.private_file(package, MAX_BLOB) == raw)
        destination = output_parent / ("lightup-human-workroom-" + secrets.token_hex(16))
        require(not destination.exists() and not destination.is_symlink())
        native.workspace.exclusive_dir_publish(temporary, destination)
        completed = True
        return destination, plan
    finally:
        if not completed:
            shutil.rmtree(temporary)


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Send or reopen one offline encrypted PRIVATE HUMAN workroom with "
        "native source-free inbox and immutable local slot assignment plan"))
    actions = parser.add_subparsers(dest="action", required=True)
    sending = actions.add_parser("send", help="Seal native inbox plus bound encrypted HUMAN plan")
    sending.add_argument("--inbox", type=Path, required=True)
    sending.add_argument("--plan", type=Path, required=True)
    sending.add_argument("--key-file", type=Path, required=True)
    sending.add_argument("--output", type=Path, required=True)
    opening = actions.add_parser("receive", help="Reconstruct full PRIVATE browser workroom atomically")
    opening.add_argument("--input", type=Path, required=True)
    opening.add_argument("--key-file", type=Path, required=True)
    opening.add_argument("--output-parent", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "send":
            plan = seal(args.inbox, args.plan, args.key_file, args.output)
            print("One PRIVATE encrypted source-free HUMAN workroom file published.")
        else:
            target, plan = open_workroom(args.input, args.key_file, args.output_parent)
            print("PRIVATE HUMAN workroom atomically published: " + str(target))
            print("Open the local index.html; never serve the PRIVATE workroom publicly.")
        print("Encrypted LOCAL HUMAN plan revision " + str(plan["revision"]) +
              "; " + str(len(plan["slots"])) +
              " source-free slots; no original evidence or verified fixes.")
        print("No customer consent, sender identity, authorization or retest certified.")
        return 2
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, OverflowError,
            RecursionError, InvalidTag, transport.binascii.Error, review.Hold):
        print("HOLD: PRIVATE HUMAN workroom admission failed; nothing authorized.",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
