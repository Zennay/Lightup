#!/usr/bin/env python3
"""PRIVATE offline encrypted HUMAN journal vault for ONE admitted Cockpit.

No original source/notes are sent, no client authentication, grant, scan,
verified fix, remediated finding, real consent or release authority.
This is a local passphrase-protected data container, NOT a sender signature.
"""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import secrets
import sys

import encrypted_cockpit as crypto
import install
import single_review
import single_brief

review = single_review.review
KIND = "lightup.private_sourcebound_human_journal_vault"
WARNING = single_review.VAULT_WARNING
DISPOSITION = "ENCRYPTED_HUMAN_JOURNAL_NOT_ACTION_AUTHORITY"
AAD = b"LIGHTUP_PRIVATE_SOURCEBOUND_HUMAN_JOURNAL_AES_GCM_V1"
MAX_JOURNAL = 262144
MAX_FILE = 360000
FIELDS = frozenset(("kind", "schema_version", "disposition", "kdf", "iterations",
                    "salt_b64", "nonce_b64", "ciphertext_b64",
                    "authority_granted", "consent_verified", "remediation_verified",
                    "warning"))

def require(ok: bool, reason: str) -> None:
    review.require(ok, reason)

def original(cockpit: Path, raw: bytes) -> None:
    require(type(raw) is bytes and 0 < len(raw) <= MAX_JOURNAL,
            "Original source-bound HUMAN journal exceeds bounded size")
    base, source_key, manifest, portfolio = single_review.original(cockpit)
    single_review.admit_journal(raw, base, source_key)
    single_review.read_cockpit.inspect(cockpit)
    require(review.private_read(cockpit / "manifest.json") == manifest
            and review.private_read(cockpit / "portfolio.json") == portfolio,
            "Original source-free owner packet changed during HUMAN journal admission")

def sealed_json(ciphertext: bytes, salt: bytes, nonce: bytes) -> bytes:
    return install.canonical({
        "kind": KIND, "schema_version": 1, "disposition": DISPOSITION,
        "kdf": "PBKDF2-HMAC-SHA256", "iterations": crypto.ITERATIONS,
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "authority_granted": False, "consent_verified": False,
        "remediation_verified": False, "warning": WARNING,
    })

def seal_bytes(raw: bytes, phrase: str) -> bytes:
    require(type(raw) is bytes and 0 < len(raw) <= MAX_JOURNAL,
            "Private HUMAN journal is too large")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(crypto.aead_key(phrase, salt)).encrypt(nonce, raw, AAD)
    result = sealed_json(ciphertext, salt, nonce)
    require(len(result) <= MAX_FILE, "PRIVATE HUMAN journal vault outside bounded size")
    return result

def encrypted_file(path: Path) -> bytes:
    # Original encrypted Cockpit reader checks owner-only 0600, no links,
    # inode/device and stable file size/mtime while reading.
    raw = crypto.private_envelope(path)
    require(1 <= len(raw) <= MAX_FILE, "Encrypted HUMAN journal envelope oversized")
    return raw

def open_bytes(raw: bytes, phrase: str) -> bytes:
    require(type(raw) is bytes and 1 <= len(raw) <= MAX_FILE,
            "Encrypted HUMAN journal envelope oversized")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=install.pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(
                             review.Hold("Nonfinite HUMAN vault member")))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise review.Hold("Malformed private encrypted HUMAN envelope") from exc
    require(type(doc) is dict and set(doc) == FIELDS
            and install.canonical(doc) == raw
            and doc["kind"] == KIND
            and type(doc["schema_version"]) is int and doc["schema_version"] == 1
            and doc["disposition"] == DISPOSITION
            and doc["kdf"] == "PBKDF2-HMAC-SHA256"
            and type(doc["iterations"]) is int and doc["iterations"] == crypto.ITERATIONS
            and doc["authority_granted"] is False
            and doc["consent_verified"] is False
            and doc["remediation_verified"] is False
            and doc["warning"] == WARNING, "Unknown or elevated encrypted HUMAN journal")
    salt = crypto.canonical_b64(doc["salt_b64"], 16, 16)
    nonce = crypto.canonical_b64(doc["nonce_b64"], 12, 12)
    ciphertext = crypto.canonical_b64(doc["ciphertext_b64"], 17, MAX_JOURNAL + 16)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    try:
        plaintext = AESGCM(crypto.aead_key(phrase, salt)).decrypt(
            nonce, ciphertext, AAD)
    except InvalidTag as exc:
        raise review.Hold("Wrong passphrase or modified HUMAN journal vault") from exc
    require(0 < len(plaintext) <= MAX_JOURNAL,
            "PRIVATE unsealed HUMAN journal outside original size bound")
    return plaintext

def require_distinct(input_file: Path, output_file: Path, cockpit: Path) -> None:
    require(output_file.is_absolute()
            and output_file.parent == output_file.parent.resolve(strict=True)
            and not output_file.exists() and not output_file.is_symlink()
            and output_file != input_file and output_file != cockpit
            and cockpit not in output_file.parents
            and output_file.parent != cockpit
            and output_file.parent != input_file,
            "Encrypted vault must not overwrite or enter original source/input folder")
    install.owner_dir(output_file.parent)

def seal(cockpit: Path, journal: Path, output_file: Path) -> None:
    require_distinct(journal, output_file, cockpit)
    journal_bytes = review.private_read(journal)
    original(cockpit, journal_bytes)
    passphrase = crypto.password(True)
    sealed = seal_bytes(journal_bytes, passphrase)
    original(cockpit, journal_bytes)
    require(review.private_read(journal) == journal_bytes,
            "Original PRIVATE HUMAN journal changed during encryption")
    review.private_publish(output_file, sealed)
    print("REVIEW_ONLY: source-bound PRIVATE HUMAN journal encrypted:", output_file)
    print("Original plaintext download remains in its previous location; operator controls retention.")

def unseal(cockpit: Path, vault: Path) -> bytes:
    archive = encrypted_file(vault)
    passphrase = crypto.password(False)
    journal = open_bytes(archive, passphrase)
    original(cockpit, journal)
    require(encrypted_file(vault) == archive,
            "Encrypted source-bound HUMAN journal changed during native admission")
    return journal

def resume(cockpit: Path, vault: Path, output: Path) -> None:
    require(output.is_absolute() and output != vault and output.parent != vault
            and vault not in output.parents and output not in vault.parents,
            "Unsealed HUMAN reviewer cannot overwrite encrypted vault")
    raw = unseal(cockpit, vault)
    single_review.publish(cockpit, output, None, journal_bytes=raw)
    print("HUMAN-only reviewer includes plaintext private notes in output 0700/0600 files.")

def brief(cockpit: Path, vault: Path, output: Path) -> None:
    require(output.is_absolute() and output != vault and output.parent != vault
            and vault not in output.parents and output not in vault.parents,
            "Unsealed HUMAN brief cannot overwrite encrypted vault")
    raw = unseal(cockpit, vault)
    single_brief.publish(cockpit, raw, output)
    print("HUMAN-only report contains plaintext private notes; keep it owner-private.")

def rekey(cockpit: Path, vault: Path, output_file: Path) -> None:
    require_distinct(vault, output_file, cockpit)
    raw = unseal(cockpit, vault)
    print("Enter a NEW passphrase, independently from the old passphrase.")
    new_phrase = crypto.password(True)
    new_archive = seal_bytes(raw, new_phrase)
    original(cockpit, raw)
    review.private_publish(output_file, new_archive)
    print("REVIEW_ONLY: source-bound HUMAN journal re-encrypted to NEW PRIVATE file:", output_file)
    print("Old ciphertext and any old plaintext files remain; operator must manage their retention.")

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Private AES-GCM HUMAN journal seal, reopen, brief and rekey, without plaintext ZIP")
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("seal", "resume", "brief", "rekey"):
        p = sub.add_parser(action)
        p.add_argument("--cockpit", type=Path, required=True)
        if action == "seal":
            p.add_argument("--journal", type=Path, required=True)
            p.add_argument("--output-file", type=Path, required=True)
        else:
            p.add_argument("--vault", type=Path, required=True)
            p.add_argument("--output-file" if action == "rekey" else "--output-dir",
                           type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "seal":
            seal(args.cockpit, args.journal, args.output_file)
        elif args.action == "resume":
            resume(args.cockpit, args.vault, args.output_dir)
        elif args.action == "brief":
            brief(args.cockpit, args.vault, args.output_dir)
        else:
            rekey(args.cockpit, args.vault, args.output_file)
        return 2
    except (review.Hold, install.Hold, OSError, ValueError, TypeError, KeyError,
            RuntimeError, UnicodeError, EOFError, ImportError) as exc:
        print("HOLD: PRIVATE source-bound HUMAN journal vault refused: " + str(exc),
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
