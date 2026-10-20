#!/usr/bin/env python3
"""One encrypted offline source-free Cockpit + source-bound PRIVATE HUMAN review.

Never handles original evidence/client names: only the original source-free
native Cockpit and its EXACT source-bound HUMAN journal. Optional trusted local
cryptography dependency. No network, real auth, consent, grant, scanner, fix.
"""
from __future__ import annotations

import argparse
import base64
import io
import json
import os
import stat
from pathlib import Path
import secrets
import sys
import zipfile

import encrypted_cockpit as crypto
import install
import journal_vault
import portable_cockpit
import single_review
import workflow

review = single_review.review
workspace = workflow.workspace
KIND = "lightup.private_encrypted_cockpit_and_human_review"
DISPOSITION = "ENCRYPTED_SOURCEFREE_HUMAN_ONLY_DRAFT_HOLD"
WARNING = ("Private source-free original Cockpit and source-bound self-declared "
           "HUMAN notes; no authenticated sender/client identity, consent, "
           "verified security finding, remediation, grant, scan or retest.")
AAD = b"LIGHTUP_SOURCEFREE_COCKPIT_HUMAN_REVIEW_AES_GCM_V1"
SOURCE_MEMBER = "source-free.luhz"
JOURNAL_MEMBER = "source-bound-human.json"
MEMBERS = frozenset((SOURCE_MEMBER, JOURNAL_MEMBER))
MAX_JOURNAL = journal_vault.MAX_JOURNAL
MAX_INNER = portable_cockpit.MAX_ZIP + MAX_JOURNAL + 65536
MAX_ENVELOPE = ((MAX_INNER + 16 + 2) // 3) * 4 + 4096
FIELDS = frozenset(("kind", "schema_version", "disposition", "kdf",
                    "iterations", "salt_b64", "nonce_b64", "ciphertext_b64",
                    "authority_granted", "consent_verified",
                    "remediation_verified", "warning"))

def require(ok: bool, reason: str) -> None:
    review.require(ok, reason)

def pack_inner(original_zip: bytes, journal: bytes) -> bytes:
    require(0 < len(original_zip) <= portable_cockpit.MAX_ZIP
            and 0 < len(journal) <= MAX_JOURNAL,
            "Original source-free Cockpit or native HUMAN journal exceeds limit")
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, mode="w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=8) as z:
        for name, value in ((SOURCE_MEMBER, original_zip), (JOURNAL_MEMBER, journal)):
            member = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.external_attr = 0o100600 << 16
            member.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(member, value, compress_type=zipfile.ZIP_DEFLATED,
                       compresslevel=8)
    output = memory.getvalue()
    require(len(output) <= MAX_INNER, "Complete original HUMAN review package too large")
    return output

def unpack_inner(raw: bytes) -> tuple[bytes, bytes]:
    require(type(raw) is bytes and 1 <= len(raw) <= MAX_INNER,
            "Decrypted source-free HUMAN package outside bound")
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        members = z.infolist()
        require(len(members) == 2 and {m.filename for m in members} == MEMBERS
                and all(not m.is_dir()
                        and (m.external_attr >> 16) == 0o100600
                        and 0 <= m.compress_size <= MAX_INNER
                        and 0 <= m.file_size <=
                        (portable_cockpit.MAX_ZIP if m.filename == SOURCE_MEMBER
                         else MAX_JOURNAL)
                        for m in members), "Unexpected nested PRIVATE source-free payload")
        source = z.read(SOURCE_MEMBER)
        journal = z.read(JOURNAL_MEMBER)
    require(0 < len(source) <= portable_cockpit.MAX_ZIP
            and 0 < len(journal) <= MAX_JOURNAL,
            "Incomplete source-bound HUMAN review archive")
    return source, journal

def sealed(ciphertext: bytes, salt: bytes, nonce: bytes) -> bytes:
    return install.canonical({
        "kind": KIND, "schema_version": 1, "disposition": DISPOSITION,
        "kdf": "PBKDF2-HMAC-SHA256", "iterations": crypto.ITERATIONS,
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "authority_granted": False, "consent_verified": False,
        "remediation_verified": False, "warning": WARNING,
    })

def open_sealed(raw: bytes, phrase: str) -> bytes:
    require(type(raw) is bytes and 1 <= len(raw) <= MAX_ENVELOPE,
            "Encrypted HUMAN handoff exceeds bounded file size")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=install.pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(
                             review.Hold("Nonfinite encrypted native review")))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise review.Hold("Malformed encrypted source-free HUMAN review package") from exc
    require(type(doc) is dict and set(doc) == FIELDS
            and install.canonical(doc) == raw
            and doc["kind"] == KIND and doc["disposition"] == DISPOSITION
            and type(doc["schema_version"]) is int and doc["schema_version"] == 1
            and doc["kdf"] == "PBKDF2-HMAC-SHA256"
            and type(doc["iterations"]) is int and doc["iterations"] == crypto.ITERATIONS
            and doc["warning"] == WARNING
            and doc["authority_granted"] is False
            and doc["consent_verified"] is False
            and doc["remediation_verified"] is False,
            "Unknown or elevated encrypted source-free HUMAN authority")
    salt = crypto.canonical_b64(doc["salt_b64"], 16, 16)
    nonce = crypto.canonical_b64(doc["nonce_b64"], 12, 12)
    ciphertext = crypto.canonical_b64(doc["ciphertext_b64"], 17, MAX_INNER + 16)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    try:
        unsealed = AESGCM(crypto.aead_key(phrase, salt)).decrypt(nonce, ciphertext, AAD)
    except InvalidTag as exc:
        raise review.Hold("Wrong passphrase or modified encrypted PRIVATE review") from exc
    require(0 < len(unsealed) <= MAX_INNER, "Decrypted source-free review exceeds bound")
    return unsealed

def incoming(path: Path) -> bytes:
    require(path.is_absolute() and path.parent == path.parent.resolve(strict=True)
            and not path.is_symlink(),
            "Incoming encrypted HUMAN package requires literal PRIVATE path")
    install.owner_dir(path.parent)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and before.st_nlink == 1 and before.st_mode & 0o077 == 0
            and 0 < before.st_size <= MAX_ENVELOPE,
            "Encrypted source-free HUMAN package must be owner-only 0600 file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        require(opened.st_dev == before.st_dev and opened.st_ino == before.st_ino
                and opened.st_size == before.st_size,
                "Incoming private encrypted HUMAN package changed before read")
        data = os.read(fd, MAX_ENVELOPE + 1)
        after = os.fstat(fd)
        require(len(data) == opened.st_size == after.st_size
                and opened.st_mtime_ns == after.st_mtime_ns,
                "Incoming private encrypted HUMAN package changed during read")
        return data
    finally:
        os.close(fd)

def create(cockpit: Path, journal: Path | None, vault: Path | None, outfile: Path) -> None:
    require((journal is None) != (vault is None),
            "Choose original source-bound plaintext HUMAN journal OR encrypted vault")
    chosen = journal if journal is not None else vault
    require(outfile.is_absolute() and outfile.parent == outfile.parent.resolve(strict=True)
            and not outfile.exists() and not outfile.is_symlink()
            and cockpit not in outfile.parents and outfile.parent != cockpit
            and chosen != outfile and chosen.parent != outfile,
            "Encrypted HUMAN review cannot modify original source/journal")
    install.owner_dir(outfile.parent)
    admitted = portable_cockpit.read_cockpit.inspect(cockpit)
    mb = review.private_read(cockpit / "manifest.json")
    filenames = portable_cockpit.inventory(mb)
    require({p.name for p in cockpit.iterdir()} == set(filenames),
            "Complete original source-free native inventory required")
    files = {name: review.private_read(cockpit / name) for name in sorted(filenames)}
    source_zip = portable_cockpit.zip_files(files)
    vault_original = journal_vault.encrypted_file(vault) if vault is not None else None
    journal_bytes = (review.private_read(journal) if journal is not None
                     else journal_vault.unseal(cockpit, vault))
    journal_vault.original(cockpit, journal_bytes)
    original = pack_inner(source_zip, journal_bytes)
    phrase = crypto.password(True)
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ciphertext = AESGCM(crypto.aead_key(phrase, salt)).encrypt(nonce, original, AAD)
    packed = sealed(ciphertext, salt, nonce)
    require(len(packed) <= MAX_ENVELOPE
            and portable_cockpit.read_cockpit.inspect(cockpit) == admitted
            and all(review.private_read(cockpit / name) == contents
                    for name, contents in files.items())
            and ((review.private_read(journal) == journal_bytes) if journal is not None
                 else (journal_vault.encrypted_file(vault) == vault_original)),
            "Original HUMAN source or PRIVATE notes changed during encryption")
    review.private_publish(outfile, packed)
    print("REVIEW_ONLY: one encrypted source-free Cockpit + HUMAN journal:", outfile)
    print("No original evidence, source owner authentication or consent copied.")

def receive(archive: Path, output: Path) -> None:
    require(output.is_absolute() and output.parent == output.parent.resolve(strict=True)
            and not output.exists() and not output.is_symlink()
            and output.parent != archive and output != archive
            and output != archive.parent and output not in archive.parents,
            "New independent PRIVATE HUMAN recipient directory required")
    install.owner_dir(output.parent)
    ciphertext = incoming(archive)
    phrase = crypto.password(False)
    original_zip, journal = unpack_inner(open_sealed(ciphertext, phrase))
    stage = output.parent / (".lightup-private-handoff-" + secrets.token_hex(12))
    os.mkdir(stage, 0o700)
    import shutil
    try:
        native = stage / "source-free-original"
        human = stage / "human-review"
        portable_cockpit.unpack_bytes(original_zip, native)
        journal_vault.original(native, journal)
        single_review.publish(native, human, None, journal_bytes=journal)
        # PRIVATE original source-free human note text is present in the
        # local view, NOT ciphertext at rest after receiving.
        portal = workflow.page(
            "PRIVATE source-free HUMAN follow-up delivery",
            [
                ("Received canonical original source-free Cockpit",
                 "source-free-original/index.html",
                 "Native admitted source-free counts only; original client records not present."),
                ("Received exact-original-bound HUMAN review",
                 "human-review/index.html",
                 "Locally editable PRIVATE HUMAN notes, NOT verified fixes or approvals."),
            ],
            "The decrypted HUMAN review is plaintext inside owner-private files. "
            "This is not client consent, source-owner identity or scan authority."
        )
        install.write_file(stage / "index.html", portal)
        receipt = {
            "kind": KIND + ".local_private_recipient",
            "schema_version": 1, "disposition": "PRIVATE_HUMAN_REVIEW_ONLY",
            "authority_granted": False, "consent_verified": False,
            "remediation_verified": False, "source_authenticated": False,
            "warning": WARNING,
        }
        install.write_file(stage / "private-summary.json", install.canonical(receipt))
        require(incoming(archive) == ciphertext, "Original encrypted handoff changed")
        install.exclusive_publish(stage, output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print("REVIEW_ONLY: original source-free Cockpit with HUMAN notes received:", output)
    print("Open local PRIVATE browser:", output / "index.html")
    print("Decrypted HUMAN journal notes now reside in private plaintext output files.")

def main() -> int:
    p = argparse.ArgumentParser(
        description="One encrypted native source-free Cockpit + exact-human journal transfer")
    actions = p.add_subparsers(dest="action", required=True)
    create_cmd = actions.add_parser("create")
    create_cmd.add_argument("--cockpit", type=Path, required=True)
    sources = create_cmd.add_mutually_exclusive_group(required=True)
    sources.add_argument("--journal", type=Path,
                         help="Existing 0600 native source-bound plaintext HUMAN journal")
    sources.add_argument("--journal-vault", type=Path,
                         help="Existing encrypted .luhj HUMAN journal (no plaintext temp file)")
    create_cmd.add_argument("--output-file", type=Path, required=True)
    recv_cmd = actions.add_parser("receive")
    recv_cmd.add_argument("--archive", type=Path, required=True)
    recv_cmd.add_argument("--output-dir", type=Path, required=True)
    args = p.parse_args()
    try:
        if args.action == "create":
            create(args.cockpit, args.journal, args.journal_vault, args.output_file)
        else:
            receive(args.archive, args.output_dir)
        return 2
    except (review.Hold, install.Hold, OSError, ValueError, TypeError, KeyError,
            ImportError, UnicodeError, EOFError, RuntimeError, zipfile.BadZipFile) as exc:
        print("HOLD: original PRIVATE encrypted HUMAN source delivery refused: " + str(exc),
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
