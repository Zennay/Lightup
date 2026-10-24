#!/usr/bin/env python3
"""Password-encrypted offline source-free HUMAN Cockpit transport.

Uses unchanged original PRIVATE native source-free admission and encrypted
in-memory canonical ZIP. No network or plaintext ZIP files, authentication,
grant, scan, evidence proof, client consent or verified remediation.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import unicodedata
import zipfile

import install
import portable_cockpit

review = portable_cockpit.review
AAD = b"LIGHTUP_SOURCEFREE_HUMAN_COCKPIT_AES256_GCM_V1"
KIND = "lightup.private_encrypted_sourcefree_human_cockpit"
DISPOSITION = "ENCRYPTED_HUMAN_COUNTS_NOT_AUTHORITY"
WARNING = ("Unsigned original source-free HUMAN counts, not sender/client "
           "authentication, current consent, verified evidence, fix, retest, "
           "grant, scan or release. Password loss is irreversible.")
ITERATIONS = 600000
MAX_ENVELOPE = ((portable_cockpit.MAX_ZIP + 16 + 2) // 3) * 4 + 4096
FIELDS = frozenset(("kind", "version", "disposition", "kdf", "iterations",
                    "salt_b64", "nonce_b64", "ciphertext_b64",
                    "authority_granted", "consent_verified", "remediation_verified",
                    "warning"))

def require(ok: bool, why: str) -> None:
    review.require(ok, why)

def private_envelope(path: Path) -> bytes:
    require(path.is_absolute() and path.parent == path.parent.resolve(strict=True)
            and not path.is_symlink(), "Incoming encrypted path must be literal absolute")
    install.owner_dir(path.parent)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0
            and 1 <= info.st_size <= MAX_ENVELOPE,
            "Incoming encrypted file requires original PRIVATE single-link 0600 mode")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        require(opened.st_ino == info.st_ino and opened.st_dev == info.st_dev
                and opened.st_size == info.st_size
                and opened.st_mode & 0o077 == 0,
                "Encrypted input changed before private admission")
        result = os.read(fd, MAX_ENVELOPE + 1)
        later = os.fstat(fd)
        require(len(result) == info.st_size == later.st_size
                and opened.st_mtime_ns == later.st_mtime_ns,
                "Encrypted file changed during reading")
        return result
    finally:
        os.close(fd)

def password(confirmation: bool) -> str:
    require(sys.stdin.isatty(), "Passphrase requires interactive private terminal")
    phrase = getpass.getpass("Private source-free handoff passphrase: ")
    require(type(phrase) is str and 14 <= len(phrase) <= 256
            and phrase == phrase.strip()
            and unicodedata.normalize("NFC", phrase) == phrase
            and all(unicodedata.category(c)[0] != "C" for c in phrase),
            "Passphrase must be 14-256 NFC chars, without outer whitespace/control marks")
    if confirmation:
        again = getpass.getpass("Confirm separate handoff passphrase: ")
        require(secrets.compare_digest(phrase, again), "Passphrase confirmation differs")
    return phrase

def aead_key(phrase: str, salt: bytes) -> bytes:
    # Import only for encrypted operations: ordinary offline Cockpit is stdlib-only.
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                      salt=salt, iterations=ITERATIONS).derive(phrase.encode("utf-8"))

def canonical_b64(value: object, minimum: int, maximum: int) -> bytes:
    require(type(value) is str and 1 <= len(value) <= MAX_ENVELOPE,
            "Invalid encrypted handoff field")
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise review.Hold("Noncanonical PRIVATE handoff binary field") from exc
    require(minimum <= len(data) <= maximum
            and base64.b64encode(data).decode("ascii") == value,
            "Encrypted field changed or exceeds original bound")
    return data

def envelope_bytes(ciphertext: bytes, salt: bytes, nonce: bytes) -> bytes:
    data = {
        "kind": KIND, "version": 1, "disposition": DISPOSITION,
        "kdf": "PBKDF2-HMAC-SHA256", "iterations": ITERATIONS,
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "authority_granted": False, "consent_verified": False,
        "remediation_verified": False, "warning": WARNING,
    }
    return install.canonical(data)

def admit_envelope(blob: bytes) -> tuple[bytes, bytes, bytes]:
    require(type(blob) is bytes and 1 <= len(blob) <= MAX_ENVELOPE,
            "Encrypted source-free handoff exceeds permitted size")
    try:
        obj = json.loads(blob.decode("utf-8"), object_pairs_hook=install.pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(
                             review.Hold("Nonfinite encrypted JSON")))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise review.Hold("Malformed PRIVATE encrypted source-free envelope") from exc
    require(type(obj) is dict and set(obj) == FIELDS
            and install.canonical(obj) == blob,
            "Noncanonical or incomplete encrypted Cockpit")
    require(obj["kind"] == KIND and type(obj["version"]) is int and obj["version"] == 1
            and obj["disposition"] == DISPOSITION
            and obj["kdf"] == "PBKDF2-HMAC-SHA256"
            and type(obj["iterations"]) is int and obj["iterations"] == ITERATIONS
            and obj["authority_granted"] is False and obj["consent_verified"] is False
            and obj["remediation_verified"] is False and obj["warning"] == WARNING,
            "Encrypted handoff identity, parameters or authorization claim invalid")
    salt = canonical_b64(obj["salt_b64"], 16, 16)
    nonce = canonical_b64(obj["nonce_b64"], 12, 12)
    ciphertext = canonical_b64(obj["ciphertext_b64"], 17,
                               portable_cockpit.MAX_ZIP + 16)
    return salt, nonce, ciphertext

def encrypt(cockpit: Path, output_file: Path) -> None:
    require(output_file.is_absolute()
            and output_file.parent == output_file.parent.resolve(strict=True)
            and not output_file.exists() and not output_file.is_symlink()
            and cockpit not in output_file.parents and output_file.parent != cockpit,
            "Encrypted handoff output must not enter original source-free Cockpit")
    install.owner_dir(output_file.parent)
    admitted = portable_cockpit.read_cockpit.inspect(cockpit)
    manifest = review.private_read(cockpit / "manifest.json")
    names = portable_cockpit.inventory(manifest)
    require({item.name for item in cockpit.iterdir()} == set(names),
            "Unexpected source-free original packet inventory")
    originals = {name: review.private_read(cockpit / name) for name in sorted(names)}
    require(sum(map(len, originals.values())) <= portable_cockpit.MAX_ZIP
            and all(len(data) <= portable_cockpit.MAX_MEMBER
                    for data in originals.values()),
            "Original native source-free packet exceeds safe bound")
    require(portable_cockpit.read_cockpit.inspect(cockpit) == admitted
            and all(review.private_read(cockpit / name) == contents
                    for name, contents in originals.items()),
            "Source-free original changed while encrypting")
    zipped = portable_cockpit.zip_files(originals)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    phrase = password(True)
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(aead_key(phrase, salt)).encrypt(nonce, zipped, AAD)
    packed = envelope_bytes(ciphertext, salt, nonce)
    require(len(packed) <= MAX_ENVELOPE and
            all(review.private_read(cockpit / name) == contents
                for name, contents in originals.items()),
            "Original source-free packet changed before PRIVATE encrypted publish")
    review.private_publish(output_file, packed)
    print("REVIEW_ONLY: encrypted original source-free Cockpit:", output_file)
    print("Keep passphrase in a separate channel. Sender identity/consent NOT authenticated.")

def decrypt(archive: Path, output: Path) -> None:
    require(output.is_absolute() and output.parent == output.parent.resolve(strict=True)
            and not output.exists() and not output.is_symlink()
            and output != archive.parent and output not in archive.parents,
            "Decrypted source-free recipient output must be new and private")
    install.owner_dir(output.parent)
    original = private_envelope(archive)
    salt, nonce, ciphertext = admit_envelope(original)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    phrase = password(False)
    try:
        zipped = AESGCM(aead_key(phrase, salt)).decrypt(nonce, ciphertext, AAD)
    except InvalidTag as exc:
        raise review.Hold("Wrong passphrase or altered PRIVATE encrypted handoff") from exc
    require(0 < len(zipped) <= portable_cockpit.MAX_ZIP,
            "Decrypted source-free payload outside original bound")
    # No plaintext ZIP temp file: in-memory bytes go directly through the
    # original native unchanged source-free manifest + HTML admission.
    portable_cockpit.unpack_bytes(
        zipped, output, lambda: private_envelope(archive) == original)
    print("REVIEW_ONLY: original source-free HUMAN Cockpit decrypted offline.")
    print("Password encryption never authenticates sender identity or consent.")

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Password-encrypted PRIVATE HUMAN Cockpit transport; offline only")
    cmds = parser.add_subparsers(dest="action", required=True)
    p = cmds.add_parser("encrypt", help="Encrypt exact original source-free Cockpit privately")
    p.add_argument("--cockpit", required=True, type=Path)
    p.add_argument("--output-file", required=True, type=Path)
    p = cmds.add_parser("decrypt", help="Decrypt directly into new original private Cockpit")
    p.add_argument("--archive", required=True, type=Path)
    p.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.action == "encrypt":
            encrypt(args.cockpit, args.output_file)
        else:
            decrypt(args.archive, args.output_dir)
        return 2
    except (review.Hold, install.Hold, OSError, ValueError, TypeError, KeyError,
            ImportError, RuntimeError, EOFError, zipfile.BadZipFile) as exc:
        print("HOLD: encrypted PRIVATE source-free handoff refused: " + str(exc),
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
