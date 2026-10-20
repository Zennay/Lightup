#!/usr/bin/env python3
"""PRIVATE offline encrypted backup of explicitly selected LightUp HUMAN workroom files."""
from __future__ import annotations
import argparse
import base64
import getpass
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import sys
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

VERSION = "lightup-private-human-backup/v1"
AAD = b"LightUp PRIVATE HUMAN archive v1 - DRAFT HOLD no authority"
MAX_FILES = 32
MAX_SINGLE = 2 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_VAULT = 38 * 1024 * 1024
ROUNDS = 600_000
FLAGS = {"consent_verified": False, "authorized": False,
         "remediation_verified": False, "release_approved": False}

class Hold(Exception):
    pass

def unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Hold("duplicate JSON key")
        value[key] = item
    return value

def parse(raw):
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Hold("invalid constant")))
    except (ValueError, UnicodeError, TypeError) as err:
        raise Hold("malformed private archive") from err

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def b64(data):
    return base64.b64encode(data).decode("ascii")

def decode(value, limit=MAX_VAULT):
    if not isinstance(value, str) or len(value) > limit * 2:
        raise Hold("oversize or non-text binary field")
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as err:
        raise Hold("invalid base64") from err
    if len(result) > limit or b64(result) != value:
        raise Hold("invalid canonical binary")
    return result

def name_safe(name):
    return (isinstance(name, str) and 1 <= len(name.encode("utf-8")) <= 160
            and name not in (".", "..") and name == Path(name).name
            and "/" not in name and "\\" not in name
            and all(32 <= ord(c) < 127 or ord(c) > 159 for c in name))

def read_file(path, limit):
    # Open the final component without following symlinks; validate the OPEN fd,
    # rather than relying on a check of a possibly swapped pathname.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > limit):
            raise Hold("nonregular, linked, or oversized file")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(limit + 1)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise Hold("file changed during read")
        if len(data) != before.st_size or len(data) > limit:
            raise Hold("file grew during read")
        return data
    finally:
        os.close(fd)

def check_rows(rows):
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_FILES:
        raise Hold("expect 1-32 files")
    names, result, total = set(), [], 0
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"name", "size", "sha256", "bytes"}:
            raise Hold("unknown file schema")
        name = row["name"]
        if not name_safe(name) or name.casefold() in names:
            raise Hold("unsafe or duplicate filename")
        names.add(name.casefold())
        size = row["size"]
        if type(size) is not int or not 0 <= size <= MAX_SINGLE:
            raise Hold("invalid file size")
        raw = decode(row["bytes"], MAX_SINGLE)
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise Hold("file bytes / digest mismatch")
        total += size
        if total > MAX_TOTAL:
            raise Hold("private archive total exceeds budget")
        result.append((name, raw, row["sha256"]))
    return result

def ask(confirm=False):
    if not sys.stdin.isatty():
        raise Hold("interactive terminal required (no password arguments, environment or pipes)")
    password = getpass.getpass("PRIVATE password: ")
    if not 12 <= len(password.encode("utf-8")) <= 1024:
        raise Hold("password must be 12-1024 UTF-8 bytes")
    if confirm and password != getpass.getpass("Confirm new password: "):
        raise Hold("passwords differ")
    return password

def key(password, salt):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                      iterations=ROUNDS).derive(password.encode("utf-8"))

def seal(document, password):
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    content = canonical(document)
    if len(content) > MAX_VAULT:
        raise Hold("encrypted content budget exceeded")
    encrypted = AESGCM(key(password, salt)).encrypt(nonce, content, AAD)
    return canonical({"version": VERSION, "kdf": "PBKDF2-HMAC-SHA256",
                      "iterations": ROUNDS, "salt": b64(salt), "nonce": b64(nonce),
                      "ciphertext": b64(encrypted), "authority": FLAGS}) + b"\n"

def unseal(file):
    env = parse(read_file(Path(file), MAX_VAULT))
    if (not isinstance(env, dict) or set(env) !=
            {"version", "kdf", "iterations", "salt", "nonce", "ciphertext", "authority"}
            or env["version"] != VERSION or env["kdf"] != "PBKDF2-HMAC-SHA256"
            or type(env["iterations"]) is not int or env["iterations"] != ROUNDS
            or env["authority"] != FLAGS):
        raise Hold("unsupported envelope or unsupported authority assertion")
    salt, nonce, encrypted = [decode(env[k]) for k in ("salt", "nonce", "ciphertext")]
    if len(salt) != 16 or len(nonce) != 12 or len(encrypted) < 16:
        raise Hold("invalid crypto parameters")
    try:
        raw = AESGCM(key(ask(), salt)).decrypt(nonce, encrypted, AAD)
    except Exception as err:
        raise Hold("password or ciphertext invalid; no output created") from err
    document = parse(raw)
    if (not isinstance(document, dict) or set(document) != {"version", "files", "authority"}
            or document["version"] != VERSION or document["authority"] != FLAGS):
        raise Hold("invalid authenticated private payload")
    files = check_rows(document["files"])
    if canonical(document) != raw:
        raise Hold("noncanonical authenticated payload")
    return document, files

def target_free(path):
    if path.exists() or path.is_symlink():
        raise Hold("destination already exists, no overwrite")
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise Hold("output parent must be an existing real directory")
    parent_stat = path.parent.stat(follow_symlinks=False)
    if (not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != os.getuid()
            or parent_stat.st_mode & 0o077):
        raise Hold("output parent must be owned by this account and mode 0700")

def private_write(path, content):
    target_free(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(fd)

def create(args):
    target = Path(args.output)
    target_free(target)
    if not 1 <= len(args.files) <= MAX_FILES:
        raise Hold("select 1-32 explicit ordinary files")
    rows, seen, total = [], set(), 0
    for filename in args.files:
        path = Path(filename)
        if not name_safe(path.name) or path.name.casefold() in seen:
            raise Hold("unsafe or duplicate source names")
        seen.add(path.name.casefold())
        raw = read_file(path, MAX_SINGLE)
        total += len(raw)
        if total > MAX_TOTAL:
            raise Hold("combined file budget exceeded")
        rows.append({"name": path.name, "size": len(raw),
                     "sha256": hashlib.sha256(raw).hexdigest(), "bytes": b64(raw)})
    check_rows(rows)
    document = {"version": VERSION, "authority": FLAGS, "files": rows}
    private_write(target, seal(document, ask(confirm=True)))
    print(f"PRIVATE DRAFT/HOLD: encrypted {len(rows)} selected files into {target}")

def inventory(args):
    _, files = unseal(args.vault)
    print("PRIVATE DRAFT/HOLD. No identity, grant, consent or fix verification.")
    for name, raw, digest in files:
        print(f"{name} | {len(raw)} bytes | sha256={digest}")

def restore(args):
    destination = Path(args.destination)
    target_free(destination)
    _, files = unseal(args.vault)
    temporary = Path(tempfile.mkdtemp(prefix=".lightup-private-hold-", dir=destination.parent))
    try:
        os.chmod(temporary, 0o700)
        for name, raw, _ in files:
            private_write(temporary / name, raw)
        if not any(name.casefold() == "review-only.txt" for name, _, _ in files):
            private_write(temporary / "REVIEW-ONLY.txt",
                          b"PRIVATE DRAFT/HOLD. Unverified operator-selected files. "
                          b"No consent, real source proof, permission, remediation verification or release.\n")
        target_free(destination)
        os.rename(temporary, destination)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    print(f"PRIVATE DRAFT/HOLD: restored {len(files)} files to owner-only new folder {destination}")

def rotate(args):
    target = Path(args.output)
    target_free(target)
    document, files = unseal(args.vault)
    print(f"Re-encrypting {len(files)} source files entirely in memory")
    private_write(target, seal(document, ask(confirm=True)))
    print(f"PRIVATE DRAFT/HOLD: new encrypted archive {target}; old archive unchanged")

def compare(args):
    # Both independently encrypted archives must authenticate completely first.
    # The caller must provide each password interactively; the result stays local.
    print("Opening first PRIVATE snapshot")
    _, left = unseal(args.before)
    print("Opening second PRIVATE snapshot")
    _, right = unseal(args.after)
    old = {name.casefold(): (name, raw, digest) for name, raw, digest in left}
    new = {name.casefold(): (name, raw, digest) for name, raw, digest in right}
    counts = {"ADDED": 0, "REMOVED": 0, "CHANGED": 0, "UNCHANGED": 0}
    print("PRIVATE HUMAN file comparison only; no chronological or fix proof")
    for key in sorted(old.keys() | new.keys()):
        if key not in old:
            state, display = "ADDED", new[key][0]
        elif key not in new:
            state, display = "REMOVED", old[key][0]
        else:
            old_name, old_data, old_digest = old[key]
            new_name, new_data, new_digest = new[key]
            display = new_name
            state = ("UNCHANGED" if old_name == new_name and old_digest == new_digest
                     and len(old_data) == len(new_data) else "CHANGED")
        counts[state] += 1
        print(f"{state:9s} {display}")
    print(" | ".join(f"{state}={counts[state]}" for state in counts))
    print("HOLD: file differences are not verified remediation, identity, consent or release")


def main():
    parser = argparse.ArgumentParser(description="PRIVATE offline HUMAN backup, never action authority")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("create", help="Encrypt selected ordinary files")
    p.add_argument("--output", required=True)
    p.add_argument("files", nargs="+")
    p = sub.add_parser("inventory", help="After password, display private file inventory")
    p.add_argument("vault")
    p = sub.add_parser("restore", help="Restore into a NEW private directory")
    p.add_argument("vault")
    p.add_argument("destination")
    p = sub.add_parser("rotate", help="Re-encrypt to a NEW private archive without plaintext output")
    p.add_argument("vault")
    p.add_argument("--output", required=True)
    p = sub.add_parser("compare", help="PRIVATE differences between two authenticated snapshots")
    p.add_argument("before")
    p.add_argument("after")
    args = parser.parse_args()
    try:
        {"create": create, "inventory": inventory, "restore": restore,
         "rotate": rotate, "compare": compare}[args.command](args)
    except (Hold, OSError) as err:
        print(f"HOLD: {err}", file=sys.stderr)
        return 3
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
