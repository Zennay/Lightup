"""Local, non-authorizing authenticated encryption for PRIVATE HUMAN LightUp ticket handoffs.

Only opaque .md/.json exported human drafts are sealed. No original findings,
tenant store, scanner, browser APIs, grants, consent or release state are touched.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

MAGIC = b"LUTKV1\x00\n"
KIND = "lightup.private_human_ticket_vault"
INNER_KIND = "lightup.private_human_ticket_contents"
ITERATIONS = 600_000
MAX_PLAIN = 4 * 1024 * 1024
MAX_VAULT = MAX_PLAIN + 4096
MAX_HEADER = 1024
MAX_PASSWORD = 4096
HEADER_FIELDS = frozenset(("kind", "schema_version", "cipher", "kdf", "iterations", "salt", "nonce"))
INNER_FIELDS = frozenset(("kind", "schema_version", "content_type", "content_size", "content_sha256",
                          "authenticated", "tenant_verified", "source_authorized", "grant",
                          "client_consent", "operator_consent", "execution", "scan",
                          "retest_verified", "release"))
FALSE_FIELDS = ("authenticated", "tenant_verified", "source_authorized", "grant",
                "client_consent", "operator_consent", "execution", "scan",
                "retest_verified", "release")
TYPES = {".md": "text/markdown", ".json": "application/json"}


class VaultError(ValueError):
    pass


def _deny_duplicate(pairs: list[tuple[str, object]]) -> dict:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise VaultError("Duplicate key in authenticated vault metadata.")
        obj[key] = value
    return obj


def _json(data: bytes) -> dict:
    try:
        value = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=_deny_duplicate,
                           parse_constant=lambda _: (_ for _ in ()).throw(VaultError("Invalid JSON constant.")))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise VaultError("Malformed authenticated vault metadata.") from exc
    if type(value) is not dict:
        raise VaultError("Vault metadata must be a JSON object.")
    return value


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _require_nofollow() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise VaultError("OS lacks required no-follow file admission; cannot safely handle PRIVATE tickets.")
    return os.O_NOFOLLOW


def _private_input(path: Path, limit: int) -> bytes:
    """No-follow, owner-only and regular-file admission before reading confidential bytes."""
    flags = os.O_RDONLY | _require_nofollow() | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise VaultError("Input must be a regular, singly-linked file owned by the current user.")
        if info.st_mode & 0o077:
            raise VaultError("Private input is group/other accessible; first restrict its mode to 0600.")
        if info.st_size <= 0 or info.st_size > limit:
            raise VaultError("Private input is empty or exceeds the bounded size.")
        chunks, size = [], 0
        while True:
            part = os.read(fd, min(65536, limit + 1 - size))
            if not part:
                break
            size += len(part)
            if size > limit:
                raise VaultError("Private input exceeds the bounded size.")
            chunks.append(part)
        # Fail closed if somebody truncated or changed size during read.
        after = os.fstat(fd)
        if after.st_size != size or after.st_size != info.st_size or after.st_ino != info.st_ino:
            raise VaultError("Private source changed during read.")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _exclusive_output(path: Path, payload: bytes) -> None:
    """A new owner-private final file. No overwrite, symlink destination or partial retained output."""
    if not path.parent.is_dir():
        raise VaultError("Destination parent must exist; use a trusted private directory.")
    directory = os.lstat(path.parent)
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid() or directory.st_mode & 0o077:
        raise VaultError("Destination must be inside an owner-owned 0700 private directory, not a symlink.")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | _require_nofollow()
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _password(label: str, *, fresh: bool) -> bytes:
    if not sys.stdin.isatty():
        raise VaultError("Passphrases require an interactive private terminal; never pass via argv/environment.")
    text = getpass.getpass(label)
    if len(text) > MAX_PASSWORD or (fresh and len(text) < 14) or not text:
        raise VaultError("Passphrase must be non-empty, at most 4096 characters (minimum 14 for new vaults).")
    if fresh and text != getpass.getpass("Confirm new private passphrase: "):
        raise VaultError("New passphrases do not match.")
    return text.encode("utf-8")


def _key(password: bytes, salt: bytes) -> bytes:
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS).derive(password)


def _decode_header(raw: bytes) -> tuple[dict, int]:
    if len(raw) < len(MAGIC) + 2 + 16 or not raw.startswith(MAGIC):
        raise VaultError("Not a supported private LightUp ticket vault.")
    header_size = struct.unpack(">H", raw[len(MAGIC):len(MAGIC)+2])[0]
    if header_size <= 0 or header_size > MAX_HEADER or len(raw) < len(MAGIC)+2+header_size+16:
        raise VaultError("Malformed, truncated or oversized vault header.")
    end = len(MAGIC)+2+header_size
    header_bytes = raw[len(MAGIC)+2:end]
    h = _json(header_bytes)
    if set(h) != HEADER_FIELDS or h["kind"] != KIND or type(h["schema_version"]) is not int or h["schema_version"] != 1 or \
       h["cipher"] != "AES-256-GCM" or h["kdf"] != "PBKDF2-HMAC-SHA256" or \
       type(h["iterations"]) is not int or h["iterations"] != ITERATIONS or _canonical(h) != header_bytes:
        raise VaultError("Unsupported or noncanonical private ticket vault header.")
    try:
        salt = base64.b64decode(h["salt"], validate=True)
        nonce = base64.b64decode(h["nonce"], validate=True)
    except (ValueError, TypeError) as exc:
        raise VaultError("Invalid vault salt or nonce.") from exc
    if len(salt) != 16 or len(nonce) != 12:
        raise VaultError("Invalid vault salt or nonce size.")
    return h, end


def _seal(inner: bytes, password: bytes) -> bytes:
    salt, nonce = os.urandom(16), os.urandom(12)
    header = _canonical(dict(kind=KIND, schema_version=1, cipher="AES-256-GCM",
                             kdf="PBKDF2-HMAC-SHA256", iterations=ITERATIONS,
                             salt=base64.b64encode(salt).decode("ascii"),
                             nonce=base64.b64encode(nonce).decode("ascii")))
    if len(header) > MAX_HEADER:
        raise VaultError("Invalid vault header length.")
    prefix = MAGIC + struct.pack(">H", len(header)) + header
    encrypted = AESGCM(_key(password, salt)).encrypt(nonce, inner, prefix)
    if len(prefix) + len(encrypted) > MAX_VAULT:
        raise VaultError("Vault size cap exceeded.")
    return prefix + encrypted


def _inner(text: bytes, kind: str) -> bytes:
    if len(text) > MAX_PLAIN:
        raise VaultError("Input too large.")
    # Content is opaque: source finding claims are NEVER interpreted as authentication.
    meta = dict(kind=INNER_KIND, schema_version=1, content_type=kind,
                content_size=len(text), content_sha256=hashlib.sha256(text).hexdigest(),
                **{key: False for key in FALSE_FIELDS})
    meta_bytes = _canonical(meta)
    return struct.pack(">I", len(meta_bytes)) + meta_bytes + text


def _open(raw: bytes, password: bytes) -> tuple[bytes, str, bytes]:
    header, end = _decode_header(raw)
    salt = base64.b64decode(header["salt"])
    nonce = base64.b64decode(header["nonce"])
    try:
        inner = AESGCM(_key(password, salt)).decrypt(nonce, raw[end:], raw[:end])
    except InvalidTag as exc:
        raise VaultError("Vault authentication failed; wrong passphrase or tampered ciphertext. No plaintext output.") from exc
    if len(inner) < 4:
        raise VaultError("Malformed decrypted ticket envelope.")
    length = struct.unpack(">I", inner[:4])[0]
    if length <= 0 or length > MAX_HEADER or 4 + length > len(inner):
        raise VaultError("Malformed decrypted ticket metadata.")
    meta = _json(inner[4:4+length])
    content = inner[4+length:]
    if set(meta) != INNER_FIELDS or meta["kind"] != INNER_KIND or type(meta["schema_version"]) is not int or \
       meta["schema_version"] != 1 or meta["content_type"] not in TYPES.values() or \
       type(meta["content_size"]) is not int or meta["content_size"] != len(content) or \
       type(meta["content_sha256"]) is not str or \
       not all(meta.get(k) is False for k in FALSE_FIELDS) or \
       meta["content_sha256"] != hashlib.sha256(content).hexdigest() or \
       _canonical(meta) != inner[4:4+length]:
        raise VaultError("Decrypted ticket metadata integrity HOLD.")
    if not content or len(content) > MAX_PLAIN:
        raise VaultError("Decrypted private ticket content exceeds bounded limits.")
    try:
        content.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise VaultError("Decrypted ticket text is not valid UTF-8.") from exc
    return content, meta["content_type"], inner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    cmds = parser.add_subparsers(dest="command", required=True)
    for cmd in ("seal", "open", "rotate", "inspect"):
        sub = cmds.add_parser(cmd)
        sub.add_argument("--input", required=True, type=Path)
        if cmd != "inspect":
            sub.add_argument("--output", required=True, type=Path)
        if cmd == "open":
            sub.add_argument("--ack-private-plaintext", action="store_true",
                             help="Confirm deliberate creation of a new PRIVATE plaintext file")
    a = parser.parse_args(argv)
    try:
        input_path = a.input.expanduser().absolute()
        raw = _private_input(input_path, MAX_PLAIN if a.command == "seal" else MAX_VAULT)
        if a.command == "inspect":
            header, _ = _decode_header(raw)
            print("PRIVATE HUMAN ticket vault header structurally valid; AES-GCM authenticity NOT checked without passphrase.")
            print("Format:", header["schema_version"], "| cipher:", header["cipher"], "| encrypted bytes:", len(raw))
            print("No original source IDs, ticket content, consent, grant or verified retest disclosed.")
            return 0
        output = a.output.expanduser().absolute()
        if input_path == output:
            raise VaultError("Input and output path may not match.")
        if a.command == "seal":
            suffix = input_path.suffix.lower()
            if suffix not in TYPES:
                raise VaultError("Only local HUMAN .md or .json handoff files can be sealed.")
            if output.suffix.lower() != ".ltv":
                raise VaultError("Encrypted output must use .ltv.")
            try:
                raw.decode("utf-8", errors="strict")
            except UnicodeError as exc:
                raise VaultError("Private handoff must be UTF-8 text.") from exc
            passwd = _password("New vault passphrase (private TTY): ", fresh=True)
            payload = _seal(_inner(raw, TYPES[suffix]), passwd)
            _exclusive_output(output, payload)
            print("Created new AES-256-GCM PRIVATE ticket vault (0600). No plaintext intermediary.")
        elif a.command == "open":
            if not a.ack_private_plaintext:
                raise VaultError("Explicit --ack-private-plaintext required; decrypted file contains confidential HUMAN content.")
            passwd = _password("Existing vault passphrase (private TTY): ", fresh=False)
            content, kind, _ = _open(raw, passwd)
            extension = ".md" if kind == TYPES[".md"] else ".json"
            if output.suffix.lower() != extension:
                raise VaultError("Private output suffix must match original content (" + extension + ").")
            _exclusive_output(output, content)
            print("Decrypted new PRIVATE plaintext file (0600). Treat as confidential; no authority inferred.")
        else:
            if input_path.suffix.lower() != ".ltv" or output.suffix.lower() != ".ltv":
                raise VaultError("Rotation requires distinct .ltv input/output paths.")
            old = _password("Old vault passphrase (private TTY): ", fresh=False)
            _, _, inner = _open(raw, old)
            fresh = _password("Replacement vault passphrase (private TTY): ", fresh=True)
            if old == fresh:
                raise VaultError("Replacement passphrase must differ from previous.")
            payload = _seal(inner, fresh)
            _exclusive_output(output, payload)
            print("Created new PRIVATE re-encrypted ticket vault (0600). Original vault preserved.")
        return 0
    except (VaultError, OSError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
