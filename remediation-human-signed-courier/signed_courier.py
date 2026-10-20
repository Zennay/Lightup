#!/usr/bin/env python3
"""PRIVATE source-redacted HUMAN reply courier with separately trusted Ed25519 provenance.

Wraps ONLY already-encrypted original .luhq + .luhr and invokes unchanged original
native two-password admission. Never identifies a client, validates a fix,
issues consent/authority, contacts targets or claims a security/release verdict.
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
import stat
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "remediation-human-replies"))
import reply  # original owner; intentionally unmodified
sys.path.insert(0, str(ROOT / "remediation-integrated-workspace"))
import install  # original private atomic publisher

KIND = "lightup.offline.original_encrypted_human_reply_signed_courier.v1"
PURPOSE = "PRIVATE_HUMAN_ONLY_ENCRYPTED_REPLY_CUSTODY_NOT_CONSENT"
DOMAIN = b"LIGHTUP:PRIVATE:HUMAN:REPLY:SIGNED:COURIER:V1\x00"
MAX_SOURCE = 2_000_000
MAX_REPLY = 500_000
MAX_COURIER = 3_500_000
MAX_KEY = 16_384
RECEIPT_KEYS = frozenset((
    "kind", "version", "purpose", "authority_granted", "consent_verified",
    "source_authenticated", "remediation_verified", "handoff_b64",
    "reply_b64", "handoff_sha256", "reply_sha256", "signing_public_b64",
    "signer_fingerprint", "signature_b64",
))
UNSIGNED = RECEIPT_KEYS - {"signature_b64"}


class Hold(ValueError):
    """A refusal is always DRAFT/HOLD, never consent or release."""


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode("ascii")


def unique_keys(pairs: list[tuple[str, object]]) -> dict:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise Hold("duplicate courier key")
        obj[key] = value
    return obj


def owner_dir(path: Path) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise Hold("only existing absolute owner-private directories are supported")
    s = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077:
        raise Hold("directory must be owned by operator and mode 0700")


def private_bytes(path: Path, ceiling: int) -> bytes:
    if not path.is_absolute() or path.is_symlink():
        raise Hold("input must be absolute, regular, direct and private")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o077:
        raise Hold("input must be owner-private, regular, nonlinked file mode 0600")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        current = os.fstat(fd)
        if not stat.S_ISREG(current.st_mode) or current.st_ino != info.st_ino or current.st_dev != info.st_dev or not 1 <= current.st_size <= ceiling:
            raise Hold("input size, type or identity changed")
        data = bytearray()
        while len(data) <= ceiling:
            block = os.read(fd, min(65536, ceiling + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        if len(data) != current.st_size or os.fstat(fd).st_size != current.st_size:
            raise Hold("input changed during bounded read")
        return bytes(data)
    finally:
        os.close(fd)


def publish_new(path: Path, content: bytes) -> None:
    owner_dir(path.parent)
    if not path.is_absolute() or path.is_symlink() or path.exists():
        raise Hold("output path must be new absolute and never overwrite")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as out:
            os.fchmod(fd, 0o600)
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    finally:
        os.close(fd)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fp(key: Ed25519PublicKey) -> str:
    return sha(key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    ))


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode(text: object, maximum: int) -> bytes:
    if type(text) is not str or len(text) > (maximum * 4 // 3) + 8:
        raise Hold("base64 field has wrong type or exceeds limits")
    try:
        data = base64.b64decode(text, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Hold("invalid canonical base64 field") from exc
    if not 1 <= len(data) <= maximum or b64(data) != text:
        raise Hold("noncanonical or over-limit base64 field")
    return data


def new_keys(directory: Path) -> None:
    if not sys.stdin.isatty():
        raise Hold("encrypted signing-key creation requires a private interactive terminal")
    owner_dir(directory.parent)
    if not directory.is_absolute() or directory.exists() or directory.is_symlink():
        raise Hold("key directory must be a fresh absolute location")
    password = getpass.getpass("New encrypted signing key passphrase: ")
    repeated = getpass.getpass("Confirm signing key passphrase: ")
    if len(password) < 12 or password != repeated:
        raise Hold("passphrase length or confirmation invalid")
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode("utf-8")),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    directory.mkdir(mode=0o700)
    try:
        publish_new(directory / "signing-private.pem", private)
        publish_new(directory / "signing-public.pem", public)
    except Exception:
        (directory / "signing-private.pem").unlink(missing_ok=True)
        (directory / "signing-public.pem").unlink(missing_ok=True)
        directory.rmdir()
        raise
    print("REVIEW_ONLY: new private signing key. Out-of-band public fingerprint:", fp(key.public_key()))
    print("Never transfer the private key or infer human identity/consent from a fingerprint.")


def public_key(raw: bytes) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(raw)
    except (ValueError, TypeError) as exc:
        raise Hold("invalid public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise Hold("courier signer must be Ed25519")
    canonical_pem = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    if raw != canonical_pem:
        raise Hold("public-key PEM must be canonical")
    return key


def original_admission(handoff: Path, response: Path) -> tuple[bytes, bytes]:
    """Only the original source owner may admit semantic HUMAN reply contents."""
    if handoff.suffix != ".luhq" or response.suffix != ".luhr" or handoff == response:
        raise Hold("separate original encrypted .luhq and .luhr inputs required")
    packet, digest, original_handoff_bytes = reply.source(handoff)
    _, original_response_bytes = reply.admitted_reply(response, packet, digest)
    if (
        reply.encrypted_cockpit.private_envelope(handoff) != original_handoff_bytes
        or reply.schedule_vault.private_vault(response) != original_response_bytes
    ):
        raise Hold("original encrypted bytes changed after native admission")
    return original_handoff_bytes, original_response_bytes


def seal(handoff: Path, response: Path, signing_key: Path, output: Path) -> None:
    if not sys.stdin.isatty():
        raise Hold("original human passphrases and signing key require a private interactive terminal")
    source_bytes, reply_bytes = original_admission(handoff, response)
    if len(source_bytes) > MAX_SOURCE or len(reply_bytes) > MAX_REPLY:
        raise Hold("original encrypted inputs exceed portable privacy limits")
    password = getpass.getpass("Separate Ed25519 signing-key passphrase: ")
    try:
        private = serialization.load_pem_private_key(private_bytes(signing_key, MAX_KEY), password.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise Hold("private signing key cannot be unlocked") from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise Hold("private signing key must be Ed25519")
    pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    unsigned = {
        "kind": KIND, "version": 1, "purpose": PURPOSE,
        "authority_granted": False, "consent_verified": False,
        "source_authenticated": False, "remediation_verified": False,
        "handoff_b64": b64(source_bytes), "reply_b64": b64(reply_bytes),
        "handoff_sha256": sha(source_bytes), "reply_sha256": sha(reply_bytes),
        "signing_public_b64": b64(pem),
        "signer_fingerprint": fp(private.public_key()),
    }
    sig = private.sign(DOMAIN + canonical(unsigned))
    record = {**unsigned, "signature_b64": b64(sig)}
    payload = canonical(record) + b"\n"
    if len(payload) > MAX_COURIER or output.suffix != ".luhs":
        raise Hold("courier exceeds limit or output extension differs")
    # The original source must remain byte-exact until transfer publication.
    if private_bytes(handoff, MAX_SOURCE) != source_bytes or private_bytes(response, MAX_REPLY) != reply_bytes:
        raise Hold("original HUMAN handoff or response changed before sealing")
    publish_new(output, payload)
    print("REVIEW_ONLY: private encrypted HUMAN courier sealed:", output)
    print("Signer key fingerprint — VERIFY FROM INDEPENDENT CHANNEL:", fp(private.public_key()))
    print("No actual sender identity, client consent, finding, fix, grant, release or HUMAN GO.")


def admit_courier(path: Path, expected_fingerprint: str) -> tuple[bytes, bytes, str, bytes]:
    if len(expected_fingerprint) != 64 or any(c not in "0123456789abcdef" for c in expected_fingerprint):
        raise Hold("recipient MUST independently confirm 64 lowercase-hex public fingerprint")
    raw = private_bytes(path, MAX_COURIER)
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_keys)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise Hold("corrupt signed HUMAN courier JSON") from exc
    if type(obj) is not dict or set(obj) != RECEIPT_KEYS:
        raise Hold("unknown signed private courier format")
    if raw != canonical(obj) + b"\n":
        raise Hold("private signed HUMAN courier has noncanonical byte encoding")
    if (
        obj["kind"] != KIND or type(obj["version"]) is not int or obj["version"] != 1
        or obj["purpose"] != PURPOSE
        or any(obj[key] is not False for key in (
            "authority_granted", "consent_verified", "source_authenticated",
            "remediation_verified",
        ))
    ):
        raise Hold("private encrypted courier attempts an authority claim or downgrade")
    pem = decode(obj["signing_public_b64"], MAX_KEY)
    pub = public_key(pem)
    actual_fp = fp(pub)
    if type(obj["signer_fingerprint"]) is not str or obj["signer_fingerprint"] != expected_fingerprint or actual_fp != expected_fingerprint:
        raise Hold("courier signing key does not match independently trusted fingerprint")
    source_bytes = decode(obj["handoff_b64"], MAX_SOURCE)
    reply_bytes = decode(obj["reply_b64"], MAX_REPLY)
    if (
        type(obj["handoff_sha256"]) is not str or obj["handoff_sha256"] != sha(source_bytes)
        or type(obj["reply_sha256"]) is not str or obj["reply_sha256"] != sha(reply_bytes)
    ):
        raise Hold("encrypted original file byte digest does not match signed receipt")
    signature = decode(obj["signature_b64"], 64)
    if len(signature) != 64:
        raise Hold("Ed25519 signature length wrong")
    unsigned = {key: obj[key] for key in UNSIGNED}
    try:
        pub.verify(signature, DOMAIN + canonical(unsigned))
    except InvalidSignature as exc:
        raise Hold("signed private HUMAN courier authenticity failed") from exc
    return source_bytes, reply_bytes, actual_fp, raw


def receive(courier: Path, fingerprint: str, destination: Path, *, resume: bool) -> None:
    if not sys.stdin.isatty():
        raise Hold("original HUMAN passwords require a private interactive terminal")
    if not destination.is_absolute() or destination.exists() or destination.is_symlink():
        raise Hold("received output must be a new absolute private directory")
    owner_dir(destination.parent)
    original_bytes, response_bytes, verified_fp, original_courier_bytes = admit_courier(courier, fingerprint)
    if destination == ROOT or ROOT in destination.parents:
        raise Hold("do not publish private HUMAN data under the source checkout")
    stage = destination.parent / (".lightup-human-courier-" + secrets.token_hex(12))
    stage.mkdir(mode=0o700)
    try:
        handoff = stage / "original-selected.luhq"
        answer = stage / "original-response.luhr"
        publish_new(handoff, original_bytes)
        publish_new(answer, response_bytes)
        # Same original source-owner admission and two-password decrypt invoked
        # only AFTER external fingerprint and Ed25519 signature verification.
        reply.open_reply(answer, handoff, stage / "native-human-report", editable=resume)
        if private_bytes(handoff, MAX_SOURCE) != original_bytes or private_bytes(answer, MAX_REPLY) != response_bytes:
            raise Hold("source or reply changed after original native admission")
        if private_bytes(courier, MAX_COURIER) != original_courier_bytes:
            raise Hold("source courier changed during private receive")
        warning = (
            "REVIEW_ONLY · INCUBATE M3/M7 PLAN/LAB ONLY · DRAFT/HOLD. "
            "Ed25519 independently trusted key fingerprint proves possession of a "
            "private signing key over EXACT encrypted source + reply bytes. "
            "It does not prove a real sender identity, client consent, original "
            "finding, evidence, remediation, authorization, HUMAN GO or release."
        )
        page = (
            "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
            "style-src 'unsafe-inline';base-uri 'none';form-action 'none'\">"
            "<title>LightUp private signed HUMAN handoff · REVIEW ONLY</title>"
            "<style>body{font:16px system-ui;background:#152033;color:#fff;"
            "max-width:850px;margin:3rem auto;padding:0 1rem}a{color:#a5ddff}"
            "aside{border:1px solid #b59d61;padding:1rem;border-radius:10px}</style>"
            "</head><body><h1>PRIVATE signed HUMAN reply · REVIEW ONLY</h1>"
            "<aside>" + html.escape(warning) + "</aside>"
            "<p>Exact private encrypted original source and HUMAN response "
            "were cryptographically signed by holder of a separately trusted key, "
            "then admitted by the unchanged original reply source owner. "
            "Neither is independently authenticated as a person or customer.</p>"
            "<p>Trusted key fingerprint: <code>" + html.escape(verified_fp) + "</code></p>"
            "<p><a href='native-human-report/index.html'>Open PRIVATE original HUMAN response</a></p>"
            "</body></html>"
        ).encode("utf-8")
        publish_new(stage / "index.html", page)
        install.exclusive_publish(stage, destination)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print("REVIEW_ONLY: original HUMAN source-bound signed private return:", destination)
    print("Open LOCAL PRIVATE:", destination / "index.html")
    print("Neither signature nor HUMAN text authorizes repairs, grants, scans or release.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    gen = sub.add_parser("keygen")
    gen.add_argument("--directory", required=True, type=Path)
    sign = sub.add_parser("seal")
    sign.add_argument("--handoff", required=True, type=Path)
    sign.add_argument("--reply", required=True, type=Path)
    sign.add_argument("--signing-key", required=True, type=Path)
    sign.add_argument("--output", required=True, type=Path)
    rec = sub.add_parser("receive")
    rec.add_argument("--courier", required=True, type=Path)
    rec.add_argument("--trusted-fingerprint", required=True)
    rec.add_argument("--output-dir", required=True, type=Path)
    rec.add_argument("--resume", action="store_true")
    check = sub.add_parser("inspect-signature")
    check.add_argument("--courier", required=True, type=Path)
    check.add_argument("--trusted-fingerprint", required=True)
    args = parser.parse_args()
    try:
        if args.action == "keygen":
            new_keys(args.directory)
        elif args.action == "seal":
            seal(args.handoff, args.reply, args.signing_key, args.output)
        elif args.action == "receive":
            receive(args.courier, args.trusted_fingerprint, args.output_dir, resume=args.resume)
        else:
            _, _, fingerprint, _ = admit_courier(args.courier, args.trusted_fingerprint)
            print("REVIEW_ONLY: encrypted ORIGINAL source + HUMAN reply bytes signed by trusted key", fingerprint)
            print("NOT VERIFIED: original decrypted admission, real signer identity, authorization, consent or release.")
    except (Hold, OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        print("HOLD:", exc, file=sys.stderr)
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
