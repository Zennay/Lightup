#!/usr/bin/env python3
"""Read-only, non-authorizing offline LightUp scope review-packet shape check.

Never interpret REVIEW_ONLY as a permit, consent, runner attestation or release.
No LightUp runtime modules, network access, subprocesses, or target parsing.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import stat
import sys
import unicodedata

MAX_BYTES = 16 * 1024
FIELDS = frozenset({
    "schema_version", "request_id", "tenant_id", "asset_id", "requester_id",
    "authorization_reference", "scope_reference", "requested_mode", "risk_level",
    "requested_capabilities", "review_evidence_digests", "window_start", "window_end",
})
IDENTITY = re.compile(r"[a-z][a-z0-9_-]{2,63}\Z", re.ASCII)
REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{2,127}\Z", re.ASCII)
DIGEST = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z", re.ASCII)
CAPABILITIES = frozenset({"http_headers", "tls_baseline", "service_inventory", "future_simulation"})
MODES = {"ANALYSIS_ONLY": {0}, "PASSIVE_PUBLIC": {0, 1}, "LAB_ACTIVE": {0, 1, 2, 3, 4, 5}, "TARGET_ACTIVE": {2, 3, 4}}
AUTHORITY_FLAGS = {
    "authorization_verified": False,
    "permit_issued": False,
    "execution_enabled": False,
    "merge_approved": False,
    "release_approved": False,
}


class PacketHold(ValueError):
    """Expected, privacy-safe HOLD with a fixed error category."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _pair_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out = {}
    for key, value in pairs:
        if key in out:
            raise PacketHold("DUPLICATE_KEY")
        out[key] = value
    return out


def _reject_number(_value: str) -> None:
    raise PacketHold("NONFINITE_NUMBER")


def _plain(value: str) -> bool:
    return unicodedata.is_normalized("NFC", value) and not any(
        unicodedata.category(c)[0] == "C" or c == "\ufeff" for c in value
    )


def _text(value: object, pattern: re.Pattern[str]) -> bool:
    return type(value) is str and _plain(value) and pattern.fullmatch(value) is not None


def _time(value: object) -> dt.datetime:
    if not _text(value, UTC):
        raise PacketHold("WINDOW_FORMAT")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise PacketHold("WINDOW_FORMAT") from None
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise PacketHold("WINDOW_FORMAT")
    return parsed


def validate_packet(packet: object) -> None:
    """Only validates untrusted packet SHAPE. No identity or consent is authenticated."""
    if type(packet) is not dict or packet.keys() != FIELDS:
        raise PacketHold("SCHEMA_FIELDS")
    if type(packet["schema_version"]) is not int or packet["schema_version"] != 1:
        raise PacketHold("SCHEMA_VERSION")
    for field in ("request_id", "tenant_id", "asset_id", "requester_id"):
        if not _text(packet[field], IDENTITY):
            raise PacketHold("IDENTITY_FORMAT")
    for field in ("authorization_reference", "scope_reference"):
        if not _text(packet[field], REF):
            raise PacketHold("REFERENCE_FORMAT")
    mode = packet["requested_mode"]
    risk = packet["risk_level"]
    if type(mode) is not str or mode not in MODES or type(risk) is not int or risk not in MODES[mode]:
        raise PacketHold("MODE_RISK")
    caps = packet["requested_capabilities"]
    if type(caps) is not list or not 1 <= len(caps) <= 4 or any(type(x) is not str or x not in CAPABILITIES for x in caps):
        raise PacketHold("CAPABILITIES")
    if caps != sorted(set(caps)):
        raise PacketHold("CAPABILITIES")
    if mode == "ANALYSIS_ONLY" and any(c != "future_simulation" for c in caps):
        raise PacketHold("MODE_CAPABILITY")
    if mode == "PASSIVE_PUBLIC" and any(c != "future_simulation" for c in caps):
        raise PacketHold("MODE_CAPABILITY")
    proofs = packet["review_evidence_digests"]
    if type(proofs) is not list or not 1 <= len(proofs) <= 8 or not all(_text(x, DIGEST) for x in proofs):
        raise PacketHold("EVIDENCE_SHAPE")
    if proofs != sorted(set(proofs)):
        raise PacketHold("EVIDENCE_SHAPE")
    start, end = _time(packet["window_start"]), _time(packet["window_end"])
    if not dt.timedelta(minutes=1) <= end - start <= dt.timedelta(hours=24):
        raise PacketHold("WINDOW_BOUNDS")


def _decode(raw: bytes) -> object:
    try:
        if raw.startswith(b"\xef\xbb\xbf"):
            raise PacketHold("ENCODING")
        content = raw.decode("utf-8", errors="strict")
        if not _plain(content):
            # JSON whitespace is allowed, so reject only controls beyond JSON's lexical whitespace.
            if any((ord(c) < 32 and c not in "\r\n\t") or unicodedata.category(c) in ("Cf", "Cs") for c in content):
                raise PacketHold("ENCODING")
        return json.loads(content, object_pairs_hook=_pair_hook, parse_constant=_reject_number)
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, PacketHold):
            raise
        raise PacketHold("INVALID_JSON") from None


def _enforce_private_file(info: os.stat_result) -> None:
    """Optional POSIX data-minimisation gate; not proof of trusted origin."""
    if (not hasattr(os, "geteuid") or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077):
        raise PacketHold("PRIVATE_FILE_REQUIRED")


def read_packet(path: str, *, require_private_file: bool = False) -> bytes:
    """Read only a bounded, regular, non-symlink local file; no external I/O."""
    if type(require_private_file) is not bool:
        raise PacketHold("INVALID_FILE_POLICY")
    fd = None
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode):
            raise PacketHold("INPUT_UNAVAILABLE")
        if not stat.S_ISREG(before.st_mode):
            raise PacketHold("NOT_REGULAR_FILE")
        if require_private_file:
            _enforce_private_file(before)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise PacketHold("NOT_REGULAR_FILE")
        if require_private_file:
            _enforce_private_file(info)
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns):
            raise PacketHold("CHANGED_INPUT")
        if info.st_size > MAX_BYTES:
            raise PacketHold("SIZE_LIMIT")
        raw = os.read(fd, MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise PacketHold("SIZE_LIMIT")
        if len(raw) != info.st_size:
            raise PacketHold("CHANGED_INPUT")
        after = os.fstat(fd)
        if require_private_file:
            _enforce_private_file(after)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns):
            raise PacketHold("CHANGED_INPUT")
        return raw
    except (OSError, OverflowError, ValueError) as exc:
        if isinstance(exc, PacketHold):
            raise
        raise PacketHold("INPUT_UNAVAILABLE") from None
    finally:
        if fd is not None:
            os.close(fd)


def evaluate(raw: bytes) -> dict[str, object]:
    state, reason = "HOLD", "INVALID_PACKET"
    try:
        if type(raw) is not bytes or len(raw) > MAX_BYTES:
            raise PacketHold("SIZE_LIMIT")
        validate_packet(_decode(raw))
        state, reason = "REVIEW_ONLY", "SHAPE_ONLY_UNVERIFIED"
    except PacketHold as exc:
        reason = exc.code
    return {"state": state, "reason": reason, "non_authorizing": True, **AUTHORITY_FLAGS}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline, non-authorizing scope packet shape review")
    parser.add_argument("packet_file", help="Local regular JSON file only; never a URL or target")
    parser.add_argument("--require-private-file", action="store_true",
                        help="Fail closed unless local file is owned by current uid, has one link and no group/other permissions (POSIX); never authorizes scope")
    args = parser.parse_args(argv)
    try:
        result = evaluate(read_packet(args.packet_file, require_private_file=args.require_private_file))
    except PacketHold as exc:
        result = {"state": "HOLD", "reason": exc.code, "non_authorizing": True, **AUTHORITY_FLAGS}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["state"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    sys.exit(main())
