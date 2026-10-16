"""Opt-in, synthetic-only transport metadata reviewer. Never grants authority.

This module is intentionally NOT imported by LightUp runtime and does no I/O
except bounded CLI stdin and a generic, privacy-minimal stdout receipt.
"""
from __future__ import annotations

import ipaddress
import json
import re
import sys
from urllib.parse import urlsplit

MAX_INPUT_BYTES = 4096
_KEYS = frozenset(("trusted_proxy_ip", "public_origin"))
_LABEL = re.compile(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
_FLAGS = {
    "grants_authority": False,
    "permits_execution": False,
    "dispatch_allowed": False,
    "scans_allowed": False,
    "deploy_allowed": False,
    "release_allowed": False,
}


class _UnsafeMetadata(ValueError):
    pass


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _UnsafeMetadata("duplicate key")
        result[key] = value
    return result


def _no_constants(_value: str) -> object:
    raise _UnsafeMetadata("invalid JSON constant")


def _canonical_synthetic_origin(origin: str) -> bool:
    if not origin.isascii() or any(ord(ch) < 33 or ord(ch) > 126 for ch in origin):
        return False
    try:
        parsed = urlsplit(origin)
        host = parsed.hostname
        if parsed.scheme != "https" or host is None or parsed.port is not None:
            return False
        if parsed.username is not None or parsed.password is not None:
            return False
        if parsed.path or parsed.query or parsed.fragment:
            return False
        if not host.endswith(".example") or host == ".example":
            return False
        if any(not _LABEL.fullmatch(label) for label in host.split(".")):
            return False
        return origin == "https://" + host
    except (ValueError, TypeError):
        return False


def _strict_preview(metadata: object) -> bool:
    # The exact type check is before every call to user-overridable methods.
    # Never hash/compare caller-supplied key objects before exact key typing.
    # dict_keys equality would otherwise invoke a spoofed str subclass __eq__.
    if type(metadata) is not dict or len(metadata) != len(_KEYS):
        return False
    if any(type(key) is not str for key in metadata):
        return False
    if metadata.keys() != _KEYS:
        return False
    proxy = metadata["trusted_proxy_ip"]
    origin = metadata["public_origin"]
    if type(proxy) is not str or type(origin) is not str:
        return False
    if proxy not in ("127.0.0.1", "::1"):
        return False
    try:
        if not ipaddress.ip_address(proxy).is_loopback:
            return False
    except ValueError:
        return False
    return _canonical_synthetic_origin(origin)


def review_metadata(metadata: object) -> dict[str, object]:
    """Never returns GO; REVIEW_ONLY means *syntax*, not proxy/origin trust."""
    try:
        safe_shape = _strict_preview(metadata)
    except Exception:
        safe_shape = False
    return {"decision": "REVIEW_ONLY" if safe_shape else "HOLD", **_FLAGS}


def review_json(data: bytes) -> dict[str, object]:
    if type(data) is not bytes or len(data) > MAX_INPUT_BYTES:
        return review_metadata(None)
    try:
        data.decode("utf-8", errors="strict")
        obj = json.loads(
            data.decode("utf-8"), object_pairs_hook=_strict_pairs,
            parse_constant=_no_constants,
        )
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return review_metadata(None)
    return review_metadata(obj)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    # A programmatic caller may pass a list/subclass with forged equality.
    # Do not access stdin until BOTH outer/inner argv types are canonical.
    opt_in = (
        type(args) is list and len(args) == 1
        and type(args[0]) is str and args[0] == "--offline-synthetic-only"
    )
    if not opt_in:
        decision = review_metadata(None)
    else:
        decision = review_json(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
    sys.stdout.write(json.dumps(decision, sort_keys=True, separators=(",", ":")) + "\n")
    return 3 if decision["decision"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
