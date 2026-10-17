"""Offline continuity reviewer for fictional scope consent snapshots; NEVER authority.

A self-contained hash chain checks internal continuity, NOT signatures, trusted
provenance, durable non-replay or real-world client/operator authorization.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

SCRIPT = Path(__file__).resolve().with_name("review_scope_consent_revocation_1551_offline.py")
SPEC = importlib.util.spec_from_file_location("scope1551_claim_review", SCRIPT)
claim = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(claim)

MAX_TIMELINE_BYTES = 128 * 1024
MAX_ENTRIES = 16


def _fail() -> None:
    raise claim.PacketError("invalid_timeline")


def _canonical(item: dict[str, object]) -> bytes:
    return json.dumps(item, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def entry_digest(entry: dict[str, object]) -> str:
    """Compute the *untrusted* internal anchor for the following entry."""
    return hashlib.sha256(_canonical(entry)).hexdigest()


def _review(raw: bytes) -> str:
    if type(raw) is not bytes or not raw or len(raw) > MAX_TIMELINE_BYTES:
        _fail()
    # A strict byte identity contract; no escaped JSON-name aliases or unicode.
    if b"\\" in raw:
        _fail()
    try:
        payload = json.loads(raw.decode("utf-8", "strict"),
                             object_pairs_hook=claim._pairs,
                             parse_constant=claim._constant)
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
        _fail()
    if type(payload) is not dict or set(payload) != {"schema_version", "entries"}:
        _fail()
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        _fail()
    entries = payload["entries"]
    if type(entries) is not list or not 2 <= len(entries) <= MAX_ENTRIES:
        _fail()

    prev_entry = None
    prev_time = None
    baseline_consents = None
    proposal = None
    scope = None
    for item in entries:
        if type(item) is not dict or set(item) != {"packet", "previous_sha256"}:
            _fail()
        packet = item["packet"]
        if type(packet) is not dict:
            _fail()
        previous = item["previous_sha256"]
        if prev_entry is None:
            if previous is not None:
                _fail()
        elif type(previous) is not str or previous != entry_digest(prev_entry):
            _fail()

        # Parent reviewer enforces exact v1 fields and all denial flags.
        outcome = claim.review(_canonical(packet))
        if outcome["status"] != "REVIEW_ONLY":
            _fail()
        now = claim._utc(packet["review_at"])
        if prev_time is not None and now <= prev_time:
            _fail()
        consents = _canonical(packet["consents"])
        if baseline_consents is None:
            baseline_consents = consents
            proposal, scope = packet["proposal_sha"], packet["scope_sha256"]
        elif (consents != baseline_consents or packet["proposal_sha"] != proposal
              or packet["scope_sha256"] != scope):
            _fail()
        prev_entry, prev_time = item, now
    return entry_digest(prev_entry)


def review(raw: bytes, *, expected_head_sha256: str | None = None) -> dict[str, object]:
    try:
        observed = _review(raw)
        if expected_head_sha256 is not None:
            if (type(expected_head_sha256) is not str
                or not claim.DIGEST.fullmatch(expected_head_sha256)
                or expected_head_sha256 == "0" * 64
                or expected_head_sha256 != observed):
                _fail()
    except (claim.PacketError, OverflowError, MemoryError, TypeError, ValueError, KeyError, RecursionError):
        return {"schema_version": 1, "status": "HOLD",
                "reason": "UNTRUSTED_OR_DISCONTINUOUS", **claim.AUTHORITY_FLAGS}
    return {"schema_version": 1, "status": "REVIEW_ONLY",
            "reason": "UNAUTHENTICATED_CONTINUITY_ONLY", **claim.AUTHORITY_FLAGS}


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    result = None
    if argv and not (len(argv) == 2 and argv[0] == "--expected-head"):
        result = review(b"")
    else:
        try:
            chunks = []
            size = 0
            while True:
                chunk = sys.stdin.buffer.read(min(4096, MAX_TIMELINE_BYTES + 1 - size))
                if type(chunk) is not bytes:
                    _fail()
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_TIMELINE_BYTES:
                    _fail()
                chunks.append(chunk)
            result = review(b"".join(chunks), expected_head_sha256=(argv[1] if argv else None))
        except (OSError, claim.PacketError, ValueError, MemoryError, OverflowError):
            result = review(b"")
    try:
        wire = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
        written = sys.stdout.write(wire)
        sys.stdout.flush()
        if type(written) is not int or written != len(wire):
            return 2
    except (OSError, ValueError, UnicodeError):
        return 2
    return 3 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
