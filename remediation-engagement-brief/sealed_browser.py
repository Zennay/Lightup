"""Encrypted source-bound offline browser handoff; never grants execution authority.

A .ltv contains only authenticated source metadata and optional historical CSV
snapshots, NOT executable HTML. On reopen the fixed local browser app is rebuilt
from a freshly authenticated original LightUp engagement source. The original
vault format, domain authentication and source admission remain unchanged.
"""
from __future__ import annotations

import hashlib
import json
import csv
import io
from pathlib import Path

from desk import build_desk
from history import review as history_review
from history_desk import build_history_desk
from ticketdesk import build_ticketdesk
from secure_export import COLUMNS, FALSE, _literal, _strict_summary, _unique_pairs, _vault

KIND = "lightup.private_source_bound_browser_handoff"
VERSION = 1
DISPOSITION = "PRIVATE_HUMAN_OFFLINE_SOURCE_ONLY"
MODES = ("current", "compare", "history", "ticketdesk")
KEYS = frozenset((
    "kind", "schema_version", "disposition", "mode", "client_id_self_declared",
    "engagement_id_self_declared", "current_original_csv_sha256", "current_original_count",
    "historical_original_csv", "authority",
))
MAX_PAYLOAD = 4 * 1024 * 1024 - 8192


def _canonical(packet: dict) -> bytes:
    return json.dumps(packet, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(source: str) -> tuple[str, int]:
    sha, count = _strict_summary(source)
    if type(sha) is not str or len(sha) != 64:
        raise ValueError("Original source identity invalid")
    return sha, count


def _check_mode(mode: str, history: list[str]) -> None:
    if type(mode) is not str or mode not in MODES or type(history) is not list:
        raise ValueError("Unknown original-source browser handoff type")
    required = {"current": 0, "compare": 1, "ticketdesk": 0}
    if mode in required and len(history) != required[mode]:
        raise ValueError("Original browser source membership incorrect")
    if mode == "history" and not 1 <= len(history) <= 12:
        raise ValueError("Original history must contain 1-12 revisions")
    for source in history:
        if type(source) is not str:
            raise ValueError("Historical browser source is not canonical text")
        _digest(source)


def pack(current_csv: str, client_id: str, engagement_id: str, *,
         mode: str, history_csv: list[str]) -> bytes:
    """Create strictly non-authorizing encrypted-payload metadata in memory."""
    sha, count = _digest(current_csv)
    _check_mode(mode, history_csv)
    packet = {
        "kind": KIND, "schema_version": VERSION, "disposition": DISPOSITION,
        "mode": mode,
        "client_id_self_declared": _literal(client_id, "client ID"),
        "engagement_id_self_declared": _literal(engagement_id, "engagement ID"),
        "current_original_csv_sha256": sha, "current_original_count": count,
        "historical_original_csv": list(history_csv),
        "authority": {flag: False for flag in FALSE},
    }
    payload = _canonical(packet)
    if not 1 <= len(payload) <= MAX_PAYLOAD:
        raise ValueError("Encrypted browser source package exceeds private vault size")
    return payload


def unpack(payload: bytes) -> dict:
    """Fail closed before interpreting any content from the encrypted handoff."""
    if not payload or len(payload) > MAX_PAYLOAD:
        raise ValueError("Encrypted browser packet length invalid")
    packet = json.loads(payload.decode("ascii", "strict"), object_pairs_hook=_unique_pairs)
    if type(packet) is not dict or set(packet) != KEYS or payload != _canonical(packet):
        raise ValueError("Unknown/noncanonical encrypted browser source metadata")
    if (
        packet["kind"] != KIND or type(packet["schema_version"]) is not int
        or packet["schema_version"] != VERSION or packet["disposition"] != DISPOSITION
        or type(packet["authority"]) is not dict
        or set(packet["authority"]) != set(FALSE)
        or any(packet["authority"][key] is not False for key in FALSE)
    ):
        raise ValueError("Browser handoff attempted to assert release/consent authority")
    _literal(packet["client_id_self_declared"], "client ID")
    _literal(packet["engagement_id_self_declared"], "engagement ID")
    if (type(packet["current_original_csv_sha256"]) is not str
        or len(packet["current_original_csv_sha256"]) != 64
        or any(c not in "0123456789abcdef" for c in packet["current_original_csv_sha256"])
        or type(packet["current_original_count"]) is not int
        or not 1 <= packet["current_original_count"] <= 350):
        raise ValueError("Source hash/count metadata invalid")
    _check_mode(packet["mode"], packet["historical_original_csv"])
    return packet


def seal(current_csv: str, client_id: str, engagement_id: str, *,
         mode: str, history_csv: list[str], output: Path) -> None:
    """Write NEW owner-private AES-GCM .ltv; never write plaintext HTML."""
    target = output.expanduser().absolute()
    if target.suffix.lower() != ".ltv":
        raise ValueError("Portable source-bound browser handoff must be a NEW .ltv")
    vault = _vault()
    encoded = vault._inner(
        pack(current_csv, client_id, engagement_id, mode=mode, history_csv=history_csv),
        "application/json",
    )
    if len(encoded) > vault.MAX_PLAIN:
        raise ValueError("Original private vault storage limit exceeded")
    secret = vault._password("New PRIVATE browser handoff passphrase: ", fresh=True)
    vault._exclusive_output(target, vault._seal(encoded, secret))



def _rows(original_csv: str) -> list[dict[str, str]]:
    """Independent literal decoding, after the canonical original full-batch gate."""
    _, expected = _digest(original_csv)
    reader = csv.DictReader(io.StringIO(original_csv, newline=""), strict=True)
    if reader.fieldnames != list(COLUMNS):
        raise ValueError("Canonical original source columns differ")
    parsed = []
    for item in reader:
        if set(item) != set(COLUMNS) or any(type(item[k]) is not str for k in COLUMNS):
            raise ValueError("Malformed original browser finding row")
        parsed.append({key: item[key] for key in COLUMNS})
    if len(parsed) != expected:
        raise ValueError("Original source browser membership changed")
    return parsed


def open_current(current_csv: str, client_id: str, engagement_id: str, *,
                 source: Path, output: Path) -> str:
    """Rebuild trusted local-only HTML only after independent current authorization.

    The caller must have already called the original authenticated source reader;
    this module cannot itself authenticate users or issue any permission.
    """
    current_sha, current_count = _digest(current_csv)
    encrypted_path = source.expanduser().absolute()
    destination = output.expanduser().absolute()
    if encrypted_path.suffix.lower() != ".ltv" or destination.suffix.lower() != ".html":
        raise ValueError("Original encrypted input and new PRIVATE HTML output required")
    if encrypted_path == destination:
        raise ValueError("Encrypted handoff must never be overwritten")
    vault = _vault()
    sealed = vault._private_input(encrypted_path, vault.MAX_VAULT)
    password = vault._password("PRIVATE browser handoff passphrase: ", fresh=False)
    payload, kind, _ = vault._open(sealed, password)
    if kind != "application/json":
        raise ValueError("Not a supported encrypted browser source package")
    packet = unpack(payload)
    if (
        packet["client_id_self_declared"] != client_id
        or packet["engagement_id_self_declared"] != engagement_id
        or packet["current_original_csv_sha256"] != current_sha
        or packet["current_original_count"] != current_count
    ):
        raise ValueError("Current original authorization/source differs: browser release HOLD")
    # These browser bytes are always regenerated from immutable local app source,
    # never evaluated, served, or copied from an arbitrary encrypted HTML string.
    now = _rows(current_csv)
    old_sources = [_rows(csv_text) for csv_text in packet["historical_original_csv"]]
    if packet["mode"] == "current":
        document = build_desk(now)
    elif packet["mode"] == "compare":
        document = build_desk(now, old_sources[0])
    elif packet["mode"] == "ticketdesk":
        # Invoke the unmodified, SHA-pinned ORIGINAL Ticket Desk builder;
        # it creates no duplicate HUMAN ticket state or alternative validator.
        document = build_ticketdesk(current_csv).encode("utf-8", "strict")
    else:
        snapshots = [(dict(historical_local_only=True), records) for records in old_sources]
        snapshots.append((dict(current_auth_read=True), now))
        document = build_history_desk(history_review(snapshots))
    vault._exclusive_output(destination, document)
    return packet["mode"]
