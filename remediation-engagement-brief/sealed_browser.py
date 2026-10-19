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
import os
import stat
from pathlib import Path

from desk import build_desk
from history import review as history_review
from history_desk import build_history_desk
from ticketdesk import build_ticketdesk
from secure_export import (COLUMNS, FALSE, _literal, _strict_summary, _unique_pairs,
                           _vault, _make_envelope, _read_envelope)

KIND = "lightup.private_source_bound_browser_handoff"
VERSION = 1
ORIGINAL_APP_VERSION = 2
WORKSPACE_VERSION = 3
ORIGINAL_MODES = ("ticketdesk", "casework")
WORKSPACE_MODES = ("workspace", "workspace_history")
DISPOSITION = "PRIVATE_HUMAN_OFFLINE_SOURCE_ONLY"
MODES = ("current", "compare", "history", "ticketdesk", "casework",
         "workspace", "workspace_history")
KEYS = frozenset((
    "kind", "schema_version", "disposition", "mode", "client_id_self_declared",
    "engagement_id_self_declared", "current_original_csv_sha256", "current_original_count",
    "historical_original_csv", "authority",
))
ORIGINAL_APP_KEYS = KEYS | frozenset(("original_app_sha256",))
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
    required = {"current": 0, "compare": 1, "ticketdesk": 0, "casework": 0,
                "workspace": 0}
    if mode in required and len(history) != required[mode]:
        raise ValueError("Original browser source membership incorrect")
    if mode in ("history", "workspace_history") and not 1 <= len(history) <= 12:
        raise ValueError("Original history must contain 1-12 revisions")
    for source in history:
        if type(source) is not str:
            raise ValueError("Historical browser source is not canonical text")
        _digest(source)


def original_owner_html(mode: str, csv_text: str, client_id: str,
                        engagement_id: str) -> bytes:
    """Build with ORIGINAL existing owner functions, never clone or rewrite an app."""
    if mode == "ticketdesk":
        return build_ticketdesk(csv_text).encode("utf-8","strict")
    if mode == "casework":
        return _read_envelope(_make_envelope(csv_text,client_id,engagement_id,
                                             app="casework"))
    raise ValueError("Not an original source-owner offline HUMAN application")


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
    if mode in ORIGINAL_MODES:
        # Exact SHA of the original source-owner-rendered app WITH the current
        # original authenticated source, anchored in AES-GCM authenticated data.
        # An independently updated source-owner builder must not silently
        # change what an earlier approved PRIVATE browser handoff will show.
        packet["schema_version"] = ORIGINAL_APP_VERSION
        packet["original_app_sha256"] = hashlib.sha256(
            original_owner_html(mode,current_csv,client_id,engagement_id)
        ).hexdigest()
    if mode in WORKSPACE_MODES:
        # The same authenticated current source anchors both unchanged
        # original owner apps. No app bytes/HTML are stored in this package.
        # Future app changes force a fresh human handoff instead of
        # silently swapping implementations.
        packet["schema_version"] = WORKSPACE_VERSION
        packet["original_app_sha256"] = {
            name: hashlib.sha256(original_owner_html(
                name,current_csv,client_id,engagement_id)).hexdigest()
            for name in ORIGINAL_MODES
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
    if type(packet) is not dict or payload != _canonical(packet):
        raise ValueError("Unknown/noncanonical encrypted browser source metadata")
    declared_mode = packet.get("mode")
    # Keep previously issued review/history packets compatible. An original
    # app always needs the newer app-byte content pin. Older app-mode packets
    # are explicitly HOLD and need resealing from currently authorized source.
    required_version = (WORKSPACE_VERSION if declared_mode in WORKSPACE_MODES
                        else ORIGINAL_APP_VERSION if declared_mode in ORIGINAL_MODES
                        else VERSION)
    required_fields = (ORIGINAL_APP_KEYS if declared_mode in
                       (*ORIGINAL_MODES,*WORKSPACE_MODES) else KEYS)
    if set(packet) != required_fields:
        raise ValueError("Missing encrypted original owner app content pin")
    if (
        packet["kind"] != KIND or type(packet["schema_version"]) is not int
        or packet["schema_version"] != required_version or packet["disposition"] != DISPOSITION
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
    if declared_mode in (*ORIGINAL_MODES,*WORKSPACE_MODES):
        pins = packet["original_app_sha256"]
        if declared_mode in ORIGINAL_MODES:
            markers = (pins,)
        else:
            if type(pins) is not dict or set(pins) != set(ORIGINAL_MODES):
                raise ValueError("Missing original source-owner workspace application pins")
            markers = pins.values()
        for marker in markers:
            if (type(marker) is not str or len(marker) != 64 or
                any(ch not in "0123456789abcdef" for ch in marker)):
                raise ValueError("Invalid encrypted original source-owner SHA256 pin")
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


def _admit_encrypted_source(current_csv: str, client_id: str,
                            engagement_id: str, source: Path) -> dict:
    """Authenticate and admit the entire existing encrypted PRIVATE source.

    The original account/tenant authentication is performed by the calling
    brief.py CLI BEFORE invoking this helper. SHA+count prove source matching,
    never a current client/operator consent to execute an action.
    """
    current_sha,current_count=_digest(current_csv)
    encrypted=source.expanduser().absolute()
    if encrypted.suffix.lower() != ".ltv":
        raise ValueError("Encrypted PRIVATE handoff must be a .ltv file")
    vault=_vault()
    raw=vault._private_input(encrypted,vault.MAX_VAULT)
    password=vault._password("PRIVATE browser handoff passphrase: ",fresh=False)
    plaintext,kind,_=vault._open(raw,password)
    if kind!="application/json":
        raise ValueError("Original PRIVATE browser packet must contain canonical JSON")
    packet=unpack(plaintext)
    if (
        packet["client_id_self_declared"] != client_id
        or packet["engagement_id_self_declared"] != engagement_id
        or packet["current_original_csv_sha256"] != current_sha
        or packet["current_original_count"] != current_count
    ):
        raise ValueError("Current original authorized source drift or tenant mismatch: HOLD")
    return packet


def _original_workspace_apps(packet: dict, current_csv: str, client_id: str,
                             engagement_id: str) -> dict[str, bytes]:
    """Require BOTH authentic original app content pins before any release."""
    if packet["mode"] not in WORKSPACE_MODES:
        raise ValueError("Not a sealed multiview original source workspace")
    apps={name: original_owner_html(name,current_csv,client_id,engagement_id)
          for name in ORIGINAL_MODES}
    for name,bytes_ in apps.items():
        if hashlib.sha256(bytes_).hexdigest()!=packet["original_app_sha256"][name]:
            raise ValueError("Original offline owner application changed: HUMAN HOLD")
    return apps


def open_current(current_csv: str, client_id: str, engagement_id: str, *,
                 source: Path, output: Path, view: str | None = None) -> str:
    """Rebuild trusted local-only HTML only after independent current authorization.

    The caller must have already called the original authenticated source reader;
    this module cannot itself authenticate users or issue any permission.
    """
    encrypted_path = source.expanduser().absolute()
    destination = output.expanduser().absolute()
    if encrypted_path.suffix.lower() != ".ltv" or destination.suffix.lower() != ".html":
        raise ValueError("Original encrypted input and new PRIVATE HTML output required")
    if encrypted_path == destination:
        raise ValueError("Encrypted handoff must never be overwritten")
    packet=_admit_encrypted_source(current_csv,client_id,engagement_id,source)
    vault=_vault()
    # These browser bytes are always regenerated from immutable local app source,
    # never evaluated, served, or copied from an arbitrary encrypted HTML string.
    now = _rows(current_csv)
    old_sources = [_rows(csv_text) for csv_text in packet["historical_original_csv"]]
    if packet["mode"] in WORKSPACE_MODES:
        allowed = ("review","ticketdesk","casework","history") if old_sources else (
            "review","ticketdesk","casework")
        if view not in allowed:
            raise ValueError("Select one supported PRIVATE workspace view, not automatic execution")
        apps=_original_workspace_apps(packet,current_csv,client_id,engagement_id)
        if view in ORIGINAL_MODES:
            document = apps[view]
        elif view == "history":
            snapshots = [(dict(historical_local_only=True), records)
                         for records in old_sources]
            snapshots.append((dict(current_auth_read=True), now))
            document = build_history_desk(history_review(snapshots))
        else:
            # Review shows the immediately preceding original history when
            # supplied, not a fabricated authenticated finding from the past.
            document = build_desk(now, old_sources[-1] if old_sources else None)
        vault._exclusive_output(destination, document)
        return "workspace/"+view
    if view is not None:
        raise ValueError("View selection is only available for sealed original workspaces")
    if packet["mode"] == "current":
        document = build_desk(now)
    elif packet["mode"] == "compare":
        document = build_desk(now, old_sources[0])
    elif packet["mode"] in ORIGINAL_MODES:
        # Both original source HTML bytes and original authorized finding bytes
        # must match the authenticated ciphertext package before export.
        # This is integrity of the HUMAN app, NOT security, grant or consent.
        document = original_owner_html(packet["mode"],current_csv,client_id,
                                       engagement_id)
        if hashlib.sha256(document).hexdigest() != packet["original_app_sha256"]:
            raise ValueError("Original source-owner offline app changed: HUMAN handoff HOLD")
    else:
        snapshots = [(dict(historical_local_only=True), records) for records in old_sources]
        snapshots.append((dict(current_auth_read=True), now))
        document = build_history_desk(history_review(snapshots))
    vault._exclusive_output(destination, document)
    return packet["mode"]
