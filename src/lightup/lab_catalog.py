"""Strict, non-authorizing bridge from private Lab Scenario Studio catalogs.

The catalog supplies only human-authored lab design metadata. It never
authenticates ownership, grants permission or supplies trusted ground truth.
All endpoint URLs remain independently provided and gated by LabScenario.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat

_SCHEMA = "lightup.lab_design_catalog.v1"
_FLAGS = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", re.ASCII)
_LEVELS = frozenset(("critical", "high", "medium", "low", "info"))
_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10",
))


def _deny() -> None:
    # Avoid disclosing private scenario names or target identities in errors.
    raise ValueError("private lab design catalog was not admitted")


def _pairs(items: list[tuple[str, object]]) -> dict:
    record: dict = {}
    for key, value in items:
        if key in record:
            _deny()
        record[key] = value
    return record


def _exact(value: object, fields: set[str]) -> bool:
    return type(value) is dict and set(value) == fields


def _label(value: object, low: int, high: int) -> bool:
    return (
        type(value) is str and low <= len(value) <= high
        and value == value.strip() and all(32 <= ord(c) <= 126 for c in value)
    )


def _private_literal(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= 45:
        _deny()
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        _deny()
    if addr.version == 4 and str(addr) != value:
        _deny()
    if addr.version == 6 and (":" not in value or "." in value or "%" in value):
        _deny()
    if not any(addr in network for network in _NETWORKS):
        _deny()
    return str(addr)


def read_selected_lab_design(file: str, scenario_id: str) -> dict:
    """Read bounded exact Studio v1 JSON and select one fully admitted design."""
    if type(scenario_id) is not str or _ID.fullmatch(scenario_id) is None:
        _deny()
    fd = -1
    try:
        # Follow neither the final symlink nor a special-device or FIFO alias.
        # Validate the OPEN descriptor rather than racy pathname stat().
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(file, flags)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 262_144:
            _deny()
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(262_145)
        if not 0 < len(raw) <= 262_144:
            _deny()
        document = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs,
            parse_constant=lambda _: _deny(),
        )
        if not _exact(document, {"schema", "status", "scenarios", *_FLAGS}):
            _deny()
        if document["schema"] != _SCHEMA or document["status"] != "DRAFT_ONLY":
            _deny()
        if any(document[field] is not False for field in _FLAGS):
            _deny()
        rows = document["scenarios"]
        if type(rows) is not list or not 1 <= len(rows) <= 32:
            _deny()
        seen_scenarios: set[str] = set()
        selected: dict | None = None
        for row in rows:
            if not _exact(row, {"scenario_id", "name", "description", "targets", "expected_findings"}):
                _deny()
            sid = row["scenario_id"]
            if type(sid) is not str or _ID.fullmatch(sid) is None or sid in seen_scenarios:
                _deny()
            seen_scenarios.add(sid)
            if not _label(row["name"], 1, 160) or not _label(row["description"], 0, 500):
                _deny()
            original_targets = row["targets"]
            if type(original_targets) is not list or not 1 <= len(original_targets) <= 16:
                _deny()
            targets = tuple(_private_literal(target) for target in original_targets)
            if len(set(targets)) != len(targets):
                _deny()
            declared = row["expected_findings"]
            if declared is not None and (type(declared) is not list or len(declared) > 64):
                _deny()
            seen_checks: set[str] = set()
            for item in declared or ():
                if not _exact(item, {"identifier", "title", "capability_id", "severity"}):
                    _deny()
                fid, cap = item["identifier"], item["capability_id"]
                if (type(fid) is not str or _ID.fullmatch(fid) is None
                    or fid in seen_checks or type(cap) is not str
                    or _ID.fullmatch(cap) is None or not _label(item["title"], 1, 160)
                    or type(item["severity"]) is not str
                    or item["severity"] not in _LEVELS):
                    _deny()
                seen_checks.add(fid)
            if sid == scenario_id:
                selected = {
                    "schema": _SCHEMA,
                    "scenario_id": sid,
                    "name": row["name"],
                    "description": row["description"],
                    "targets": targets,
                    "declared_expected_count": None if declared is None else len(declared),
                    "catalog_sha256": hashlib.sha256(raw).hexdigest(),
                    "source_authenticated": False,
                    "declared_ground_truth_used": False,
                    "authorization_granted": False,
                }
        if selected is None:
            _deny()
        return selected
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError,
            OverflowError, RecursionError, MemoryError):
        raise ValueError("private lab design catalog was not admitted") from None
    finally:
        if fd >= 0:
            os.close(fd)
