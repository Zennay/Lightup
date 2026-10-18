"""Conservative admission of separately owned LightUp Studio v1 scope drafts.

Input is untrusted DRAFT_ONLY planning material, never consent or authorization.
No imports from/edits to the independent Studio PR #1567.
"""
from __future__ import annotations

import hashlib
import json
import ipaddress
from pathlib import Path
import re

from .request_binding_readiness_cli import _assets

MAX_BYTES = 65536
MAX_PROPOSALS = 8
AUTHORITY_FALSE = (
    "authorization", "client_consent", "operator_consent", "grant",
    "execution", "revocation_checked",
)
REQUIRED = {
    "schema_version", "kind", "state", *AUTHORITY_FALSE,
    "proposal_name", "client_label", "requested_assets", "excluded_assets",
    "requested_mode", "requested_risk", "notes", "proposed_activities",
    "proposed_window_local", "proposed_window_utc", "exported_at_utc",
}
OPTIONAL = {"scope_fingerprint_sha256"}


def _unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate Studio draft JSON key")
        result[name] = value
    return result


def _reject_constant(value: str):
    raise ValueError("nonfinite Studio draft values are forbidden")


def _canonical_asset(source: str) -> str:
    if type(source) is not str:
        raise ValueError("non-text Studio asset")
    ip = None
    try:
        ip = ipaddress.ip_network(source, strict=True)
    except ValueError:
        pass
    if ip is not None:
        canonical = str(ip)
        if "/" not in source:
            canonical = canonical.split("/")[0]
        if canonical != source:
            raise ValueError("noncanonical Studio IP/CIDR")
        return source
    if source != source.lower():
        raise ValueError("Studio DNS host must be original canonical lowercase")
    return source


def _verify_schema(raw: dict) -> tuple[str, tuple[str, ...], int]:
    if (type(raw) is not dict or not REQUIRED <= set(raw)
            or set(raw) - REQUIRED - OPTIONAL or raw["schema_version"] != 1
            or raw["kind"] != "lightup.scope_proposal_draft"
            or raw["state"] != "DRAFT_ONLY"
            or any(raw[field] is not False for field in AUTHORITY_FALSE)):
        raise ValueError("Studio draft does not have exact false authority envelope")
    name = raw["proposal_name"]
    if type(name) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _./()-]{0,63}", name):
        raise ValueError("Studio draft name not suitable for local option label")
    if (type(raw["client_label"]) is not str or len(raw["client_label"]) > 100
            or type(raw["notes"]) is not str or len(raw["notes"]) > 3000):
        raise ValueError("Studio label or notes exceed bounds")
    if raw["requested_mode"] != "authorized_assessment":
        raise ValueError("passive Studio draft not eligible for assessment request matching")
    risk = raw["requested_risk"]
    if type(risk) is not int or risk not in (1, 2, 3, 4):
        raise ValueError("Studio risk not canonical")
    requested = raw["requested_assets"]
    excluded = raw["excluded_assets"]
    if type(requested) is not list or type(excluded) is not list:
        raise ValueError("Studio assets not lists")
    if excluded:
        raise ValueError("Studio exclusions must not be discarded or silently narrowed")
    assets = _assets(requested)
    if any(_canonical_asset(v) != v for v in assets):
        raise ValueError("noncanonical Studio asset")
    activities = raw["proposed_activities"]
    if type(activities) is not dict or set(activities) != {
            "passive_analysis", "configuration_review", "private_lab_network_checks"
    } or any(type(value) is not bool for value in activities.values()):
        raise ValueError("invalid Studio activity envelope")
    if activities["private_lab_network_checks"]:
        raise ValueError("lab-network activity may not be promoted to grant preview")
    local = raw["proposed_window_local"]
    window = raw["proposed_window_utc"]
    if (type(local) is not dict or set(local) != {"start", "end"}
            or type(window) is not dict or
            set(window) - {"status", "timezone", "start", "end",
                           "start_offset_minutes", "end_offset_minutes"}):
        raise ValueError("unsupported Studio UTC proposal window")
    if type(window.get("timezone")) is not str or len(window["timezone"]) > 100:
        raise ValueError("invalid Studio timezone label")
    # Studio planning time is NEVER an issuance time; only preserve valid
    # original representation or fail rather than silently dropping it.
    if window.get("status") == "unscheduled":
        if local != {"start": None, "end": None} or window.get("start") is not None or window.get("end") is not None:
            raise ValueError("inconsistent unscheduled window")
    elif window.get("status") == "incomplete":
        if not ((local.get("start") is None) != (local.get("end") is None)):
            raise ValueError("inconsistent incomplete window")
        if window.get("start") is not None or window.get("end") is not None:
            raise ValueError("incorrect partial UTC interval")
    elif window.get("status") == "resolved":
        from datetime import datetime, timedelta, timezone
        def resolve(wall: object, offset: object) -> str:
            if type(wall) is not str or not re.fullmatch(r"20[2-9][0-9]-(0[1-9]|1[0-2])-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]", wall):
                raise ValueError("unsupported local datetime")
            if type(offset) is not int or abs(offset) > 840:
                raise ValueError("unsupported timezone offset")
            parsed = datetime.strptime(wall, "%Y-%m-%dT%H:%M")
            moment = (parsed + timedelta(minutes=offset)).replace(tzinfo=timezone.utc)
            return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        start = resolve(local.get("start"), window.get("start_offset_minutes"))
        end = resolve(local.get("end"), window.get("end_offset_minutes"))
        if window.get("start") != start or window.get("end") != end or start >= end:
            raise ValueError("Studio source UTC window inconsistent")
    else:
        raise ValueError("Studio DST-ambiguous or unsupported proposed window")
    stamp = raw["exported_at_utc"]
    if type(stamp) is not str or len(stamp) > 50:
        raise ValueError("Studio draft export date invalid")
    # Mirror the separately owned Studio v1 scope-fingerprint.js field order
    # and exact canonical JSON.stringify compact representation. This confirms
    # self-consistency only, NOT a signature, client ownership or consent.
    canonical = {
        "format": "LIGHTUP_NON_AUTHORIZING_SCOPE_DRAFT_REVISION_V1",
        "proposal_name": name,
        "client_label": raw["client_label"],
        "notes": raw["notes"],
        "requested_assets": sorted(assets),
        "excluded_assets": [],
        "requested_mode": raw["requested_mode"],
        "requested_risk": risk,
        "proposed_activities": {
            "passive_analysis": activities["passive_analysis"],
            "configuration_review": activities["configuration_review"],
            "private_lab_network_checks": activities["private_lab_network_checks"],
        },
        "proposed_window_local": {
            "start": local["start"], "end": local["end"]
        },
        "proposed_window_utc": {
            "status": window["status"], "timezone": window["timezone"],
            "start": window["start"], "end": window["end"],
        },
    }
    if window["status"] == "resolved":
        canonical["proposed_window_utc"].update({
            "start_offset_minutes": window["start_offset_minutes"],
            "end_offset_minutes": window["end_offset_minutes"],
        })
    digest = hashlib.sha256(json.dumps(
        canonical, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")).hexdigest()
    checksum = raw.get("scope_fingerprint_sha256")
    if checksum is not None and (type(checksum) is not str or checksum != digest):
        raise ValueError("original Studio checksum does not match canonical draft")
    return name, assets, risk


def read_studio_proposals(paths: list[Path]) -> list[tuple[str, tuple[str, ...], int]]:
    if not 1 <= len(paths) <= MAX_PROPOSALS:
        raise ValueError("1–8 original Studio v1 draft paths required")
    scenarios = []
    labels, definitions = set(), set()
    for source in paths:
        if source.is_symlink() or not source.is_file() or not 0 < source.stat().st_size <= MAX_BYTES:
            raise ValueError("missing/oversized Studio source")
        data = source.read_bytes()
        if data.startswith(b"\xef\xbb\xbf"):
            raise ValueError("Studio source BOM forbidden")
        try:
            doc = json.loads(data.decode("utf-8", "strict"), object_pairs_hook=_unique,
                             parse_constant=_reject_constant)
        except (ValueError, UnicodeError) as exc:
            raise ValueError("malformed original Studio draft") from exc
        label, assets, risk = _verify_schema(doc)
        if label in labels or (assets, risk) in definitions:
            raise ValueError("duplicate Studio proposal label or identical scope/risk")
        labels.add(label)
        definitions.add((assets, risk))
        scenarios.append((label, assets, risk))
    return scenarios
