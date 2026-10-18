"""Import a LightUp Scope Planning Studio v1 draft without conferring authority.

The browser draft is attacker-controlled planning data. A preview can discuss it;
only the independently authenticated client-domain method can submit a request.
Never silently drop exclusions, schedule restrictions, or lab activity requests.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

MAX_PROPOSAL_BYTES = 65536

_REQUIRED = frozenset({
    "kind", "schema_version", "state", "authorization", "client_consent",
    "operator_consent", "grant", "execution", "revocation_checked",
    "proposal_name", "client_label", "requested_assets", "excluded_assets",
    "requested_mode", "requested_risk", "notes", "proposed_activities",
    "proposed_window_local",
})
_OPTIONAL = frozenset({"proposed_window_utc", "exported_at_utc", "scope_fingerprint_sha256"})
_ACTIVITY_NAMES = ("passive_analysis", "configuration_review", "private_lab_network_checks")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate proposal property (ambiguous JSON)")
        result[name] = value
    return result


def read_studio_draft(filename: str) -> tuple[dict, str]:
    """Read and validate an untrusted exported Studio v1 draft for local review.

    This does NOT assert owner identity, timezone authenticity, consent,
    an enforceable exclusion, or operator-reviewed schedule. Real submissions
    must additionally pass load_studio_proposal's strict lossless admission.
    """
    path = Path(filename).expanduser()
    if path.is_symlink() or not path.is_file():
        raise ValueError("proposal must be an existing, non-symlink regular file")
    if path.stat().st_size > MAX_PROPOSAL_BYTES:
        raise ValueError("studio proposal file exceeds 64 KiB")
    with path.open("rb") as stream:
        raw = stream.read(MAX_PROPOSAL_BYTES + 1)
    if len(raw) > MAX_PROPOSAL_BYTES:
        raise ValueError("studio proposal file exceeds 64 KiB")
    try:
        proposal = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite number")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("proposal is not canonical UTF-8 JSON") from exc

    if type(proposal) is not dict or set(proposal) - (_REQUIRED | _OPTIONAL) or _REQUIRED - set(proposal):
        raise ValueError("missing or unrecognized studio v1 proposal properties")
    if (proposal["kind"] != "lightup.scope_proposal_draft"
            or type(proposal["schema_version"]) is not int or proposal["schema_version"] != 1
            or proposal["state"] != "DRAFT_ONLY"):
        raise ValueError("only the original studio v1 DRAFT_ONLY proposal is accepted")
    for key in ("authorization", "client_consent", "operator_consent",
                "grant", "execution", "revocation_checked"):
        if proposal[key] is not False:
            raise ValueError(f"studio property {key} cannot assert authorization")
    if "scope_fingerprint_sha256" in proposal:
        digest = proposal["scope_fingerprint_sha256"]
        if (type(digest) is not str or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)):
            raise ValueError("invalid unsigned fingerprint form")
        # Deliberately never regard an unsigned browser digest as authenticity.

    title, client_label, notes = (proposal[k] for k in ("proposal_name", "client_label", "notes"))
    if (type(title) is not str or not title.strip() or len(title) > 120
            or type(client_label) is not str or len(client_label) > 100
            or type(notes) is not str or not notes.strip() or len(notes) > 3000):
        raise ValueError("studio name, client label or safety notes are invalid")

    from .grant_request_binding import _asset

    for field in ("requested_assets", "excluded_assets"):
        values = proposal[field]
        if type(values) is not list or len(values) > 80 or (
            field == "requested_assets" and not values
        ):
            raise ValueError("invalid Studio " + field + " count")
        aliases: set[str] = set()
        for value in values:
            kind, parsed = _asset(value)
            identity = kind + ":" + str(parsed)
            if identity in aliases:
                raise ValueError("duplicate Studio " + field + " identity")
            aliases.add(identity)
    if (proposal["requested_mode"] not in ("analysis_only", "authorized_assessment")
            or type(proposal["requested_risk"]) is not int
            or not 1 <= proposal["requested_risk"] <= 4):
        raise ValueError("invalid Studio mode or risk")
    activity = proposal["proposed_activities"]
    if (type(activity) is not dict or set(activity) != set(_ACTIVITY_NAMES)
            or any(type(activity[name]) is not bool for name in _ACTIVITY_NAMES)):
        raise ValueError("invalid Studio activities")
    local = proposal["proposed_window_local"]
    if type(local) is not dict or set(local) != {"start", "end"}:
        raise ValueError("invalid Studio local time envelope")
    import re
    clock_pattern = re.compile(r"^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}$")
    for field in ("start", "end"):
        val = local[field]
        if val is not None and (
            type(val) is not str or not clock_pattern.fullmatch(val)
        ):
            raise ValueError("invalid Studio local-time syntax")
    # This is a read-only review envelope, not authoritative scheduling.
    # Accept only the declared Studio v1 scheduled/unscheduled/incomplete states.
    window = proposal.get("proposed_window_utc")
    if window is not None:
        if type(window) is not dict or type(window.get("timezone")) is not str:
            raise ValueError("invalid Studio UTC metadata")
        if len(window["timezone"]) > 100:
            raise ValueError("Studio timezone label is too long")
        state = window.get("status")
        if state in ("unscheduled", "incomplete"):
            if set(window) != {"status", "timezone", "start", "end"}:
                raise ValueError("invalid Studio unscheduled UTC fields")
            if window["start"] is not None or window["end"] is not None:
                raise ValueError("unscheduled Studio clock cannot contain UTC instants")
            has_start = local["start"] is not None
            has_end = local["end"] is not None
            if (state == "unscheduled" and (has_start or has_end)) or (
                state == "incomplete" and has_start == has_end
            ):
                raise ValueError("Studio UTC state contradicts its local clock")
        elif state == "resolved":
            if set(window) != {
                "status", "timezone", "start", "end",
                "start_offset_minutes", "end_offset_minutes"
            }:
                raise ValueError("invalid resolved Studio UTC fields")
            from datetime import datetime, timedelta, timezone
            for field, offset_field in (
                ("start", "start_offset_minutes"), ("end", "end_offset_minutes")
            ):
                val, offset = window[field], window[offset_field]
                if type(val) is not str or type(offset) is not int or not -840 <= offset <= 840:
                    raise ValueError("invalid Studio UTC bound or offset")
                wall = local[field]
                if wall is None:
                    raise ValueError("resolved UTC requires both local bounds")
                try:
                    naive = datetime.strptime(wall, "%Y-%m-%dT%H:%M")
                    instant = datetime.strptime(val, "%Y-%m-%dT%H:%M:%S.000Z").replace(
                        tzinfo=timezone.utc
                    )
                except ValueError as exc:
                    raise ValueError("invalid Studio UTC datetime") from exc
                derived = (naive + timedelta(minutes=offset)).replace(tzinfo=timezone.utc)
                if derived != instant:
                    raise ValueError("Studio local/UTC provenance inconsistent")
            if window["start"] >= window["end"]:
                raise ValueError("Studio UTC interval is reversed")
        else:
            raise ValueError("unsupported Studio UTC status")
    if "exported_at_utc" in proposal and (
        type(proposal["exported_at_utc"]) is not str
        or len(proposal["exported_at_utc"]) > 50
    ):
        raise ValueError("invalid Studio export timestamp")
    return proposal, hashlib.sha256(raw).hexdigest()


def load_studio_proposal(filename: str) -> dict:
    """Convert the *exact* studio draft to one safe native request proposal.

    Exclusions or time windows cannot be mapped to the durable request schema.
    Failing them closed prevents operators mistaking narrowed draft scope for
    the wider request stored by DomainStore. Unknown authority fields also HOLD.
    """
    from .client_request_cli import prepare_request

    proposal, raw_sha256 = read_studio_draft(filename)
    if (type(proposal["requested_assets"]) is not list
            or type(proposal["excluded_assets"]) is not list
            or len(proposal["excluded_assets"]) > 80
            or not all(type(v) is str for v in proposal["excluded_assets"])):
        raise ValueError("invalid proposal asset collections")
    if proposal["excluded_assets"]:
        raise ValueError(
            "HOLD: exclusions would be lost in the native request schema; "
            "remove them only after independent human scope review"
        )
    if proposal["requested_mode"] != "authorized_assessment":
        raise ValueError("native client intake accepts only authorized_assessment proposals")

    activities = proposal["proposed_activities"]
    if (type(activities) is not dict or set(activities) != set(_ACTIVITY_NAMES)
            or any(type(activities[k]) is not bool for k in _ACTIVITY_NAMES)):
        raise ValueError("invalid activity claims")
    if activities["private_lab_network_checks"]:
        raise ValueError("HOLD: lab activity requires a separate private-lab workflow")

    window = proposal["proposed_window_local"]
    if (type(window) is not dict or set(window) != {"start", "end"}
            or window["start"] is not None or window["end"] is not None):
        raise ValueError(
            "HOLD: the native request has no persisted schedule constraint; "
            "resolve the window in the dedicated operator handoff"
        )
    utc = proposal.get("proposed_window_utc")
    if utc is not None and (
        type(utc) is not dict or set(utc) != {"status", "timezone", "start", "end"}
        or utc["status"] != "unscheduled"
        or type(utc["timezone"]) is not str or len(utc["timezone"]) > 100
        or utc["start"] is not None or utc["end"] is not None
    ):
        raise ValueError("HOLD: inconsistent or restricted UTC planning provenance")

    explanation = ["Planning draft: " + title.strip()]
    if client_label.strip():
        explanation.append("Unverified proposal client label: " + client_label.strip())
    listed = [name.replace("_", " ") for name in _ACTIVITY_NAMES
              if activities[name]]
    if listed:
        explanation.append("Requested planning activities (NOT permissions): " + ", ".join(listed))
    explanation.append(notes.strip())
    # Exact bytes are a review continuity hint, never an authenticated signature.
    explanation.append("Untrusted proposal-file SHA-256 (not consent): " + raw_sha256)
    native = prepare_request(
        proposal["requested_assets"], proposal["requested_risk"],
        "\n".join(explanation),
    )
    native["proposal_file_sha256"] = raw_sha256
    native["source_format"] = "lightup.scope_proposal_draft/v1"
    native["source_verified"] = False
    native["scope_fingerprint_authenticated"] = False
    native["schedule_bound"] = False
    native["exclusions_enforced"] = False
    return native
