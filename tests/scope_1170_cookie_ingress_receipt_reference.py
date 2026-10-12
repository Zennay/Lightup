"""Non-authorizing, offline-only receipt reviewer for LightUp issue #1170.

This only verifies the *shape and internal consistency* of a caller-supplied
synthetic/redacted ingress receipt. It does NOT capture installed traffic,
authenticate evidence, prove Nginx/Gunicorn configuration, or approve release.
"""
from __future__ import annotations

import re

SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_SHA = re.compile(r"[0-9a-f]{40}")
SESSION = "A" * 43

# Values are fixtures; no socket, DNS, proxy or application is contacted.
SCENARIOS = {
    "anonymous": (),
    "single_session": ("lightup_session=" + SESSION,),
    "duplicate_semicolon": ("lightup_session=" + SESSION + "; lightup_session=" + SESSION,),
    "duplicate_wire_headers": ("lightup_session=" + SESSION, "lightup_session=" + SESSION),
    "comma_coalesced": ("lightup_session=" + SESSION + ", lightup_session=" + SESSION,),
    "quoted_cookie": ('lightup_session="' + SESSION + '"',),
    "control_byte": ("lightup_session=" + SESSION + chr(0),),
    "unrelated_and_session": ("pref=ok; lightup_session=" + SESSION,),
}
DENIED = frozenset({
    "duplicate_semicolon", "duplicate_wire_headers", "comma_coalesced",
    "quoted_cookie", "control_byte",
})
FIELDS = frozenset({
    "scenario", "wire_cookie_fields", "edge_status", "backend_cookie_fields",
    "backend_reached", "application_session_lookups", "persistent_writes",
    "set_cookie", "no_store", "authenticated", "second_request_admitted",
})
TOP_FIELDS = frozenset({
    "repository_commit", "nginx_config_sha256", "backend_capture_sha256",
    "case_observations", "fixture_only",
})


def _sha(text: object, regex: re.Pattern[str]) -> bool:
    return type(text) is str and regex.fullmatch(text) is not None


def review_cookie_ingress_receipt(receipt: object, external_pins: object) -> bool:
    """Fail closed on malformed or contradictory offline receipt structures.

    'external_pins' are independently supplied expected hashes, NOT hashes
    copied out of the receipt. Matching values are not proof of provenance.
    The return value never conveys production-activation authorization.
    """
    if type(receipt) is not dict or type(external_pins) is not dict:
        return False
    if set(receipt) != TOP_FIELDS or set(external_pins) != {
        "repository_commit", "nginx_config_sha256", "backend_capture_sha256"
    }:
        return False
    for name in ("repository_commit", "nginx_config_sha256", "backend_capture_sha256"):
        pattern = GIT_SHA if name == "repository_commit" else SHA256
        if not _sha(receipt[name], pattern) or not _sha(external_pins[name], pattern):
            return False
        if receipt[name] != external_pins[name]:
            return False
    if receipt["fixture_only"] is not True:
        return False
    rows = receipt["case_observations"]
    if type(rows) is not list or len(rows) != len(SCENARIOS):
        return False
    seen: set[str] = set()
    for row in rows:
        if type(row) is not dict or set(row) != FIELDS:
            return False
        name = row["scenario"]
        if type(name) is not str or name not in SCENARIOS or name in seen:
            return False
        seen.add(name)
        wire = row["wire_cookie_fields"]
        if type(wire) is not list or any(type(v) is not str for v in wire):
            return False
        if tuple(wire) != SCENARIOS[name]:
            return False
        backend = row["backend_cookie_fields"]
        if type(backend) is not list or any(type(v) is not str for v in backend):
            return False
        if any(type(row[k]) is not bool for k in (
            "backend_reached", "set_cookie", "no_store", "authenticated",
            "second_request_admitted"
        )):
            return False
        if any(type(row[k]) is not int or not 0 <= row[k] <= 100 for k in (
            "application_session_lookups", "persistent_writes"
        )):
            return False
        if type(row["edge_status"]) is not int:
            return False
        if row["backend_reached"] is False and backend:
            return False
        if row["backend_reached"] is True and backend != wire:
            # The fixture must not silently erase/normalize header ambiguity.
            # A real ingress may legitimately reject before the backend.
            return False
        if name in DENIED:
            if not 400 <= row["edge_status"] <= 499:
                return False
            if (row["application_session_lookups"] != 0
                    or row["persistent_writes"] != 0
                    or row["authenticated"]
                    or row["set_cookie"]
                    or not row["no_store"]
                    or row["second_request_admitted"]):
                return False
        else:
            if row["edge_status"] != 200 or not row["backend_reached"]:
                return False
            if (row["persistent_writes"] != 0 or row["set_cookie"]
                    or row["authenticated"] or row["second_request_admitted"]):
                return False
    return seen == set(SCENARIOS)
