"""Non-authorizing, offline shape check for *supplied* synthetic ingress receipts.

Issue #1158: checks that an owner-provided capture covers each required route
and negative control. NEVER collects packets, opens sockets or verifies the
truth/origin of self-reported capture metadata. Passing is NOT deployment proof.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

PATH_HINTS = (
    "x-original-url", "x-rewrite-url", "x-original-uri",
    "x-forwarded-uri", "x-forwarded-path", "x-forwarded-prefix",
    "x-script-name",
)

# (method, request_path, backend_route, HTTP status, count of DB writes,
#  actor, csrf_valid, logout_invalidates_session, expected hint header names)
SCENARIOS = {
    **{
        "get:" + header: (
            "GET", "/nonexistent", "not_found", 404, 0,
            "anonymous", False, False, (header,),
        )
        for header in PATH_HINTS
    },
    "get:conflicting": (
        "GET", "/nonexistent", "not_found", 404, 0,
        "anonymous", False, False, PATH_HINTS,
    ),
    "post:unknown": (
        "POST", "/nonexistent", "not_found", 404, 0,
        "operator", True, False, ("x-original-url",),
    ),
    "post:authorized": (
        "POST", "/clients", "clients_created", 303, 1,
        "operator", True, False, (),
    ),
    "get:foreign-tenant": (
        "GET", "/clients/foreign", "tenant_denied", 403, 0,
        "client", False, False, ("x-original-url",),
    ),
    "post:logout": (
        "POST", "/logout", "logout", 303, 0,
        "operator", True, True, (),
    ),
}


class IngressReceiptRejected(ValueError):
    """Incomplete or contradictory structural evidence (not ingress status)."""


@dataclass(frozen=True)
class SyntheticRouteObservation:
    scenario: str
    request_method: str
    request_path: str
    forwarded_hint_names: tuple[str, ...]
    backend_path: str
    backend_route: str
    response_status: int
    durable_write_count: int
    actor_class: str
    csrf_valid: bool
    session_invalidated: bool


@dataclass(frozen=True)
class SuppliedIngressReceipt:
    repository_head: str
    loaded_config_sha256: str
    backend_capture_sha256: str
    nginx_version: str
    gunicorn_version: str
    environment_label: str
    observations: tuple[SyntheticRouteObservation, ...]


def _hex_sha(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def _bounded_label(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 80
        and re.fullmatch(r"[A-Za-z0-9._+:-]+", value) is not None
    )


def check_supplied_ingress_receipt(receipt: SuppliedIngressReceipt) -> None:
    """Validate shape and mandatory case coverage, return *no* trust decision.

    This is a pure function. It cannot establish the installed config was
    hashed, whether a request was sent, or who captured backend observations.
    """
    if type(receipt) is not SuppliedIngressReceipt:
        raise IngressReceiptRejected("noncanonical receipt")
    if not all(
        _hex_sha(value)
        for value in (
            receipt.repository_head,
            receipt.loaded_config_sha256,
            receipt.backend_capture_sha256,
        )
    ):
        raise IngressReceiptRejected("missing exact evidence digest")
    if not all(
        _bounded_label(value)
        for value in (
            receipt.nginx_version,
            receipt.gunicorn_version,
            receipt.environment_label,
        )
    ):
        raise IngressReceiptRejected("missing bounded environment provenance")
    if receipt.environment_label != "disposable-loopback-lab":
        raise IngressReceiptRejected("not an isolated loopback lab receipt")
    if type(receipt.observations) is not tuple:
        raise IngressReceiptRejected("noncanonical observation container")
    if len(receipt.observations) != len(SCENARIOS):
        raise IngressReceiptRejected("incomplete or duplicate case coverage")

    observed: set[str] = set()
    for case in receipt.observations:
        if type(case) is not SyntheticRouteObservation:
            raise IngressReceiptRejected("noncanonical observation")
        if type(case.scenario) is not str or case.scenario not in SCENARIOS:
            raise IngressReceiptRejected("unknown scenario")
        if case.scenario in observed:
            raise IngressReceiptRejected("duplicate scenario")
        observed.add(case.scenario)
        expected = SCENARIOS[case.scenario]
        (
            expected_method, expected_path, expected_route, expected_status,
            expected_writes, expected_actor, expected_csrf, expected_logout,
            expected_hints,
        ) = expected
        if type(case.forwarded_hint_names) is not tuple or not all(
            type(name) is str
            and re.fullmatch(r"[A-Za-z0-9-]{1,64}", name) is not None
            for name in case.forwarded_hint_names
        ):
            raise IngressReceiptRejected("noncanonical forwarded header list")
        normalized = tuple(name.lower() for name in case.forwarded_hint_names)
        if len(set(normalized)) != len(normalized):
            raise IngressReceiptRejected("duplicate header in a case")
        if (
            len(normalized) != len(expected_hints)
            or set(normalized) != set(expected_hints)
        ):
            raise IngressReceiptRejected("required original hint not evidenced")
        for label, value, required in (
            ("method", case.request_method, expected_method),
            ("original path", case.request_path, expected_path),
            ("backend PATH_INFO", case.backend_path, expected_path),
            ("observed backend route", case.backend_route, expected_route),
            ("HTTP status", case.response_status, expected_status),
            ("durable write delta", case.durable_write_count, expected_writes),
            ("actor class", case.actor_class, expected_actor),
            ("CSRF control", case.csrf_valid, expected_csrf),
            ("logout invalidation", case.session_invalidated, expected_logout),
        ):
            if type(value) is not type(required) or value != required:
                raise IngressReceiptRejected("mismatched " + label)
    if observed != set(SCENARIOS):
        raise IngressReceiptRejected("missing required synthetic scenario")
    return None
