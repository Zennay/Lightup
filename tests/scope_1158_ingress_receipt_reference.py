"""Non-authorizing, offline shape check for *supplied* synthetic ingress receipts.

Issue #1158: checks that an owner-provided capture covers each required route
and negative control. NEVER collects packets, opens sockets or verifies the
truth/origin of self-reported capture metadata. Passing is NOT deployment proof.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import re

PATH_HINTS = (
    "x-original-url", "x-rewrite-url", "x-original-uri",
    "x-forwarded-uri", "x-forwarded-path", "x-forwarded-prefix",
    "x-script-name",
)

# (method, request_path, backend_route, HTTP status, count of DB writes,
#  actor, csrf_valid, logout_invalidates_session, hint names, hint paths)
SCENARIOS = {
    **{
        "get:" + header: (
            "GET", "/nonexistent", "not_found", 404, 0,
            "anonymous", False, False, (header,), ("/clients",),
        )
        for header in PATH_HINTS
    },
    "get:conflicting": (
        "GET", "/nonexistent", "not_found", 404, 0,
        "anonymous", False, False, PATH_HINTS,
        tuple("/clients" if index % 2 == 0 else "/logout"
              for index in range(len(PATH_HINTS))),
    ),
    "post:unknown": (
        "POST", "/nonexistent", "not_found", 404, 0,
        "operator", True, False, ("x-original-url",), ("/clients",),
    ),
    "post:authorized": (
        "POST", "/clients", "clients_created", 303, 1,
        "operator", True, False, (), (),
    ),
    "get:foreign-tenant": (
        "GET", "/clients/foreign", "tenant_denied", 403, 0,
        "client", False, False, ("x-original-url",), ("/clients",),
    ),
    "post:logout": (
        "POST", "/logout", "logout", 303, 0,
        "operator", True, True, (), (),
    ),
}


class IngressReceiptRejected(ValueError):
    """Incomplete or contradictory structural evidence (not ingress status)."""


@dataclass(frozen=True)
class SyntheticRouteObservation:
    scenario: str
    request_method: str
    request_path: str
    injected_request_hint_names: tuple[str, ...]
    requested_hint_paths: tuple[str, ...]
    backend_observed_hint_names: tuple[str, ...]
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
            expected_hints, expected_hint_paths,
        ) = expected
        if type(case.injected_request_hint_names) is not tuple or not all(
            type(name) is str
            and re.fullmatch(r"[A-Za-z0-9-]{1,64}", name) is not None
            for name in case.injected_request_hint_names
        ):
            raise IngressReceiptRejected("noncanonical forwarded header list")
        normalized = tuple(name.lower() for name in case.injected_request_hint_names)
        if len(set(normalized)) != len(normalized):
            raise IngressReceiptRejected("duplicate header in a case")
        if (
            len(normalized) != len(expected_hints)
            or set(normalized) != set(expected_hints)
        ):
            raise IngressReceiptRejected("required original hint not evidenced")
        # Raw client-side hint injection and backend forwarding are different
        # evidence streams: a secure stripping proxy must not deliver any of
        # these seven route hints to WSGI, even when they were on the wire.
        if type(case.backend_observed_hint_names) is not tuple:
            raise IngressReceiptRejected("noncanonical backend header capture")
        if case.backend_observed_hint_names:
            raise IngressReceiptRejected("backend received a stripped path hint")
        if type(case.requested_hint_paths) is not tuple or not all(
            type(value) is str
            and value in {"/clients", "/logout"}
            for value in case.requested_hint_paths
        ):
            raise IngressReceiptRejected("noncanonical hinted path values")
        if case.requested_hint_paths != expected_hint_paths:
            raise IngressReceiptRejected("adversarial hint target not evidenced")
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


def check_locally_supplied_fixture_digests(
    receipt: SuppliedIngressReceipt,
    installed_config_fixture_bytes: bytes,
    backend_capture_fixture_bytes: bytes,
) -> None:
    """Cross-check the *provided local* bytes against declared digests.

    This does not authenticate their origin, prove installed config identity,
    verify an ingress trace, or issue any kind of release/permission decision.
    Never log, return, write or upload the supplied bytes from this helper.
    """
    check_supplied_ingress_receipt(receipt)
    for supplied in (
        installed_config_fixture_bytes,
        backend_capture_fixture_bytes,
    ):
        if type(supplied) is not bytes or not 0 < len(supplied) <= 1024 * 1024:
            raise IngressReceiptRejected("invalid bounded local fixture")
    if not hmac.compare_digest(
        hashlib.sha256(installed_config_fixture_bytes).hexdigest(),
        receipt.loaded_config_sha256,
    ):
        raise IngressReceiptRejected("config fixture digest mismatch")
    if not hmac.compare_digest(
        hashlib.sha256(backend_capture_fixture_bytes).hexdigest(),
        receipt.backend_capture_sha256,
    ):
        raise IngressReceiptRejected("backend fixture digest mismatch")
    return None


def check_receipt_against_external_pins(
    receipt: SuppliedIngressReceipt,
    *,
    expected_repository_head: str,
    expected_config_sha256: str,
    expected_capture_sha256: str,
) -> None:
    """Fail closed on a stale or mismatched self-reported receipt.

    Pins MUST come from an independent trusted owner-run capture/review step,
    never be copied automatically from `receipt`. This function cannot verify
    their provenance and returns no permission or deployment clearance.
    """
    check_supplied_ingress_receipt(receipt)
    pins = (
        (expected_repository_head, receipt.repository_head),
        (expected_config_sha256, receipt.loaded_config_sha256),
        (expected_capture_sha256, receipt.backend_capture_sha256),
    )
    if not all(_hex_sha(expected) for expected, _ in pins):
        raise IngressReceiptRejected("invalid external evidence pin")
    # No raw data, full hash, labels or caller values in any diagnostic.
    for expected, supplied in pins:
        if not hmac.compare_digest(expected, supplied):
            raise IngressReceiptRejected("receipt differs from pinned context")
    return None
