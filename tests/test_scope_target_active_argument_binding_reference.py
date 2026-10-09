"""Offline reference contract for TARGET_ACTIVE argument-to-asset binding.

This module is intentionally standalone and performs no network I/O. It models
one narrow invariant for the production authorization owner:

    trusted destination-bearing arguments must remain inside the independently
    authorized asset/endpoint boundary.

A True result is only argument consistency. It is never authorization,
provenance, approval, revocation, risk, capability permission, or dispatch
permission.
"""

from __future__ import annotations

import unittest
from urllib.parse import urlsplit


_MAX_NETWORK_VALUE = 2048
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _canonical_endpoint(value: object) -> tuple[str, int | None] | None:
    if type(value) is not str:
        return None
    if not value or len(value) > _MAX_NETWORK_VALUE or value != value.strip():
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        return None

    candidate = value if "://" in value else f"//{value}"
    try:
        parsed = urlsplit(candidate)
        scheme = parsed.scheme.lower()
        if scheme and scheme not in _DEFAULT_PORTS:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    if not host or "%" in host:
        return None
    if host.endswith(".."):
        return None

    canonical_host = (host[:-1] if host.endswith(".") else host).lower()
    if not canonical_host:
        return None

    if port is None and scheme:
        port = _DEFAULT_PORTS[scheme]

    return canonical_host, port


def _canonical_host_literal(value: object) -> str | None:
    if type(value) is not str or "://" in value or "/" in value or "@" in value:
        return None
    endpoint = _canonical_endpoint(value)
    if endpoint is None:
        return None
    host, port = endpoint
    if port is not None:
        return None
    return host


def _canonical_port(value: object) -> int | None:
    if type(value) is not int:
        return None
    if not 1 <= value <= 65535:
        return None
    return value


def _canonical_port_set(value: object) -> frozenset[int] | None:
    if type(value) is not str or not value or value != value.strip():
        return None
    if len(value) > _MAX_NETWORK_VALUE:
        return None

    ports: set[int] = set()
    for token in value.split(","):
        if not token or not token.isascii() or not token.isdecimal():
            return None
        if token != str(int(token)):
            return None
        port = int(token)
        if not 1 <= port <= 65535 or port in ports:
            return None
        ports.add(port)
    return frozenset(ports)


def declared_network_arguments_match_asset(
    authorized_asset: object,
    arguments: object,
    *,
    host_argument_names: frozenset[str] = frozenset(),
    endpoint_argument_names: frozenset[str] = frozenset(),
    port_argument_names: frozenset[str] = frozenset(),
    port_set_argument_names: frozenset[str] = frozenset(),
) -> bool:
    """Return only whether trusted destination arguments match the asset.

    The caller must independently authenticate and authorize the asset and must
    source all argument-role sets from immutable trusted tool-registry metadata.
    """

    role_sets = (
        host_argument_names,
        endpoint_argument_names,
        port_argument_names,
        port_set_argument_names,
    )
    if any(type(names) is not frozenset for names in role_sets):
        return False
    all_role_names = set().union(*role_sets)
    if sum(len(names) for names in role_sets) != len(all_role_names):
        return False

    asset_endpoint = _canonical_endpoint(authorized_asset)
    if asset_endpoint is None or type(arguments) is not tuple:
        return False
    asset_host, asset_port = asset_endpoint

    seen: set[str] = set()
    for item in arguments:
        if type(item) is not tuple or len(item) != 2:
            return False
        key, value = item
        if type(key) is not str or not key or key in seen:
            return False
        seen.add(key)

        if key in host_argument_names:
            if _canonical_host_literal(value) != asset_host:
                return False
            continue

        if key in endpoint_argument_names:
            argument_endpoint = _canonical_endpoint(value)
            if argument_endpoint is None:
                return False
            argument_host, argument_port = argument_endpoint
            if argument_host != asset_host:
                return False
            if asset_port is not None and argument_port != asset_port:
                return False
            continue

        if key in port_argument_names:
            argument_port = _canonical_port(value)
            if argument_port is None:
                return False
            if asset_port is not None and argument_port != asset_port:
                return False
            continue

        if key in port_set_argument_names:
            argument_ports = _canonical_port_set(value)
            if argument_ports is None:
                return False
            if asset_port is not None and argument_ports != frozenset({asset_port}):
                return False

    return True


class TargetActiveArgumentBindingReferenceTests(unittest.TestCase):
    HOST_KEYS = frozenset({"host"})
    ENDPOINT_KEYS = frozenset({"url", "target", "endpoint"})
    PORT_KEYS = frozenset({"port"})
    PORT_SET_KEYS = frozenset({"ports"})

    def _matches(self, asset: object, arguments: object) -> bool:
        return declared_network_arguments_match_asset(
            asset,
            arguments,
            host_argument_names=self.HOST_KEYS,
            endpoint_argument_names=self.ENDPOINT_KEYS,
            port_argument_names=self.PORT_KEYS,
            port_set_argument_names=self.PORT_SET_KEYS,
        )

    def test_host_level_asset_can_use_same_host_with_port_path_and_query(self):
        self.assertTrue(
            self._matches(
                "Example.test",
                (("url", "https://example.test:8443/a?b=1"),),
            )
        )

    def test_explicit_asset_port_cannot_be_widened_inside_url(self):
        self.assertFalse(
            self._matches(
                "https://example.test:443",
                (("url", "https://example.test:8443/a"),),
            )
        )

    def test_scheme_default_port_preserves_explicit_endpoint_identity(self):
        self.assertTrue(
            self._matches(
                "https://example.test",
                (("url", "https://example.test:443/a"),),
            )
        )

    def test_different_default_scheme_port_is_rejected_when_asset_is_url(self):
        self.assertFalse(
            self._matches(
                "https://example.test",
                (("url", "http://example.test/a"),),
            )
        )

    def test_split_host_and_port_can_match_explicit_asset_endpoint(self):
        self.assertTrue(
            self._matches(
                "https://example.test",
                (("host", "EXAMPLE.TEST."), ("port", 443)),
            )
        )

    def test_split_port_cannot_widen_explicit_asset_endpoint(self):
        self.assertFalse(
            self._matches(
                "https://example.test",
                (("host", "example.test"), ("port", 8443)),
            )
        )

    def test_port_set_cannot_widen_explicit_asset_endpoint(self):
        self.assertFalse(
            self._matches(
                "https://example.test",
                (("host", "example.test"), ("ports", "443,8443")),
            )
        )

    def test_singleton_port_set_can_match_explicit_asset_endpoint(self):
        self.assertTrue(
            self._matches(
                "https://example.test",
                (("host", "example.test"), ("ports", "443")),
            )
        )

    def test_host_level_asset_leaves_valid_ports_to_capability_contract(self):
        self.assertTrue(
            self._matches(
                "example.test",
                (("host", "example.test"), ("port", 8443)),
            )
        )
        self.assertTrue(
            self._matches(
                "example.test",
                (("host", "example.test"), ("ports", "443,8443")),
            )
        )

    def test_port_selector_rejects_bool_string_and_out_of_range_values(self):
        for value in (True, "443", 0, 65536):
            with self.subTest(value=value):
                self.assertFalse(
                    self._matches(
                        "example.test",
                        (("host", "example.test"), ("port", value)),
                    )
                )

    def test_port_set_rejects_noncanonical_or_duplicate_values(self):
        for value in ("0443", "443,443", "443, 8443", "0", "65536", ""):
            with self.subTest(value=value):
                self.assertFalse(
                    self._matches(
                        "example.test",
                        (("host", "example.test"), ("ports", value)),
                    )
                )

    def test_hostname_case_and_single_trailing_dot_do_not_change_identity(self):
        self.assertTrue(self._matches("example.test.", (("host", "EXAMPLE.TEST"),)))

    def test_multiple_trailing_dots_are_rejected_as_noncanonical(self):
        self.assertFalse(
            self._matches(
                "example.test",
                (("url", "https://example.test../a"),),
            )
        )

    def test_different_url_host_is_rejected(self):
        self.assertFalse(
            self._matches(
                "https://approved.example",
                (("url", "https://other.example/path"),),
            )
        )

    def test_different_host_argument_is_rejected(self):
        self.assertFalse(
            self._matches("approved.example", (("host", "other.example"),))
        )

    def test_different_target_argument_is_rejected(self):
        self.assertFalse(
            self._matches(
                "approved.example",
                (("target", "https://other.example"),),
            )
        )

    def test_different_endpoint_argument_is_rejected(self):
        self.assertFalse(
            self._matches(
                "approved.example",
                (("endpoint", "https://other.example/v1"),),
            )
        )

    def test_duplicate_argument_names_fail_closed_before_projection(self):
        self.assertFalse(
            self._matches(
                "approved.example",
                (
                    ("url", "https://approved.example"),
                    ("url", "https://other.example"),
                ),
            )
        )

    def test_endpoint_argument_must_be_exact_string(self):
        self.assertFalse(self._matches("approved.example", (("url", 123),)))

    def test_userinfo_in_endpoint_argument_is_rejected_as_ambiguous(self):
        self.assertFalse(
            self._matches(
                "approved.example",
                (("url", "https://approved.example@other.example/path"),),
            )
        )

    def test_unsupported_scheme_is_rejected(self):
        self.assertFalse(
            self._matches(
                "approved.example",
                (("url", "ftp://approved.example/file"),),
            )
        )

    def test_blank_or_whitespace_padded_endpoint_argument_is_rejected(self):
        for value in ("", " https://approved.example", "https://approved.example "):
            with self.subTest(value=value):
                self.assertFalse(self._matches("approved.example", (("url", value),)))

    def test_host_role_rejects_url_or_inline_port(self):
        for value in ("https://approved.example", "approved.example:443"):
            with self.subTest(value=value):
                self.assertFalse(self._matches("approved.example", (("host", value),)))

    def test_non_network_metadata_is_not_reinterpreted_as_destination(self):
        self.assertTrue(
            self._matches(
                "approved.example",
                (("path", "/admin"), ("note", "other.example")),
            )
        )

    def test_reference_check_is_input_pure(self):
        arguments = (
            ("host", "approved.example"),
            ("port", 443),
            ("path", "/b"),
        )
        snapshot = tuple(arguments)
        self.assertTrue(self._matches("approved.example", arguments))
        self.assertEqual(arguments, snapshot)

    def test_registry_declared_role_sets_are_strictly_typed(self):
        self.assertFalse(
            declared_network_arguments_match_asset(
                "approved.example",
                (("url", "https://approved.example"),),
                endpoint_argument_names={"url"},  # type: ignore[arg-type]
            )
        )

    def test_registry_declared_role_sets_must_be_disjoint(self):
        self.assertFalse(
            declared_network_arguments_match_asset(
                "approved.example",
                (("host", "approved.example"),),
                host_argument_names=frozenset({"host"}),
                endpoint_argument_names=frozenset({"host"}),
            )
        )


if __name__ == "__main__":
    unittest.main()
