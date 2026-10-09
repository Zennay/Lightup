"""Offline reference contract for TARGET_ACTIVE argument-to-asset binding.

This module is intentionally standalone and performs no network I/O. It models
one narrow invariant for the production authorization owner:

    every declared network-bearing tool argument must resolve to the same host
    as the independently authorized top-level asset, while preserving any
    endpoint restriction explicitly present in that asset.

A True result is only argument consistency. It is never authorization,
provenance, approval, revocation, risk, or dispatch permission.
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


def declared_network_arguments_match_asset(
    authorized_asset: object,
    arguments: object,
    *,
    network_argument_names: frozenset[str],
) -> bool:
    """Return only whether declared destination arguments match the asset.

    The caller must independently authenticate and authorize the asset and must
    source network_argument_names from the trusted tool registry.
    """

    asset_endpoint = _canonical_endpoint(authorized_asset)
    if asset_endpoint is None or type(arguments) is not tuple:
        return False
    if type(network_argument_names) is not frozenset:
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

        if key not in network_argument_names:
            continue

        argument_endpoint = _canonical_endpoint(value)
        if argument_endpoint is None:
            return False
        argument_host, argument_port = argument_endpoint
        if argument_host != asset_host:
            return False

        # A host-only grant leaves port selection to the already-authorized
        # capability contract. An asset that explicitly carries endpoint
        # semantics must not be widened to another port.
        if asset_port is not None and argument_port != asset_port:
            return False

    return True


class TargetActiveArgumentBindingReferenceTests(unittest.TestCase):
    NETWORK_KEYS = frozenset({"url", "host", "target", "endpoint"})

    def test_host_level_asset_can_use_same_host_with_port_path_and_query(self):
        self.assertTrue(
            declared_network_arguments_match_asset(
                "Example.test",
                (("url", "https://example.test:8443/a?b=1"),),
                network_argument_names=self.NETWORK_KEYS,
            )
        )

    def test_explicit_asset_port_cannot_be_widened(self):
        self.assertFalse(
            declared_network_arguments_match_asset(
                "https://example.test:443",
                (("url", "https://example.test:8443/a"),),
                network_argument_names=self.NETWORK_KEYS,
            )
        )

    def test_scheme_default_port_preserves_explicit_endpoint_identity(self):
        self.assertTrue(
            declared_network_arguments_match_asset(
                "https://example.test",
                (("url", "https://example.test:443/a"),),
                network_argument_names=self.NETWORK_KEYS,
            )
        )

    def test_different_default_scheme_port_is_rejected_when_asset_is_url(self):
        self.assertFalse(
            declared_network_arguments_match_asset(
                "https://example.test",
                (("url", "http://example.test/a"),),
                network_argument_names=self.NETWORK_KEYS,
            )
        )

    def test_hostname_case_and_single_trailing_dot_do_not_change_identity(self):
        self.assertTrue(
            declared_network_arguments_match_asset(
                "example.test.",
                (("host", "EXAMPLE.TEST"),),
                network_argument_names=self.NETWORK_KEYS,
            )
        )

    def test_multiple_trailing_dots_are_rejected_as_noncanonical(self):
        self.assertFalse(
            declared_network_arguments_match_asset(
                "example.test",
                (("url", "https://example.test../a"),),
                network_argument_names=self.NETWORK_KEYS,
            )
        )

    def test_different_url_host_is_rejected(self):
        self.assertFalse(
            declared_network_arguments_match_asset(
                "https://approved.example",
                (("url", "https://other.example/path"),),
                network_argument_names=self.NETWORK_KEYS,
            )
        )

    def test_different_host_argument_is_rejected(self):
        self.assertFalse(
            declared_network_arguments_match_asset(
                "approved.example",
                (("host", "other.example"),),
                network_argument_names=self.NETWORK_KEYS,
            )
        )

    def test_different_target_argument_is_rejected(self):
        self.assertFalse(
            declared_network_arguments_match_asset(
                "approved.example",
                (("target", "https://other.example"),),
                network_argument_names=self.NETWORK_KEYS,
            )
        )

    def test_different_endpoint_argument_is_rejected(self):
        self.assertFalse(
            declared_network_arguments_match_asset(
                "approved.example",
                (("endpoint", "https://other.example/v1"),),
                network_argument_names=self.NETWORK_KEYS,
            )
        )

    def test_duplicate_argument_names_fail_closed_before_projection(self):
        self.assertFalse(
            declared_network_arguments_match_asset(
                "approved.example",
                (
                    ("url", "https://approved.example"),
                    ("url", "https://other.example"),
                ),
                network_argument_names=self.NETWORK_KEYS,
            )
        )

    def test_network_argument_must_be_exact_string(self):
        self.assertFalse(
            declared_network_arguments_match_asset(
                "approved.example",
                (("url", 123),),
                network_argument_names=self.NETWORK_KEYS,
            )
        )

    def test_userinfo_in_network_argument_is_rejected_as_ambiguous(self):
        self.assertFalse(
            declared_network_arguments_match_asset(
                "approved.example",
                (("url", "https://approved.example@other.example/path"),),
                network_argument_names=self.NETWORK_KEYS,
            )
        )

    def test_unsupported_scheme_is_rejected(self):
        self.assertFalse(
            declared_network_arguments_match_asset(
                "approved.example",
                (("url", "ftp://approved.example/file"),),
                network_argument_names=self.NETWORK_KEYS,
            )
        )

    def test_blank_or_whitespace_padded_network_argument_is_rejected(self):
        for value in ("", " https://approved.example", "https://approved.example "):
            with self.subTest(value=value):
                self.assertFalse(
                    declared_network_arguments_match_asset(
                        "approved.example",
                        (("url", value),),
                        network_argument_names=self.NETWORK_KEYS,
                    )
                )

    def test_non_network_metadata_is_not_reinterpreted_as_destination(self):
        self.assertTrue(
            declared_network_arguments_match_asset(
                "approved.example",
                (("path", "/admin"), ("note", "other.example")),
                network_argument_names=self.NETWORK_KEYS,
            )
        )

    def test_reference_check_is_input_pure(self):
        arguments = (
            ("url", "https://approved.example/a"),
            ("path", "/b"),
        )
        snapshot = tuple(arguments)
        self.assertTrue(
            declared_network_arguments_match_asset(
                "approved.example",
                arguments,
                network_argument_names=self.NETWORK_KEYS,
            )
        )
        self.assertEqual(arguments, snapshot)

    def test_registry_declared_destination_set_is_itself_strictly_typed(self):
        self.assertFalse(
            declared_network_arguments_match_asset(
                "approved.example",
                (("url", "https://approved.example"),),
                network_argument_names={"url"},  # type: ignore[arg-type]
            )
        )


if __name__ == "__main__":
    unittest.main()
