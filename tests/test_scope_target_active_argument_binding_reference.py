"""Offline reference contract for TARGET_ACTIVE argument-to-asset binding.

This module is intentionally standalone and performs no network I/O. It models
one narrow invariant for the production authorization owner:

    every declared network-bearing tool argument must resolve to the same host
    as the independently authorized top-level asset.

A True result is only argument consistency. It is never authorization,
provenance, approval, revocation, risk, or dispatch permission.
"""

from __future__ import annotations

import unittest
from urllib.parse import urlsplit


_MAX_NETWORK_VALUE = 2048


def _canonical_host(value: object) -> str | None:
    if type(value) is not str:
        return None
    if not value or len(value) > _MAX_NETWORK_VALUE or value != value.strip():
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        return None

    candidate = value if "://" in value else f"//{value}"
    try:
        parsed = urlsplit(candidate)
        if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        host = parsed.hostname
    except ValueError:
        return None

    if not host or "%" in host:
        return None
    return host.rstrip(".").lower() or None


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

    asset_host = _canonical_host(authorized_asset)
    if asset_host is None or type(arguments) is not tuple:
        return False
    if type(network_argument_names) is not frozenset:
        return False

    seen: set[str] = set()
    for item in arguments:
        if type(item) is not tuple or len(item) != 2:
            return False
        key, value = item
        if type(key) is not str or not key or key in seen:
            return False
        seen.add(key)

        if key in network_argument_names:
            argument_host = _canonical_host(value)
            if argument_host is None or argument_host != asset_host:
                return False

    return True


class TargetActiveArgumentBindingReferenceTests(unittest.TestCase):
    NETWORK_KEYS = frozenset({"url", "host", "target", "endpoint"})

    def test_same_host_url_with_port_path_and_query_is_consistent(self):
        self.assertTrue(
            declared_network_arguments_match_asset(
                "https://Example.test",
                (("url", "https://example.test:8443/a?b=1"),),
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
