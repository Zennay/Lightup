"""Synthetic, offline-only acceptance for #297; production policy remains unmodified."""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy
from lightup.scope_public_config_integrity_20261012 import (
    InvalidPublicScopeConfiguration,
    validate_public_scope_configuration,
)


class ImpostorText(str):
    def strip(self, *args, **kwargs):
        return "security.example.test"


class ImpostorPolicy(ScopePolicy):
    pass


class AtomicPublicScopeConfigurationTests(unittest.TestCase):
    @staticmethod
    def policy(**kwargs):
        fields = dict(
            allow_private_lab=False,
            explicit_hosts=frozenset({"security.example.test"}),
            explicit_networks=("192.0.2.0/24", "2001:db8::/32"),
            require_authorization_for_public=True,
        )
        fields.update(kwargs)
        return ScopePolicy(**fields)

    def test_canonical_host_and_both_ip_families(self):
        self.assertIsNone(validate_public_scope_configuration(self.policy()))

    def test_empty_allowlist_is_well_formed_but_not_authority(self):
        self.assertIsNone(validate_public_scope_configuration(ScopePolicy()))
        # Shape validation never returns a grant, permit or allowed decision.
        self.assertIsNone(validate_public_scope_configuration(self.policy()))

    def test_invalid_network_blocks_valid_host_configuration(self):
        with self.assertRaises(InvalidPublicScopeConfiguration):
            validate_public_scope_configuration(
                self.policy(explicit_networks=("not-a-cidr",))
            )

    def test_invalid_network_after_valid_network_denied_atomically(self):
        with self.assertRaises(InvalidPublicScopeConfiguration):
            validate_public_scope_configuration(
                self.policy(explicit_networks=("192.0.2.0/24", "not-a-cidr"))
            )

    def test_invalid_network_before_valid_network_denied_atomically(self):
        with self.assertRaises(InvalidPublicScopeConfiguration):
            validate_public_scope_configuration(
                self.policy(explicit_networks=("not-a-cidr", "192.0.2.0/24"))
            )

    def test_host_bit_ipv4_cidr_rejected(self):
        with self.assertRaises(InvalidPublicScopeConfiguration):
            validate_public_scope_configuration(
                self.policy(explicit_networks=("192.0.2.17/24",))
            )

    def test_uncompressed_ipv6_network_alias_rejected(self):
        with self.assertRaises(InvalidPublicScopeConfiguration):
            validate_public_scope_configuration(
                self.policy(explicit_networks=("2001:0db8:0000:0000::/32",))
            )

    def test_bad_network_shapes_are_denied(self):
        values = (None, 24, True, "", " 192.0.2.0/24",
                  "192.0.2.0/24 ", "10.0.0.0/33", "192.0.2.1",
                  "0.0.0.0/0\n", "2001:db8::/129", "EXAMPLE", 
                  ImpostorText("192.0.2.0/24"))
        for value in values:
            with self.subTest(value=repr(value)):
                with self.assertRaises(InvalidPublicScopeConfiguration):
                    validate_public_scope_configuration(
                        self.policy(explicit_networks=(value,))
                    )

    def test_bad_hosts_poison_entire_configuration(self):
        values = ("", "security.example.test.", "SECURITY.EXAMPLE.TEST",
                  " security.example.test", "security.example.test ",
                  "*.example.test", "https://security.example.test",
                  "a..example.test", "-a.example.test", "a-.example.test",
                  "a" * 64 + ".test", "exámple.test", "a\\b.test",
                  ImpostorText("security.example.test"), None, 12)
        for host in values:
            with self.subTest(host=repr(host)):
                with self.assertRaises(InvalidPublicScopeConfiguration):
                    validate_public_scope_configuration(
                        self.policy(explicit_hosts=frozenset({host}))
                    )

    def test_mixed_canonical_and_noncanonical_hosts_rejected(self):
        with self.assertRaises(InvalidPublicScopeConfiguration):
            validate_public_scope_configuration(self.policy(
                explicit_hosts=frozenset({
                    "security.example.test", "https://bad.example.test",
                })
            ))

    def test_ip_literals_cannot_hide_in_hostname_allowlist(self):
        for host in ("127.0.0.1", "192.0.2.1", "10.0.0.1"):
            with self.subTest(host=host):
                with self.assertRaisesRegex(InvalidPublicScopeConfiguration, "IP literal"):
                    validate_public_scope_configuration(
                        self.policy(explicit_hosts=frozenset({host}))
                    )

    def test_link_local_ipv6_zone_is_not_portable_network_scope(self):
        for scope in ("fe80::%eth0/128", "fe80::%lo/64"):
            with self.subTest(scope=scope):
                with self.assertRaisesRegex(
                    InvalidPublicScopeConfiguration, "interface-scoped network"
                ):
                    validate_public_scope_configuration(
                        self.policy(explicit_networks=(scope,))
                    )

    def test_internet_wide_networks_cannot_be_explicit_scope(self):
        for route in ("0.0.0.0/0", "::/0"):
            with self.subTest(route=route):
                with self.assertRaisesRegex(
                    InvalidPublicScopeConfiguration, "internet-wide network"
                ):
                    validate_public_scope_configuration(
                        self.policy(explicit_networks=(route,))
                    )

    def test_precise_ip_network_scope_positive_control(self):
        for network in ("127.0.0.1/32", "192.0.2.1/32", "2001:db8::1/128"):
            with self.subTest(network=network):
                self.assertIsNone(validate_public_scope_configuration(
                    self.policy(explicit_networks=(network,))
                ))

    def test_mixed_safe_and_unsafe_networks_deny_atomically(self):
        for bad in ("::/0", "fe80::%eth0/128", "0.0.0.0/0"):
            for networks in (("192.0.2.0/24", bad), (bad, "192.0.2.0/24")):
                with self.subTest(networks=networks):
                    with self.assertRaises(InvalidPublicScopeConfiguration):
                        validate_public_scope_configuration(
                            self.policy(explicit_networks=networks)
                        )

    def test_noncanonical_policy_class_and_collection_types(self):
        invalid = (
            ImpostorPolicy(),
            self.policy(explicit_hosts=["security.example.test"]),
            self.policy(explicit_hosts=("security.example.test",)),
            self.policy(explicit_networks=["192.0.2.0/24"]),
            self.policy(explicit_networks=ImpostorTuple(("192.0.2.0/24",))),
        )
        for policy in invalid:
            with self.subTest(policy=repr(policy)):
                with self.assertRaises(InvalidPublicScopeConfiguration):
                    validate_public_scope_configuration(policy)

    def test_false_or_nonboolean_public_auth_switch_rejected(self):
        for enabled in (False, 0, 1, "true", None):
            with self.subTest(enabled=enabled):
                with self.assertRaises(InvalidPublicScopeConfiguration):
                    validate_public_scope_configuration(self.policy(
                        require_authorization_for_public=enabled
                    ))

    def test_nonboolean_lab_switch_rejected(self):
        for value in (0, 1, "false", None):
            with self.subTest(value=value):
                with self.assertRaises(InvalidPublicScopeConfiguration):
                    validate_public_scope_configuration(self.policy(
                        allow_private_lab=value
                    ))

    def test_is_pure_and_does_not_normalize_input(self):
        policy = self.policy()
        before = (policy.explicit_hosts, policy.explicit_networks,
                  policy.allow_private_lab, policy.require_authorization_for_public)
        validate_public_scope_configuration(policy)
        self.assertEqual(
            before,
            (policy.explicit_hosts, policy.explicit_networks,
             policy.allow_private_lab, policy.require_authorization_for_public)
        )

    def test_no_successful_shape_check_mints_auth(self):
        validate_public_scope_configuration(self.policy())
        target = Target("security.example.test")
        self.assertFalse(self.policy().decide(target).allowed)

    @unittest.expectedFailure
    def test_installed_policy_must_reject_malformed_network_even_on_host_path(self):
        # Known current defect, intentionally XFAIL; not a safety assertion.
        policy = self.policy(explicit_networks=("not-a-cidr",))
        synthetic_validity = Authorization(
            owner="synthetic-owner", reference="synthetic-ref",
            valid_until=datetime.now(timezone.utc) + timedelta(days=1),
        )
        decision = policy.decide(
            Target("security.example.test", authorization=synthetic_validity)
        )
        self.assertFalse(decision.allowed)


class ImpostorTuple(tuple):
    pass


if __name__ == "__main__":
    unittest.main()
