"""Offline regression: X-Original-Host is never a target authorization source.

These tests exercise the existing pure ScopePolicy API. They do not authorize
network requests or represent trusted, persisted customer consent.
"""
import unittest

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class OriginalHostNonAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"approved.example"}),
        )

    def test_unknown_host_denied_despite_original_host_label(self):
        for hint in (
            "X-Original-Host: approved.example",
            "x-original-host=approved.example",
            "X-Original-Host: APPROVED.EXAMPLE",
            "X-Original-Host: approved.example:443",
            "X-Original-Host: approved.example, unknown.example",
        ):
            with self.subTest(hint=hint):
                target = Target("unknown.example", labels=(hint,))
                result = self.policy.decide(target)
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)
                self.assertEqual(result.normalized_host, "unknown.example")

    def test_hint_does_not_replace_missing_grant_for_allowlisted_host(self):
        result = self.policy.decide(
            Target("approved.example", labels=("X-Original-Host: approved.example",))
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_hint_does_not_authorize_unlisted_host_even_with_synthetic_grant(self):
        synthetic = Authorization(owner="fixture", reference="NOT-TRUSTED")
        result = self.policy.decide(
            Target("unknown.example", authorization=synthetic,
                   labels=("X-Original-Host: approved.example",))
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)

    def test_hint_does_not_deny_authorized_host_by_rewriting_identity(self):
        synthetic = Authorization(owner="fixture", reference="NOT-TRUSTED")
        result = self.policy.decide(
            Target("approved.example", authorization=synthetic,
                   labels=("X-Original-Host: unknown.example",))
        )
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, ScopeReason.EXPLICIT_HOST)
        self.assertEqual(result.normalized_host, "approved.example")

    def test_forwarding_label_does_not_override_url_authority(self):
        result = self.policy.decide(
            Target("https://unknown.example/path",
                   labels=("X-Original-Host: approved.example",))
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.normalized_host, "unknown.example")

    def test_userinfo_in_hint_never_replaces_target_authority(self):
        result = self.policy.decide(
            Target("https://unknown.example/",
                   labels=("X-Original-Host: approved.example@unknown.example",))
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)


    def test_original_host_is_not_inspected_as_a_label_object(self):
        class PoisonLabels:
            def __iter__(self):
                raise AssertionError("untrusted labels must not be inspected")
            def __len__(self):
                raise AssertionError("untrusted labels must not be measured")
            def __bool__(self):
                raise AssertionError("untrusted labels must not be evaluated")

        result = self.policy.decide(
            Target("unknown.example", labels=PoisonLabels())
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)

    def test_expired_grant_cannot_be_revived_by_original_host(self):
        from datetime import datetime, timedelta, timezone

        expired = Authorization(
            owner="fixture", reference="NOT-TRUSTED",
            valid_until=datetime.now(timezone.utc) - timedelta(days=1),
        )
        result = self.policy.decide(Target(
            "approved.example", authorization=expired,
            labels=("X-Original-Host: approved.example",),
        ))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_future_grant_cannot_be_activated_by_original_host(self):
        from datetime import datetime, timedelta, timezone

        future = Authorization(
            owner="fixture", reference="NOT-TRUSTED",
            valid_from=datetime.now(timezone.utc) + timedelta(days=1),
        )
        result = self.policy.decide(Target(
            "approved.example", authorization=future,
            labels=("X-Original-Host: approved.example",),
        ))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_original_host_cannot_change_network_allowlist_identity(self):
        network_policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("203.0.113.0/24",),
        )
        synthetic = Authorization(owner="fixture", reference="NOT-TRUSTED")
        for label in ("X-Original-Host: 203.0.113.8",
                      "X-Original-Host: approved.example"):
            with self.subTest(label=label):
                result = network_policy.decide(Target(
                    "198.51.100.8", authorization=synthetic, labels=(label,),
                ))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)


    def test_header_like_labels_never_grant_any_public_target(self):
        synthetic = Authorization(owner="fixture", reference="NOT-TRUSTED")
        hints = (
            "X-Original-Host: approved.example",
            "X-Original-Host: localhost",
            "X-Original-Host: 127.0.0.1",
            "X-Original-Host: [::1]",
            "X-Original-Host: approved.example" + chr(13) + chr(10) + "Host: unknown.example",
            "X-Original-Host: approved.example" + chr(10) + "X-Forwarded-Host: approved.example",
            "X-Original-Host: approved.example" + chr(0) + "unknown.example",
            "X-Original-Host: APPROVED.EXAMPLE.",
        )
        for hint in hints:
            with self.subTest(hint=hint):
                result = self.policy.decide(Target(
                    "unknown.example", authorization=synthetic, labels=(hint,),
                ))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)

    def test_lab_disabled_hint_cannot_promote_private_address(self):
        for host in ("10.2.3.4", "192.168.44.5"):
            with self.subTest(host=host):
                result = self.policy.decide(Target(
                    host, labels=("X-Original-Host: approved.example",),
                ))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)

    def test_original_host_does_not_mutate_immutable_target(self):
        synthetic = Authorization(owner="fixture", reference="NOT-TRUSTED")
        target = Target(
            "unknown.example", authorization=synthetic,
            labels=("X-Original-Host: approved.example",),
        )
        self.policy.decide(target)
        self.assertEqual(target.value, "unknown.example")
        self.assertEqual(target.labels, ("X-Original-Host: approved.example",))
        self.assertIs(target.authorization, synthetic)


    def test_loopback_exception_is_local_identity_not_header_authority(self):
        allowed = self.policy.decide(Target(
            "127.0.0.1", labels=("X-Original-Host: unknown.example",),
        ))
        self.assertTrue(allowed.allowed)
        self.assertEqual(allowed.reason, ScopeReason.LOOPBACK)
        denied = self.policy.decide(Target(
            "unknown.example", labels=("X-Original-Host: 127.0.0.1",),
        ))
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.reason, ScopeReason.OUT_OF_SCOPE)


    def test_forged_original_host_denial_never_resolves_or_connects(self):
        from unittest.mock import patch

        def forbidden(*args, **kwargs):
            raise AssertionError("scope decision must not perform target I/O")

        with (
            patch("socket.getaddrinfo", side_effect=forbidden) as lookup,
            patch("socket.gethostbyname", side_effect=forbidden) as resolve,
            patch("socket.create_connection", side_effect=forbidden) as connect,
        ):
            decision = self.policy.decide(Target(
                "unknown.example",
                labels=("X-Original-Host: approved.example",),
            ))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)
        lookup.assert_not_called()
        resolve.assert_not_called()
        connect.assert_not_called()

    def test_original_host_hint_does_not_make_grant_lookups_on_deny(self):
        class PoisonAuthorization:
            def __getattribute__(self, name):
                raise AssertionError("unlisted target must not inspect grant")

        result = self.policy.decide(Target(
            "unknown.example", authorization=PoisonAuthorization(),
            labels=("X-Original-Host: approved.example",),
        ))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)


    def test_missing_grant_is_checked_without_network_calls(self):
        from unittest.mock import patch

        with (
            patch("socket.getaddrinfo") as lookup,
            patch("socket.create_connection") as connect,
        ):
            result = self.policy.decide(Target(
                "approved.example",
                labels=("X-Original-Host: approved.example",),
            ))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_MISSING)
        lookup.assert_not_called()
        connect.assert_not_called()

    def test_forged_header_cannot_change_ipv6_scope_identity(self):
        result = self.policy.decide(Target(
            "https://[2001:db8::9]/",
            labels=("X-Original-Host: approved.example",),
        ))
        self.assertFalse(result.allowed)
        self.assertEqual(result.normalized_host, "2001:db8::9")
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)


    def test_header_spoof_cannot_change_policy_opt_out(self):
        restrictive = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"approved.example"}),
            require_authorization_for_public=True,
        )
        permissive = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"approved.example"}),
            require_authorization_for_public=False,
        )
        hint = ("X-Original-Host: approved.example",)
        denied = restrictive.decide(Target("approved.example", labels=hint))
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.reason, ScopeReason.AUTHORIZATION_MISSING)
        allowed_reference = permissive.decide(Target("approved.example", labels=hint))
        self.assertTrue(allowed_reference.allowed)
        self.assertEqual(allowed_reference.reason, ScopeReason.EXPLICIT_HOST)
        # The policy opt-out is a trusted config choice, never extracted from hint.

    def test_repeated_spoofed_headers_cannot_mutate_policy(self):
        original_hosts = self.policy.explicit_hosts
        original_networks = self.policy.explicit_networks
        for count in (1, 10, 100):
            labels = ("X-Original-Host: approved.example",) * count
            with self.subTest(count=count):
                result = self.policy.decide(Target("unknown.example", labels=labels))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)
        self.assertEqual(self.policy.explicit_hosts, original_hosts)
        self.assertEqual(self.policy.explicit_networks, original_networks)


    def test_case_variant_host_hint_cannot_expand_target_allowlist(self):
        for hint in (
            "X-ORIGINAL-HOST: approved.example",
            "x-original-host: approved.example",
            "X_Original_Host: approved.example",
        ):
            with self.subTest(hint=hint):
                decision = self.policy.decide(Target(
                    "unlisted.example", labels=(hint,),
                ))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_injected_hint_does_not_skip_expired_grant_check(self):
        from datetime import datetime, timedelta, timezone
        expired = Authorization(
            owner="fixture", reference="NOT-TRUSTED",
            valid_until=datetime.now(timezone.utc) - timedelta(hours=2),
        )
        target = Target(
            "https://approved.example/resource",
            authorization=expired,
            labels=("X-Original-Host: localhost",),
        )
        decision = self.policy.decide(target)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)
        self.assertEqual(decision.normalized_host, "approved.example")


    def test_untrusted_host_header_cannot_override_explicit_network_deny(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("198.51.100.0/24",),
        )
        for target_host in ("203.0.113.7", "192.0.2.8"):
            with self.subTest(target_host=target_host):
                decision = policy.decide(Target(
                    target_host,
                    labels=("X-Original-Host: 198.51.100.9",),
                ))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_missing_grant_cannot_be_supplied_as_header_label(self):
        for label in (
            "X-Original-Host: approved.example; authorization=fixture",
            "X-Original-Host: approved.example; approved=true",
        ):
            with self.subTest(label=label):
                decision = self.policy.decide(Target(
                    "approved.example", labels=(label,),
                ))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)


    def test_synthetic_grant_cannot_follow_header_to_other_domain(self):
        grant = Authorization(owner="fixture", reference="NOT-TRUSTED")
        for host in ("unlisted.example", "other.example"):
            with self.subTest(host=host):
                result = self.policy.decide(Target(
                    "https://" + host + "/",
                    authorization=grant,
                    labels=("X-Original-Host: approved.example",),
                ))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)
                self.assertEqual(result.normalized_host, host)

    def test_original_host_label_cannot_inject_authorization_window(self):
        for label in (
            "X-Original-Host: approved.example; valid_until=2999-01-01",
            "X-Original-Host: approved.example; valid_from=2000-01-01",
        ):
            with self.subTest(label=label):
                result = self.policy.decide(Target(
                    "approved.example", labels=(label,),
                ))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_MISSING)


    def test_denied_host_hint_has_stable_reason_for_many_labels(self):
        for n in (0, 1, 8, 64, 256):
            with self.subTest(n=n):
                decision = self.policy.decide(Target(
                    "unlisted.example",
                    labels=("X-Original-Host: approved.example",) * n,
                ))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.normalized_host, "unlisted.example")
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_grant_metadata_in_header_does_not_count_as_current_grant(self):
        for claim in ("owner=fixture", "reference=NOT-TRUSTED",
                      "issuer=admin", "revoked=false", "capability=scan"):
            with self.subTest(claim=claim):
                decision = self.policy.decide(Target(
                    "approved.example",
                    labels=("X-Original-Host: approved.example; " + claim,),
                ))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)


    def test_routing_hint_cannot_supply_missing_engagement_or_asset_grant(self):
        for claim in ("tenant=customer-a", "engagement=eng-123",
                      "asset=approved.example", "scope=all"):
            with self.subTest(claim=claim):
                result = self.policy.decide(Target(
                    "approved.example",
                    labels=("X-Original-Host: approved.example; " + claim,),
                ))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_nonmatching_target_stays_denied_with_header_claimed_admin(self):
        synthetic = Authorization(owner="fixture", reference="NOT-TRUSTED")
        result = self.policy.decide(Target(
            "unlisted.example", authorization=synthetic,
            labels=("X-Original-Host: approved.example; role=admin",),
        ))
        self.assertFalse(result.allowed)
        self.assertEqual(result.normalized_host, "unlisted.example")
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)


    def test_header_claimed_capability_does_not_grant_missing_authorization(self):
        for capability in ("http_headers", "tls", "port_scan", "all"):
            with self.subTest(capability=capability):
                result = self.policy.decide(Target(
                    "approved.example",
                    labels=("X-Original-Host: approved.example; capability=" + capability,),
                ))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_header_claimed_revocation_clear_does_not_restore_expired_grant(self):
        from datetime import datetime, timedelta, timezone
        expired = Authorization(
            owner="fixture", reference="NOT-TRUSTED",
            valid_until=datetime.now(timezone.utc) - timedelta(days=2),
        )
        result = self.policy.decide(Target(
            "approved.example", authorization=expired,
            labels=("X-Original-Host: approved.example; revoked=false",),
        ))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_EXPIRED)


    def test_header_claimed_operator_approval_does_not_supply_grant(self):
        for claim in ("operator_approved=true", "approval_id=fixture",
                      "risk_level=0", "mode=analysis_only"):
            with self.subTest(claim=claim):
                result = self.policy.decide(Target(
                    "approved.example",
                    labels=("X-Original-Host: approved.example; " + claim,),
                ))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_different_host_remains_denied_under_claimed_operator_approval(self):
        result = self.policy.decide(Target(
            "unlisted.example",
            authorization=Authorization(owner="fixture", reference="NOT-TRUSTED"),
            labels=("X-Original-Host: approved.example; operator_approved=true",),
        ))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)


    def test_host_header_does_not_convert_unknown_url_to_loopback(self):
        for claimed_local in ("localhost", "127.0.0.1", "[::1]"):
            with self.subTest(claimed_local=claimed_local):
                decision = self.policy.decide(Target(
                    "https://unlisted.example/path",
                    labels=("X-Original-Host: " + claimed_local,),
                ))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)
                self.assertEqual(decision.normalized_host, "unlisted.example")

    def test_header_claimed_mode_cannot_authorize_without_grant(self):
        for claimed_mode in ("plan_only", "lab_only", "active", "passive"):
            with self.subTest(claimed_mode=claimed_mode):
                decision = self.policy.decide(Target(
                    "https://approved.example/",
                    labels=("X-Original-Host: approved.example; mode=" + claimed_mode,),
                ))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)


    def test_claimed_approval_does_not_override_missing_grant_on_ipv6(self):
        result = self.policy.decide(Target(
            "https://[2001:db8::9]/",
            labels=("X-Original-Host: approved.example; operator_approved=true",),
        ))
        self.assertFalse(result.allowed)
        self.assertEqual(result.normalized_host, "2001:db8::9")
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)

    def test_grant_reference_hint_does_not_authorize_different_url_host(self):
        target = Target(
            "https://unlisted.example/resource",
            authorization=Authorization(owner="fixture", reference="NOT-TRUSTED"),
            labels=("X-Original-Host: approved.example; grant_ref=NOT-TRUSTED",),
        )
        decision = self.policy.decide(target)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "unlisted.example")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)


    def test_header_like_mapping_cannot_supply_authorization(self):
        forged_headers = {
            "X-Original-Host": "approved.example",
            "X-Operator-Approved": "true",
            "X-Authorization-Reference": "NOT-TRUSTED",
        }
        result = self.policy.decide(Target(
            "approved.example", labels=forged_headers,
        ))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_MISSING)
        self.assertEqual(forged_headers["X-Original-Host"], "approved.example")

    def test_denied_foreign_url_does_not_touch_hostile_label_mapping(self):
        class HostileHeaders(dict):
            def __iter__(self):
                raise AssertionError("routing hints must not be iterated")
            def __getitem__(self, key):
                raise AssertionError("routing hints must not be read")
            def get(self, key, default=None):
                raise AssertionError("routing hints must not be consulted")

        decision = self.policy.decide(Target(
            "https://unlisted.example/", labels=HostileHeaders(),
        ))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)
        self.assertEqual(decision.normalized_host, "unlisted.example")


    def test_hostile_mapping_methods_cannot_reclassify_allowed_host(self):
        class HostileHeaders(dict):
            def items(self):
                raise AssertionError("cannot consume untrusted header mapping")
            def keys(self):
                raise AssertionError("cannot inspect untrusted header keys")
            def values(self):
                raise AssertionError("cannot inspect untrusted header values")

        result = self.policy.decide(Target(
            "approved.example", labels=HostileHeaders(),
        ))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_combined_fake_consent_metadata_still_denied(self):
        claims = (
            "X-Original-Host: approved.example",
            "operator_approved=true",
            "issuer=trusted",
            "client=customer-a",
            "engagement=eng-123",
            "asset=approved.example",
            "capability=http_headers",
            "revoked=false",
        )
        result = self.policy.decide(Target("approved.example", labels=claims))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_MISSING)


    def test_header_claimed_lease_cannot_approve_missing_grant(self):
        for claim in ("lease_id=synthetic", "run_id=synthetic",
                      "nonce=synthetic", "approval_signature=synthetic"):
            with self.subTest(claim=claim):
                result = self.policy.decide(Target(
                    "approved.example",
                    labels=("X-Original-Host: approved.example; " + claim,),
                ))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_forged_lease_does_not_authorize_unlisted_host(self):
        result = self.policy.decide(Target(
            "unlisted.example",
            authorization=Authorization(owner="fixture", reference="NOT-TRUSTED"),
            labels=("X-Original-Host: approved.example; lease_id=synthetic",),
        ))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)


    def test_claimed_signed_consent_in_header_cannot_replace_grant(self):
        for claim in ("consent_signed=true", "authorization_verified=true",
                      "scope_hash=synthetic", "approval_expires=2999-01-01"):
            with self.subTest(claim=claim):
                result = self.policy.decide(Target(
                    "approved.example",
                    labels=("X-Original-Host: approved.example; " + claim,),
                ))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_mismatched_target_denied_despite_signed_consent_hint(self):
        result = self.policy.decide(Target(
            "unlisted.example",
            authorization=Authorization(owner="fixture", reference="NOT-TRUSTED"),
            labels=("X-Original-Host: approved.example; consent_signed=true",),
        ))
        self.assertFalse(result.allowed)
        self.assertEqual(result.normalized_host, "unlisted.example")
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
