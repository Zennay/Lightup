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


if __name__ == "__main__":
    unittest.main()
