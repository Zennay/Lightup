"""Offline opt-in atomic scope batch preview real integration acceptance.

No ActivationGate, permit, network, DNS, scanner or real target. Synthetic
reserved .test domains and RFC1918/loopback literals only.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import unittest

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy
from lightup.strict_target_scope_optin import StrictTargetScopePolicy
from lightup.strict_scope_batch_preview_optin import (
    ScopeBatchPreview, ScopeBatchRejected, preview_scope_batch,
)


class AuthorizationSubclass(Authorization):
    pass


class TargetSubclass(Target):
    pass


class BatchPreviewOptInTest(unittest.TestCase):
    def setUp(self):
        self.strict = StrictTargetScopePolicy(
            ScopePolicy(explicit_hosts=frozenset({"app.example.test"}))
        )
        now = datetime.now(timezone.utc)
        self.auth = Authorization(
            owner="synthetic-owner", reference="LAB-123",
            valid_from=now - timedelta(minutes=10),
            valid_until=now + timedelta(days=1),
        )

    def _deny(self, values):
        with self.assertRaisesRegex(ScopeBatchRejected, "^scope batch refused$"):
            preview_scope_batch(self.strict, values)

    def test_positive_mixed_local_private_and_authorized_public(self):
        targets = (
            Target("http://localhost:8787", labels=("lab",)),
            Target("10.20.30.40"),
            Target("https://app.example.test:443/path", authorization=self.auth),
        )
        before = repr(targets)
        receipt = preview_scope_batch(self.strict, targets)
        self.assertIs(type(receipt), ScopeBatchPreview)
        self.assertEqual(receipt.target_count, 3)
        self.assertEqual(receipt.reason_counts, (
            ("explicit_host", 1), ("loopback", 1), ("private_lab", 1),
        ))
        self.assertIs(receipt.grant_issued, False)
        self.assertIs(receipt.execution_enabled, False)
        self.assertEqual(repr(targets), before)

    def test_inprocess_receipt_never_contains_private_target_or_reference(self):
        result = preview_scope_batch(
            self.strict,
            (Target("https://app.example.test/path", authorization=self.auth),),
        )
        rendered = repr(result)
        for private in ("app.example.test", "LAB-123", "synthetic-owner"):
            self.assertNotIn(private, rendered)
        self.assertEqual(result.reason_counts, (("explicit_host", 1),))

    def test_canonical_host_identity_collision_denied_atomically(self):
        self._deny((Target("LOCALHOST."), Target("https://localhost:443/")))

    def test_port_variants_do_not_duplicate_authority(self):
        self._deny((Target("localhost:80"), Target("http://localhost:443")))

    def test_late_parser_normalization_refused_not_partially_returned(self):
        self._deny((Target("localhost"), Target("http://lo\ncalhost")))

    def test_bad_port_userinfo_and_encoded_authority_refused(self):
        for bad in (
            "http://localhost:notaport",
            "http://operator@localhost",
            "http://localhost:65536",
            "http://loc%61lhost",
        ):
            with self.subTest(bad=repr(bad)):
                self._deny((Target("127.0.0.1"), Target(bad)))

    def test_missing_or_expired_public_authorization_refused(self):
        self._deny((Target("localhost"), Target("app.example.test")))
        expired = replace(self.auth,
                          valid_until=datetime.now(timezone.utc) - timedelta(days=1))
        self._deny((Target("app.example.test", authorization=expired),))

    def test_unallowlisted_public_target_refused_with_present_auth(self):
        self._deny((Target("other.example.test", authorization=self.auth),))

    def test_disabled_private_lab_policy_remains_authoritative(self):
        strict = StrictTargetScopePolicy(ScopePolicy(allow_private_lab=False))
        with self.assertRaises(ScopeBatchRejected):
            preview_scope_batch(strict, (Target("10.0.0.10"),))

    def test_empty_oversized_and_non_tuple_rejected_without_processing(self):
        self._deny(())
        self._deny(tuple(Target(f"10.0.0.{i}") for i in range(1, 66)))
        for bad in (None, [Target("localhost")], "localhost", object()):
            with self.subTest(kind=type(bad).__name__):
                self._deny(bad)

    def test_exact_policy_required_no_duck_or_subclass(self):
        with self.assertRaises(ScopeBatchRejected):
            preview_scope_batch(object(), (Target("localhost"),))
        class SubPolicy(StrictTargetScopePolicy):
            pass
        with self.assertRaises(ScopeBatchRejected):
            preview_scope_batch(SubPolicy(ScopePolicy()), (Target("localhost"),))

    def test_target_subclass_or_arbitrary_member_type_rejected(self):
        canonical = Target("localhost")
        fake = TargetSubclass(**vars(canonical))
        self._deny((fake,))
        self._deny((canonical, object()))

    def test_nested_authorization_subclass_and_duck_refused(self):
        fake = AuthorizationSubclass(**vars(self.auth))
        self._deny((Target("localhost", authorization=fake),))
        self._deny((Target("localhost", authorization=object()),))

    def test_nested_authorization_lexical_and_type_integrity(self):
        for bad in (
            replace(self.auth, owner="  owner"),
            replace(self.auth, reference="\nsecret"),
            replace(self.auth, owner="a" * 129),
            replace(self.auth, reference=1),
            replace(self.auth, owner=True),
        ):
            with self.subTest(bad=repr(bad)):
                self._deny((Target("localhost", authorization=bad),))

    def test_naive_noncanonical_or_reversed_authorization_times_refused(self):
        now = datetime.now(timezone.utc)
        for bad in (
            replace(self.auth, valid_from=now.replace(tzinfo=None)),
            replace(self.auth, valid_until="tomorrow"),
            replace(self.auth, valid_from=now + timedelta(days=2)),
        ):
            with self.subTest(bad=repr(bad)):
                self._deny((Target("localhost", authorization=bad),))

    def test_labels_must_be_canonical_bounded_and_exact(self):
        for labels in (
            ["not-tuple"], ("bad\nlabel",), ("",),
            tuple("label" for _ in range(17)),
            (object(),),
            ("x" * 65,),
        ):
            with self.subTest(labels=repr(labels)):
                self._deny((Target("localhost", labels=labels),))

    def test_all_outer_and_nested_type_checks_happen_before_decide(self):
        with patch.object(StrictTargetScopePolicy, "decide", autospec=True) as decide:
            self._deny((
                Target("localhost"),
                Target("app.example.test", authorization=object()),
            ))
            decide.assert_not_called()

    def test_legacy_scope_decision_does_not_create_activation_permit(self):
        # This entrypoint has no ActivationGate reference at all.
        result = preview_scope_batch(self.strict, (Target("127.0.0.1"),))
        self.assertEqual(result.reason_counts, (("loopback", 1),))
        self.assertFalse(result.grant_issued)
        self.assertFalse(result.execution_enabled)

    def test_rejection_text_never_echoes_reference_or_private_input(self):
        bad = Target("http://operator@localhost", authorization=self.auth)
        with self.assertRaises(ScopeBatchRejected) as caught:
            preview_scope_batch(self.strict, (bad,))
        self.assertEqual(str(caught.exception), "scope batch refused")
        self.assertNotIn("operator", str(caught.exception))
        self.assertNotIn("LAB-123", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
