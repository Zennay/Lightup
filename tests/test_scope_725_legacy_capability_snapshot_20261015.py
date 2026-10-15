"""#725 -- independent, synthetic legacy capability snapshot regressions.

Pinned to the unchanged source-owner #122. No targets, transport or handlers.
Source REDs are expectedFailure until the owning implementation is repaired.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timezone

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy


HOST = "synthetic-snapshot.example.test"
CAPABILITY = "fixture-web-baseline"
NEW_CAPABILITY = "fixture-api-baseline"


def gate(mode: ActivationMode = ActivationMode.AUTHORIZED) -> ActivationGate:
    return ActivationGate(
        ScopePolicy(allow_private_lab=False, explicit_hosts=frozenset({HOST})),
        ActivationPolicy(mode=mode, activation_reference="fixture-review-only"),
    )


def fixture_authorization(capabilities):
    return Authorization(
        owner="fictional-owner",
        reference="fixture-authorization-review",
        assets=(HOST,),
        capabilities=capabilities,
    )


def fixture_target(authorization):
    return Target(value=HOST, authorization=authorization)


class LegacyCapabilitySnapshotAcceptance(unittest.TestCase):
    def test_exact_tuple_keeps_preexisting_capability_authority(self):
        authorization = fixture_authorization((CAPABILITY,))
        self.assertTrue(authorization.allows_capability(CAPABILITY))
        permit = gate().issue(fixture_target(authorization), CAPABILITY)
        self.assertEqual(permit.capability_id, CAPABILITY)
        self.assertEqual(permit.target, HOST)

    def test_exact_tuple_denies_nonmember_capability(self):
        authorization = fixture_authorization((CAPABILITY,))
        self.assertFalse(authorization.allows_capability(NEW_CAPABILITY))
        with self.assertRaises(PermissionError):
            gate().issue(fixture_target(authorization), NEW_CAPABILITY)

    def test_empty_tuple_never_grants_a_capability(self):
        authorization = fixture_authorization(())
        for value in (CAPABILITY, NEW_CAPABILITY):
            with self.subTest(value=value):
                self.assertFalse(authorization.allows_capability(value))
                with self.assertRaises(PermissionError):
                    gate().issue(fixture_target(authorization), value)

    def test_unknown_asset_stays_denied_even_with_explicit_capability(self):
        authorization = fixture_authorization((CAPABILITY,))
        with self.assertRaises(PermissionError):
            gate().issue(Target("other-synthetic.example.test", authorization), CAPABILITY)

    def test_plan_only_stays_denied_even_for_exact_allowlisted_capability(self):
        with self.assertRaises(PermissionError):
            gate(ActivationMode.PLAN_ONLY).issue(
                fixture_target(fixture_authorization((CAPABILITY,))), CAPABILITY
            )

    def test_missing_authorization_stays_denied(self):
        with self.assertRaises(PermissionError):
            gate().issue(fixture_target(None), CAPABILITY)

    def test_authorization_expiry_stays_denied(self):
        authorization = Authorization(
            owner="fictional-owner",
            reference="fixture-expired-review",
            assets=(HOST,),
            capabilities=(CAPABILITY,),
            valid_until=datetime(2000, 1, 1, tzinfo=timezone.utc),
        )
        with self.assertRaises(PermissionError):
            gate().issue(fixture_target(authorization), CAPABILITY)

    @unittest.expectedFailure  # open source RED: list accepted and retained by frozen dataclass
    def test_mutable_caller_input_must_snapshot_to_exact_tuple(self):
        mutable = [CAPABILITY]
        authorization = fixture_authorization(mutable)
        self.assertIs(type(authorization.capabilities), tuple)
        self.assertEqual(authorization.capabilities, (CAPABILITY,))

    @unittest.expectedFailure  # open source RED: post-issuance append grants new capability
    def test_mutating_caller_owned_list_cannot_change_membership(self):
        mutable = [CAPABILITY]
        authorization = fixture_authorization(mutable)
        self.assertFalse(authorization.allows_capability(NEW_CAPABILITY))
        mutable.append(NEW_CAPABILITY)
        self.assertFalse(authorization.allows_capability(NEW_CAPABILITY))

    @unittest.expectedFailure  # open source RED: real ActivationGate honors new list member
    def test_mutating_caller_owned_list_cannot_mint_new_permit(self):
        mutable = [CAPABILITY]
        authorization = fixture_authorization(mutable)
        with self.assertRaises(PermissionError):
            gate().issue(fixture_target(authorization), NEW_CAPABILITY)
        mutable.append(NEW_CAPABILITY)
        with self.assertRaises(PermissionError):
            gate().issue(fixture_target(authorization), NEW_CAPABILITY)

    @unittest.expectedFailure  # open source RED: post-issuance removal revokes old entry
    def test_caller_removal_must_not_revoke_snapshotted_capability(self):
        mutable = [CAPABILITY]
        authorization = fixture_authorization(mutable)
        self.assertTrue(authorization.allows_capability(CAPABILITY))
        mutable.clear()
        self.assertTrue(authorization.allows_capability(CAPABILITY))

    @unittest.expectedFailure  # open source RED: list mutation changes permit success
    def test_caller_removal_must_not_change_original_permit_decision(self):
        mutable = [CAPABILITY]
        authorization = fixture_authorization(mutable)
        self.assertEqual(
            gate().issue(fixture_target(authorization), CAPABILITY).capability_id,
            CAPABILITY,
        )
        mutable.clear()
        self.assertEqual(
            gate().issue(fixture_target(authorization), CAPABILITY).capability_id,
            CAPABILITY,
        )


if __name__ == "__main__":
    unittest.main()
