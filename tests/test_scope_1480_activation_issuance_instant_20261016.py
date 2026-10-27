"""#1480: real ActivationGate issuance-time coherence, purely in-process.

This is independent acceptance, NOT a runtime fix. The deliberately expected
failure proves a source gap using fictional .example.test identities and two
deterministic clocks. It makes no network calls, grants or tool dispatch.
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy

EXPIRY = datetime(2026, 10, 16, 8, 0, 0, tzinfo=timezone.utc)
INSIDE = EXPIRY - timedelta(seconds=1)
OUTSIDE = EXPIRY + timedelta(seconds=1)
PUBLIC_HOST = "review.example.test"


class _InsideCheckClock(datetime):
    @classmethod
    def now(cls, tz=None):
        return INSIDE if tz is not None else INSIDE.replace(tzinfo=None)


class _OutsideCheckClock(datetime):
    @classmethod
    def now(cls, tz=None):
        return OUTSIDE if tz is not None else OUTSIDE.replace(tzinfo=None)


class _ExactlyAtExpiryClock(datetime):
    @classmethod
    def now(cls, tz=None):
        return EXPIRY if tz is not None else EXPIRY.replace(tzinfo=None)


def _target() -> Target:
    return Target(
        PUBLIC_HOST,
        authorization=Authorization(
            owner="synthetic-owner",
            reference="synthetic-grant-reference",
            valid_from=EXPIRY - timedelta(hours=1),
            valid_until=EXPIRY,
        ),
    )


def _gate(mode=ActivationMode.AUTHORIZED) -> ActivationGate:
    return ActivationGate(
        ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({PUBLIC_HOST}),
            require_authorization_for_public=True,
        ),
        ActivationPolicy(
            mode=mode,
            activation_reference="synthetic-activation-reference",
        ),
    )


class ActivationIssuanceInstant1480Tests(unittest.TestCase):
    def test_fixture_has_distinct_utc_instants(self):
        self.assertEqual(_InsideCheckClock.now(timezone.utc), INSIDE)
        self.assertEqual(_OutsideCheckClock.now(timezone.utc), OUTSIDE)
        self.assertEqual(_ExactlyAtExpiryClock.now(timezone.utc), EXPIRY)
        self.assertLess(INSIDE, EXPIRY)
        self.assertLess(EXPIRY, OUTSIDE)

    def test_authorized_exact_public_asset_inside_entire_window(self):
        with patch("lightup.models.datetime", _InsideCheckClock), patch(
            "lightup.activation.datetime", _InsideCheckClock
        ):
            permit = _gate().issue(_target(), "synthetic-capability")
        self.assertEqual(permit.mode, ActivationMode.AUTHORIZED)
        self.assertEqual(permit.target, PUBLIC_HOST)
        self.assertEqual(permit.capability_id, "synthetic-capability")
        self.assertEqual(permit.activation_reference, "synthetic-activation-reference")
        self.assertEqual(permit.issued_at, INSIDE)
        self.assertLessEqual(permit.issued_at, _target().authorization.valid_until)

    def test_exact_expiry_inclusive_control(self):
        with patch("lightup.models.datetime", _ExactlyAtExpiryClock), patch(
            "lightup.activation.datetime", _ExactlyAtExpiryClock
        ):
            permit = _gate().issue(_target(), "synthetic-capability")
        self.assertEqual(permit.issued_at, EXPIRY)

    def test_expired_at_scope_check_denies(self):
        with patch("lightup.models.datetime", _OutsideCheckClock), patch(
            "lightup.activation.datetime", _OutsideCheckClock
        ):
            with self.assertRaises(PermissionError):
                _gate().issue(_target(), "synthetic-capability")

    def test_plan_only_denies_without_issuing(self):
        with patch("lightup.models.datetime", _InsideCheckClock), patch(
            "lightup.activation.datetime", _OutsideCheckClock
        ):
            with self.assertRaises(PermissionError):
                _gate(ActivationMode.PLAN_ONLY).issue(_target(), "synthetic-capability")

    def test_lab_only_rejects_fictional_public_host(self):
        with patch("lightup.models.datetime", _InsideCheckClock), patch(
            "lightup.activation.datetime", _OutsideCheckClock
        ):
            with self.assertRaises(PermissionError):
                _gate(ActivationMode.LAB_ONLY).issue(_target(), "synthetic-capability")

    def test_denied_unlisted_asset_even_with_valid_authorization(self):
        bad = Target("outside.example.test", authorization=_target().authorization)
        with patch("lightup.models.datetime", _InsideCheckClock):
            with self.assertRaises(PermissionError):
                _gate().issue(bad, "synthetic-capability")

    @unittest.expectedFailure
    def test_expected_red_authorized_permit_cannot_be_stamped_after_expiry(self):
        """Source RED: both checks see INSIDE; issued_at sees OUTSIDE.

        Desired permanent behavior: refuse to issue an AUTHORIZED permit when
        its issuance instant is no longer within the original authorization
        window. A future source fix makes this an unexpectedSuccess until the
        owner explicitly promotes it to an ordinary passing test.
        """
        with patch("lightup.models.datetime", _InsideCheckClock), patch(
            "lightup.activation.datetime", _OutsideCheckClock
        ):
            with self.assertRaises(PermissionError):
                _gate().issue(_target(), "synthetic-capability")


if __name__ == "__main__":
    unittest.main()
