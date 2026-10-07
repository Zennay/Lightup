from __future__ import annotations

import unittest

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy


class _MatchingCapability(str):
    pass


class _EqualitySpoofCapability:
    def __eq__(self, other: object) -> bool:
        return other == "web-baseline"


class LegacyActivationCapabilityIdentityAcceptanceTest(unittest.TestCase):
    @staticmethod
    def _gate() -> ActivationGate:
        return ActivationGate(
            ScopePolicy(),
            ActivationPolicy(
                mode=ActivationMode.AUTHORIZED,
                activation_reference="ACT-726",
            ),
        )

    @staticmethod
    def _target() -> Target:
        return Target(
            "127.0.0.1",
            authorization=Authorization(
                owner="client-owner",
                reference="AUTH-726",
                assets=("127.0.0.1",),
                capabilities=("web-baseline",),
            ),
        )

    def test_exact_builtin_allowlisted_capability_is_preserved(self):
        permit = self._gate().issue(self._target(), "web-baseline")

        self.assertIs(type(permit.capability_id), str)
        self.assertEqual(permit.capability_id, "web-baseline")

    def test_matching_text_string_subclass_fails_closed(self):
        capability_id = _MatchingCapability("web-baseline")

        with self.assertRaises((TypeError, ValueError, PermissionError)):
            self._gate().issue(self._target(), capability_id)

    def test_non_string_equality_spoof_fails_closed(self):
        capability_id = _EqualitySpoofCapability()

        with self.assertRaises((TypeError, ValueError, PermissionError)):
            self._gate().issue(self._target(), capability_id)  # type: ignore[arg-type]

    def test_plain_foreign_builtin_string_remains_denied(self):
        with self.assertRaises(PermissionError):
            self._gate().issue(self._target(), "api-baseline")


if __name__ == "__main__":
    unittest.main()
