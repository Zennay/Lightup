from __future__ import annotations

import dataclasses
import unittest

import test_future_remediation_authoring_request as request_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_authoring_request import (
    FutureRemediationAuthoringRequest,
    validate_future_remediation_authoring_request,
)


class EqualitySpoofingAuthoringRequest(FutureRemediationAuthoringRequest):
    """Non-canonical runtime type that lies about equality with a live rebuild."""

    def __eq__(self, other: object) -> bool:
        return True

    def __ne__(self, other: object) -> bool:
        return False


class FutureRemediationAuthoringRequestLiveObjectIdentityTest(unittest.TestCase):
    def setUp(self):
        self.base = request_tests.FutureRemediationAuthoringRequestTest(
            "test_request_is_deterministic_and_export_is_bounded"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _request(self, classification, *, suffix: str):
        return self.base._request(classification, suffix=suffix)

    @staticmethod
    def _as_subclass(
        request: FutureRemediationAuthoringRequest,
        **overrides: object,
    ) -> EqualitySpoofingAuthoringRequest:
        values = {
            field.name: getattr(request, field.name)
            for field in dataclasses.fields(FutureRemediationAuthoringRequest)
        }
        values.update(overrides)
        return EqualitySpoofingAuthoringRequest(**values)

    def _validate(self, request: FutureRemediationAuthoringRequest, produced: tuple):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            bundle,
            _,
        ) = produced
        return validate_future_remediation_authoring_request(
            request,
            bundle,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )

    def test_exact_producer_request_remains_green(self):
        produced = self._request(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="authoring-live-object-exact",
        )
        request = produced[-1]

        self.assertIs(type(request), FutureRemediationAuthoringRequest)
        self.assertEqual(self._validate(request, produced), request)

    def test_equality_spoofing_request_subclass_fails_closed(self):
        produced = self._request(
            AttackPathTransitionClassification.WORSENED,
            suffix="authoring-live-object-subclass",
        )
        request = produced[-1]
        spoofed = self._as_subclass(request)
        before = tuple(
            (field.name, getattr(spoofed, field.name))
            for field in dataclasses.fields(FutureRemediationAuthoringRequest)
        )

        for _ in range(2):
            with self.assertRaisesRegex(
                ValueError,
                "request must be a FutureRemediationAuthoringRequest",
            ):
                self._validate(spoofed, produced)

        after = tuple(
            (field.name, getattr(spoofed, field.name))
            for field in dataclasses.fields(FutureRemediationAuthoringRequest)
        )
        self.assertEqual(after, before)

    def test_equality_spoof_cannot_hide_widened_execution_authority(self):
        produced = self._request(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="authoring-live-object-authority",
        )
        request = produced[-1]
        spoofed = self._as_subclass(request, execution_allowed=True)

        self.assertTrue(spoofed.execution_allowed)
        self.assertEqual(spoofed, request)
        self.assertFalse(spoofed != request)

        with self.assertRaisesRegex(
            ValueError,
            "request must be a FutureRemediationAuthoringRequest",
        ):
            self._validate(spoofed, produced)


if __name__ == "__main__":
    unittest.main()
