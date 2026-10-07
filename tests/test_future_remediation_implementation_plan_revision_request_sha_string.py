from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_revision_request_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_revision_request_handoff import (
    future_remediation_implementation_plan_revision_request_from_dict,
)


class _NonCanonicalShaThatLooksCanonical(str):
    def __len__(self):
        return 64

    def __iter__(self):
        return iter("a" * 64)


class _CanonicalShaSubclass(str):
    pass


_LINEAGE_SHA_FIELDS = (
    "review_sha256",
    "review_request_sha256",
    "plan_sha256",
    "implementation_request_sha256",
)


def _rebind_outer_digest(payload: dict) -> None:
    payload["revision_request_sha256"] = handoff_tests._request_digest(
        review_sha256=str(payload["review_sha256"]),
        review_request_sha256=str(payload["review_request_sha256"]),
        plan_sha256=str(payload["plan_sha256"]),
        implementation_request_sha256=str(
            payload["implementation_request_sha256"]
        ),
        reviewer_provider_id=str(payload["reviewer_provider_id"]),
        reviewer_model_id=str(payload["reviewer_model_id"]),
        required_revisions=tuple(payload["required_revisions"]),
    )


class FutureRemediationImplementationPlanRevisionRequestShaStringTest(
    unittest.TestCase
):
    def test_exact_builtin_sha_control_remains_accepted(self):
        request = handoff_tests._request()
        parsed = future_remediation_implementation_plan_revision_request_from_dict(
            request.as_dict()
        )

        self.assertEqual(parsed, request)
        for field in (*_LINEAGE_SHA_FIELDS, "revision_request_sha256"):
            self.assertIs(type(getattr(parsed, field)), str)
            self.assertEqual(len(getattr(parsed, field)), 64)

    def test_lineage_sha_string_subclasses_cannot_spoof_canonicality(self):
        for field in _LINEAGE_SHA_FIELDS:
            with self.subTest(field=field):
                request = handoff_tests._request()
                payload = request.as_dict()
                payload[field] = _NonCanonicalShaThatLooksCanonical(
                    "NOT-A-CANONICAL-SHA"
                )
                _rebind_outer_digest(payload)

                self.assertEqual(str(payload[field]), "NOT-A-CANONICAL-SHA")
                self.assertEqual(len(payload[field]), 64)
                self.assertEqual("".join(payload[field]), "a" * 64)

                with self.assertRaisesRegex(
                    ValueError,
                    "exact built-in string",
                ):
                    future_remediation_implementation_plan_revision_request_from_dict(
                        payload
                    )

    def test_outer_revision_request_digest_must_be_exact_builtin_string(self):
        request = handoff_tests._request()
        payload = request.as_dict()
        payload["revision_request_sha256"] = _CanonicalShaSubclass(
            payload["revision_request_sha256"]
        )

        self.assertIsNot(type(payload["revision_request_sha256"]), str)
        self.assertEqual(
            str(payload["revision_request_sha256"]),
            request.revision_request_sha256,
        )

        with self.assertRaisesRegex(ValueError, "exact built-in string"):
            future_remediation_implementation_plan_revision_request_from_dict(
                payload
            )


if __name__ == "__main__":
    unittest.main()
