from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import test_future_security_evidence_sufficiency_review_request as request_tests
import lightup.future_security_evidence_sufficiency_review_request_consumer as consumer


class FutureSecurityEvidenceSufficiencyReviewRequestConsumerFailFastTest(unittest.TestCase):
    def setUp(self):
        self.base = request_tests.FutureSecurityEvidenceSufficiencyReviewRequestTest(
            "test_live_metadata_review_becomes_bounded_independent_review_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.state = self.base.state

    def _producer(self, *, suffix: str):
        return self.base._request(suffix=suffix)

    def _consume(self, persisted: object, produced: tuple):
        (
            _,
            proposal,
            source_context,
            resolution,
            preview,
            report,
            plan,
            request,
            constraints,
            candidate_context,
            admission,
            review,
            _,
        ) = produced
        return consumer.load_and_validate_future_security_evidence_sufficiency_review_request(
            persisted,
            review,
            admission,
            constraints,
            candidate_context=candidate_context,
            request=request,
            plan=plan,
            report=report,
            preview=preview,
            proposal=proposal,
            resolutions=(resolution,),
            source_contexts=(source_context,),
            state=self.state,
        )

    def test_invalid_persisted_input_fails_before_live_validation(self):
        produced = self._producer(suffix="sufficiency-review-consumer-failfast")
        review_request = produced[-1]
        canonical = json.loads(review_request.to_json())

        schema_invalid = dict(canonical)
        schema_invalid["unexpected"] = "field"

        digest_invalid = dict(canonical)
        digest_invalid["sufficiency_request_sha256"] = "0" * 64

        cases = {
            "malformed-json": "{",
            "duplicate-key-json": '{"schema_version":"a","schema_version":"b"}',
            "non-object-json": "[]",
            "unsupported-runtime-type": 123,
            "strict-schema-rejection": schema_invalid,
            "strict-digest-rejection": digest_invalid,
        }

        def forbidden_live_validator(*args, **kwargs):
            self.fail("live sufficiency-review validator must not run for invalid persisted input")

        for name, persisted in cases.items():
            with self.subTest(name=name):
                with patch.object(
                    consumer,
                    "validate_future_security_evidence_sufficiency_review_request",
                    side_effect=forbidden_live_validator,
                ) as live_validator:
                    with self.assertRaises(ValueError):
                        self._consume(persisted, produced)
                    live_validator.assert_not_called()


if __name__ == "__main__":
    unittest.main()
