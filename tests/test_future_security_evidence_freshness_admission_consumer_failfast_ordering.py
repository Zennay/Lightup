from __future__ import annotations

import json
import unittest
from unittest import mock

import test_future_security_evidence_freshness_admission_consumer as consumer_tests
import lightup.future_security_evidence_freshness_admission_consumer as consumer_module


class FutureSecurityEvidenceFreshnessAdmissionConsumerFailFastOrderingTest(unittest.TestCase):
    def setUp(self):
        self.base = consumer_tests.FutureSecurityEvidenceFreshnessAdmissionConsumerTest(
            "test_real_producer_json_is_strictly_parsed_and_live_validated"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _producer(self, *, suffix: str):
        return self.base._producer(suffix=suffix)

    def _assert_rejected_before_live_validation(
        self,
        persisted: object,
        produced: tuple,
        *,
        pattern: str | None = None,
    ) -> None:
        with mock.patch.object(
            consumer_module,
            "validate_future_security_evidence_freshness_admission",
            side_effect=AssertionError("live admission validator must not run"),
        ) as validator:
            if pattern is None:
                with self.assertRaises(ValueError):
                    self.base._consume(persisted, produced)
            else:
                with self.assertRaisesRegex(ValueError, pattern):
                    self.base._consume(persisted, produced)

        validator.assert_not_called()

    def test_outer_persisted_rejections_precede_live_validation(self):
        produced = self._producer(suffix="admission-consumer-failfast-outer")
        cases = (
            ("{", "persisted JSON is invalid"),
            ('{"schema_version":"a","schema_version":"b"}', "duplicate object keys"),
            ("[]", "persisted payload must be an object"),
            (123, "persisted value must be JSON text or object"),
        )
        for persisted, pattern in cases:
            with self.subTest(pattern=pattern):
                self._assert_rejected_before_live_validation(
                    persisted,
                    produced,
                    pattern=pattern,
                )

    def test_strict_schema_rejection_precedes_live_validation(self):
        produced = self._producer(suffix="admission-consumer-failfast-schema")
        payload = json.loads(produced[-1].to_json())
        payload["unexpected_field"] = "must-fail-before-live-validation"
        self._assert_rejected_before_live_validation(payload, produced)

    def test_strict_digest_rejection_precedes_live_validation(self):
        produced = self._producer(suffix="admission-consumer-failfast-digest")
        payload = json.loads(produced[-1].to_json())
        payload["admission_sha256"] = "0" * 64
        self._assert_rejected_before_live_validation(
            payload,
            produced,
            pattern="digest mismatch",
        )


if __name__ == "__main__":
    unittest.main()
