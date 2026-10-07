from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import test_future_security_evidence_freshness as freshness_tests
import lightup.future_security_evidence_freshness_constraints_consumer as consumer


class FutureSecurityEvidenceFreshnessConstraintsConsumerFailFastTest(unittest.TestCase):
    def setUp(self):
        self.base = freshness_tests.FutureSecurityEvidenceFreshnessConstraintsTest(
            "test_live_gap_binds_prior_evidence_and_run_as_forbidden"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _producer(self, *, suffix: str):
        return self.base._constraints(suffix=suffix)

    def _consume(self, persisted: object, produced: tuple):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            _,
        ) = produced
        return consumer.load_and_validate_future_security_evidence_freshness_constraints(
            persisted,
            request,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )

    def test_invalid_persisted_input_fails_before_live_validation(self):
        produced = self._producer(suffix="constraints-consumer-failfast")
        constraints = produced[-1]
        canonical = json.loads(constraints.to_json())

        schema_invalid = dict(canonical)
        schema_invalid["unexpected"] = "field"

        digest_invalid = dict(canonical)
        digest_invalid["constraints_sha256"] = "0" * 64

        cases = {
            "malformed-json": "{",
            "duplicate-key-json": '{"schema_version":"a","schema_version":"b"}',
            "non-object-json": "[]",
            "unsupported-runtime-type": 123,
            "strict-schema-rejection": schema_invalid,
            "strict-digest-rejection": digest_invalid,
        }

        def forbidden_live_validator(*args, **kwargs):
            self.fail("live freshness validator must not run for invalid persisted input")

        for name, persisted in cases.items():
            with self.subTest(name=name):
                with patch.object(
                    consumer,
                    "validate_future_security_evidence_freshness_constraints",
                    side_effect=forbidden_live_validator,
                ) as live_validator:
                    with self.assertRaises(ValueError):
                        self._consume(persisted, produced)
                    live_validator.assert_not_called()


if __name__ == "__main__":
    unittest.main()
