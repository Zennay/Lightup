from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import test_future_security_evidence_sufficiency_attestation as attestation_tests
import lightup.future_security_evidence_sufficiency_attestation_consumer as consumer
from lightup.future_security_evidence_sufficiency_attestation import (
    EvidenceSufficiencyAttestationDisposition,
)


class FutureSecurityEvidenceSufficiencyAttestationConsumerFailFastTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = attestation_tests.FutureSecurityEvidenceSufficiencyAttestationTest(
            "test_all_dispositions_derive_exact_fail_closed_semantics"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _producer(self, *, suffix: str):
        return self.base._attest(
            EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_JUSTIFIED,
            suffix=suffix,
        )

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
            sufficiency_request,
            source_verifier,
            preflight,
            _,
        ) = produced
        return consumer.load_and_validate_future_security_evidence_sufficiency_attestation(
            persisted,
            preflight,
            sufficiency_request,
            review,
            admission,
            constraints,
            verifier=source_verifier,
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
        produced = self._producer(suffix="attestation-consumer-failfast")
        attestation = produced[-1]
        canonical = json.loads(attestation.to_json())

        schema_invalid = dict(canonical)
        schema_invalid["unexpected"] = "field"

        digest_invalid = dict(canonical)
        digest_invalid["attestation_sha256"] = "0" * 64

        cases = {
            "malformed-json": "{",
            "duplicate-key-json": '{"schema_version":"a","schema_version":"b"}',
            "non-object-json": "[]",
            "unsupported-runtime-type": 123,
            "strict-schema-rejection": schema_invalid,
            "strict-digest-rejection": digest_invalid,
        }

        def forbidden_live_validator(*args, **kwargs):
            self.fail(
                "live sufficiency-attestation validator must not run for invalid persisted input"
            )

        for name, persisted in cases.items():
            with self.subTest(name=name):
                with patch.object(
                    consumer,
                    "validate_future_security_evidence_sufficiency_attestation",
                    side_effect=forbidden_live_validator,
                ) as live_validator:
                    with self.assertRaises(ValueError):
                        self._consume(persisted, produced)
                    live_validator.assert_not_called()


if __name__ == "__main__":
    unittest.main()
