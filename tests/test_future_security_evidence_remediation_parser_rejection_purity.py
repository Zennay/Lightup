from __future__ import annotations

import copy
import json
import unittest

import test_future_security_classification_review_request as request_tests
from lightup.future_security_classification_review_request_handoff import (
    future_security_classification_review_request_from_dict,
)
from lightup.future_security_evidence_collection_request import (
    future_security_evidence_collection_request_from_dict,
)
from lightup.future_security_evidence_freshness import (
    future_security_evidence_freshness_constraints_from_dict,
)
from lightup.future_security_evidence_freshness_admission_handoff import (
    future_security_evidence_freshness_admission_from_dict,
)
from lightup.future_security_evidence_sufficiency_attestation import (
    EvidenceSufficiencyAttestationDisposition,
)
from lightup.future_security_evidence_sufficiency_attestation_handoff import (
    future_security_evidence_sufficiency_attestation_from_dict,
)


class FutureSecurityEvidenceRemediationParserRejectionPurityTest(unittest.TestCase):
    def setUp(self):
        self.base = request_tests.FutureSecurityClassificationReviewRequestTest(
            "test_positive_attestation_creates_bounded_deterministic_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _artifacts(self):
        values = self.base._build(
            disposition=(
                EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_JUSTIFIED
            ),
            suffix="parser-rejection-purity",
        )
        return (
            (
                "evidence_collection_request",
                values[7],
                future_security_evidence_collection_request_from_dict,
            ),
            (
                "freshness_constraints",
                values[8],
                future_security_evidence_freshness_constraints_from_dict,
            ),
            (
                "freshness_admission",
                values[10],
                future_security_evidence_freshness_admission_from_dict,
            ),
            (
                "evidence_sufficiency_attestation",
                values[15],
                future_security_evidence_sufficiency_attestation_from_dict,
            ),
            (
                "classification_review_request",
                values[16],
                future_security_classification_review_request_from_dict,
            ),
        )

    @classmethod
    def _container_identities(cls, value, path="$"):
        identities = {}
        if isinstance(value, dict):
            identities[path] = id(value)
            for key, nested in value.items():
                identities.update(
                    cls._container_identities(nested, f"{path}.{key}")
                )
        elif isinstance(value, list):
            identities[path] = id(value)
            for index, nested in enumerate(value):
                identities.update(
                    cls._container_identities(nested, f"{path}[{index}]")
                )
        return identities

    def _assert_rejection_is_input_pure(self, name, payload, parser):
        before = copy.deepcopy(payload)
        identities_before = self._container_identities(payload)
        json_before = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=False,
        )

        for attempt in range(2):
            with self.subTest(stage=name, attempt=attempt + 1):
                with self.assertRaises(ValueError):
                    parser(payload)
                self.assertEqual(payload, before, name)
                self.assertEqual(
                    self._container_identities(payload),
                    identities_before,
                    name,
                )
                self.assertEqual(
                    json.dumps(
                        payload,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=False,
                    ),
                    json_before,
                    name,
                )

    @staticmethod
    def _flip_sha256(value):
        if not isinstance(value, str) or len(value) != 64:
            raise AssertionError("expected canonical SHA-256 test fixture")
        replacement = "0" if value[0] != "0" else "1"
        return replacement + value[1:]

    def test_schema_rejection_does_not_mutate_caller_owned_payload(self):
        for name, artifact, parser in self._artifacts():
            with self.subTest(stage=name):
                payload = json.loads(artifact.to_json())
                payload["unexpected_failure_path_probe"] = True
                self._assert_rejection_is_input_pure(name, payload, parser)

    def test_digest_rejection_does_not_mutate_caller_owned_payload(self):
        for name, artifact, parser in self._artifacts():
            with self.subTest(stage=name):
                payload = json.loads(artifact.to_json())
                digest_keys = [
                    key
                    for key, value in payload.items()
                    if key.endswith("_sha256")
                    and isinstance(value, str)
                    and len(value) == 64
                ]
                self.assertTrue(digest_keys, name)

                for key in digest_keys:
                    payload[key] = self._flip_sha256(payload[key])

                self._assert_rejection_is_input_pure(name, payload, parser)


if __name__ == "__main__":
    unittest.main()
