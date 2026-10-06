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


_AUTHORITY_FLAGS = (
    "classification_selected",
    "transition_resolution_created",
    "collection_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "remediation_authoring_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


class FutureSecurityEvidenceRemediationParserRejectionInputPurityTest(
    unittest.TestCase
):
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
            suffix="parser-rejection-input-purity",
        )
        return (
            (
                "evidence_collection_request",
                values[7],
                future_security_evidence_collection_request_from_dict,
                "request_sha256",
            ),
            (
                "freshness_constraints",
                values[8],
                future_security_evidence_freshness_constraints_from_dict,
                "constraints_sha256",
            ),
            (
                "freshness_admission",
                values[10],
                future_security_evidence_freshness_admission_from_dict,
                "admission_sha256",
            ),
            (
                "evidence_sufficiency_attestation",
                values[15],
                future_security_evidence_sufficiency_attestation_from_dict,
                "attestation_sha256",
            ),
            (
                "classification_review_request",
                values[16],
                future_security_classification_review_request_from_dict,
                "classification_review_request_sha256",
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

    @staticmethod
    def _ordered_json(value):
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=False,
        )

    def _assert_stop_line_unchanged(self, payload, name):
        for field in _AUTHORITY_FLAGS:
            if field in payload:
                self.assertIs(payload[field], False, f"{name}.{field}")
        if "future_semantics" in payload:
            self.assertEqual(payload["future_semantics"], "unresolved", name)
        if "security_verdict" in payload:
            self.assertEqual(payload["security_verdict"], "not_evaluated", name)

    def _assert_rejection_is_input_pure(self, name, payload, parser):
        before = copy.deepcopy(payload)
        json_before = self._ordered_json(payload)
        identities_before = self._container_identities(payload)
        self._assert_stop_line_unchanged(payload, name)

        messages = []
        for attempt in range(2):
            with self.subTest(stage=name, attempt=attempt + 1):
                with self.assertRaises(ValueError) as raised:
                    parser(payload)
                messages.append(str(raised.exception))
                self.assertEqual(payload, before, name)
                self.assertEqual(self._ordered_json(payload), json_before, name)
                self.assertEqual(
                    self._container_identities(payload),
                    identities_before,
                    name,
                )
                self._assert_stop_line_unchanged(payload, name)

        self.assertEqual(messages[0], messages[1], name)

    def test_schema_rejections_leave_caller_owned_payloads_untouched(self):
        for name, artifact, parser, _digest_field in self._artifacts():
            payload = json.loads(artifact.to_json())
            payload["unexpected"] = "schema-widening-must-fail"
            with self.subTest(stage=name):
                self._assert_rejection_is_input_pure(
                    f"{name}.schema",
                    payload,
                    parser,
                )

    def test_digest_rejections_leave_caller_owned_payloads_untouched(self):
        for name, artifact, parser, digest_field in self._artifacts():
            payload = json.loads(artifact.to_json())
            current = payload[digest_field]
            payload[digest_field] = (
                "0" * 64 if current != "0" * 64 else "f" * 64
            )
            with self.subTest(stage=name):
                self._assert_rejection_is_input_pure(
                    f"{name}.digest",
                    payload,
                    parser,
                )


if __name__ == "__main__":
    unittest.main()
