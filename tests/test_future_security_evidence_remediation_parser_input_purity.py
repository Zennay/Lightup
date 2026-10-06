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


class FutureSecurityEvidenceRemediationParserInputPurityTest(unittest.TestCase):
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
            suffix="parser-input-purity",
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

    def _assert_parser_is_input_pure(self, name, artifact, parser):
        payload = json.loads(artifact.to_json())
        before = copy.deepcopy(payload)
        json_before = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=False,
        )
        identities_before = self._container_identities(payload)

        first = parser(payload)
        self.assertEqual(first, artifact, name)
        self.assertEqual(payload, before, name)
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
        self.assertEqual(
            self._container_identities(payload),
            identities_before,
            name,
        )

        second = parser(payload)
        self.assertEqual(second, artifact, name)
        self.assertEqual(second, first, name)
        self.assertEqual(payload, before, name)
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
        self.assertEqual(
            self._container_identities(payload),
            identities_before,
            name,
        )

        for field in (
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
        ):
            if hasattr(first, field):
                self.assertIs(getattr(first, field), False, f"{name}.{field}")

        if hasattr(first, "future_semantics"):
            self.assertEqual(first.future_semantics, "unresolved", name)
        if hasattr(first, "security_verdict"):
            self.assertEqual(first.security_verdict, "not_evaluated", name)

    def test_strict_evidence_remediation_parsers_do_not_mutate_inputs(self):
        for name, artifact, parser in self._artifacts():
            with self.subTest(stage=name):
                self._assert_parser_is_input_pure(name, artifact, parser)


if __name__ == "__main__":
    unittest.main()
