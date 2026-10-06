from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_authoring_request as request_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_authoring_request_handoff import (
    future_remediation_authoring_request_from_dict,
    future_remediation_authoring_request_from_json,
    load_and_validate_future_remediation_authoring_request,
)


class FutureRemediationAuthoringRequestHandoffTest(unittest.TestCase):
    def setUp(self):
        self.base = request_tests.FutureRemediationAuthoringRequestTest(
            "test_request_is_deterministic_and_export_is_bounded"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _request(self, classification, *, suffix: str):
        return self.base._request(classification, suffix=suffix)

    def _consume(self, persisted: object, produced: tuple):
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
        return load_and_validate_future_remediation_authoring_request(
            persisted,
            bundle,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )

    def test_real_request_round_trips_and_is_live_validated(self):
        for classification in (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
        ):
            with self.subTest(classification=classification.value):
                produced = self._request(
                    classification,
                    suffix=f"authoring-handoff-{classification.value}",
                )
                request = produced[-1]

                self.assertEqual(
                    future_remediation_authoring_request_from_json(
                        request.to_json()
                    ),
                    request,
                )
                self.assertEqual(
                    future_remediation_authoring_request_from_dict(
                        json.loads(request.to_json())
                    ),
                    request,
                )
                self.assertEqual(
                    self._consume(request.to_json(), produced),
                    request,
                )

    def test_malformed_duplicate_nonobject_and_schema_drift_fail_closed(self):
        produced = self._request(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="authoring-handoff-json",
        )
        request = produced[-1]

        with self.assertRaisesRegex(ValueError, "JSON is invalid"):
            future_remediation_authoring_request_from_json("{")

        with self.assertRaisesRegex(ValueError, "payload must be an object"):
            future_remediation_authoring_request_from_json("[]")

        duplicate_top = request.to_json()[:-1] + ',"request_sha256":"' + (
            "0" * 64
        ) + '"}'
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_authoring_request_from_json(duplicate_top)

        duplicate_nested = request.to_json().replace(
            '"requested_output":"remediation_text_proposal"',
            '"requested_output":"remediation_text_proposal","requested_output":"other"',
            1,
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_authoring_request_from_json(duplicate_nested)

        unknown = json.loads(request.to_json())
        unknown["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_authoring_request_from_dict(unknown)

    def test_type_confusion_and_authority_forgery_fail_closed(self):
        produced = self._request(
            AttackPathTransitionClassification.WORSENED,
            suffix="authoring-handoff-types",
        )
        payload = json.loads(produced[-1].to_json())

        bad_version = copy.deepcopy(payload)
        bad_version["current_twin_version"] = True
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            future_remediation_authoring_request_from_dict(bad_version)

        missing_authoring = copy.deepcopy(payload)
        missing_authoring["authoring_requested"] = False
        with self.assertRaisesRegex(ValueError, "must remain true"):
            future_remediation_authoring_request_from_dict(missing_authoring)

        positive_authority = copy.deepcopy(payload)
        positive_authority["code_change_authorized"] = True
        with self.assertRaisesRegex(ValueError, "must remain false"):
            future_remediation_authoring_request_from_dict(positive_authority)

        type_confused_authority = copy.deepcopy(payload)
        type_confused_authority["execution_allowed"] = 0
        with self.assertRaisesRegex(ValueError, "must remain false"):
            future_remediation_authoring_request_from_dict(type_confused_authority)

    def test_item_output_evidence_and_digest_semantics_fail_closed(self):
        produced = self._request(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="authoring-handoff-integrity",
        )
        payload = json.loads(produced[-1].to_json())

        wrong_output = copy.deepcopy(payload)
        wrong_output["items"][0]["requested_output"] = "apply_fix"
        with self.assertRaisesRegex(ValueError, "requested_output"):
            future_remediation_authoring_request_from_dict(wrong_output)

        wrong_classification = copy.deepcopy(payload)
        wrong_classification["items"][0]["classification"] = (
            AttackPathTransitionClassification.IMPROVED.value
        )
        with self.assertRaisesRegex(ValueError, "not authoring eligible"):
            future_remediation_authoring_request_from_dict(wrong_classification)

        duplicated_evidence = copy.deepcopy(payload)
        duplicated_evidence["items"][0]["evidence"].append(
            copy.deepcopy(duplicated_evidence["items"][0]["evidence"][0])
        )
        with self.assertRaisesRegex(ValueError, "evidence IDs must be unique"):
            future_remediation_authoring_request_from_dict(duplicated_evidence)

        outside_capability = copy.deepcopy(payload)
        outside_capability["items"][0]["evidence"][0]["capability_id"] = (
            "unexpected-capability"
        )
        with self.assertRaisesRegex(ValueError, "outside item lineage"):
            future_remediation_authoring_request_from_dict(outside_capability)

        manifest_drift = copy.deepcopy(payload)
        original = manifest_drift["items"][0]["evidence"][0]["sha256"]
        manifest_drift["items"][0]["evidence"][0]["sha256"] = (
            "f" * 64 if original != "f" * 64 else "e" * 64
        )
        with self.assertRaisesRegex(ValueError, "manifest digest mismatch"):
            future_remediation_authoring_request_from_dict(manifest_drift)

        request_drift = copy.deepcopy(payload)
        request_drift["request_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "request digest mismatch"):
            future_remediation_authoring_request_from_dict(request_drift)

    def test_live_ledger_drift_rejects_canonical_persisted_request(self):
        produced = self._request(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="authoring-handoff-live-drift",
        )
        request = produced[-1]
        bundle = produced[-2]
        evidence_id = bundle.items[0].evidence[0].evidence_id
        current_sha = bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64

        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaisesRegex(
            ValueError,
            "does not match its live validated lineage",
        ):
            self._consume(request.to_json(), produced)

    def test_non_json_object_types_fail_before_live_validation(self):
        produced = self._request(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="authoring-handoff-input-type",
        )
        with self.assertRaisesRegex(ValueError, "JSON text or object"):
            self._consume(123, produced)


if __name__ == "__main__":
    unittest.main()
