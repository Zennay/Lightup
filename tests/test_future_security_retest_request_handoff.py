from __future__ import annotations

import copy
import json
import unittest

import test_future_security_retest_request as request_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_retest_request_handoff import (
    future_security_retest_request_from_dict,
    future_security_retest_request_from_json,
    validate_future_security_retest_request_handoff,
)


class FutureSecurityRetestRequestHandoffTest(unittest.TestCase):
    def setUp(self):
        self.r = request_tests.FutureSecurityRetestRequestTest(
            "test_request_is_deterministic_lineage_bound_and_read_only"
        )
        self.r.setUp()
        self.addCleanup(self.r.tearDown)
        self.state = self.r.state

    def _request(self, classification, *, suffix):
        return self.r._request(classification, suffix=suffix)

    def test_round_trip_accepts_exact_builder_output_for_all_supported_classifications(self):
        for classification in (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
            AttackPathTransitionClassification.IMPROVED,
            AttackPathTransitionClassification.REMOVED,
        ):
            with self.subTest(classification=classification.value):
                *_, request = self._request(
                    classification,
                    suffix=f"retest-handoff-{classification.value}",
                )
                parsed = future_security_retest_request_from_json(request.to_json())
                self.assertEqual(parsed, request)
                self.assertTrue(parsed.request_complete)
                self.assertTrue(parsed.isolated_future_state_required)
                self.assertFalse(parsed.execution_allowed)
                self.assertFalse(parsed.target_interaction_allowed)
                self.assertFalse(parsed.deployment_authorized)
                self.assertFalse(parsed.attack_path_mutation_allowed)
                self.assertEqual(parsed.future_semantics, "unresolved")
                self.assertEqual(parsed.security_verdict, "not_evaluated")

    def test_exact_schema_strict_primitives_and_stop_line_fail_closed(self):
        *_, request = self._request(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="retest-handoff-schema",
        )
        payload = json.loads(request.to_json())

        extra = copy.deepcopy(payload)
        extra["unexpected"] = False
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_security_retest_request_from_dict(extra)

        missing = copy.deepcopy(payload)
        missing.pop("security_verdict")
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_security_retest_request_from_dict(missing)

        bool_as_int = copy.deepcopy(payload)
        bool_as_int["current_twin_version"] = True
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            future_security_retest_request_from_dict(bool_as_int)

        for field, value in (
            ("request_complete", False),
            ("isolated_future_state_required", False),
            ("execution_allowed", 0),
            ("target_interaction_allowed", True),
            ("deployment_authorized", True),
            ("attack_path_mutation_allowed", True),
        ):
            with self.subTest(field=field):
                forged = copy.deepcopy(payload)
                forged[field] = value
                with self.assertRaises(ValueError):
                    future_security_retest_request_from_dict(forged)

        resolved = copy.deepcopy(payload)
        resolved["future_semantics"] = "resolved"
        with self.assertRaisesRegex(ValueError, "future semantics"):
            future_security_retest_request_from_dict(resolved)

        verdict = copy.deepcopy(payload)
        verdict["security_verdict"] = "secure"
        with self.assertRaisesRegex(ValueError, "security verdict"):
            future_security_retest_request_from_dict(verdict)

    def test_item_semantics_and_aggregate_lineage_fail_closed(self):
        *_, request = self._request(
            AttackPathTransitionClassification.WORSENED,
            suffix="retest-handoff-semantics",
        )
        payload = json.loads(request.to_json())

        graph_action = copy.deepcopy(payload)
        graph_action["items"][0]["graph_diff_action"] = "modify_existing_path_risk_down"
        with self.assertRaisesRegex(ValueError, "semantics mismatch"):
            future_security_retest_request_from_dict(graph_action)

        purpose = copy.deepcopy(payload)
        purpose["items"][0]["purpose"] = "improvement_verification"
        with self.assertRaisesRegex(ValueError, "semantics mismatch"):
            future_security_retest_request_from_dict(purpose)

        remediation = copy.deepcopy(payload)
        remediation["items"][0]["remediation_required"] = False
        with self.assertRaisesRegex(ValueError, "semantics mismatch"):
            future_security_retest_request_from_dict(remediation)

        unsupported = copy.deepcopy(payload)
        unsupported["items"][0]["classification"] = "insufficient_evidence"
        with self.assertRaisesRegex(ValueError, "cannot produce a retest"):
            future_security_retest_request_from_dict(unsupported)

        duplicate_item = copy.deepcopy(payload)
        duplicate_item["items"].append(copy.deepcopy(duplicate_item["items"][0]))
        with self.assertRaisesRegex(ValueError, "identity must be unique"):
            future_security_retest_request_from_dict(duplicate_item)

        forged_capabilities = copy.deepcopy(payload)
        forged_capabilities["requested_capability_ids"] = ["forged-capability"]
        with self.assertRaisesRegex(ValueError, "do not match item lineage"):
            future_security_retest_request_from_dict(forged_capabilities)

        forged_evidence = copy.deepcopy(payload)
        forged_evidence["evidence_ids"] = ["forged-evidence"]
        with self.assertRaisesRegex(ValueError, "do not match item lineage"):
            future_security_retest_request_from_dict(forged_evidence)

        duplicate_capability = copy.deepcopy(payload)
        duplicate_capability["requested_capability_ids"].append(
            duplicate_capability["requested_capability_ids"][0]
        )
        with self.assertRaisesRegex(ValueError, "must not contain duplicates"):
            future_security_retest_request_from_dict(duplicate_capability)

    def test_digest_sha_and_duplicate_json_keys_are_verified(self):
        *_, request = self._request(
            AttackPathTransitionClassification.IMPROVED,
            suffix="retest-handoff-digest",
        )
        payload = json.loads(request.to_json())

        bad_sha = copy.deepcopy(payload)
        bad_sha["remediation_plan_sha256"] = "A" * 64
        with self.assertRaisesRegex(ValueError, "canonical SHA-256"):
            future_security_retest_request_from_dict(bad_sha)

        stale_digest = copy.deepcopy(payload)
        stale_digest["request_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_security_retest_request_from_dict(stale_digest)

        raw = request.to_json()
        duplicated = raw[:-1] + ',"request_complete":true}'
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_security_retest_request_from_json(duplicated)

    def test_parsed_request_requires_exact_live_rebuilt_lineage(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
        ) = self._request(
            AttackPathTransitionClassification.REMOVED,
            suffix="retest-handoff-live",
        )
        parsed = future_security_retest_request_from_json(request.to_json())
        validated = validate_future_security_retest_request_handoff(
            parsed,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        self.assertEqual(validated, request)

        (
            _,
            other_proposal,
            other_context,
            other_resolution,
            other_preview,
            other_report,
            other_plan,
            _,
        ) = self._request(
            AttackPathTransitionClassification.REMOVED,
            suffix="retest-handoff-live-other",
        )
        with self.assertRaisesRegex(ValueError, "does not match its live validated lineage"):
            validate_future_security_retest_request_handoff(
                parsed,
                other_plan,
                other_report,
                other_preview,
                other_proposal,
                (other_resolution,),
                (other_context,),
                self.state,
            )


if __name__ == "__main__":
    unittest.main()
