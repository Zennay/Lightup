from __future__ import annotations

import copy
import json
import unittest

import test_future_security_evidence_freshness_admission as admission_tests
from lightup.future_security_evidence_freshness_admission import (
    validate_future_security_evidence_freshness_admission,
)
from lightup.future_security_evidence_freshness_admission_handoff import (
    future_security_evidence_freshness_admission_from_dict,
)


class FutureSecurityEvidenceFreshnessAdmissionHandoffTest(unittest.TestCase):
    def setUp(self):
        self.base = admission_tests.FutureSecurityEvidenceFreshnessAdmissionTest(
            "test_fresh_new_run_evidence_passes_without_security_classification"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _payload(self):
        *_, admission = self.base._admission(suffix="admission-handoff")
        return admission, json.loads(admission.to_json())

    def test_round_trip_restores_exact_typed_admission(self):
        admission, payload = self._payload()
        restored = future_security_evidence_freshness_admission_from_dict(payload)
        self.assertEqual(restored, admission)

    def test_extra_missing_and_malformed_schema_fields_fail_closed(self):
        _, payload = self._payload()

        extra = copy.deepcopy(payload)
        extra["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "payload schema mismatch"):
            future_security_evidence_freshness_admission_from_dict(extra)

        missing = copy.deepcopy(payload)
        del missing["constraints_sha256"]
        with self.assertRaisesRegex(ValueError, "payload schema mismatch"):
            future_security_evidence_freshness_admission_from_dict(missing)

        evidence_extra = copy.deepcopy(payload)
        evidence_extra["candidate_evidence"][0]["source"] = "test://hidden"
        with self.assertRaisesRegex(ValueError, "candidate evidence schema mismatch"):
            future_security_evidence_freshness_admission_from_dict(evidence_extra)

        bool_version = copy.deepcopy(payload)
        bool_version["current_twin_version"] = True
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            future_security_evidence_freshness_admission_from_dict(bool_version)

    def test_candidate_evidence_identity_run_and_capability_drift_fail_closed(self):
        _, payload = self._payload()

        ids = copy.deepcopy(payload)
        ids["candidate_evidence_ids"] = ["different-evidence"]
        with self.assertRaisesRegex(ValueError, "must match fingerprints"):
            future_security_evidence_freshness_admission_from_dict(ids)

        run = copy.deepcopy(payload)
        run["candidate_evidence"][0]["run_id"] = "different-run"
        with self.assertRaisesRegex(ValueError, "must match candidate_run_id"):
            future_security_evidence_freshness_admission_from_dict(run)

        capabilities = copy.deepcopy(payload)
        capabilities["candidate_capability_ids"] = ["different-capability"]
        with self.assertRaisesRegex(ValueError, "capabilities must match fingerprints"):
            future_security_evidence_freshness_admission_from_dict(capabilities)

    def test_candidate_evidence_order_and_duplicates_fail_closed(self):
        _, payload = self._payload()
        original = copy.deepcopy(payload["candidate_evidence"][0])

        duplicate = copy.deepcopy(payload)
        duplicate["candidate_evidence"].append(copy.deepcopy(original))
        duplicate["candidate_evidence_ids"].append(original["evidence_id"])
        with self.assertRaisesRegex(
            ValueError,
            "sorted and unique|IDs must be unique",
        ):
            future_security_evidence_freshness_admission_from_dict(duplicate)

        noncanonical = copy.deepcopy(payload)
        second = copy.deepcopy(original)
        second["evidence_id"] = "000-" + original["evidence_id"]
        noncanonical["candidate_evidence"].append(second)
        noncanonical["candidate_evidence_ids"] = sorted(
            [original["evidence_id"], second["evidence_id"]]
        )
        with self.assertRaisesRegex(ValueError, "canonically ordered"):
            future_security_evidence_freshness_admission_from_dict(noncanonical)

    def test_parsed_admission_still_requires_live_validation(self):
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
            evidence_id,
            admission,
        ) = self.base._admission(suffix="admission-handoff-live-gate")
        restored = future_security_evidence_freshness_admission_from_dict(
            json.loads(admission.to_json())
        )
        self.assertEqual(restored, admission)

        with self.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                ("0" * 64, evidence_id),
            )

        with self.assertRaisesRegex(ValueError, "live validated evidence"):
            validate_future_security_evidence_freshness_admission(
                restored,
                constraints,
                candidate_context=candidate_context,
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.base.state,
            )

    def test_safety_semantics_and_digest_fail_closed(self):
        _, payload = self._payload()

        executable = copy.deepcopy(payload)
        executable["execution_allowed"] = True
        with self.assertRaisesRegex(ValueError, "execution_allowed must remain false"):
            future_security_evidence_freshness_admission_from_dict(executable)

        classified = copy.deepcopy(payload)
        classified["classification_selected"] = True
        with self.assertRaisesRegex(ValueError, "classification_selected must remain false"):
            future_security_evidence_freshness_admission_from_dict(classified)

        suitability = copy.deepcopy(payload)
        suitability["evidence_suitability_evaluated"] = True
        with self.assertRaisesRegex(
            ValueError,
            "evidence_suitability_evaluated must remain false",
        ):
            future_security_evidence_freshness_admission_from_dict(suitability)

        freshness = copy.deepcopy(payload)
        freshness["freshness_check_passed"] = False
        with self.assertRaisesRegex(ValueError, "must retain a passed freshness check"):
            future_security_evidence_freshness_admission_from_dict(freshness)

        verdict = copy.deepcopy(payload)
        verdict["security_verdict"] = "secure"
        with self.assertRaisesRegex(ValueError, "must not claim a security verdict"):
            future_security_evidence_freshness_admission_from_dict(verdict)

        digest = copy.deepcopy(payload)
        digest["admission_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_security_evidence_freshness_admission_from_dict(digest)


if __name__ == "__main__":
    unittest.main()
