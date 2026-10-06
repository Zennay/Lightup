from __future__ import annotations

import copy
import json
import unittest

import test_future_security_evidence_freshness as freshness_tests
from lightup.future_security_evidence_freshness import (
    future_security_evidence_freshness_constraints_from_dict,
)


class FutureSecurityEvidenceFreshnessHandoffTest(unittest.TestCase):
    def setUp(self):
        self.base = freshness_tests.FutureSecurityEvidenceFreshnessConstraintsTest(
            "test_live_gap_binds_prior_evidence_and_run_as_forbidden"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _payload(self):
        *_, constraints = self.base._constraints(suffix="freshness-handoff")
        return constraints, json.loads(constraints.to_json())

    def test_round_trip_restores_exact_typed_constraints(self):
        constraints, payload = self._payload()
        restored = future_security_evidence_freshness_constraints_from_dict(payload)
        self.assertEqual(restored, constraints)

    def test_extra_missing_and_malformed_schema_fields_fail_closed(self):
        _, payload = self._payload()

        extra = copy.deepcopy(payload)
        extra["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "payload schema mismatch"):
            future_security_evidence_freshness_constraints_from_dict(extra)

        missing = copy.deepcopy(payload)
        del missing["request_sha256"]
        with self.assertRaisesRegex(ValueError, "payload schema mismatch"):
            future_security_evidence_freshness_constraints_from_dict(missing)

        item_extra = copy.deepcopy(payload)
        item_extra["items"][0]["target"] = "127.0.0.1"
        with self.assertRaisesRegex(ValueError, "item schema mismatch"):
            future_security_evidence_freshness_constraints_from_dict(item_extra)

        evidence_extra = copy.deepcopy(payload)
        evidence_extra["items"][0]["prior_evidence"][0]["source"] = "hidden"
        with self.assertRaisesRegex(ValueError, "prior evidence schema mismatch"):
            future_security_evidence_freshness_constraints_from_dict(evidence_extra)

    def test_forbidden_evidence_and_run_sets_must_match_prior_fingerprints(self):
        _, payload = self._payload()

        evidence_ids = copy.deepcopy(payload)
        evidence_ids["items"][0]["forbidden_evidence_ids"] = ["different-evidence"]
        with self.assertRaisesRegex(ValueError, "must match prior evidence"):
            future_security_evidence_freshness_constraints_from_dict(evidence_ids)

        run_ids = copy.deepcopy(payload)
        run_ids["items"][0]["forbidden_run_ids"] = ["different-run"]
        with self.assertRaisesRegex(ValueError, "must match prior evidence"):
            future_security_evidence_freshness_constraints_from_dict(run_ids)

        capabilities = copy.deepcopy(payload)
        capabilities["items"][0]["prior_capability_ids"] = ["different-capability"]
        with self.assertRaisesRegex(ValueError, "capabilities must match prior evidence"):
            future_security_evidence_freshness_constraints_from_dict(capabilities)

    def test_safety_flags_and_digest_fail_closed(self):
        _, payload = self._payload()

        executable = copy.deepcopy(payload)
        executable["execution_allowed"] = True
        with self.assertRaisesRegex(ValueError, "execution_allowed must remain false"):
            future_security_evidence_freshness_constraints_from_dict(executable)

        selected = copy.deepcopy(payload)
        selected["items"][0]["capability_selected"] = True
        with self.assertRaisesRegex(ValueError, "cannot select a capability"):
            future_security_evidence_freshness_constraints_from_dict(selected)

        outcome = copy.deepcopy(payload)
        outcome["items"][0]["outcome_classification_selected"] = True
        with self.assertRaisesRegex(ValueError, "cannot select an outcome classification"):
            future_security_evidence_freshness_constraints_from_dict(outcome)

        digest = copy.deepcopy(payload)
        digest["constraints_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_security_evidence_freshness_constraints_from_dict(digest)

    def test_noncanonical_lineage_and_duplicate_prior_evidence_fail_closed(self):
        _, payload = self._payload()

        unsorted = copy.deepcopy(payload)
        unsorted["items"][0]["effect_ids"].append("000-artificial")
        with self.assertRaisesRegex(ValueError, "sorted and unique"):
            future_security_evidence_freshness_constraints_from_dict(unsorted)

        duplicate = copy.deepcopy(payload)
        duplicate["items"][0]["prior_evidence"].append(
            copy.deepcopy(duplicate["items"][0]["prior_evidence"][0])
        )
        duplicate["items"][0]["forbidden_evidence_ids"].append(
            duplicate["items"][0]["forbidden_evidence_ids"][0]
        )
        with self.assertRaisesRegex(ValueError, "sorted and unique|IDs must be unique"):
            future_security_evidence_freshness_constraints_from_dict(duplicate)

        nonlist = copy.deepcopy(payload)
        nonlist["items"][0]["current_attack_path_ids"] = None
        with self.assertRaisesRegex(ValueError, "must be a string list"):
            future_security_evidence_freshness_constraints_from_dict(nonlist)

    def test_duplicate_item_identity_and_bad_primitive_types_fail_closed(self):
        _, payload = self._payload()

        duplicate = copy.deepcopy(payload)
        duplicate["items"].append(copy.deepcopy(duplicate["items"][0]))
        duplicate["freshness_item_count"] = 2
        with self.assertRaisesRegex(ValueError, "identities must be unique"):
            future_security_evidence_freshness_constraints_from_dict(duplicate)

        bool_version = copy.deepcopy(payload)
        bool_version["current_twin_version"] = True
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            future_security_evidence_freshness_constraints_from_dict(bool_version)

        bad_sha = copy.deepcopy(payload)
        bad_sha["items"][0]["prior_evidence"][0]["sha256"] = "A" * 64
        with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
            future_security_evidence_freshness_constraints_from_dict(bad_sha)


if __name__ == "__main__":
    unittest.main()
