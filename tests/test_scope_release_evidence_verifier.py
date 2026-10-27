"""Offline denial regressions for the non-authoritative ST5 evidence verifier."""
import copy
import unittest

from tools.verify_scope_release_evidence import valid

SHA = "a" * 40
URL = "https://github.com/Zennay/Lightup/actions/runs/123"
PROOF = "https://github.com/Zennay/Lightup/pull/107"


def evidence():
    return {
        "integration_sha": SHA,
        "checks": {
            name: {"conclusion": "success", "trigger_sha": SHA, "run_url": URL, "runner": name}
            for name in ("hosted", "permanent_vps", "negative_regressions", "positive_controls")
        },
        "gates": {
            f"G{i}": {"outcome": "PASS", "proof_url": PROOF}
            for i in range(1, 11)
        },
        "author": "author-identity",
        "reviewer": "independent-reviewer",
        "decision": "APPROVE",
        "deployment_approved": True,
    }


class EvidenceGateTests(unittest.TestCase):
    def test_reference_complete_is_only_review_evidence(self):
        self.assertEqual(valid(evidence()), (True, []))

    def test_missing_vps_check_denied(self):
        record = evidence()
        del record["checks"]["permanent_vps"]
        self.assertFalse(valid(record)[0])

    def test_stale_green_sha_denied(self):
        record = evidence()
        record["checks"]["hosted"]["trigger_sha"] = "b" * 40
        self.assertFalse(valid(record)[0])

    def test_pending_denied(self):
        record = evidence()
        record["checks"]["permanent_vps"]["conclusion"] = "queued"
        self.assertFalse(valid(record)[0])

    def test_truthy_decisions_denied(self):
        for value in (1, True, "APPROVED", None):
            with self.subTest(value=value):
                record = evidence()
                record["decision"] = value
                self.assertFalse(valid(record)[0])

    def test_self_review_denied(self):
        record = evidence()
        record["reviewer"] = record["author"]
        self.assertFalse(valid(record)[0])

    def test_missing_gate_denied(self):
        record = evidence()
        del record["gates"]["G10"]
        self.assertFalse(valid(record)[0])

    def test_missing_proof_denied(self):
        record = evidence()
        record["gates"]["G4"]["proof_url"] = "UNVERIFIED"
        self.assertFalse(valid(record)[0])

    def test_deployment_boolean_identity(self):
        for value in (1, "true", False, None):
            with self.subTest(value=value):
                record = evidence()
                record["deployment_approved"] = value
                self.assertFalse(valid(record)[0])

    def test_malformed_and_unexpected_record_denied(self):
        for value in (None, [], {}, "approved"):
            with self.subTest(value=value):
                self.assertFalse(valid(value)[0])

    def test_ambiguous_extra_check_denied(self):
        record = evidence()
        record["checks"]["optional"] = record["checks"]["hosted"]
        self.assertFalse(valid(record)[0])


if __name__ == "__main__":
    unittest.main()
