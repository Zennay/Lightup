"""Offline real-Finding regressions for non-authorizing retest review."""
from __future__ import annotations

from copy import deepcopy
import unittest

from lightup.finding_retest_preflight import preflight_retest_transition
from lightup.models import Finding, RetestStatus, Severity


def before() -> Finding:
    return Finding(
        finding_id="finding-001",
        title="Missing strict transport security",
        severity=Severity.MEDIUM,
        target="https://lab.example.test",
        remediation="Configure and verify an HSTS policy.",
        evidence=["initial header observation"],
        retest_status=RetestStatus.FIX_PENDING,
        metadata={"session": "do-not-print-metadata"},
    )


def later() -> Finding:
    finding = before()
    finding.retest_status = RetestStatus.FIXED
    finding.evidence.append("independent retest header observation")
    return finding


class RetestPreflightTests(unittest.TestCase):
    def assert_blocked(self, candidate: Finding, code: str) -> None:
        result = preflight_retest_transition(before(), candidate)
        self.assertFalse(result.ready_for_independent_review)
        self.assertIn(code, result.reasons)
        self.assertFalse(result.externally_verified)
        self.assertFalse(result.remediation_authorized)
        self.assertFalse(result.release_authorized)

    def test_new_evidence_is_reviewable_but_not_verified(self):
        review = preflight_retest_transition(before(), later())
        self.assertTrue(review.ready_for_independent_review)
        self.assertEqual((), review.reasons)
        self.assertEqual(1, review.new_evidence_count)
        self.assertFalse(review.externally_verified)
        self.assertFalse(review.remediation_authorized)
        self.assertFalse(review.release_authorized)

    def test_unchanged_claim_is_not_new_retest_evidence(self):
        self.assert_blocked(before(), "no_new_evidence")

    def test_status_flip_alone_not_proof(self):
        candidate = before()
        candidate.retest_status = RetestStatus.FIXED
        self.assert_blocked(candidate, "no_new_evidence")

    def test_prior_evidence_disappearance_fails_closed(self):
        candidate = later()
        candidate.evidence = ["replacement only"]
        self.assert_blocked(candidate, "historical_evidence_removed")

    def test_identity_change_denied(self):
        candidate = later()
        candidate.finding_id = "finding-002"
        self.assert_blocked(candidate, "finding_identity_changed")

    def test_target_change_denied(self):
        candidate = later()
        candidate.target = "https://elsewhere.example.test"
        self.assert_blocked(candidate, "target_identity_changed")

    def test_severity_change_denied_for_same_transition(self):
        candidate = later()
        candidate.severity = Severity.INFO
        self.assert_blocked(candidate, "severity_changed")

    def test_title_change_requires_separate_review(self):
        candidate = later()
        candidate.title = "Different issue"
        self.assert_blocked(candidate, "title_changed")

    def test_duplicate_evidence_rejected(self):
        candidate = later()
        candidate.evidence.append(candidate.evidence[-1])
        self.assert_blocked(candidate, "invalid_finding_shape")

    def test_invalid_retest_enum_denied(self):
        candidate = later()
        candidate.retest_status = "fixed"
        self.assert_blocked(candidate, "invalid_finding_shape")

    def test_polymorphic_finding_rejected(self):
        class ForgedFinding(Finding):
            pass
        old = before()
        fabricated = ForgedFinding(**old.__dict__)
        review = preflight_retest_transition(fabricated, later())
        self.assertEqual(("invalid_finding_shape",), review.reasons)

    def test_polymorphic_evidence_rejected(self):
        candidate = later()
        candidate.evidence = tuple(candidate.evidence)
        self.assert_blocked(candidate, "invalid_finding_shape")

    def test_truthy_and_control_byte_evidence_rejected(self):
        for payload in ("next\nreview", " next", "next ", "\x00", 123, True, ""):
            with self.subTest(payload=repr(payload)):
                candidate = later()
                candidate.evidence = ["initial header observation", payload]
                self.assert_blocked(candidate, "invalid_finding_shape")

    def test_size_and_item_limits_denied(self):
        candidates = [
            ["initial header observation", "x" * 2049],
            ["initial header observation"] + [f"sample-{i}" for i in range(64)],
            ["initial header observation"] + [f"{i}-" + "\U0001f600" * 512 for i in range(33)],
        ]
        for evidence in candidates:
            with self.subTest(length=len(evidence)):
                candidate = later()
                candidate.evidence = evidence
                self.assert_blocked(candidate, "invalid_finding_shape")

    def test_unchanged_finding_objects_after_comparison(self):
        old, candidate = before(), later()
        snapshot = deepcopy((old, candidate))
        preflight_retest_transition(old, candidate)
        self.assertEqual((old, candidate), snapshot)

    def test_output_is_bounded_and_redacts_source_text(self):
        old, candidate = before(), later()
        candidate.target = "https://secret-host.invalid"
        candidate.metadata["session"] = "session-secret"
        result = preflight_retest_transition(old, candidate)
        serialized = repr(result.as_dict())
        self.assertNotIn("secret-host", serialized)
        self.assertNotIn("session-secret", serialized)
        self.assertNotIn("header observation", serialized)
        self.assertIn("target_identity_changed", serialized)

    def test_reviewability_independent_of_status_claim(self):
        for status in RetestStatus:
            with self.subTest(status=status):
                candidate = later()
                candidate.retest_status = status
                result = preflight_retest_transition(before(), candidate)
                self.assertTrue(result.ready_for_independent_review)
                self.assertFalse(result.externally_verified)

    def test_new_evidence_count_does_not_reveal_content(self):
        candidate = later()
        candidate.evidence.append("second distinct observation")
        result = preflight_retest_transition(before(), candidate)
        self.assertEqual(2, result.new_evidence_count)
        self.assertEqual([], result.as_dict()["reasons"])

    def test_unicode_format_control_and_surrogate_fail_closed(self):
        for entry in ("redacted\\u202eTXET", "value\\ud800", "proof\\u200dencoded"):
            with self.subTest(entry=ascii(entry)):
                candidate = later()
                candidate.evidence[-1] = entry
                self.assert_blocked(candidate, "invalid_finding_shape")

    def test_invalid_source_text_does_not_escape_via_error(self):
        candidate = later()
        candidate.target = "https://valid.example.test\\ud800"
        review = preflight_retest_transition(before(), candidate)
        self.assertEqual(("invalid_finding_shape",), review.reasons)

    def test_no_network_or_authority_embedded(self):
        result = preflight_retest_transition(before(), later())
        self.assertEqual(
            {"ready_for_independent_review", "reasons", "new_evidence_count",
             "externally_verified", "remediation_authorized", "release_authorized"},
            set(result.as_dict()),
        )


if __name__ == "__main__":
    unittest.main()
