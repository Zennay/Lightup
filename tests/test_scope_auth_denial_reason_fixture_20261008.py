"""Offline fixture checks for the denial-reason diagnostic boundary.

This checks a review matrix, not production authorization enforcement.
No networking, target calls, executor imports or external dependencies.
"""
import unittest

CASES = (
    ("missing_reason", False, None, False),
    ("unknown_reason", False, "new_reason_code", False),
    ("localized_reason", False, "autorisation refusée", False),
    ("malformed_reason", False, {"allowed": True}, False),
    ("revoked_grant", False, "grant_revoked", False),
    ("expired_grant", False, "grant_expired", False),
    ("narrowed_scope", False, "out_of_scope", False),
    ("stale_replay", False, "previously_allowed", False),
    ("current_exact_grant_control", True, "explicit_host", True),
)

class DenialReasonFixtureTests(unittest.TestCase):
    def test_unique_complete_cases(self):
        self.assertEqual(len({case[0] for case in CASES}), len(CASES))
        self.assertGreaterEqual(len(CASES), 9)

    def test_denials_never_promote_by_diagnostic(self):
        for name, authoritative_allow, reason, expected_allow in CASES:
            with self.subTest(name=name):
                self.assertEqual(authoritative_allow, expected_allow)
                if not authoritative_allow:
                    self.assertFalse(expected_allow)

    def test_diagnostic_values_do_not_determine_authority(self):
        diagnostics = [case[2] for case in CASES if not case[1]]
        self.assertIn(None, diagnostics)
        self.assertTrue(any(isinstance(reason, dict) for reason in diagnostics))
        self.assertTrue(any(reason == "previously_allowed" for reason in diagnostics))

    def test_only_positive_control_has_independent_authority(self):
        approvals = [case for case in CASES if case[3]]
        self.assertEqual([case[0] for case in approvals], ["current_exact_grant_control"])

if __name__ == "__main__":
    unittest.main()
