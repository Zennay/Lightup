"""Offline tests for the release-evidence gate: never confers target permission."""
from __future__ import annotations

import copy
import unittest

from scripts.check_scope_release_evidence import REQUIRED_JOBS, evaluate


SHA = "a" * 40


def sample():
    return {
        "integration_sha": SHA,
        "trusted_grant_enforced": True,
        "zero_side_effect_denials": True,
        "revocation_fence_verified": True,
        "source_owner_reviewed": True,
        "remaining_xfails": 0,
        "jobs": {
            name: {"head_sha": SHA, "conclusion": "success", "run_url": "https://github.com/Zennay/Lightup/actions/runs/123"}
            for name in REQUIRED_JOBS
        },
    }


class ScopeReleaseEvidenceTests(unittest.TestCase):
    def test_missing_evidence_holds(self):
        self.assertFalse(evaluate(None)[0])
        self.assertFalse(evaluate({})[0])

    def test_complete_synthetic_fixture_is_only_review_eligible(self):
        allowed, reasons = evaluate(sample())
        self.assertTrue(allowed, reasons)

    def test_security_claims_must_be_exact_booleans(self):
        for field in ("trusted_grant_enforced", "zero_side_effect_denials", "revocation_fence_verified", "source_owner_reviewed"):
            for invalid in (False, 1, "true", None):
                with self.subTest(field=field, invalid=invalid):
                    case = sample()
                    case[field] = invalid
                    self.assertFalse(evaluate(case)[0])

    def test_xfail_count_requires_exact_integer_zero(self):
        for value in (True, False, "0", None, 1, 10, 0.0):
            with self.subTest(value=value):
                case = sample()
                case["remaining_xfails"] = value
                self.assertFalse(evaluate(case)[0])

    def test_each_job_is_required_on_identical_sha(self):
        for name in REQUIRED_JOBS:
            for mutation in ("missing", "queued", "wrong_sha", "missing_url"):
                with self.subTest(name=name, mutation=mutation):
                    case = sample()
                    if mutation == "missing":
                        case["jobs"].pop(name)
                    elif mutation == "queued":
                        case["jobs"][name]["conclusion"] = "queued"
                    elif mutation == "wrong_sha":
                        case["jobs"][name]["head_sha"] = "b" * 40
                    else:
                        case["jobs"][name]["run_url"] = ""
                    self.assertFalse(evaluate(case)[0])

    def test_hostile_evidence_links_denied(self):
        hostile = (
            "https://github.com.evil.example/Zennay/Lightup/actions/runs/123",
            "https://github.com@evil.example/Zennay/Lightup/actions/runs/123",
            "http://github.com/Zennay/Lightup/actions/runs/123",
            "https://github.com/other/repo/actions/runs/123",
            "https://github.com/Zennay/Lightup/actions/runs/not-a-number",
            "https://github.com/Zennay/Lightup/actions/runs/123?approved=true",
            "https://github.com/Zennay/Lightup/actions/runs/123#approved",
            "https://github.com/Zennay/Lightup/actions/runs/123/extra",
            "https://github.com/Zennay/Lightup/actions/runs/123/",
            "https://github.com:443/Zennay/Lightup/actions/runs/123",
            "https://github.com/Zennay/Lightup/actions/runs/0",
            "https://github.com/Zennay/Lightup/actions/runs/000000000000000000001",
            "https://github.com/Zennay/Lightup/actions/runs/123%2fextra",
            "https://github.com/Zennay/Lightup/actions/runs/123@evil.example",
        )
        for url in hostile:
            with self.subTest(url=url):
                case = sample()
                case["jobs"]["permanent_vps"]["run_url"] = url
                self.assertFalse(evaluate(case)[0])

    def test_sha_requires_full_lowercase_digest(self):
        for invalid in (None, "", "abc", "A" * 40, 3):
            with self.subTest(invalid=invalid):
                case = sample()
                case["integration_sha"] = invalid
                self.assertFalse(evaluate(case)[0])

    def test_no_mutation_of_input(self):
        case = sample()
        before = copy.deepcopy(case)
        evaluate(case)
        self.assertEqual(case, before)


if __name__ == "__main__":
    unittest.main()
