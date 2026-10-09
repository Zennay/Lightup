"""Offline tests for the release-evidence gate: never confers target permission."""
from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
import unittest

from scripts.check_scope_release_evidence import REQUIRED_JOBS, evaluate, reject_duplicate_keys, reject_nonfinite_constant, main


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
    def test_duplicate_root_authorization_claim_is_rejected(self):
        for payload in (
            '{"trusted_grant_enforced":false,"trusted_grant_enforced":true}',
            '{"jobs":{"permanent_vps":null,"permanent_vps":{"conclusion":"success"}}}',
            '{"integration_sha":"a","integration_sha":"b"}',
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    json.loads(payload, object_pairs_hook=reject_duplicate_keys)

    def test_unambiguous_json_parses_without_mutation(self):
        parsed = json.loads('{"jobs":{"py311_unit":{"conclusion":"queued"}}}', object_pairs_hook=reject_duplicate_keys)
        self.assertEqual(parsed, {"jobs": {"py311_unit": {"conclusion": "queued"}}})

    def test_nonfinite_json_constants_fail_closed(self):
        for literal in ("NaN", "Infinity", "-Infinity"):
            for payload in (f'{{"remaining_xfails":{literal}}}',
                            f'{{"jobs":{{"permanent_vps":{{"head_sha":{literal}}}}}}}'):
                with self.subTest(payload=payload):
                    with self.assertRaises(ValueError):
                        json.loads(payload, object_pairs_hook=reject_duplicate_keys,
                                   parse_constant=reject_nonfinite_constant)

    def test_cli_rejects_duplicate_and_nonfinite_json(self):
        for payload in (
            '{"remaining_xfails":0,"remaining_xfails":10}',
            '{"remaining_xfails":NaN}',
            '{"jobs":{"permanent_vps":Infinity}}',
        ):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                evidence_path = Path(directory) / "evidence.json"
                evidence_path.write_text(payload, encoding="utf-8")
                output = StringIO()
                with redirect_stdout(output):
                    exit_code = main(["check_scope_release_evidence.py", str(evidence_path)])
                self.assertEqual(exit_code, 2)
                self.assertIn("HOLD:", output.getvalue())

    def test_cli_rejects_oversized_and_invalid_utf8_evidence(self):
        for raw in (b" " * (64 * 1024 + 1), bytes((255, 254))):
            with self.subTest(length=len(raw)), tempfile.TemporaryDirectory() as directory:
                evidence_path = Path(directory) / "evidence.json"
                evidence_path.write_bytes(raw)
                output = StringIO()
                with redirect_stdout(output):
                    exit_code = main(["check_scope_release_evidence.py", str(evidence_path)])
                self.assertEqual(exit_code, 2)
                self.assertIn("HOLD:", output.getvalue())

    def test_cli_does_not_echo_sensitive_duplicate_key(self):
        secret = "private-approval-token-DO-NOT-ECHO"
        payload = json.dumps({secret: 1})[:-1] + ',' + json.dumps(secret) + ':2}'
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "evidence.json"
            evidence_path.write_text(payload, encoding="utf-8")
            output = StringIO()
            errors = StringIO()
            with redirect_stdout(output), redirect_stderr(errors):
                exit_code = main(["check_scope_release_evidence.py", str(evidence_path)])
            self.assertEqual(exit_code, 2)
            self.assertIn("HOLD:", errors.getvalue() + output.getvalue())
            self.assertNotIn(secret, errors.getvalue() + output.getvalue())

    def test_cli_never_calls_synthetic_evidence_authorized(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.json"
            path.write_text(json.dumps(sample()), encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                result = main(["check_scope_release_evidence.py", str(path)])
            self.assertEqual(result, 0)
            self.assertIn("STRUCTURE-ONLY PASS", output.getvalue())
            self.assertIn("unverified", output.getvalue())
            self.assertIn("NOT release authorization", output.getvalue())

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
            " https://github.com/Zennay/Lightup/actions/runs/123",
            "https://github.com/Zennay/Lightup/actions/runs/123" + chr(10),
            "https://github.com/Zennay/Lightup/actions/runs/123" + chr(9),
            "https://github.com/Zennay/Lightup/actions/runs/123" + chr(0),
            "https://github.com/Zennay/Lightup/actions/runs/123" + chr(127),
        )
        for url in hostile:
            with self.subTest(url=url):
                case = sample()
                case["jobs"]["permanent_vps"]["run_url"] = url
                self.assertFalse(evaluate(case)[0])

    def test_unicode_lookalike_url_is_denied(self):
        for candidate in (
            "https://github.com/Zennay/Lightup/actions/runs/１２３",
            "https://github.com/Zennay/Lightup/actions/runs/123" + chr(0x200b),
            "https://github.com/Zennay/Lightup/actions/runs/123" + chr(0x202e),
        ):
            with self.subTest(candidate=candidate):
                case = sample()
                case["jobs"]["permanent_vps"]["run_url"] = candidate
                self.assertFalse(evaluate(case)[0])

    def test_sha_requires_full_lowercase_digest(self):
        for invalid in (None, "", "abc", "A" * 40, 3):
            with self.subTest(invalid=invalid):
                case = sample()
                case["integration_sha"] = invalid
                self.assertFalse(evaluate(case)[0])

    def test_unknown_evidence_fields_fail_closed(self):
        for level in ("root", "jobs", "job"):
            with self.subTest(level=level):
                case = sample()
                if level == "root":
                    case["operator_approved"] = True
                elif level == "jobs":
                    case["jobs"]["untrusted_runner"] = case["jobs"]["py311_unit"].copy()
                else:
                    case["jobs"]["permanent_vps"]["verified_by_user"] = True
                self.assertFalse(evaluate(case)[0])

    def test_no_mutation_of_input(self):
        case = sample()
        before = copy.deepcopy(case)
        evaluate(case)
        self.assertEqual(case, before)


if __name__ == "__main__":
    unittest.main()
