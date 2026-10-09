"""Offline, synthetic GitHub Actions job evidence tests; no real targets."""
import importlib.util
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("scope_job_provenance", SCRIPTS / "verify_scope_job_provenance.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

SHA = "a" * 40


def proof():
    return dict(
        schema_version=1, implementation_sha=SHA, base_sha="b" * 40,
        trusted_grant_reviewed=True, revocation_race_passed=True,
        denied_side_effects_zero=True, positive_loopback_control_passed=True,
        real_target_activation_disabled=True, hosted_py311_sha=SHA,
        hosted_py314_sha=SHA, permanent_vps_sha=SHA, owner_review_sha=SHA,
        hosted_py311_run_id=100, hosted_py314_run_id=100, permanent_vps_run_id=101,
        hosted_py311_job_id=201, hosted_py314_job_id=202, permanent_vps_job_id=203,
        denial_side_effect_counts=dict(handler=0, socket=0, queue=0, action_evidence=0),
    )


def jobs():
    return [
        dict(id=201, run_id=100, head_sha=SHA, name="Offline preflight Python 3.11",
             status="completed", conclusion="success"),
        dict(id=202, run_id=100, head_sha=SHA, name="Offline preflight Python 3.14",
             status="completed", conclusion="success"),
        dict(id=203, run_id=101, head_sha=SHA, name="LightUp plan-only VPS",
             status="completed", conclusion="success"),
    ]


class OfflineJobProvenanceTests(unittest.TestCase):
    def test_valid_matrix_and_distinct_vps(self):
        self.assertEqual(module.check(proof(), jobs()), [])

    def test_fail_closed_for_wrong_commit_run_name_status(self):
        for field, value in (("head_sha", "b" * 40), ("run_id", 999),
                             ("name", "Hosted other job"), ("status", "queued"),
                             ("conclusion", "failure")):
            for index in range(3):
                with self.subTest(field=field, index=index):
                    evidence = jobs()
                    evidence[index][field] = value
                    self.assertTrue(module.check(proof(), evidence))

    def test_missing_or_duplicate_job_fails(self):
        self.assertTrue(module.check(proof(), jobs()[:-1]))
        self.assertTrue(module.check(proof(), jobs() + [jobs()[0]]))

    def test_malformed_jobs_fail(self):
        for value in (None, {}, "jobs", [None]):
            with self.subTest(value=value):
                self.assertTrue(module.check(proof(), value))

    def test_forged_proof_structure_cannot_pass(self):
        document = proof()
        document["trusted_grant_reviewed"] = False
        self.assertTrue(module.check(document, jobs()))


if __name__ == "__main__":
    unittest.main()
