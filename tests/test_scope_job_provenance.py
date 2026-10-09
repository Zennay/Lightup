"""Offline, synthetic GitHub Actions job evidence tests; no real targets."""
import importlib.util
import json
import tempfile
from unittest import mock
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
        dict(id=203, run_id=101, head_sha=SHA, name="LightUp plan-only safety tests (Python 3.11)",
             status="completed", conclusion="success"),
    ]


class OfflineJobProvenanceTests(unittest.TestCase):
    def test_snapshot_symlink_is_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "proof.json"
            source.write_text(json.dumps(proof()), encoding="utf-8")
            link = Path(directory) / "proof-link.json"
            link.symlink_to(source)
            jobs_path = Path(directory) / "jobs.json"
            jobs_path.write_text(json.dumps(jobs()), encoding="utf-8")
            self.assertEqual(module.main(["verify", str(link), str(jobs_path)]), 2)

    def test_duplicate_json_job_field_is_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            proof_path = Path(directory) / "proof.json"
            proof_path.write_text(json.dumps(proof()), encoding="utf-8")
            jobs_path = Path(directory) / "jobs.json"
            raw = json.dumps(jobs()).replace('"id": 201', '"id": 999, "id": 201')
            jobs_path.write_text(raw, encoding="utf-8")
            self.assertEqual(module.main(["verify", str(proof_path), str(jobs_path)]), 2)

    def test_cli_accepts_consistent_snapshot_only_as_structural_check(self):
        with tempfile.TemporaryDirectory() as directory:
            proof_path = Path(directory) / "proof.json"
            jobs_path = Path(directory) / "jobs.json"
            proof_path.write_text(json.dumps(proof()), encoding="utf-8")
            jobs_path.write_text(json.dumps(jobs()), encoding="utf-8")
            self.assertEqual(module.main(["verify", str(proof_path), str(jobs_path)]), 0)

    def test_cli_denies_wrong_job_commit_and_unexpected_record(self):
        with tempfile.TemporaryDirectory() as directory:
            proof_path = Path(directory) / "proof.json"
            jobs_path = Path(directory) / "jobs.json"
            proof_path.write_text(json.dumps(proof()), encoding="utf-8")
            bad = jobs()
            bad[2]["head_sha"] = "f" * 40
            jobs_path.write_text(json.dumps(bad), encoding="utf-8")
            self.assertEqual(module.main(["verify", str(proof_path), str(jobs_path)]), 1)
            jobs_path.write_text(json.dumps(jobs() + [dict(id=999)]), encoding="utf-8")
            self.assertEqual(module.main(["verify", str(proof_path), str(jobs_path)]), 1)

    def test_unrelated_python_job_name_cannot_impersonate_preflight(self):
        for index, version in ((0, "3.11"), (1, "3.14")):
            with self.subTest(version=version):
                evidence = jobs()
                evidence[index]["name"] = f"Unrelated Python {version} integration"
                self.assertTrue(any("expected job label" in e for e in module.check(proof(), evidence)))

    def test_proof_job_name_rejects_unrelated_suffix(self):
        for index in range(3):
            with self.subTest(index=index):
                evidence = jobs()
                evidence[index]["name"] += " unrelated"
                self.assertTrue(any("expected job label" in e for e in module.check(proof(), evidence)))

    def test_generic_lightup_job_is_not_vps_safety_proof(self):
        evidence = jobs()
        evidence[2]["name"] = "LightUp unrelated task"
        self.assertTrue(any("expected job label" in error for error in module.check(proof(), evidence)))

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

    def test_unreferenced_successful_or_failed_jobs_are_rejected(self):
        for conclusion in ("success", "failure"):
            with self.subTest(conclusion=conclusion):
                evidence = jobs()
                evidence.append(dict(id=999, run_id=100, head_sha=SHA,
                                     name="unreferenced", status="completed",
                                     conclusion=conclusion))
                self.assertTrue(module.check(proof(), evidence))

    def test_missing_or_duplicate_job_fails(self):
        self.assertTrue(module.check(proof(), jobs()[:-1]))
        self.assertTrue(module.check(proof(), jobs() + [jobs()[0]]))

    def test_unreferenced_malformed_record_never_ignored(self):
        evidence = jobs()
        evidence.append(None)
        self.assertTrue(any("all job records" in error for error in module.check(proof(), evidence)))

    def test_each_missing_job_metadata_field_fails_closed(self):
        for key in ("id", "run_id", "head_sha", "name", "status", "conclusion"):
            with self.subTest(key=key):
                evidence = jobs()
                del evidence[0][key]
                self.assertTrue(module.check(proof(), evidence))

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
