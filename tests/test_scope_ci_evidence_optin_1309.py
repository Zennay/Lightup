"""Synthetic GitHub workflow payload regression suite; zero network/targets."""
import importlib.util
import json
from io import StringIO
from pathlib import Path
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_scope_ci_evidence_optin.py"
spec = importlib.util.spec_from_file_location("scope_ci_optin", PATH)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
HEAD = "a" * 40

def sample():
    host = {"id": 1001, "head_sha": HEAD, "status": "completed", "conclusion": "success", "run_attempt": 1}
    vps = {**host, "id": 1002}
    hj = {"total_count": 4, "jobs": [
        {"name": name, "head_sha": HEAD, "status": "completed", "conclusion": "success",
         "runner_name": "GitHub Actions 9", "labels": ["ubuntu-latest"]}
        for name in sorted(gate.HOSTED)]}
    vj = {"total_count": 2, "jobs": [
        {"name": name, "head_sha": HEAD, "status": "completed", "conclusion": "success",
         "runner_name": "zcloud-vps-1", "labels": ["self-hosted", "zcloud", "vps"]}
        for name in sorted(gate.PERMANENT)]}
    return [host, hj, vps, vj]

def evaluate(data=None):
    return gate.evaluate(HEAD, 1001, 1002, *(sample() if data is None else data))

class CIEvidenceGateTests(unittest.TestCase):
    def hold(self, receipt, expected):
        self.assertEqual(receipt["state"], "HOLD")
        self.assertIn(expected, receipt["missing_gates"])
        for flag in ("authorization_verified", "permit_issued", "execution_enabled", "release_approved"):
            self.assertIs(receipt[flag], False)

    def test_all_green_still_not_authorization(self):
        receipt = evaluate()
        self.assertEqual(receipt["state"], "EVIDENCE_COMPLETE_NOT_AUTHORIZED")
        self.assertTrue(receipt["run_evidence_consistent"])
        self.assertFalse(receipt["release_approved"])

    def test_queued_vps_is_hold(self):
        data = sample()
        data[2].update(status="queued", conclusion=None)
        for job in data[3]["jobs"]:
            job.update(status="queued", conclusion=None, runner_name="")
        self.hold(evaluate(data), "permanent_vps_run_not_successful")

    def test_stale_hosted_sha_is_hold(self):
        data = sample(); data[0]["head_sha"] = "b" * 40
        self.hold(evaluate(data), "hosted_head_or_run_mismatch")

    def test_stale_vps_job_is_hold(self):
        data = sample(); data[3]["jobs"][0]["head_sha"] = "b" * 40
        self.hold(evaluate(data), "permanent_vps_job_not_successful_on_head")

    def test_failed_integration_is_hold(self):
        data = sample(); data[1]["jobs"][0]["conclusion"] = "failure"
        self.hold(evaluate(data), "hosted_job_not_successful_on_head")

    def test_duplicate_or_renamed_jobs_are_hold(self):
        data = sample(); data[1]["jobs"][0]["name"] = data[1]["jobs"][1]["name"]
        self.hold(evaluate(data), "hosted_job_set_mismatch")

    def test_paginated_jobs_are_hold(self):
        data = sample(); data[3]["total_count"] = 101
        self.hold(evaluate(data), "permanent_vps_incomplete_jobs")

    def test_wrong_vps_runner_is_hold(self):
        data = sample(); data[3]["jobs"][0]["runner_name"] = "unregistered"
        self.hold(evaluate(data), "permanent_vps_runner_unverified")

    def test_missing_runner_label_is_hold(self):
        data = sample(); data[3]["jobs"][0]["labels"] = ["self-hosted", "vps"]
        self.hold(evaluate(data), "permanent_vps_runner_unverified")

    def test_run_id_confusion_is_hold(self):
        data = sample(); data[0]["id"] = 1002
        self.hold(evaluate(data), "hosted_head_or_run_mismatch")

    def test_boolean_run_id_refused(self):
        self.hold(gate.evaluate(HEAD, True, 1002, *sample()), "invalid_run_identity")

    def test_noncanonical_head_refused(self):
        self.hold(gate.evaluate(HEAD.upper(), 1001, 1002, *sample()), "invalid_head")

    def test_bad_attempt_is_hold(self):
        data = sample(); data[2]["run_attempt"] = 0
        self.hold(evaluate(data), "permanent_vps_run_not_successful")

    def test_bad_job_type_is_hold(self):
        data = sample(); data[3]["jobs"][0] = {"name": False}
        self.hold(evaluate(data), "permanent_vps_malformed_jobs")

    def test_private_api_exception_does_not_echo(self):
        with patch.object(gate, "_get_json", side_effect=RuntimeError("SECRET-SYNTHETIC-CANARY")):
            with patch("sys.stdout", new_callable=StringIO) as out:
                self.assertEqual(gate.main(["--head", HEAD, "--hosted-run", "1001", "--vps-run", "1002"]), 2)
        self.assertNotIn("SECRET-SYNTHETIC-CANARY", out.getvalue())
        self.hold(json.loads(out.getvalue()), "metadata_unavailable")

    def test_cli_uses_only_fixed_github_origin(self):
        with patch.object(gate, "_get_json", side_effect=sample()) as get:
            with patch("sys.stdout", new_callable=StringIO):
                self.assertEqual(gate.main(["--head", HEAD, "--hosted-run", "1001", "--vps-run", "1002"]), 0)
        self.assertEqual([c.args[0] for c in get.call_args_list], [
            f"{gate.API_ROOT}1001", f"{gate.API_ROOT}1001/jobs?per_page=100",
            f"{gate.API_ROOT}1002", f"{gate.API_ROOT}1002/jobs?per_page=100",
        ])

if __name__ == "__main__":
    unittest.main()
