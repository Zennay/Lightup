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

def pr_link():
    return {"number": 1310,
            "head": {"ref": "scope-draft", "sha": HEAD},
            "base": {"ref": "main", "sha": "b" * 40}}


def sample():
    host = {"id": 1001, "head_sha": HEAD, "status": "completed", "conclusion": "success",
            "run_attempt": 1, "created_at": "2026-10-13T00:00:00Z",
            "run_started_at": "2026-10-13T00:01:00Z",
            "updated_at": "2026-10-13T00:05:00Z"}
    host.update(name="LightUp offline preflight",
                path=".github/workflows/lightup-preflight.yml", workflow_id=375432315,
                event="pull_request", repository={"full_name": "Zennay/Lightup"},
                head_repository={"full_name": "Zennay/Lightup"})
    host.update(head_branch="scope-draft", pull_requests=[pr_link()])
    vps = {**host, "id": 1002, "name": "LightUp CI",
           "path": ".github/workflows/lightup-ci.yml", "workflow_id": 373018063,
           "pull_requests": [pr_link()]}
    hj = {"total_count": 4, "jobs": [
        {"name": name, "head_sha": HEAD, "status": "completed", "conclusion": "success",
         "run_id": 1001, "run_attempt": 1,
         "runner_name": "GitHub Actions 9", "labels": ["ubuntu-latest"]}
        for name in sorted(gate.HOSTED)]}
    vj = {"total_count": 2, "jobs": [
        {"name": name, "head_sha": HEAD, "status": "completed", "conclusion": "success",
         "run_id": 1002, "run_attempt": 1,
         "runner_name": "zcloud-vps-1", "labels": ["self-hosted", "zcloud", "vps"]}
        for name in sorted(gate.PERMANENT)]}
    for job in (*hj["jobs"], *vj["jobs"]):
        job.update(created_at="2026-10-13T00:01:10Z",
                   started_at="2026-10-13T00:02:00Z",
                   completed_at="2026-10-13T00:04:00Z")
    for job in hj["jobs"]:
        needed = (gate.HOSTED_INTEGRATION_ORDER if job["name"].startswith("Real producer")
                  else gate.HOSTED_PREFLIGHT_ORDER)
        job["steps"] = [{"name": name, "number": i, "status": "completed", "conclusion": "success"}
                        for i, name in enumerate(needed, 2)]
    for job in vj["jobs"]:
        job["steps"] = [{"name": name, "number": i, "status": "completed", "conclusion": "success"}
                        for i, name in enumerate(gate.VPS_CRITICAL_ORDER, 1)]
    return [host, hj, vps, vj]

def pr_files_fixture():
    return [
        {"filename": "docs/scope-1309-exact-head-ci-vps-evidence-check-20261013.md",
         "status": "added"},
        {"filename": "scripts/check_scope_ci_evidence_optin.py", "status": "added"},
        {"filename": "tests/test_scope_ci_evidence_optin_1309.py", "status": "added"},
    ]


def pr_fixture():
    return {"number": 1310, "state": "open", "draft": True,
            "changed_files": 3,
            "head": {"ref": "scope-draft", "sha": HEAD, "repo": {"full_name": "Zennay/Lightup"}},
            "base": {"ref": "main", "sha": "b" * 40, "repo": {"full_name": "Zennay/Lightup"}}}


def final_runs_fixture():
    fresh = sample()
    return [fresh[0], fresh[2]]


def main_fixture():
    return {"ref": "refs/heads/main", "object": {"type": "commit", "sha": "b" * 40}}


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

    def test_hosted_suite_step_skipped_is_hold(self):
        data = sample()
        steps = data[1]["jobs"][0]["steps"]
        self.assertTrue(any(s["name"] == "Compile and unit suite" for s in steps)
                        or any(s["name"] == "Combined unit suite and real producer integration"
                               for s in steps))
        steps[0]["conclusion"] = "skipped"
        self.hold(evaluate(data), "hosted_critical_steps_unverified")

    def test_missing_runner_identity_guard_is_hold(self):
        data = sample()
        data[3]["jobs"][0]["steps"] = [
            s for s in data[3]["jobs"][0]["steps"]
            if s["name"] != "Guard permanent VPS runner"]
        self.hold(evaluate(data), "permanent_vps_critical_steps_unverified")

    def test_missing_permanent_safety_canary_is_hold(self):
        data = sample()
        data[3]["jobs"][0]["steps"] = [
            s for s in data[3]["jobs"][0]["steps"]
            if s["name"] != "Offline activation and web canaries (isolated state)"]
        self.hold(evaluate(data), "permanent_vps_critical_steps_unverified")

    def test_overall_green_cannot_mask_failed_integration_step(self):
        data = sample()
        steps = data[3]["jobs"][0]["steps"]
        next(s for s in steps if s["name"].startswith("Real producer integration"))["conclusion"] = "failure"
        self.hold(evaluate(data), "permanent_vps_critical_steps_unverified")

    def test_duplicate_step_names_fail_closed(self):
        data = sample()
        steps = data[1]["jobs"][0]["steps"]
        steps.append(dict(steps[0]))
        self.hold(evaluate(data), "hosted_critical_steps_unverified")

    def test_opaque_malformed_step_structure_fails_closed(self):
        data = sample()
        data[3]["jobs"][0]["steps"] = [{"name": False}]
        self.hold(evaluate(data), "permanent_vps_critical_steps_unverified")

    def test_step_free_success_is_not_proof(self):
        data = sample()
        data[1]["jobs"][0]["steps"] = []
        self.hold(evaluate(data), "hosted_critical_steps_unverified")

    def test_reordered_permanent_guard_is_hold(self):
        data = sample()
        steps = data[3]["jobs"][0]["steps"]
        steps[0], steps[1] = steps[1], steps[0]
        self.hold(evaluate(data), "permanent_vps_critical_steps_unverified")

    def test_reordered_critical_step_numbers_are_hold(self):
        data = sample()
        steps = data[1]["jobs"][0]["steps"]
        steps[2]["number"] = steps[1]["number"]
        self.hold(evaluate(data), "hosted_critical_steps_unverified")

    def test_boolean_step_number_is_not_valid_integer(self):
        data = sample()
        data[3]["jobs"][0]["steps"][0]["number"] = True
        self.hold(evaluate(data), "permanent_vps_critical_steps_unverified")

    def test_missing_critical_step_number_denied(self):
        data = sample()
        del data[1]["jobs"][0]["steps"][0]["number"]
        self.hold(evaluate(data), "hosted_critical_steps_unverified")

    def test_honest_critical_order_keeps_non_authorizing_outcome(self):
        receipt = evaluate()
        self.assertEqual(receipt["state"], "EVIDENCE_COMPLETE_NOT_AUTHORIZED")
        self.assertFalse(receipt["permit_issued"])

    def test_queued_vps_is_hold(self):
        data = sample()
        data[2].update(status="queued", conclusion=None)
        for job in data[3]["jobs"]:
            job.update(status="queued", conclusion=None, runner_name="")
        self.hold(evaluate(data), "permanent_vps_run_not_successful")

    def test_wrong_workflow_identity_is_hold(self):
        data = sample(); data[0]["workflow_id"] = 373018063
        self.hold(evaluate(data), "hosted_workflow_identity_mismatch")

    def test_wrong_repository_is_hold(self):
        data = sample(); data[2]["head_repository"] = {"full_name": "forged/Lightup"}
        self.hold(evaluate(data), "permanent_vps_workflow_identity_mismatch")

    def test_push_event_is_not_pull_request_evidence(self):
        data = sample(); data[0]["event"] = "push"
        self.hold(evaluate(data), "hosted_workflow_identity_mismatch")

    def test_stale_hosted_sha_is_hold(self):
        data = sample(); data[0]["head_sha"] = "b" * 40
        self.hold(evaluate(data), "hosted_head_or_run_mismatch")

    def test_stale_vps_job_is_hold(self):
        data = sample(); data[3]["jobs"][0]["head_sha"] = "b" * 40
        self.hold(evaluate(data), "permanent_vps_job_not_successful_on_head")

    def test_replayed_prior_run_job_is_hold(self):
        data = sample(); data[3]["jobs"][0]["run_id"] = 9000
        self.hold(evaluate(data), "permanent_vps_job_run_identity_mismatch")

    def test_replayed_previous_attempt_is_hold(self):
        data = sample(); data[2]["run_attempt"] = 2
        self.hold(evaluate(data), "permanent_vps_job_run_identity_mismatch")

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

    def test_github_redirect_is_rejected(self):
        handler = gate._DenyRedirects()
        self.assertIsNone(handler.redirect_request(
            None, None, 302, "synthetic", {}, "https://untrusted.invalid/"))

    def test_pr_head_must_match_current_revision(self):
        pr = pr_fixture()
        pr["head"]["sha"] = "b" * 40
        self.assertEqual(gate.verify_pr_head(HEAD, 1310, pr),
                         ["pr_current_head_or_repository_mismatch"])

    def test_pr_must_be_open_draft_and_same_repo(self):
        pr = pr_fixture()
        pr["draft"] = False
        self.assertEqual(gate.verify_pr_head(HEAD, 1310, pr),
                         ["pr_state_or_identity_mismatch"])
        pr = pr_fixture()
        pr["base"]["repo"]["full_name"] = "untrusted/repo"
        self.assertEqual(gate.verify_pr_head(HEAD, 1310, pr),
                         ["pr_current_head_or_repository_mismatch"])

    def test_matching_run_pr_links_are_metadata_only(self):
        self.assertEqual(gate.verify_run_pr_binding(
            HEAD, 1310, pr_fixture(), sample()[0], sample()[2]), [])

    def test_run_belonging_to_other_pr_refused(self):
        data = sample()
        data[0]["pull_requests"][0]["number"] = 1308
        self.assertEqual(gate.verify_run_pr_binding(
            HEAD, 1310, pr_fixture(), data[0], data[2]),
            ["hosted_pr_binding_mismatch"])

    def test_run_linked_to_old_base_refused(self):
        data = sample()
        data[2]["pull_requests"][0]["base"]["sha"] = "c" * 40
        self.assertEqual(gate.verify_run_pr_binding(
            HEAD, 1310, pr_fixture(), data[0], data[2]),
            ["permanent_vps_pr_binding_mismatch"])

    def test_run_on_other_branch_refused(self):
        data = sample()
        data[0]["head_branch"] = "other-branch"
        self.assertEqual(gate.verify_run_pr_binding(
            HEAD, 1310, pr_fixture(), data[0], data[2]),
            ["hosted_pr_binding_mismatch"])

    def test_missing_ambiguous_and_forged_pr_links_refused(self):
        for links in (None, [], [pr_link(), pr_link()], [{"number": True}]):
            with self.subTest(links=links):
                data = sample()
                data[2]["pull_requests"] = links
                self.assertEqual(gate.verify_run_pr_binding(
                    HEAD, 1310, pr_fixture(), data[0], data[2]),
                    ["permanent_vps_pr_binding_mismatch"])

    def test_pr_base_must_be_canonical_main(self):
        pr = pr_fixture()
        pr["base"]["ref"] = "feature"
        self.assertEqual(gate.verify_run_pr_binding(
            HEAD, 1310, pr, sample()[0], sample()[2]),
            ["pr_base_or_branch_invalid"])

    def test_main_combines_current_pr_binding_denial(self):
        data = sample()
        data[2]["pull_requests"][0]["head"]["sha"] = "c" * 40
        with patch.object(gate, "_get_json", side_effect=[pr_fixture(), main_fixture(), pr_files_fixture(), *data, pr_fixture(), main_fixture(), *final_runs_fixture()]):
            with patch("sys.stdout", new_callable=StringIO) as out:
                exit_status = gate.main(["--pr", "1310", "--head", HEAD,
                                         "--hosted-run", "1001", "--vps-run", "1002"])
        self.assertEqual(exit_status, 2)
        self.hold(json.loads(out.getvalue()), "permanent_vps_pr_binding_mismatch")

    def test_good_utc_timeline_metadata_remains_non_authorizing(self):
        self.assertTrue(gate._ordered_run_timestamps(sample()[0]))
        self.assertTrue(gate._ordered_job_timestamps(sample()[1]["jobs"][0]))
        self.assertEqual(evaluate()["state"], "EVIDENCE_COMPLETE_NOT_AUTHORIZED")

    def test_reversed_run_timeline_is_hold(self):
        data = sample()
        data[0]["run_started_at"] = "2026-10-12T23:59:00Z"
        self.hold(evaluate(data), "hosted_run_timeline_unverified")

    def test_job_completed_before_start_is_hold(self):
        data = sample()
        data[3]["jobs"][0]["completed_at"] = "2026-10-13T00:01:00Z"
        self.hold(evaluate(data), "permanent_vps_job_timeline_unverified")

    def test_malformed_utc_or_boolean_job_time_is_hold(self):
        for value in (False, "2026-10-13T00:00:00+00:00",
                      "2026-02-31T00:00:00Z", "2026-10-13T00:00:00",
                      "2026-10-13T00:00:00.123Z"):
            with self.subTest(value=value):
                data = sample()
                data[1]["jobs"][0]["started_at"] = value
                self.hold(evaluate(data), "hosted_job_timeline_unverified")

    def test_incomplete_timeline_cannot_substitute_green_run(self):
        data = sample()
        data[2].pop("run_started_at")
        self.hold(evaluate(data), "permanent_vps_run_timeline_unverified")

    def test_fixed_transport_allows_only_canonical_github_metadata_urls(self):
        examples = (
            gate.MAIN_REF, f"{gate.PR_ROOT}1310", f"{gate.PR_ROOT}1310/files?per_page=100",
            f"{gate.API_ROOT}1001", f"{gate.API_ROOT}1001/jobs?per_page=100",
        )
        for url in examples:
            with self.subTest(url=url):
                self.assertIsNotNone(gate._ALLOWED_API_URL.fullmatch(url))

    def test_transport_blocks_token_forwarding_to_untrusted_origins(self):
        examples = (
            "https://untrusted.invalid/steal", "http://api.github.com/repos/Zennay/Lightup/pulls/1310",
            "https://api.github.com.evil.invalid/repos/Zennay/Lightup/pulls/1310",
            "https://operator@api.github.com/repos/Zennay/Lightup/pulls/1310",
            "https://api.github.com/repos/Zennay/Lightup/pulls/1310/../../untrusted",
            "https://api.github.com/repos/Zennay/Lightup/pulls/1310#fragment",
            "https://api.github.com/repos/Zennay/Lightup/pulls/1310?redirect=true",
            "https://api.github.com/repos/Zennay/Lightup/actions/runs/1001/jobs?per_page=200",
            "https://api.github.com/repos/Zennay/Lightup/pulls/0001",
        )
        with patch.object(gate, "build_opener") as opener:
            for url in examples:
                with self.subTest(url=url), self.assertRaises(ValueError):
                    gate._get_json(url, "SECRET-SYNTHETIC-GITHUB-TOKEN")
        opener.assert_not_called()

    def test_transport_rejects_non_string_url_without_network(self):
        with patch.object(gate, "build_opener") as opener:
            for url in (None, False, 10, ["https://api.github.com"]):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    gate._get_json(url, "SECRET-TOKEN")
        opener.assert_not_called()

    def test_api_json_duplicate_nested_keys_refused(self):
        payload = b'{"run":{"head_sha":"a","head_sha":"b"}}'
        with patch.object(gate, "build_opener") as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = payload
            with self.assertRaises(ValueError):
                gate._get_json(gate.API_ROOT + "1001", None)

    def test_api_json_nonfinite_refused(self):
        payload = b'{"run":{"status":NaN}}'
        with patch.object(gate, "build_opener") as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = payload
            with self.assertRaises(ValueError):
                gate._get_json(gate.API_ROOT + "1001", None)

    def test_api_json_bounded_and_valid_control(self):
        with patch.object(gate, "build_opener") as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.read.return_value = b'{"run":{"id":1001}}'
            self.assertEqual(gate._get_json(gate.API_ROOT + "1001", None),
                             {"run": {"id": 1001}})
            response.read.return_value = b" " * 524289
            with self.assertRaises(ValueError):
                gate._get_json(gate.API_ROOT + "1001", None)

    def test_invalid_numeric_cli_does_not_echo_private_text(self):
        marker = "SECRET-SYNTHETIC-CLI-CANARY"
        with patch("sys.stdout", new_callable=StringIO) as out:
            with patch("sys.stderr", new_callable=StringIO) as err:
                result = gate.main(["--pr", marker, "--head", HEAD,
                                    "--hosted-run", "1001", "--vps-run", "1002"])
        self.assertEqual(result, 2)
        self.hold(json.loads(out.getvalue()), "invalid_input")
        self.assertNotIn(marker, out.getvalue() + err.getvalue())

    def test_unknown_cli_flag_does_not_echo_private_text(self):
        marker = "SECRET-SYNTHETIC-UNKNOWN-CANARY"
        with patch("sys.stdout", new_callable=StringIO) as out:
            with patch("sys.stderr", new_callable=StringIO) as err:
                result = gate.main(["--pr", "1310", "--head", HEAD,
                                    "--hosted-run", "1001", "--vps-run", "1002",
                                    "--unknown=" + marker])
        self.assertEqual(result, 2)
        self.hold(json.loads(out.getvalue()), "invalid_input")
        self.assertNotIn(marker, out.getvalue() + err.getvalue())

    def test_last_pr_read_catches_changed_head(self):
        final = pr_fixture()
        final["head"]["sha"] = "c" * 40
        with patch.object(gate, "_get_json",
                          side_effect=[pr_fixture(), main_fixture(), pr_files_fixture(), *sample(), final, main_fixture(), *final_runs_fixture()]):
            with patch("sys.stdout", new_callable=StringIO) as out:
                result = gate.main(["--pr", "1310", "--head", HEAD,
                                    "--hosted-run", "1001", "--vps-run", "1002"])
        self.assertEqual(result, 2)
        self.hold(json.loads(out.getvalue()), "pr_changed_during_evidence_read")

    def test_last_pr_read_catches_retargeted_base(self):
        final = pr_fixture()
        final["base"]["sha"] = "c" * 40
        with patch.object(gate, "_get_json",
                          side_effect=[pr_fixture(), main_fixture(), pr_files_fixture(), *sample(), final, main_fixture(), *final_runs_fixture()]):
            with patch("sys.stdout", new_callable=StringIO) as out:
                result = gate.main(["--pr", "1310", "--head", HEAD,
                                    "--hosted-run", "1001", "--vps-run", "1002"])
        self.assertEqual(result, 2)
        self.hold(json.loads(out.getvalue()), "pr_changed_during_evidence_read")

    def test_last_pr_read_catches_closed_or_undrafted_pr(self):
        for mutation in ({"state": "closed"}, {"draft": False}):
            with self.subTest(mutation=mutation):
                final = pr_fixture()
                final.update(mutation)
                with patch.object(gate, "_get_json",
                                  side_effect=[pr_fixture(), main_fixture(), pr_files_fixture(), *sample(), final, main_fixture(), *final_runs_fixture()]):
                    with patch("sys.stdout", new_callable=StringIO) as out:
                        result = gate.main(["--pr", "1310", "--head", HEAD,
                                            "--hosted-run", "1001", "--vps-run", "1002"])
                self.assertEqual(result, 2)
                self.hold(json.loads(out.getvalue()), "pr_changed_during_evidence_read")

    def test_main_pin_matches_current_pr_base(self):
        self.assertEqual(gate.verify_current_main(pr_fixture(), main_fixture()), [])

    def test_changed_main_head_is_hold(self):
        final_main = main_fixture()
        final_main["object"]["sha"] = "c" * 40
        with patch.object(gate, "_get_json",
                          side_effect=[pr_fixture(), main_fixture(), pr_files_fixture(), *sample(),
                                       pr_fixture(), final_main, *final_runs_fixture()]):
            with patch("sys.stdout", new_callable=StringIO) as out:
                result = gate.main(["--pr", "1310", "--head", HEAD,
                                    "--hosted-run", "1001", "--vps-run", "1002"])
        self.assertEqual(result, 2)
        self.hold(json.loads(out.getvalue()), "main_changed_during_evidence_read")

    def test_incoherent_main_base_is_hold(self):
        invalid_main = main_fixture()
        invalid_main["object"]["sha"] = "c" * 40
        self.assertEqual(gate.verify_current_main(pr_fixture(), invalid_main),
                         ["current_main_unverified"])

    def test_main_ref_type_or_shape_must_be_canonical(self):
        for change in ({"ref": "refs/heads/dev"}, {"object": {"sha": "b" * 40, "type": "tag"}},
                       {"object": {"sha": False, "type": "commit"}}):
            with self.subTest(change=change):
                ref = main_fixture()
                ref.update(change)
                self.assertEqual(gate.verify_current_main(pr_fixture(), ref),
                                 ["current_main_unverified"])

    def test_safe_additive_scope_pr_files_accepted(self):
        self.assertEqual(gate.verify_pr_guard_files(pr_fixture(), pr_files_fixture()), [])

    def test_modified_ci_workflow_requires_independent_review(self):
        for path in (".github/workflows/lightup-ci.yml",
                     ".github/workflows/lightup-preflight.yml",
                     ".github/workflows/other.yml",
                     "scripts/check_safety_canaries.py"):
            with self.subTest(path=path):
                files = pr_files_fixture()
                files[0]["filename"] = path
                self.assertEqual(
                    gate.verify_pr_guard_files(pr_fixture(), files),
                    ["verification_workflow_or_canary_modified"])

    def test_renamed_away_verifier_cannot_hide_modified_workflow(self):
        files = pr_files_fixture()
        files[0] = {"filename": "docs/renamed.md",
                    "previous_filename": ".github/workflows/lightup-ci.yml",
                    "status": "renamed"}
        self.assertEqual(gate.verify_pr_guard_files(pr_fixture(), files),
                         ["verification_workflow_or_canary_modified"])

    def test_truncated_or_paged_pr_listing_is_hold(self):
        files = pr_files_fixture()
        self.assertEqual(gate.verify_pr_guard_files(pr_fixture(), files[:-1]),
                         ["pr_files_unverified"])
        pr = pr_fixture()
        pr["changed_files"] = 101
        self.assertEqual(gate.verify_pr_guard_files(pr, files),
                         ["pr_files_unverified"])

    def test_missing_duplicate_or_malformed_file_records_refused(self):
        for invalid in (None, ["unexpected"], [{"filename": "foo", "status": "added"}],
                        [pr_files_fixture()[0]] * 3):
            with self.subTest(invalid=invalid):
                self.assertEqual(gate.verify_pr_guard_files(pr_fixture(), invalid),
                                 ["pr_files_unverified"])

    def test_unsafe_changed_workflow_cli_emits_hold_not_authority(self):
        bad = pr_files_fixture()
        bad[0]["filename"] = ".github/workflows/lightup-ci.yml"
        with patch.object(gate, "_get_json",
                          side_effect=[pr_fixture(), main_fixture(), bad, *sample(),
                                       pr_fixture(), main_fixture(), *final_runs_fixture()]):
            with patch("sys.stdout", new_callable=StringIO) as out:
                code = gate.main(["--pr", "1310", "--head", HEAD,
                                  "--hosted-run", "1001", "--vps-run", "1002"])
        self.assertEqual(code, 2)
        self.hold(json.loads(out.getvalue()), "verification_workflow_or_canary_modified")

    def test_completed_run_second_read_still_not_authority(self):
        initial = sample()
        self.assertEqual(gate.verify_run_stability(
            initial[0], final_runs_fixture()[0], "hosted"), [])
        self.assertEqual(gate.verify_run_stability(
            initial[2], final_runs_fixture()[1], "permanent_vps"), [])

    def test_rerun_attempt_during_read_is_hold(self):
        newer = final_runs_fixture()
        newer[0]["run_attempt"] = 2
        with patch.object(gate, "_get_json",
                          side_effect=[pr_fixture(), main_fixture(), pr_files_fixture(),
                                       *sample(), pr_fixture(), main_fixture(), *newer]):
            with patch("sys.stdout", new_callable=StringIO) as out:
                code = gate.main(["--pr", "1310", "--head", HEAD,
                                  "--hosted-run", "1001", "--vps-run", "1002"])
        self.assertEqual(code, 2)
        self.hold(json.loads(out.getvalue()), "hosted_run_changed_during_evidence_read")

    def test_run_conclusion_change_during_read_is_hold(self):
        newer = final_runs_fixture()
        newer[1]["status"] = "queued"
        newer[1]["conclusion"] = None
        self.assertEqual(gate.verify_run_stability(
            sample()[2], newer[1], "permanent_vps"),
            ["permanent_vps_run_changed_during_evidence_read"])

    def test_run_pr_link_mutation_during_read_is_hold(self):
        newer = final_runs_fixture()
        newer[0]["pull_requests"][0]["head"]["sha"] = "c" * 40
        self.assertEqual(gate.verify_run_stability(
            sample()[0], newer[0], "hosted"),
            ["hosted_run_changed_during_evidence_read"])

    def test_missing_second_run_metadata_is_hold(self):
        self.assertEqual(gate.verify_run_stability(sample()[0], None, "hosted"),
                         ["hosted_run_changed_during_evidence_read"])

    def test_private_api_exception_does_not_echo(self):
        with patch.object(gate, "_get_json", side_effect=RuntimeError("SECRET-SYNTHETIC-CANARY")):
            with patch("sys.stdout", new_callable=StringIO) as out:
                self.assertEqual(gate.main(["--pr", "1310", "--head", HEAD, "--hosted-run", "1001", "--vps-run", "1002"]), 2)
        self.assertNotIn("SECRET-SYNTHETIC-CANARY", out.getvalue())
        self.hold(json.loads(out.getvalue()), "metadata_unavailable")

    def test_cli_uses_only_fixed_github_origin(self):
        with patch.object(gate, "_get_json", side_effect=[pr_fixture(), main_fixture(), pr_files_fixture(), *sample(), pr_fixture(), main_fixture(), *final_runs_fixture()]) as get:
            with patch("sys.stdout", new_callable=StringIO):
                self.assertEqual(gate.main(["--pr", "1310", "--head", HEAD, "--hosted-run", "1001", "--vps-run", "1002"]), 0)
        self.assertEqual([c.args[0] for c in get.call_args_list], [
            f"{gate.PR_ROOT}1310", gate.MAIN_REF,
            f"{gate.PR_ROOT}1310/files?per_page=100",
            f"{gate.API_ROOT}1001", f"{gate.API_ROOT}1001/jobs?per_page=100",
            f"{gate.API_ROOT}1002", f"{gate.API_ROOT}1002/jobs?per_page=100",
            f"{gate.PR_ROOT}1310", gate.MAIN_REF,
            f"{gate.API_ROOT}1001", f"{gate.API_ROOT}1002",
        ])

if __name__ == "__main__":
    unittest.main()
