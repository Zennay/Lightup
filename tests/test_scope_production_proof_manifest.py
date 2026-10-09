"""Fail-closed, offline release-evidence gate; never dispatches any tools or network."""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from urllib.parse import urlsplit

MANIFEST = Path(__file__).resolve().parents[1] / "docs" / "scope-production-proof-manifest-20261009.json"
SHA = re.compile(r"^[0-9a-f]{40}$")
COUNTERS = ("handler_calls", "dns_calls", "socket_opens", "http_calls",
            "subprocess_calls", "retry_submissions", "queue_submissions",
            "action_evidence_writes")
MANIFEST_KEYS = frozenset(("schema_version", "release_gate", "real_target_activation",
    "implementation_sha", "owner_review_url", "hosted_python_311", "hosted_python_314",
    "permanent_vps", "negative_real_executor_trace", "positive_loopback_lab_trace",
    "persistent_revocation_proof", "trusted_destination_metadata_proof"))


def _valid_artifact_url(value: object) -> bool:
    if type(value) is not str or any(ord(ch) < 33 or ord(ch) == 127 for ch in value):
        return False
    try:
        parts = urlsplit(value)
        return (parts.scheme == "https" and bool(parts.hostname) and
                parts.netloc == parts.hostname and
                "\\" not in value and "%" not in parts.netloc and
                bool(re.fullmatch(r"[a-z0-9-]+(?:[.][a-z0-9-]+)+", parts.hostname)) and
                parts.username is None and parts.password is None and
                parts.port is None and bool(parts.path) and parts.path != "/" and
                not parts.query and not parts.fragment and
                parts.hostname.endswith(".invalid") is False)
    except ValueError:
        return False


def is_release_evidence_complete(m: dict) -> bool:
    if type(m) is not dict or type(m.get("schema_version")) is not int or m["schema_version"] != 2:
        return False
    if set(m) != MANIFEST_KEYS or type(m.get("release_gate")) is not str or m["release_gate"] != "REVIEWED":
        return False
    sha = m.get("implementation_sha")
    if type(sha) is not str or not SHA.fullmatch(sha):
        return False
    if m.get("real_target_activation") is not False:
        return False  # evidence approval never flips activation
    if type(m.get("owner_review_url")) is not str or not re.fullmatch(r"https://github[.]com/([^/?#]+)/([^/?#]+)/pull/[1-9][0-9]*", m["owner_review_url"]):
        return False
    repo_path = "/".join(m["owner_review_url"].split("/")[3:5])
    job_ids = set()
    hosted_run_url = None
    for name in ("hosted_python_311", "hosted_python_314", "permanent_vps"):
        run = m.get(name)
        if type(run) is not dict or set(run) != {"sha", "conclusion", "run_url", "job_id"} or type(run.get("sha")) is not str or run["sha"] != sha or type(run.get("conclusion")) is not str or run["conclusion"] != "success":
            return False
        if type(run.get("run_url")) is not str or not re.fullmatch(r"https://github[.]com/" + re.escape(repo_path) + r"/actions/runs/[1-9][0-9]*", run["run_url"]):
            return False
        if type(run.get("job_id")) is not int or run["job_id"] <= 0 or run["job_id"] in job_ids:
            return False
        job_ids.add(run["job_id"])
        if name.startswith("hosted_"):
            if hosted_run_url is None:
                hosted_run_url = run["run_url"]
            elif hosted_run_url != run["run_url"]:
                return False
        elif run["run_url"] == hosted_run_url:
            return False
    negative = m.get("negative_real_executor_trace")
    positive = m.get("positive_loopback_lab_trace")
    trace_schemas = ((negative, {"sha", "artifact_url", *COUNTERS}),
                     (positive, {"sha", "artifact_url", "handler_calls"}),
                     (m.get("persistent_revocation_proof"), {"sha", "artifact_url"}),
                     (m.get("trusted_destination_metadata_proof"), {"sha", "artifact_url"}))
    for trace, keys in trace_schemas:
        if type(trace) is not dict or set(trace) != keys or type(trace.get("sha")) is not str or trace["sha"] != sha:
            return False
        if not _valid_artifact_url(trace.get("artifact_url")):
            return False
    for counter in COUNTERS:
        if type(negative.get(counter)) is not int or negative[counter] != 0:
            return False
    return type(positive.get("handler_calls")) is int and positive["handler_calls"] == 1


def verify_observed_ci_jobs(manifest: dict, observed: dict) -> bool:
    """Compare caller-supplied snapshots; no network access or release authority."""
    if not is_release_evidence_complete(manifest) or type(observed) is not dict:
        return False
    # Structural comparison alone is never an authenticated attestation.
    # The caller must still independently verify GitHub API provenance.
    if set(observed) != {"hosted_python_311", "hosted_python_314", "permanent_vps"}:
        return False
    for lane, required_version in (("hosted_python_311", "3.11"),
                                   ("hosted_python_314", "3.14"),
                                   ("permanent_vps", None)):
        expected = manifest[lane]
        run = observed.get(lane)
        if type(run) is not dict or type(expected) is not dict:
            return False
        if set(run) != {"job_id", "run_url", "sha", "status", "conclusion",
                        "python_version", "runner_class", "job_name", "run_id"}:
            return False
        if any(type(run.get(key)) is not type(expected[key]) or run[key] != expected[key] for key in ("job_id", "run_url", "sha")):
            return False
        expected_run_id = int(expected["run_url"].rsplit("/", 1)[-1])
        if type(run["run_id"]) is not int or run["run_id"] != expected_run_id:
            return False
        if (type(run["job_name"]) is not str or not run["job_name"].strip() or
                (lane == "permanent_vps" and ("not vps proof" in run["job_name"].lower() or
                                               "offline preflight" in run["job_name"].lower()))):
            return False
        if type(run["python_version"]) is not str or not re.search(r"(?<![A-Za-z0-9.])Python " + re.escape(run["python_version"]) + r"(?![0-9.])", run["job_name"]):
            return False
        if (type(run["status"]) is not str or run["status"] != "completed" or
                type(run["conclusion"]) is not str or run["conclusion"] != "success"):
            return False
        if required_version is not None:
            if (type(run["runner_class"]) is not str or run["runner_class"] != "hosted" or
                    type(run["python_version"]) is not str or run["python_version"] != required_version):
                return False
        elif (type(run["runner_class"]) is not str or run["runner_class"] != "permanent_vps" or
              type(run["python_version"]) is not str or run["python_version"] not in ("3.11", "3.14")):
            return False
    return True


def classify_supplied_hosted_run_jobs(run: dict, jobs: list, expected_sha: str, *, all_pages_verified: bool = False) -> dict:
    """Classify supplied hosted-job records only; this cannot authenticate API provenance or VPS identity."""
    if (all_pages_verified is not True or type(run) is not dict or type(jobs) is not list or
            type(expected_sha) is not str or not SHA.fullmatch(expected_sha)):
        return {}
    # Only caller-supplied snapshots: this function cannot establish data provenance.
    if (type(run.get("head_sha")) is not str or run["head_sha"] != expected_sha or
            type(run.get("id")) is not int or run["id"] <= 0 or
            type(run.get("status")) is not str or run["status"] != "completed" or
            type(run.get("conclusion")) is not str or run["conclusion"] != "success"):
        return {}
    # Reject duplicated job identities before selecting either interpreter lane.
    if any(type(job) is not dict for job in jobs):
        return {}
    ids = [job.get("id") for job in jobs]
    if any(type(identifier) is not int or identifier <= 0 for identifier in ids) or len(ids) != len(set(ids)):
        return {}
    if any(type(job.get("run_id")) is not int or job["run_id"] != run["id"] for job in jobs):
        return {}
    if any(type(job.get("status")) is not str or job["status"] != "completed" or
           type(job.get("conclusion")) is not str or job["conclusion"] != "success" for job in jobs):
        return {}
    if any(type(job.get("name")) is not str or not job["name"].strip() for job in jobs):
        return {}
    result = {}
    for version in ("3.11", "3.14"):
        matches = [job for job in jobs if type(job) is dict and
                   type(job.get("name")) is str and
                   job["name"] == "Offline preflight Python " + version + " (not VPS proof)" and
                   type(job.get("id")) is int and job["id"] > 0 and
                   type(job.get("run_id")) is int and job["run_id"] == run["id"] and
                   type(job.get("status")) is str and job["status"] == "completed" and
                   type(job.get("conclusion")) is str and job["conclusion"] == "success"]
        if len(matches) != 1:
            return {}
        result[version] = matches[0]["id"]
    if result["3.11"] == result["3.14"]:
        return {}
    return {"hosted_python_311": result["3.11"], "hosted_python_314": result["3.14"]}


class ScopeProductionProofManifestTests(unittest.TestCase):
    def test_authenticated_hosted_classifier_never_asserts_vps(self):
        sha = "a" * 40
        run = {"id": 91, "head_sha": sha, "status": "completed", "conclusion": "success"}
        jobs = [
            {"id": 100, "run_id": 91, "name": "Offline preflight Python 3.11 (not VPS proof)",
             "status": "completed", "conclusion": "success"},
            {"id": 101, "run_id": 91, "name": "Offline preflight Python 3.14 (not VPS proof)",
             "status": "completed", "conclusion": "success"},
        ]
        expected = {"hosted_python_311": 100, "hosted_python_314": 101}
        self.assertEqual(classify_supplied_hosted_run_jobs(run, jobs, sha, all_pages_verified=True), expected)
        self.assertEqual(classify_supplied_hosted_run_jobs(run, jobs, sha), {})
        # Even a matching, successful first page must not pass without completeness proof.
        truncated = [dict(jobs[0])]
        self.assertEqual(classify_supplied_hosted_run_jobs(run, truncated, sha), {})
        self.assertEqual(classify_supplied_hosted_run_jobs(run, truncated, sha, all_pages_verified=True), {})
        self.assertEqual(classify_supplied_hosted_run_jobs(run, jobs, sha, all_pages_verified=1), {})
        for incomplete in (None, False, 0, "", "true", [], {}):
            self.assertEqual(classify_supplied_hosted_run_jobs(
                run, jobs, sha, all_pages_verified=incomplete), {})
        duplicate_unrelated = [dict(job) for job in jobs] + [{
            "id": 100, "run_id": 91, "name": "Unrelated job",
            "status": "completed", "conclusion": "success"}]
        self.assertEqual(classify_supplied_hosted_run_jobs(run, duplicate_unrelated, sha, all_pages_verified=True), {})
        self.assertEqual(classify_supplied_hosted_run_jobs(run, jobs + [None], sha, all_pages_verified=True), {})
        self.assertEqual(classify_supplied_hosted_run_jobs(run, jobs + ["unknown"], sha, all_pages_verified=True), {})
        self.assertEqual(classify_supplied_hosted_run_jobs(run, jobs + [{"name": "unrelated"}], sha, all_pages_verified=True), {})
        unrelated_wrong_run = [dict(j) for j in jobs] + [{
            "id": 102, "run_id": 92, "name": "Unrelated job",
            "status": "completed", "conclusion": "success"}]
        self.assertEqual(classify_supplied_hosted_run_jobs(run, unrelated_wrong_run, sha, all_pages_verified=True), {})
        class EqualString(str):
            pass
        for field in ("status", "conclusion"):
            unrelated_polymorphic = [dict(j) for j in jobs] + [{
                "id": 102, "run_id": 91, "name": "Unrelated job",
                "status": "completed", "conclusion": "success"}]
            unrelated_polymorphic[2][field] = EqualString(unrelated_polymorphic[2][field])
            self.assertEqual(classify_supplied_hosted_run_jobs(run, unrelated_polymorphic, sha, all_pages_verified=True), {})
        for malformed in (None, "", "   ", 123, True):
            unrelated_name = [dict(j) for j in jobs] + [{
                "id": 102, "run_id": 91, "name": malformed,
                "status": "completed", "conclusion": "success"}]
            self.assertEqual(classify_supplied_hosted_run_jobs(run, unrelated_name, sha, all_pages_verified=True), {})
        for key, bad in (("status", "queued"), ("conclusion", "failure"),
                         ("status", None), ("conclusion", None)):
            unrelated_bad = [dict(j) for j in jobs] + [{
                "id": 102, "run_id": 91, "name": "Unrelated job",
                "status": "completed", "conclusion": "success"}]
            unrelated_bad[2][key] = bad
            self.assertEqual(classify_supplied_hosted_run_jobs(run, unrelated_bad, sha, all_pages_verified=True), {})
        class EqualString(str):
            pass
        for key in ("status", "conclusion"):
            poisoned_run = dict(run)
            poisoned_run[key] = EqualString(poisoned_run[key])
            self.assertEqual(classify_supplied_hosted_run_jobs(poisoned_run, jobs, sha, all_pages_verified=True), {})
            poisoned_jobs = [dict(job) for job in jobs]
            poisoned_jobs[0][key] = EqualString(poisoned_jobs[0][key])
            self.assertEqual(classify_supplied_hosted_run_jobs(run, poisoned_jobs, sha, all_pages_verified=True), {})
        self.assertNotIn("permanent_vps", expected)
        for mutation in ("queued", "failure"):
            changed = dict(run)
            changed["status" if mutation == "queued" else "conclusion"] = mutation
            self.assertEqual(classify_supplied_hosted_run_jobs(changed, jobs, sha, all_pages_verified=True), {})
        for index, key, wrong in ((0, "run_id", 92), (1, "conclusion", "failure"),
                                  (0, "name", "Permanent VPS Python 3.11"),
                                  (1, "id", 100)):
            changed = [dict(j) for j in jobs]
            changed[index][key] = wrong
            self.assertEqual(classify_supplied_hosted_run_jobs(run, changed, sha, all_pages_verified=True), {})
        self.assertEqual(classify_supplied_hosted_run_jobs(run, jobs, "b" * 40, all_pages_verified=True), {})

    def test_artifact_url_rejects_spoofed_or_ambiguous_locations(self):
        self.assertTrue(_valid_artifact_url("https://evidence.example.org/evidence"))
        for candidate in (
            "https://github.com@evil.example.org/artifact",
            "https://EVIDENCE.example.org/artifact",
            "https://evidence.example.org./artifact",
            "https://évidence.example.org/artifact",
            "https://evidence.example.org\\artifact",
            "https://evidence.example.org%2f.evil.test/artifact",
            "https://evidence.example.org:443/artifact",
            "https://evidence.example.org/artifact?override=true",
            "https://evidence.example.org/artifact#fragment",
            "https://evidence.example.org/",
            "https://example.invalid/artifact",
            "https://evidence.example.org/artifact\n",
            "http://evidence.example.org/artifact",
            None,
        ):
            with self.subTest(candidate=candidate):
                self.assertFalse(_valid_artifact_url(candidate))

    def test_unknown_evidence_cannot_activate_targets(self):
        import copy
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertFalse(is_release_evidence_complete(manifest))
        for field, value in (
            ("release_gate", "REVIEWED"),
            ("real_target_activation", True),
            ("owner_review_url", "https://github.com/example/repo/pull/1"),
        ):
            with self.subTest(field=field):
                candidate = copy.deepcopy(manifest)
                candidate[field] = value
                self.assertFalse(is_release_evidence_complete(candidate))

    def test_ci_job_identifiers_cannot_be_swapped_or_reused(self):
        """Job IDs alone are untrusted; even structural evidence needs strict lane binding."""
        sha = "a" * 40
        run_url = "https://github.com/example/repo/actions/runs/1"
        run = {"sha": sha, "conclusion": "success", "run_url": run_url}
        trace = {"sha": sha, "artifact_url": "https://evidence.example.org/evidence"}
        valid = {
            "schema_version": 2, "release_gate": "REVIEWED",
            "real_target_activation": False, "implementation_sha": sha,
            "owner_review_url": "https://github.com/example/repo/pull/1",
            "hosted_python_311": {**run, "job_id": 111},
            "hosted_python_314": {**run, "job_id": 114},
            "permanent_vps": {**run, "run_url": "https://github.com/example/repo/actions/runs/2", "job_id": 200},
            "negative_real_executor_trace": {**trace, **{key: 0 for key in COUNTERS}},
            "positive_loopback_lab_trace": {**trace, "handler_calls": 1},
            "persistent_revocation_proof": dict(trace),
            "trusted_destination_metadata_proof": dict(trace),
        }
        self.assertTrue(is_release_evidence_complete(valid))
        for lane in ("hosted_python_314", "permanent_vps"):
            mutated = json.loads(json.dumps(valid))
            mutated[lane]["job_id"] = 111
            self.assertFalse(is_release_evidence_complete(mutated), lane)
        for lane in ("hosted_python_311", "hosted_python_314", "permanent_vps"):
            mutated = json.loads(json.dumps(valid))
            mutated[lane]["job_id"] = "111"
            self.assertFalse(is_release_evidence_complete(mutated), lane)

    def test_observed_hosted_job_names_are_not_vps_proof(self):
        """Observed run/job identity is not an authorization grant."""
        observed = (
            {"id": 113817670080, "name": "Offline preflight Python 3.14 (not VPS proof)",
             "status": "in_progress", "conclusion": None},
            {"id": 113817670400, "name": "Offline preflight Python 3.11 (not VPS proof)",
             "status": "in_progress", "conclusion": None},
        )
        for job in observed:
            with self.subTest(job_id=job["id"]):
                self.assertNotEqual(job["conclusion"], "success")
                self.assertIn("not VPS proof", job["name"])
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertIsNone(manifest["permanent_vps"]["job_id"])
        self.assertFalse(is_release_evidence_complete(manifest))

    def test_observed_jobs_fail_closed_without_authenticated_evidence(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertFalse(verify_observed_ci_jobs(manifest, {}))
        self.assertFalse(verify_observed_ci_jobs(manifest, None))
        self.assertFalse(verify_observed_ci_jobs(manifest, {
            "hosted_python_311": {"status": "completed", "conclusion": "success"},
            "hosted_python_314": {"status": "completed", "conclusion": "success"},
            "permanent_vps": {"status": "completed", "conclusion": "success"},
        }))

    def test_observed_job_comparison_positive_and_negative_controls(self):
        sha = "a" * 40
        trace = {"sha": sha, "artifact_url": "https://evidence.example.org/evidence"}
        base_run = {"sha": sha, "conclusion": "success",
                    "run_url": "https://github.com/example/repo/actions/runs/1"}
        manifest = {
            "schema_version": 2, "release_gate": "REVIEWED",
            "real_target_activation": False, "implementation_sha": sha,
            "owner_review_url": "https://github.com/example/repo/pull/1",
            "hosted_python_311": {**base_run, "job_id": 11},
            "hosted_python_314": {**base_run, "job_id": 12},
            "permanent_vps": {**base_run, "job_id": 13,
                "run_url": "https://github.com/example/repo/actions/runs/2"},
            "negative_real_executor_trace": {**trace, **{k: 0 for k in COUNTERS}},
            "positive_loopback_lab_trace": {**trace, "handler_calls": 1},
            "persistent_revocation_proof": trace.copy(),
            "trusted_destination_metadata_proof": trace.copy(),
        }
        self.assertTrue(is_release_evidence_complete(manifest))
        observed = {}
        for name, version, runner in (
            ("hosted_python_311", "3.11", "hosted"),
            ("hosted_python_314", "3.14", "hosted"),
            ("permanent_vps", "3.11", "permanent_vps"),
        ):
            expected = manifest[name]
            observed[name] = {
                "job_id": expected["job_id"], "run_url": expected["run_url"],
                "sha": sha, "status": "completed", "conclusion": "success",
                "python_version": version, "runner_class": runner,
                "job_name": "Offline preflight Python " + version if runner == "hosted" else "Permanent VPS Python " + version,
                "run_id": int(expected["run_url"].rsplit("/", 1)[-1]),
            }
        self.assertTrue(verify_observed_ci_jobs(manifest, observed))
        wrong_run_id = json.loads(json.dumps(observed))
        wrong_run_id["permanent_vps"]["run_id"] = 1
        self.assertFalse(verify_observed_ci_jobs(manifest, wrong_run_id))
        boolean_run_id = json.loads(json.dumps(observed))
        boolean_run_id["hosted_python_311"]["run_id"] = True
        self.assertFalse(verify_observed_ci_jobs(manifest, boolean_run_id))
        marked = json.loads(json.dumps(observed))
        misleading = json.loads(json.dumps(observed))
        misleading["permanent_vps"]["job_name"] = "Permanent VPS Python 3.11"
        misleading["permanent_vps"]["runner_class"] = "hosted"
        self.assertFalse(verify_observed_ci_jobs(manifest, misleading))
        marked["permanent_vps"]["job_name"] = "Offline preflight Python 3.11 (not VPS proof)"
        self.assertFalse(verify_observed_ci_jobs(manifest, marked))
        wrong_version_name = json.loads(json.dumps(observed))
        wrong_version_name["hosted_python_311"]["job_name"] = "Offline preflight Python 3.14"
        self.assertFalse(verify_observed_ci_jobs(manifest, wrong_version_name))
        suffix_spoof = json.loads(json.dumps(observed))
        suffix_spoof["hosted_python_311"]["job_name"] = "Offline preflight Python 3.110"
        self.assertFalse(verify_observed_ci_jobs(manifest, suffix_spoof))
        prefix_spoof = json.loads(json.dumps(observed))
        prefix_spoof["hosted_python_311"]["job_name"] = "Offline preflight MyPython 3.11"
        self.assertFalse(verify_observed_ci_jobs(manifest, prefix_spoof))

        preflight = json.loads(json.dumps(observed))
        preflight["permanent_vps"]["job_name"] = "Offline preflight Python 3.11"
        self.assertFalse(verify_observed_ci_jobs(manifest, preflight))
        misleading_case = json.loads(json.dumps(observed))
        misleading_case["permanent_vps"]["job_name"] = "OFFLINE PREFLIGHT PYTHON 3.11"
        self.assertFalse(verify_observed_ci_jobs(manifest, misleading_case))
        unknown = json.loads(json.dumps(observed))
        unknown["permanent_vps"]["job_name"] = " "
        self.assertFalse(verify_observed_ci_jobs(manifest, unknown))

        for lane in ("hosted_python_311", "hosted_python_314", "permanent_vps"):
            missing = json.loads(json.dumps(observed))
            missing.pop(lane)
            self.assertFalse(verify_observed_ci_jobs(manifest, missing), lane)
            extra = json.loads(json.dumps(observed))
            extra[lane]["untrusted_override"] = "success"
            self.assertFalse(verify_observed_ci_jobs(manifest, extra), lane)
        top_extra = json.loads(json.dumps(observed))
        top_extra["override"] = {"conclusion": "success"}
        self.assertFalse(verify_observed_ci_jobs(manifest, top_extra))
        swapped = json.loads(json.dumps(observed))
        swapped["hosted_python_311"], swapped["hosted_python_314"] = (
            swapped["hosted_python_314"], swapped["hosted_python_311"])
        self.assertFalse(verify_observed_ci_jobs(manifest, swapped))
        for lane in ("hosted_python_311", "hosted_python_314", "permanent_vps"):
            for key, bad in (("job_id", True), ("job_id", False),
                             ("job_id", 11.0), ("run_url", None),
                             ("sha", None), ("status", True),
                             ("conclusion", True), ("python_version", True),
                             ("runner_class", True)):
                malformed = json.loads(json.dumps(observed))
                malformed[lane][key] = bad
                with self.subTest(lane=lane, key=key, malformed=repr(bad)):
                    self.assertFalse(verify_observed_ci_jobs(manifest, malformed))
        for lane, key, bad in (
            ("hosted_python_311", "python_version", "3.14"),
            ("hosted_python_314", "runner_class", "permanent_vps"),
            ("permanent_vps", "runner_class", "hosted"),
            ("permanent_vps", "status", "queued"),
            ("permanent_vps", "conclusion", "failure"),
            ("permanent_vps", "sha", "b" * 40),
            ("permanent_vps", "job_id", 99),
        ):
            mutated = json.loads(json.dumps(observed))
            mutated[lane][key] = bad
            with self.subTest(lane=lane, field=key):
                self.assertFalse(verify_observed_ci_jobs(manifest, mutated))

    def test_snapshot_subclass_values_never_count_as_verified(self):
        class DeceptiveString(str):
            pass
        sha = "a" * 40
        run = {"sha": sha, "conclusion": "success",
               "run_url": "https://github.com/example/repo/actions/runs/1"}
        trace = {"sha": sha, "artifact_url": "https://evidence.example.org/evidence"}
        manifest = {
            "schema_version": 2, "release_gate": "REVIEWED",
            "real_target_activation": False, "implementation_sha": sha,
            "owner_review_url": "https://github.com/example/repo/pull/1",
            "hosted_python_311": {**run, "job_id": 11},
            "hosted_python_314": {**run, "job_id": 12},
            "permanent_vps": {**run, "job_id": 13,
                "run_url": "https://github.com/example/repo/actions/runs/2"},
            "negative_real_executor_trace": {**trace, **{key: 0 for key in COUNTERS}},
            "positive_loopback_lab_trace": {**trace, "handler_calls": 1},
            "persistent_revocation_proof": dict(trace),
            "trusted_destination_metadata_proof": dict(trace),
        }
        observed = {}
        for lane, version, runner in (
            ("hosted_python_311", "3.11", "hosted"),
            ("hosted_python_314", "3.14", "hosted"),
            ("permanent_vps", "3.11", "permanent_vps"),
        ):
            expected = manifest[lane]
            observed[lane] = {
                "job_id": expected["job_id"], "run_url": expected["run_url"],
                "sha": sha, "status": "completed", "conclusion": "success",
                "python_version": version, "runner_class": runner,
                "job_name": "Offline preflight Python " + version if runner == "hosted" else "Permanent VPS Python " + version,
                "run_id": int(expected["run_url"].rsplit("/", 1)[-1]),
            }
        self.assertTrue(verify_observed_ci_jobs(manifest, observed))
        for field in ("status", "conclusion", "python_version", "runner_class",
                      "run_url", "sha"):
            changed = {name: dict(item) for name, item in observed.items()}
            changed["hosted_python_311"][field] = DeceptiveString(changed["hosted_python_311"][field])
            self.assertFalse(verify_observed_ci_jobs(manifest, changed), field)

    def test_polymorphic_manifest_sha_and_success_never_count(self):
        class EqualString(str):
            pass
        sha = "a" * 40
        run = {"sha": sha, "conclusion": "success",
               "run_url": "https://github.com/example/repo/actions/runs/1"}
        artifact = {"sha": sha, "artifact_url": "https://evidence.example.org/evidence"}
        valid = {
            "schema_version": 2, "release_gate": "REVIEWED", "real_target_activation": False,
            "implementation_sha": sha, "owner_review_url": "https://github.com/example/repo/pull/1",
            "hosted_python_311": {**run, "job_id": 11},
            "hosted_python_314": {**run, "job_id": 12},
            "permanent_vps": {**run, "job_id": 13,
                              "run_url": "https://github.com/example/repo/actions/runs/2"},
            "negative_real_executor_trace": {**artifact, **{k: 0 for k in COUNTERS}},
            "positive_loopback_lab_trace": {**artifact, "handler_calls": 1},
            "persistent_revocation_proof": artifact.copy(),
            "trusted_destination_metadata_proof": artifact.copy(),
        }
        self.assertTrue(is_release_evidence_complete(valid))
        for lane in ("hosted_python_311", "hosted_python_314", "permanent_vps"):
            for key in ("sha", "conclusion"):
                changed = {k: (dict(v) if type(v) is dict else v) for k, v in valid.items()}
                changed[lane][key] = EqualString(changed[lane][key])
                self.assertFalse(is_release_evidence_complete(changed), (lane, key))
        for lane in ("negative_real_executor_trace", "positive_loopback_lab_trace",
                     "persistent_revocation_proof", "trusted_destination_metadata_proof"):
            changed = {k: (dict(v) if type(v) is dict else v) for k, v in valid.items()}
            changed[lane]["sha"] = EqualString(sha)
            self.assertFalse(is_release_evidence_complete(changed), lane)

    def test_manifest_gate_rejects_boolean_and_polymorphic_state(self):
        class EqualString(str):
            pass
        sha = "a" * 40
        run = {"sha": sha, "conclusion": "success",
               "run_url": "https://github.com/example/repo/actions/runs/1"}
        trace = {"sha": sha, "artifact_url": "https://evidence.example.org/evidence"}
        valid = {
            "schema_version": 2, "release_gate": "REVIEWED",
            "real_target_activation": False, "implementation_sha": sha,
            "owner_review_url": "https://github.com/example/repo/pull/1",
            "hosted_python_311": {**run, "job_id": 11},
            "hosted_python_314": {**run, "job_id": 12},
            "permanent_vps": {**run, "job_id": 13,
                "run_url": "https://github.com/example/repo/actions/runs/2"},
            "negative_real_executor_trace": {**trace, **{k: 0 for k in COUNTERS}},
            "positive_loopback_lab_trace": {**trace, "handler_calls": 1},
            "persistent_revocation_proof": dict(trace),
            "trusted_destination_metadata_proof": dict(trace),
        }
        self.assertTrue(is_release_evidence_complete(valid))
        for field, bad in (("release_gate", EqualString("REVIEWED")),
                           ("schema_version", True),
                           ("implementation_sha", EqualString(sha)),
                           ("real_target_activation", True)):
            changed = dict(valid)
            changed[field] = bad
            self.assertFalse(is_release_evidence_complete(changed), field)

    def test_unverified_snapshots_never_change_persisted_hold_manifest(self):
        import copy
        original = json.loads(MANIFEST.read_text(encoding="utf-8"))
        before = copy.deepcopy(original)
        self.assertFalse(verify_observed_ci_jobs(original, {}))
        self.assertEqual(original, before)
        self.assertEqual(original["release_gate"], "HOLD")
        self.assertIs(original["real_target_activation"], False)
        for lane in ("hosted_python_311", "hosted_python_314", "permanent_vps"):
            self.assertIsNone(original[lane]["conclusion"])

    def test_manifest_unknown_ci_does_not_accept_fabricated_success(self):
        original = json.loads(MANIFEST.read_text(encoding="utf-8"))
        fake_success = {}
        for lane, version, klass in (
            ("hosted_python_311", "3.11", "hosted"),
            ("hosted_python_314", "3.14", "hosted"),
            ("permanent_vps", "3.11", "permanent_vps"),
        ):
            fake_success[lane] = {
                "job_id": 1, "run_url": "https://github.com/example/repo/actions/runs/1",
                "sha": "a" * 40, "status": "completed", "conclusion": "success",
                "python_version": version, "runner_class": klass,
                "job_name": "Offline preflight Python " + version if klass == "hosted" else "Permanent VPS Python " + version,
                "run_id": 1 if klass == "hosted" else 2,
            }
        self.assertFalse(verify_observed_ci_jobs(original, fake_success))
        self.assertFalse(is_release_evidence_complete(original))

    def test_current_manifest_is_explicitly_held_and_incomplete(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(manifest["release_gate"], "HOLD")
        self.assertIs(manifest["real_target_activation"], False)
        self.assertFalse(is_release_evidence_complete(manifest))

    def test_synthetic_complete_evidence_does_not_activate_targets(self):
        sha = "a" * 40
        run = {"sha": sha, "conclusion": "success",
               "run_url": "https://github.com/example/repo/actions/runs/1"}
        trace = {"sha": sha, "artifact_url": "https://evidence.example.org/evidence"}
        manifest = {
            "schema_version": 2, "release_gate": "REVIEWED", "implementation_sha": sha,
            "real_target_activation": False,
            "owner_review_url": "https://github.com/example/repo/pull/1",
            "hosted_python_311": {**run, "job_id": 11},
            "hosted_python_314": {**run, "job_id": 12},
            "permanent_vps": {**run, "job_id": 13, "run_url": "https://github.com/example/repo/actions/runs/3"},
            "negative_real_executor_trace": {**trace, **{key: 0 for key in COUNTERS}},
            "positive_loopback_lab_trace": {**trace, "handler_calls": 1},
            "persistent_revocation_proof": trace.copy(),
            "trusted_destination_metadata_proof": trace.copy(),
        }
        self.assertTrue(is_release_evidence_complete(manifest))
        changed = json.loads(json.dumps(manifest))
        changed["hosted_python_314"]["job_id"] = changed["hosted_python_311"]["job_id"]
        self.assertFalse(is_release_evidence_complete(changed))
        changed = json.loads(json.dumps(manifest))
        changed["hosted_python_314"]["run_url"] = "https://github.com/example/repo/actions/runs/2"
        self.assertFalse(is_release_evidence_complete(changed))
        changed = json.loads(json.dumps(manifest))
        changed["permanent_vps"]["run_url"] = "https://github.com/example/repo/actions/runs/3/extra"
        self.assertFalse(is_release_evidence_complete(changed))
        for invalid_id in (None, True, 0, -1, "12", 11):
            changed = json.loads(json.dumps(manifest))
            changed["hosted_python_314"]["job_id"] = invalid_id
            self.assertFalse(is_release_evidence_complete(changed), invalid_id)
        for status in ("HOLD", "PENDING", None, True):
            changed = json.loads(json.dumps(manifest))
            changed["release_gate"] = status
            self.assertFalse(is_release_evidence_complete(changed), status)
        changed = json.loads(json.dumps(manifest))
        changed["schema_version"] = True
        self.assertFalse(is_release_evidence_complete(changed))
        for key in COUNTERS:
            changed = json.loads(json.dumps(manifest))
            changed["negative_real_executor_trace"][key] = None
            self.assertFalse(is_release_evidence_complete(changed), key)
            changed["negative_real_executor_trace"][key] = 1
            self.assertFalse(is_release_evidence_complete(changed), key)
        for name in ("hosted_python_311", "hosted_python_314", "permanent_vps"):
            changed = json.loads(json.dumps(manifest))
            changed[name]["sha"] = "b" * 40
            self.assertFalse(is_release_evidence_complete(changed), name)
        changed = json.loads(json.dumps(manifest))
        changed["real_target_activation"] = True
        self.assertFalse(is_release_evidence_complete(changed))
        for value in (True, False, "0", -1, None):
            changed = json.loads(json.dumps(manifest))
            changed["negative_real_executor_trace"]["handler_calls"] = value
            self.assertFalse(is_release_evidence_complete(changed))
        for field in ("positive_loopback_lab_trace", "persistent_revocation_proof",
                      "trusted_destination_metadata_proof"):
            changed = json.loads(json.dumps(manifest))
            changed.pop(field)
            self.assertFalse(is_release_evidence_complete(changed), field)
            changed = json.loads(json.dumps(manifest))
            changed[field]["sha"] = "b" * 40
            self.assertFalse(is_release_evidence_complete(changed), field)
        for conclusion in ("queued", "cancelled", "skipped", "failure", None):
            changed = json.loads(json.dumps(manifest))
            changed["permanent_vps"]["conclusion"] = conclusion
            self.assertFalse(is_release_evidence_complete(changed), conclusion)
        changed = json.loads(json.dumps(manifest))
        changed["positive_loopback_lab_trace"]["handler_calls"] = True
        self.assertFalse(is_release_evidence_complete(changed))
        changed = json.loads(json.dumps(manifest))
        changed["owner_review_url"] = None
        self.assertFalse(is_release_evidence_complete(changed))
        for url in ("https://github.com.evil.invalid/example/repo/pull/1",
                    "https://github.com@example.invalid/example/repo/pull/1",
                    "http://github.com/example/repo/pull/1",
                    "https://github.com/example/repo/pull/1?fake=1"):
            changed = json.loads(json.dumps(manifest))
            changed["owner_review_url"] = url
            self.assertFalse(is_release_evidence_complete(changed), url)
        changed = json.loads(json.dumps(manifest))
        changed["permanent_vps"]["run_url"] = "https://github.com/other/repo/actions/runs/3"
        self.assertFalse(is_release_evidence_complete(changed))
        for url in ("https://github.com.evil.invalid/example/repo/actions/runs/3",
                    "https://github.com/example/repo/actions/runs/3?redirect=1",
                    "https://github.com/example/repo/actions/runs/3#fragment",
                    "https://github.com/example/repo/actions/runs/0",
                    "https://github.com/example/repo/actions/runs/3/extra"):
            changed = json.loads(json.dumps(manifest))
            changed["permanent_vps"]["run_url"] = url
            self.assertFalse(is_release_evidence_complete(changed), url)
        changed = json.loads(json.dumps(manifest))
        changed["hosted_python_311"]["run_url"] = "https://github.com/other/repo/actions/runs/1"
        changed["hosted_python_314"]["run_url"] = "https://github.com/other/repo/actions/runs/1"
        self.assertFalse(is_release_evidence_complete(changed))



    def test_unknown_and_missing_top_level_evidence_fields_fail_closed(self):
        sha = "a" * 40
        run = {"sha": sha, "conclusion": "success",
               "run_url": "https://github.com/example/repo/actions/runs/1"}
        trace = {"sha": sha, "artifact_url": "https://evidence.example.org/evidence"}
        valid = {
            "schema_version": 2, "release_gate": "REVIEWED",
            "implementation_sha": sha, "real_target_activation": False,
            "owner_review_url": "https://github.com/example/repo/pull/1",
            "hosted_python_311": {**run, "job_id": 11},
            "hosted_python_314": {**run, "job_id": 12},
            "permanent_vps": {**run, "job_id": 13,
                "run_url": "https://github.com/example/repo/actions/runs/2"},
            "negative_real_executor_trace": {**trace, **{k: 0 for k in COUNTERS}},
            "positive_loopback_lab_trace": {**trace, "handler_calls": 1},
            "persistent_revocation_proof": trace.copy(),
            "trusted_destination_metadata_proof": trace.copy(),
        }
        self.assertTrue(is_release_evidence_complete(valid))
        for key in MANIFEST_KEYS:
            with self.subTest(missing=key):
                missing = dict(valid)
                del missing[key]
                self.assertFalse(is_release_evidence_complete(missing))
        extra = dict(valid)
        extra["review_override"] = True
        self.assertFalse(is_release_evidence_complete(extra))
        for name in ("hosted_python_311", "negative_real_executor_trace", "persistent_revocation_proof"):
            invalid = json.loads(json.dumps(valid))
            invalid[name]["override"] = True
            self.assertFalse(is_release_evidence_complete(invalid), name)

    def test_malformed_manifest_shapes_fail_closed_without_exceptions(self):
        """Untrusted evidence envelopes must never crash the release checker."""
        for payload in (None, True, False, 0, 1, "", [], (), "REVIEWED"):
            with self.subTest(payload=repr(payload)):
                self.assertFalse(is_release_evidence_complete(payload))

        sha = "a" * 40
        run = {"sha": sha, "conclusion": "success",
               "run_url": "https://github.com/example/repo/actions/runs/1"}
        trace = {"sha": sha, "artifact_url": "https://evidence.example.org/evidence"}
        raw = {
            "schema_version": 2, "release_gate": "REVIEWED",
            "implementation_sha": sha, "real_target_activation": False,
            "owner_review_url": "https://github.com/example/repo/pull/1",
            "hosted_python_311": {**run, "job_id": 11},
            "hosted_python_314": {**run, "job_id": 12},
            "permanent_vps": {**run, "job_id": 13,
                              "run_url": "https://github.com/example/repo/actions/runs/2"},
            "negative_real_executor_trace": {**trace, **{k: 0 for k in COUNTERS}},
            "positive_loopback_lab_trace": {**trace, "handler_calls": 1},
            "persistent_revocation_proof": trace.copy(),
            "trusted_destination_metadata_proof": trace.copy(),
        }
        self.assertTrue(is_release_evidence_complete(raw))
        for key in ("hosted_python_311", "hosted_python_314", "permanent_vps",
                    "negative_real_executor_trace", "positive_loopback_lab_trace",
                    "persistent_revocation_proof", "trusted_destination_metadata_proof"):
            for malformed in (None, [], "", 1, True):
                candidate = json.loads(json.dumps(raw))
                candidate[key] = malformed
                with self.subTest(field=key, shape=repr(malformed)):
                    self.assertFalse(is_release_evidence_complete(candidate))


if __name__ == "__main__":
    unittest.main()
