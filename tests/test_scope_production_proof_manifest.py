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
        if type(run) is not dict or set(run) != {"sha", "conclusion", "run_url", "job_id"} or run.get("sha") != sha or run.get("conclusion") != "success":
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
        if type(trace) is not dict or set(trace) != keys or trace.get("sha") != sha:
            return False
        if not _valid_artifact_url(trace.get("artifact_url")):
            return False
    for counter in COUNTERS:
        if type(negative.get(counter)) is not int or negative[counter] != 0:
            return False
    return type(positive.get("handler_calls")) is int and positive["handler_calls"] == 1


class ScopeProductionProofManifestTests(unittest.TestCase):
    def test_artifact_url_rejects_spoofed_or_ambiguous_locations(self):
        self.assertTrue(_valid_artifact_url("https://evidence.example.org/evidence"))
        for candidate in (
            "https://github.com@evil.example.org/artifact",
            "https://evidence.example.org:443/artifact",
            "https://evidence.example.org/artifact?override=true",
            "https://evidence.example.org/artifact#fragment",
            "https://evidence.example.org/",
            "https://example.invalid/artifact",
            "https://evidence.example.org/artifact\\n",
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
        trace = {"sha": sha, "artifact_url": "https://example.invalid/evidence"}
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
        trace = {"sha": sha, "artifact_url": "https://example.invalid/evidence"}
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
