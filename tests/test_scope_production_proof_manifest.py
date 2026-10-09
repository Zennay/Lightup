"""Fail-closed, offline release-evidence gate; never dispatches any tools or network."""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

MANIFEST = Path(__file__).resolve().parents[1] / "docs" / "scope-production-proof-manifest-20261009.json"
SHA = re.compile(r"^[0-9a-f]{40}$")
COUNTERS = ("handler_calls", "dns_calls", "socket_opens", "http_calls",
            "subprocess_calls", "retry_submissions", "queue_submissions",
            "action_evidence_writes")


def is_release_evidence_complete(m: dict) -> bool:
    if type(m) is not dict or type(m.get("schema_version")) is not int or m["schema_version"] != 1:
        return False
    if m.get("release_gate") != "REVIEWED":
        return False
    sha = m.get("implementation_sha")
    if type(sha) is not str or not SHA.fullmatch(sha):
        return False
    if m.get("real_target_activation") is not False:
        return False  # evidence approval never flips activation
    if not isinstance(m.get("owner_review_url"), str) or not m["owner_review_url"].startswith("https://github.com/"):
        return False
    run_urls = set()
    for name in ("hosted_python_311", "hosted_python_314", "permanent_vps"):
        run = m.get(name)
        if type(run) is not dict or run.get("sha") != sha or run.get("conclusion") != "success":
            return False
        if type(run.get("run_url")) is not str or not re.fullmatch(r"https://github\.com/[^/]+/[^/]+/actions/runs/[1-9][0-9]*", run["run_url"]):
            return False
        if run["run_url"] in run_urls:
            return False
        run_urls.add(run["run_url"])
    negative = m.get("negative_real_executor_trace")
    positive = m.get("positive_loopback_lab_trace")
    for trace in (negative, positive, m.get("persistent_revocation_proof"),
                  m.get("trusted_destination_metadata_proof")):
        if type(trace) is not dict or trace.get("sha") != sha:
            return False
        if not isinstance(trace.get("artifact_url"), str) or not trace["artifact_url"].startswith("https://"):
            return False
    for counter in COUNTERS:
        if type(negative.get(counter)) is not int or negative[counter] != 0:
            return False
    return type(positive.get("handler_calls")) is int and positive["handler_calls"] == 1


class ScopeProductionProofManifestTests(unittest.TestCase):
    def test_current_manifest_is_explicitly_held_and_incomplete(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(manifest["release_gate"], "HOLD")
        self.assertIs(manifest["real_target_activation"], False)
        self.assertFalse(is_release_evidence_complete(manifest))

    def test_synthetic_complete_evidence_does_not_activate_targets(self):
        sha = "a" * 40
        run = {"sha": sha, "conclusion": "success",
               "run_url": "https://github.com/example/repo/actions/runs/1"}
        trace = {"sha": sha, "artifact_url": "https://example.invalid/evidence"}
        manifest = {
            "schema_version": 1, "release_gate": "REVIEWED", "implementation_sha": sha,
            "real_target_activation": False,
            "owner_review_url": "https://github.com/example/repo/pull/1",
            "hosted_python_311": {**run, "run_url": "https://github.com/example/repo/actions/runs/1"},
            "hosted_python_314": {**run, "run_url": "https://github.com/example/repo/actions/runs/2"},
            "permanent_vps": {**run, "run_url": "https://github.com/example/repo/actions/runs/3"},
            "negative_real_executor_trace": {**trace, **{key: 0 for key in COUNTERS}},
            "positive_loopback_lab_trace": {**trace, "handler_calls": 1},
            "persistent_revocation_proof": trace.copy(),
            "trusted_destination_metadata_proof": trace.copy(),
        }
        self.assertTrue(is_release_evidence_complete(manifest))
        changed = json.loads(json.dumps(manifest))
        changed["hosted_python_314"]["run_url"] = changed["hosted_python_311"]["run_url"]
        self.assertFalse(is_release_evidence_complete(changed))
        changed = json.loads(json.dumps(manifest))
        changed["permanent_vps"]["run_url"] = "https://github.com/example/repo/actions/runs/3/extra"
        self.assertFalse(is_release_evidence_complete(changed))
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


if __name__ == "__main__":
    unittest.main()
