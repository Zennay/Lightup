"""Adversarial synthetic Git environment tests; no real Git state mutation."""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/scope_git_env_attestation_20261017.py"


def module():
    spec = importlib.util.spec_from_file_location("git_env_review", SCRIPT)
    assert spec and spec.loader
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


class EnvironmentFenceTests(unittest.TestCase):
    def test_empty_is_only_review_never_authority(self):
        value = module().review_environment({})
        self.assertEqual(value["status"], "REVIEW_ONLY")
        self.assertEqual(set(value), {
            "status", "authorized", "consent_verified",
            "dispatch_allowed", "release_allowed",
        })
        self.assertTrue(all(value[k] is False for k in set(value)-{"status"}))

    def test_every_git_override_is_hold(self):
        names = (
            "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
            "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_NOSYSTEM", "GIT_NAMESPACE", "GIT_ATTR_SOURCE",
            "GIT_LITERAL_PATHSPECS", "GIT_CEILING_DIRECTORIES",
            "GIT_SSH_COMMAND", "GIT_TRACE", "GIT_UNKNOWN_FUTURE_SWITCH",
        )
        for name in names:
            for value in ("", "0", "sensitive-secret-123"):
                with self.subTest(name=name, value=value):
                    result = module().review_environment({name:value})
                    self.assertEqual(result["status"], "HOLD")
                    self.assertNotIn("sensitive-secret-123", json.dumps(result))

    def test_unrelated_context_is_not_claimed_as_authority(self):
        review = module().review_environment({"HOME":"/tmp/x", "GITHUB_REF":"refs/pull/1/merge"})
        self.assertEqual(review["status"], "REVIEW_ONLY")
        self.assertFalse(review["authorized"])

    def test_malformed_input_fails_closed(self):
        for value in (None, [], 123, {"GIT_DIR":None}, {1:"x"}):
            with self.subTest(value=repr(value)):
                self.assertEqual(module().review_environment(value)["status"], "HOLD")

    def test_cli_constant_output_no_secret_and_no_exit_zero(self):
        for name, rc, status in (
            (None, 2, "REVIEW_ONLY"), ("GIT_INDEX_FILE", 3, "HOLD"),
            ("GIT_CONFIG_COUNT", 3, "HOLD"),
        ):
            with self.subTest(name=name):
                env={"PATH":os.environ.get("PATH","/usr/bin")}
                if name:
                    env[name]="private-secret-12345"
                child=subprocess.run(
                    [sys.executable,str(SCRIPT)],env=env,cwd=ROOT,
                    capture_output=True,timeout=6,
                )
                self.assertEqual(child.returncode,rc)
                self.assertEqual(child.stderr,b"")
                self.assertNotIn(b"private-secret-12345",child.stdout)
                obj=json.loads(child.stdout)
                self.assertEqual(obj["status"],status)
                self.assertTrue(all(obj[k] is False for k in obj if k!="status"))

    def test_environment_limits_do_not_exhaust_attestation(self):
        review = module().review_environment
        for case in (
            {f"K{i}": "x" for i in range(513)},
            {"K" * 4097: "value"},
            {"SAFE": "x" * 8193},
            {"KEY": "value", "GIT_DIR": ""},
        ):
            with self.subTest(items=len(case)):
                self.assertEqual(review(case)["status"], "HOLD")

    def test_potentially_hostile_mapping_fails_closed(self):
        from collections.abc import Mapping
        class Broken(Mapping):
            def __iter__(self): raise RuntimeError("broken iterable")
            def __len__(self): return 1
            def __getitem__(self, key): raise ValueError("broken lookup")
        self.assertEqual(module().review_environment(Broken())["status"], "HOLD")

    def test_cli_disallows_grant_switch(self):
        child=subprocess.run(
            [sys.executable,str(SCRIPT),"--grant"],
            env={"PATH":os.environ.get("PATH","/usr/bin")},
            capture_output=True,timeout=6,
        )
        self.assertEqual(child.returncode,3)
        self.assertEqual(json.loads(child.stdout)["status"],"HOLD")


if __name__=="__main__":
    unittest.main()
