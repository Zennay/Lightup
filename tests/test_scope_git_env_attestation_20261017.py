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

    def test_real_disposable_git_dir_redirection(self):
        # Demonstrate, without altering a real project, that GIT_DIR and
        # GIT_WORK_TREE can redirect a dirty repository to a clean one.
        import tempfile
        with tempfile.TemporaryDirectory(prefix="scope_env_lab_", dir=ROOT) as dirname:
            parent = Path(dirname)
            dirty, clean = parent / "dirty", parent / "clean"
            dirty.mkdir()
            clean.mkdir()
            def git(directory, *args, env=None):
                return subprocess.run(
                    ["git", *args], cwd=directory, env=env, capture_output=True,
                    timeout=6, check=True,
                ).stdout
            for directory in (dirty, clean):
                git(directory, "init", "--quiet")
                git(directory, "-c", "user.name=Offline Reviewer",
                    "-c", "user.email=offline@example.invalid",
                    "commit", "-q", "--allow-empty", "-m", "fictional baseline")
            (dirty / "changed.txt").write_text("original")
            git(dirty, "add", "changed.txt")
            git(dirty, "-c", "user.name=Offline Reviewer",
                "-c", "user.email=offline@example.invalid",
                "commit", "-q", "-m", "fictional fixture")
            (dirty / "changed.txt").write_text("modified")
            self.assertIn(b"changed.txt", git(dirty, "status", "--porcelain"))
            redirect = dict(os.environ)
            redirect.update(GIT_DIR=str(clean / ".git"), GIT_WORK_TREE=str(clean))
            self.assertEqual(git(dirty, "status", "--porcelain", env=redirect), b"")
            self.assertEqual(module().review_environment(redirect)["status"], "HOLD")

    def test_static_source_has_no_executor_or_network_imports(self):
        import ast
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            if isinstance(node, ast.ImportFrom):
                imports.add(node.module)
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, {
                        "eval", "exec", "open", "__import__", "compile",
                    })
                if isinstance(node.func, ast.Attribute):
                    self.assertNotIn(node.func.attr, {
                        "system", "popen", "run", "Popen", "urlopen",
                        "write_text", "write_bytes",
                    })
        self.assertEqual(imports, {
            "__future__", "json", "os", "re", "sys", "collections.abc",
        })

    def test_dedicated_hosted_workflow_is_read_only(self):
        content = (ROOT / ".github" / "workflows" /
                   "scope-git-env-attestation-20261017.yml").read_text()
        self.assertIn("contents: read", content)
        self.assertIn("runs-on: ubuntu-latest", content)
        self.assertIn("['3.11', '3.14']", content)
        self.assertIn("persist-credentials: false", content)
        # Pinned base now lives in the separately owned mode validator,
        # not a mutable YAML inline implementation.
        source = (ROOT / "scripts/check_scope_git_env_tree_20261017.py").read_text()
        self.assertIn("7b9142bb9e9d5403d7a3e41914edddef4511c8a8", source)
        self.assertEqual(content.count("python scripts/check_scope_git_env_tree_20261017.py"), 2)
        self.assertIn("tests/test_scope_git_env_tree_20261017.py", content)
        self.assertNotIn("workflow_dispatch", content)
        self.assertNotIn("pull_request:", content)
        self.assertNotIn("contents: write", content)
        self.assertNotIn("self-hosted", content)

    def test_ci_attests_real_environment_before_git_checks(self):
        workflow = (ROOT / ".github" / "workflows" /
                    "scope-git-env-attestation-20261017.yml").read_text()
        check = "python scripts/scope_git_env_attestation_20261017.py"
        self.assertEqual(workflow.count(check), 2)
        first = workflow.index(check)
        last = workflow.rindex(check)
        self.assertLess(first, workflow.index("git rev-parse HEAD"))
        self.assertGreater(last, workflow.index("python -m unittest discover"))
        self.assertIn("test \"$review_rc\" -eq 2", workflow)
        self.assertIn("test \"$review_out\" = ", workflow)

    def test_runtime_loader_overrides_are_hold(self):
        # Dynamic loader and Python module search overrides can compromise
        # integrity of a Git or Python evidence process *before* its script runs.
        for key in (
            "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG",
            "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
            "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
            "PYTHONINSPECT",
        ):
            with self.subTest(name=key):
                value = module().review_environment({key: "/fictional-only"})
                self.assertEqual(value["status"], "HOLD")
                self.assertFalse(value["authorized"])
        self.assertEqual(module().review_environment(
            {"LD_LIBRARY_PATH": "", "HOME": "/tmp"}
        )["status"], "HOLD")

    def test_untrusted_mapping_iterator_errors_fail_closed(self):
        from collections.abc import Mapping
        class BadValues(Mapping):
            def __iter__(self):
                raise IndexError("fictional mapping error")
            def __len__(self):
                return 2
            def __getitem__(self, key):
                raise KeyError(key)
        self.assertEqual(module().review_environment(BadValues())["status"], "HOLD")

    def test_exact_github_python_toolcache_profile_is_non_authorizing(self):
        for version in ("3.11.17", "3.14.8"):
            with self.subTest(version=version):
                root = "/opt/hostedtoolcache/Python/" + version + "/x64"
                env = {
                    "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push",
                    "GITHUB_REF": "refs/heads/chatgpt/scope-auth-git-env-fence-20261017-0115",
                    "GITHUB_SHA": "a" * 40,
                    "RUNNER_OS": "Linux",
                    "pythonLocation": root, "Python_ROOT_DIR": root,
                    "LD_LIBRARY_PATH": root + "/lib",
                }
                receipt = module().review_environment(env)
                self.assertEqual(receipt["status"], "REVIEW_ONLY")
                self.assertTrue(all(receipt[k] is False for k in receipt if k != "status"))
                for key, bad in (
                    ("GITHUB_ACTIONS", "false"),
                    ("GITHUB_REF", "refs/pull/2/merge"),
                    ("GITHUB_SHA", "not-a-sha"),
                    ("RUNNER_OS", "Windows"),
                    ("Python_ROOT_DIR", root + "/elsewhere"),
                    ("LD_LIBRARY_PATH", root + "/lib:/tmp/inject"),
                    ("LD_LIBRARY_PATH", "/tmp/inject"),
                    ("pythonLocation", root + "/../other"),
                ):
                    with self.subTest(key=key, bad=bad):
                        self.assertEqual(
                            module().review_environment(dict(env, **{key: bad}))["status"],
                            "HOLD",
                        )
                self.assertEqual(
                    module().review_environment(dict(env, LD_PRELOAD="fictional.so"))["status"],
                    "HOLD",
                )

    def test_deceptive_environment_mapping_is_hold(self):
        from collections.abc import Mapping
        class HiddenOverride(Mapping):
            def __iter__(self):
                return iter(("GIT_DIR",))
            def __len__(self):
                return 1
            def __getitem__(self, name):
                return "fictional-git-path"
            def items(self):
                # An untrusted object can lie about the keys it reports.
                return {}.items()
        self.assertEqual(module().review_environment(HiddenOverride())["status"], "HOLD")
        class HiddenDict(dict):
            def items(self):
                return {}.items()
        self.assertEqual(module().review_environment(
            HiddenDict(GIT_DIR="fictional-git-path")
        )["status"], "HOLD")

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
