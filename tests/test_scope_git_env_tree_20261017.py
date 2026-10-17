"""Adversarial synthetic Git tree mode proof. Never touches a real Git tree."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

FILE = Path(__file__).resolve().parents[1] / "scripts/check_scope_git_env_tree_20261017.py"
spec = importlib.util.spec_from_file_location("test_owned_tree", FILE)
assert spec and spec.loader
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

PATHS = sorted(guard.OWNED)
OID = b"a" * 40


def delta(paths=PATHS, status=b"A"):
    return b"".join(status + b"\0" + p.encode() + b"\0" for p in paths)


def tree(paths=PATHS, mode=b"100644", kind=b"blob", oid=OID):
    return b"".join(mode + b" " + kind + b" " + oid
                    + b"\t" + p.encode() + b"\0" for p in paths)


class OfflineTreeModesTests(unittest.TestCase):
    def test_all_five_new_regular_git_blobs_pass(self):
        self.assertEqual(len(guard.OWNED), 6)
        self.assertTrue(guard.safe_tree(tree(), delta()))

    def test_symlinks_executables_gitlinks_and_mismatched_objects_hold(self):
        for mode, kind in (
            (b"120000", b"blob"), (b"100755", b"blob"),
            (b"160000", b"commit"), (b"040000", b"tree"),
            (b"100644", b"commit"), (b"100664", b"blob"),
        ):
            with self.subTest(mode=mode, kind=kind):
                self.assertFalse(guard.safe_tree(tree(mode=mode, kind=kind), delta()))

    def test_diff_must_be_exactly_new_owned_files(self):
        self.assertTrue(guard.parse_additions(delta()) == guard.OWNED)
        cases = (
            delta()[:-1],
            delta() + delta()[:20],
            delta(PATHS[:-1]),
            delta(PATHS + ["src/lightup/scope.py"]),
            delta(status=b"M"),
            delta() + b"A\0src/lightup/scope.py\0",
            delta() + b" " * 9000,
            delta().replace(b"scripts", b"scr\xffpts"),
        )
        for raw in cases:
            with self.subTest(raw=raw[:65]):
                self.assertIsNone(guard.parse_additions(raw))
                self.assertFalse(guard.safe_tree(tree(), raw))

    def test_tree_metadata_must_be_exact_and_unique(self):
        valid = tree()
        bad = (
            valid[:-1],
            valid + valid,
            tree(oid=b"g" * 40),
            tree(oid=b"a" * 64),
            tree(paths=PATHS[:-1]),
            tree(paths=PATHS[:-1] + [PATHS[-2]]),
            tree().replace(b"scripts", b"scr\xffpts"),
            valid + b"\0" * 18000,
        )
        for raw in bad:
            with self.subTest(raw=raw[:65]):
                self.assertFalse(guard.safe_tree(raw, delta()))

    def test_original_status_ignores_submodules_on_synthetic_success(self):
        """No inherited fsmonitor/filter execution in nested repositories."""
        from subprocess import CompletedProcess
        from contextlib import redirect_stdout
        from unittest.mock import patch
        import io
        calls = []
        sha = "a" * 40
        expected = {
            "status": b"", "rev-parse": sha.encode() + b"\n",
            "merge-base": b"", "diff": delta(), "ls-tree": tree(),
        }
        def fake_git(*args):
            calls.append(args)
            payload = (
                str(guard.ROOT.resolve()).encode() + b"\n"
                if args[:2] == ("rev-parse", "--show-toplevel")
                else expected[args[0]]
            )
            return CompletedProcess(args, 0, payload, b"")
        env = {
            "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": "refs/heads/" + guard.BRANCH,
            "GITHUB_SHA": sha,
        }
        with patch.object(guard, "git", side_effect=fake_git):
            with patch.dict(guard.os.environ, env, clear=True):
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(guard.main(), 0)
        status = [call for call in calls if call[0] == "status"]
        self.assertEqual(len(status), 1)
        self.assertIn("--ignore-submodules=all", status[0])

    def test_main_exact_push_and_tampered_modes(self):
        from subprocess import CompletedProcess
        from contextlib import redirect_stdout
        from unittest.mock import patch
        import io
        sha = "a" * 40
        event = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": "refs/heads/" + guard.BRANCH,
            "GITHUB_SHA": sha,
        }
        expected = {
            "status": b"",
            "rev-parse": sha.encode() + b"\n",
            "merge-base": b"",
            "diff": delta(),
            "ls-tree": tree(),
        }
        def fake_git(*argv):
            name = argv[0]
            data = (
                str(guard.ROOT.resolve()).encode("utf8") + b"\n"
                if argv[:2] == ("rev-parse", "--show-toplevel")
                else expected[name]
            )
            return CompletedProcess(argv, 0, data, b"")
        with patch.object(guard, "git", side_effect=fake_git):
            with patch.dict(guard.os.environ, event, clear=True):
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(guard.main(), 0)
                self.assertEqual(output.getvalue().strip(), "scope_env_owned_tree=PASS")
            with patch.dict(guard.os.environ, dict(event, GITHUB_SHA="b" * 40), clear=True):
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(guard.main(), 3)
                self.assertEqual(output.getvalue().strip(), "scope_env_owned_tree=HOLD")
            with patch.dict(guard.os.environ, dict(event, GIT_DIR="/fake"), clear=True):
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(guard.main(), 3)
                self.assertEqual(output.getvalue().strip(), "scope_env_owned_tree=HOLD")
            expected["ls-tree"] = tree(mode=b"120000")
            with patch.dict(guard.os.environ, event, clear=True):
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(guard.main(), 3)
                self.assertEqual(output.getvalue().strip(), "scope_env_owned_tree=HOLD")

    def test_real_disposable_git_mode_transitions(self):
        """Read real Git object modes in a temporary, never-live repository."""
        import os
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory(prefix="scope_env_git_modes_", dir=FILE.parents[1]) as tmp:
            root = Path(tmp)
            def git(*argv):
                return subprocess.run(
                    ["git", *argv], cwd=root, check=True,
                    capture_output=True, timeout=6,
                ).stdout
            git("init", "-q")
            for path in PATHS:
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("fictional, offline, no authority")
            git("add", ".")
            git("-c", "user.name=Offline Reviewer",
                "-c", "user.email=offline@example.invalid",
                "commit", "-q", "-m", "six regular blobs")
            proof = git("ls-tree", "-r", "-z", "HEAD", "--", *PATHS)
            self.assertTrue(guard.safe_tree(proof, delta()))
            candidate = root / PATHS[-1]
            candidate.unlink()
            candidate.symlink_to("fictional-target.txt")
            git("add", ".")
            git("-c", "user.name=Offline Reviewer",
                "-c", "user.email=offline@example.invalid",
                "commit", "-q", "-m", "tracked symlink")
            self.assertFalse(guard.safe_tree(
                git("ls-tree", "-r", "-z", "HEAD", "--", *PATHS), delta()
            ))
            candidate.unlink()
            candidate.write_text("fictional regular executable")
            candidate.chmod(0o755)
            git("-c", "core.fileMode=true", "add", ".")
            git("-c", "user.name=Offline Reviewer",
                "-c", "user.email=offline@example.invalid",
                "commit", "-q", "-m", "tracked executable")
            self.assertFalse(guard.safe_tree(
                git("ls-tree", "-r", "-z", "HEAD", "--", *PATHS), delta()
            ))

    def test_path_shadowed_git_executable_is_not_used(self):
        """A fake 'git' earlier in PATH must never supply our evidence."""
        import os
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix="scope_fake_git_", dir=FILE.parents[1]) as temp:
            fake = Path(temp) / "git"
            fake.write_text("#!/bin/sh\necho fake-git-version\n")
            fake.chmod(0o755)
            with patch.dict(os.environ, {"PATH": str(Path(temp)) + ":/usr/bin:/bin"}):
                real = guard.git("--version")
            self.assertEqual(real.returncode, 0)
            self.assertTrue(real.stdout.startswith(b"git version "), real.stdout)

    def test_git_status_does_not_execute_repo_fsmonitor(self):
        import subprocess
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix="scope_fsmon_fixture_", dir=FILE.parents[1]) as tmp:
            root = Path(tmp).resolve()
            def setup_git(*argv):
                return subprocess.run(
                    [guard.GIT_BINARY, *argv], cwd=root, capture_output=True,
                    check=True, timeout=5,
                ).stdout
            setup_git("init", "-q")
            tracked = root / "fixture.txt"
            tracked.write_text("fictional offline fixture")
            setup_git("add", "fixture.txt")
            setup_git("-c", "user.name=Reviewer",
                      "-c", "user.email=reviewer@example.invalid",
                      "commit", "-q", "-m", "synthetic fixture")
            mark = root / "hook-was-executed.txt"
            hook = root / "fsmonitor-fixture.sh"
            hook.write_text("#!/bin/sh\nprintf invoked > " + str(mark) + "\n")
            hook.chmod(0o755)
            setup_git("config", "core.fsmonitor", str(hook))
            # Verify this is a meaningful negative case: unprotected Git
            # really executes the local fixture hook on git status.
            setup_git("status", "--porcelain")
            self.assertTrue(mark.is_file())
            mark.unlink()
            with patch.object(guard, "ROOT", root):
                result = guard.git("status", "--porcelain")
            self.assertEqual(result.returncode, 0)
            self.assertFalse(mark.exists(), "offline proof invoked fsmonitor")

    def test_main_rejects_config_redirected_worktree(self):
        from subprocess import CompletedProcess
        from unittest.mock import patch
        from contextlib import redirect_stdout
        import io
        sha = "a" * 40
        context = {
            "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": "refs/heads/" + guard.BRANCH,
            "GITHUB_SHA": sha,
        }
        def fake_git(*argv):
            if argv[:2] == ("rev-parse", "--show-toplevel"):
                output = b"/fictional/other-worktree\n"
            else:
                output = {
                    "status": b"",
                    "rev-parse": sha.encode() + b"\n",
                    "merge-base": b"",
                    "diff": delta(),
                    "ls-tree": tree(),
                }[argv[0]]
            return CompletedProcess(argv, 0, output, b"")
        with patch.object(guard, "git", side_effect=fake_git):
            with patch.dict(guard.os.environ, context, clear=True):
                with redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(guard.main(), 3)
                self.assertEqual(out.getvalue().strip(), "scope_env_owned_tree=HOLD")

    def test_disposable_git_config_worktree_rebind_is_observable(self):
        import tempfile
        import subprocess
        with tempfile.TemporaryDirectory(prefix="scope_worktree_redirect_", dir=FILE.parents[1]) as tmp:
            base = Path(tmp).resolve()
            repo, foreign = base / "repo", base / "foreign"
            repo.mkdir()
            foreign.mkdir()
            def git(*argv):
                return subprocess.run(
                    [guard.GIT_BINARY, *argv], cwd=repo,
                    check=True, capture_output=True, timeout=5,
                ).stdout.strip()
            git("init", "-q")
            self.assertEqual(git("rev-parse", "--show-toplevel").decode(), str(repo))
            git("config", "core.worktree", str(foreign))
            self.assertEqual(git("rev-parse", "--show-toplevel").decode(), str(foreign))

    def test_git_warning_on_success_is_not_clean_proof(self):
        from subprocess import CompletedProcess
        from contextlib import redirect_stdout
        from unittest.mock import patch
        import io
        sha = "a" * 40
        expected = {
            "status": b"",
            "rev-parse": sha.encode() + b"\n",
            "merge-base": b"",
            "diff": delta(),
            "ls-tree": tree(),
        }
        event = {
            "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": "refs/heads/" + guard.BRANCH,
            "GITHUB_SHA": sha,
        }
        for warned in ("status", "rev-parse", "merge-base", "diff", "ls-tree"):
            with self.subTest(command=warned):
                def fake_git(*args):
                    result = (
                        str(guard.ROOT.resolve()).encode() + b"\n"
                        if args[:2] == ("rev-parse", "--show-toplevel")
                        else expected[args[0]]
                    )
                    stderr = b"fictional integrity warning\n" if args[0] == warned else b""
                    return CompletedProcess(args, 0, result, stderr)
                with patch.object(guard, "git", side_effect=fake_git):
                    with patch.dict(guard.os.environ, event, clear=True):
                        with redirect_stdout(io.StringIO()):
                            self.assertEqual(guard.main(), 3)

    def test_git_stdin_ceiling_rejects_before_process_spawn(self):
        from unittest.mock import patch
        with patch.object(guard.subprocess, "Popen", side_effect=AssertionError("spawn")):
            with self.assertRaisesRegex(ValueError, "bounded Git stdin"):
                guard._git_raw("hash-object", "--stdin", data=b"x" * 262145)
            with self.assertRaisesRegex(ValueError, "bounded Git stdin"):
                guard._git_raw("hash-object", "--stdin", data=bytearray(b"x"))

    def test_git_streaming_handles_bounded_pipe_stdin(self):
        import hashlib
        import subprocess
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix="scope_git_pipe_", dir=FILE.parents[1]) as tmp:
            root = Path(tmp)
            subprocess.run([guard.GIT_BINARY, "init", "-q"], cwd=root,
                           check=True, capture_output=True)
            content = b"x" * 262144
            digest = hashlib.sha1(
                b"blob " + str(len(content)).encode() + b"\0" + content
            ).hexdigest().encode() + b"\n"
            with patch.object(guard, "ROOT", root):
                result = guard._git_raw("hash-object", "--stdin", data=content)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, digest)
            self.assertEqual(result.stderr, b"")

    def test_timeout_terminates_descendant_git_alias_process_group(self):
        """A child inheriting stdout must not outlive rejected Git evidence."""
        import shlex
        import subprocess
        import tempfile
        import time
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix="scope_git_descendant_", dir=FILE.parents[1]) as tmp:
            root = Path(tmp)
            subprocess.run([guard.GIT_BINARY, "init", "-q"], cwd=root,
                           check=True, capture_output=True, timeout=6)
            started = root / "started"
            late = root / "late"
            script = root / "nested-fixture.sh"
            script.write_text(
                "#!/bin/sh\nprintf started > " + shlex.quote(str(started)) +
                "\nsleep 0.7\nprintf late > " + shlex.quote(str(late)) + "\n"
            )
            script.chmod(0o755)
            alias = "alias.delayed=!" + shlex.quote(str(script))
            with patch.object(guard, "ROOT", root), \
                 patch.object(guard, "GIT_TIMEOUT_SECONDS", 0.5):
                with self.assertRaises(subprocess.TimeoutExpired):
                    guard._git_raw("-c", alias, "delayed")
            self.assertTrue(started.is_file(), "synthetic descendant did not start")
            time.sleep(0.85)
            self.assertFalse(late.exists(), "orphaned Git helper survived the timeout")

    def test_git_stderr_over_limit_is_rejected_during_capture(self):
        import shlex
        import subprocess
        import sys
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix="scope_git_stderr_", dir=FILE.parents[1]) as tmp:
            root = Path(tmp)
            subprocess.run([guard.GIT_BINARY, "init", "-q"], cwd=root,
                           check=True, capture_output=True, timeout=6)
            fixture = 'import sys;sys.stderr.write("X"*25000)'
            alias = "alias.noisy=!" + shlex.quote(sys.executable) + " -c " + shlex.quote(fixture)
            with patch.object(guard, "ROOT", root):
                with self.assertRaisesRegex(ValueError, "Git output exceeds"):
                    guard._git_raw("-c", alias, "noisy")
                after = guard._git_raw("status", "--porcelain")
            self.assertEqual(after.returncode, 0)
            self.assertEqual(after.stdout, b"")
            self.assertEqual(after.stderr, b"")

    def test_git_stdout_over_limit_is_rejected_during_capture(self):
        import subprocess
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix="scope_git_output_", dir=FILE.parents[1]) as tmp:
            root = Path(tmp)
            def setup(*args):
                subprocess.run([guard.GIT_BINARY, *args], cwd=root,
                               check=True, capture_output=True, timeout=6)
            setup("init", "-q")
            (root / "large.txt").write_bytes(b"x" * 786433)
            setup("add", "large.txt")
            setup("-c", "user.name=Offline", "-c",
                  "user.email=offline@example.invalid",
                  "commit", "-qm", "only fictional bounded-output fixture")
            with patch.object(guard, "ROOT", root):
                with self.assertRaisesRegex(ValueError, "Git output exceeds"):
                    guard._git_raw("show", "HEAD:large.txt")
                status = guard.git("status", "--porcelain=v1")
            self.assertEqual(status.returncode, 0)
            self.assertEqual(status.stdout, b"")
    def test_no_reusing_other_worker_paths(self):
        for item in ("src/lightup/scope.py", "tests/test_scope.py",
                     "scripts/check_scope_literal_branch_20261016.py"):
            with self.subTest(path=item):
                self.assertIsNone(guard.parse_additions(
                    delta(PATHS[:-1] + [item])
                ))


    def test_status_refuses_repo_filter_before_executable_can_run(self):
        """A clean/process driver may execute from read-only Git status."""
        import subprocess
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix="scope_git_filter_", dir=FILE.parents[1]) as tmp:
            root = Path(tmp)
            def git(*args):
                return subprocess.run(
                    [guard.GIT_BINARY, *args], cwd=root, check=True,
                    capture_output=True, timeout=6,
                ).stdout
            git("init", "-q")
            (root / ".gitattributes").write_text("file.txt filter=fictional\n")
            tracked = root / "file.txt"
            tracked.write_text("before\n")
            git("add", ".gitattributes", "file.txt")
            git("-c", "user.name=Offline Review", "-c",
                "user.email=offline@example.invalid",
                "commit", "-q", "-m", "fictional filter baseline")
            marker = root / "external-filter-ran"
            hook = root / "filter.sh"
            hook.write_text(
                "#!/bin/sh\nprintf invoked > '" + str(marker) + "'\ncat\n"
            )
            hook.chmod(0o755)
            git("config", "filter.fictional.clean", str(hook))
            tracked.write_text("AFTER!\n")
            with patch.object(guard, "ROOT", root):
                protected = guard.git("status", "--porcelain=v1", "-z",
                                      "--untracked-files=all")
            self.assertEqual(protected.returncode, 3)
            self.assertFalse(marker.exists(), "preflight executed configured filter")
            # Separate controlled witness proves the original read-only call
            # really would launch the local script without this preflight.
            git("-c", "core.fsmonitor=false", "status", "--porcelain=v1")
            self.assertTrue(marker.exists())

    def test_explicit_unspecified_filter_driver_is_not_absent(self):
        """Git 'filter=unspecified' must never pass as absent filter metadata."""
        import subprocess
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix="scope_filter_unspecified_", dir=FILE.parents[1]) as tmp:
            root = Path(tmp)
            def git(*args, data=None):
                return subprocess.run(
                    [guard.GIT_BINARY, *args], cwd=root, input=data,
                    check=True, capture_output=True, timeout=6,
                ).stdout
            git("init", "-q")
            attrs = root / ".gitattributes"
            attrs.write_text("file.txt filter=unspecified\n")
            tracked = root / "file.txt"
            tracked.write_text("before\n")
            git("add", ".gitattributes", "file.txt")
            git("-c", "user.name=Offline", "-c",
                "user.email=offline@example.invalid",
                "commit", "-qm", "fictional ambiguous-filter fixture")
            marker = root / "external-filter-ran"
            hook = root / "filter.sh"
            hook.write_text("#!/bin/sh\nprintf invoked > '" + str(marker) + "'\ncat\n")
            hook.chmod(0o755)
            git("config", "filter.unspecified.clean", str(hook))
            tracked.write_text("AFTER!\n")
            # This looks identical to a truly absent filter with check-attr
            # without --all. The preflight must not trust that ambiguity.
            self.assertEqual(
                git("check-attr", "-z", "--stdin", "filter", data=b"file.txt\0"),
                b"file.txt\0filter\0unspecified\0",
            )
            self.assertIn(
                b"file.txt\0filter\0unspecified\0",
                git("check-attr", "--all", "-z", "--stdin", data=b"file.txt\0"),
            )
            with patch.object(guard, "ROOT", root):
                self.assertFalse(guard._tracked_files_have_no_filters())
                result = guard.git("status", "--porcelain=v1", "-z")
            self.assertEqual(result.returncode, 3)
            self.assertFalse(marker.exists(), "guard ran explicit unspecified driver")
            # Separate disposable red witness for the unprotected Git path.
            git("-c", "core.fsmonitor=false", "status", "--porcelain=v1")
            self.assertTrue(marker.exists())

    def test_selected_filter_attribute_from_info_or_global_file_is_hold(self):
        """Git must respect every resolved attribute source, not just .gitattributes."""
        import subprocess
        import tempfile
        from unittest.mock import patch
        for origin in ("info", "global"):
            with self.subTest(origin=origin):
                with tempfile.TemporaryDirectory(
                    prefix="scope_git_filter_source_", dir=FILE.parents[1]
                ) as tmp:
                    root = Path(tmp)
                    def git(*args):
                        return subprocess.run(
                            [guard.GIT_BINARY, *args], cwd=root, check=True,
                            capture_output=True, timeout=6,
                        ).stdout
                    git("init", "-q")
                    tracked = root / "file.txt"
                    tracked.write_text("before\n")
                    git("add", "file.txt")
                    git("-c", "user.name=Offline", "-c",
                        "user.email=offline@example.invalid",
                        "commit", "-qm", "fictional attribute origin fixture")
                    target = (
                        root / ".git" / "info" / "attributes"
                        if origin == "info" else root / "global_attrs"
                    )
                    target.write_text("file.txt filter=unspecified\n")
                    if origin == "global":
                        git("config", "core.attributesFile", str(target))
                    marker = root / "ran-external-driver"
                    hook = root / "driver.sh"
                    hook.write_text(
                        "#!/bin/sh\nprintf invoked > '" + str(marker) + "'\ncat\n"
                    )
                    hook.chmod(0o755)
                    git("config", "filter.unspecified.clean", str(hook))
                    tracked.write_text("AFTER!\n")
                    with patch.object(guard, "ROOT", root):
                        self.assertFalse(guard._tracked_files_have_no_filters())
                        result = guard.git("status", "--porcelain=v1", "-z")
                    self.assertEqual(result.returncode, 3)
                    self.assertFalse(marker.exists())
                    git("-c", "core.fsmonitor=false", "status", "--porcelain=v1")
                    self.assertTrue(marker.exists())
                    
    def test_status_allows_tracked_nonfilter_attributes(self):
        """Normal end-of-line settings are not external filter drivers."""
        import subprocess
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix="scope_no_filter_", dir=FILE.parents[1]) as tmp:
            root = Path(tmp)
            def git(*args):
                return subprocess.run(
                    [guard.GIT_BINARY, *args], cwd=root, check=True,
                    capture_output=True, timeout=6,
                ).stdout
            git("init", "-q")
            (root / ".gitattributes").write_text("file.txt text eol=lf\n")
            (root / "file.txt").write_text("canonical\n")
            git("add", ".gitattributes", "file.txt")
            git("-c", "user.name=Offline Review", "-c",
                "user.email=offline@example.invalid",
                "commit", "-q", "-m", "fictional ordinary attributes")
            with patch.object(guard, "ROOT", root):
                self.assertTrue(guard._tracked_files_have_no_filters())
                actual = guard.git("status", "--porcelain=v1", "-z")
            self.assertEqual(actual.returncode, 0)
            self.assertEqual(actual.stdout, b"")
            self.assertEqual(actual.stderr, b"")

    def test_filter_preflight_fails_closed_on_malformed_git_evidence(self):
        from subprocess import CompletedProcess
        from unittest.mock import patch
        names = b"file.txt\0"
        attr = b"file.txt\0text\0set\0"
        good_files = CompletedProcess([], 0, names, b"")
        for abnormal in (
            CompletedProcess([], 1, names, b""),
            CompletedProcess([], 0, names, b"warning"),
            CompletedProcess([], 0, b"file.txt", b""),
            CompletedProcess([], 0, names * 2, b""),
            CompletedProcess([], 0, b"x" * 262145 + b"\0", b""),
        ):
            with self.subTest(variant=repr(abnormal)[:75]):
                with patch.object(guard, "_git_raw", return_value=abnormal):
                    self.assertFalse(guard._tracked_files_have_no_filters())
        for abnormal in (
            CompletedProcess([], 0, b"file.txt\0filter\0evil\0", b""),
            CompletedProcess([], 0, b"file.txt\0filter\0unspecified\0", b""),
            CompletedProcess([], 0, b"file.txt\0filter\0unset\0", b""),
            CompletedProcess([], 0, b"file.txt\0FILTER\0set\0", b""),
            CompletedProcess([], 0, b"file.txt\0text\0set\0file.txt\0text\0set\0", b""),
            CompletedProcess([], 0, attr[:-1], b""),
            CompletedProcess([], 0, attr + attr, b""),
            CompletedProcess([], 0, b"other.txt\0filter\0unspecified\0", b""),
            CompletedProcess([], 0, attr, b"warning"),
            CompletedProcess([], 2, attr, b""),
        ):
            with self.subTest(variant=repr(abnormal)[:75]):
                with patch.object(guard, "_git_raw", side_effect=[good_files, abnormal]):
                    self.assertFalse(guard._tracked_files_have_no_filters())
        with patch.object(guard, "_git_raw", side_effect=[
            good_files, CompletedProcess([], 0, attr, b""),
        ]):
            self.assertTrue(guard._tracked_files_have_no_filters())
        with patch.object(guard, "_git_raw", side_effect=[
            good_files, CompletedProcess([], 0, b"", b""),
        ]):
            self.assertTrue(guard._tracked_files_have_no_filters())




if __name__ == "__main__":
    unittest.main()
