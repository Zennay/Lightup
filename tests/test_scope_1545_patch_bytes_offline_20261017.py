"""Original-source Git patch bytes acceptance and non-authorizing isolated reviewer.

Only disposable synthetic repos without remotes/hooks, no targets or grants.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "review_scope_patch_bytes_offline_1545.py"
spec = importlib.util.spec_from_file_location("scope1545", SCRIPT)
assert spec and spec.loader
reviewer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reviewer)

GOOD = b"@@ -1 +1,2 @@\n-old\n+new\n+extra"
UTF = "@@ -1 +1 @@\n-# cafe\n+# café".encode("utf-8")
MISSING_NL = b"@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new"


def document(*patches: bytes) -> dict:
    return {
        "schema": reviewer.SCHEMA,
        "patches": [
            {
                "path_id": f"fixture_{i+1}",
                "patch_b64": base64.b64encode(blob).decode("ascii"),
                "sha256": hashlib.sha256(blob).hexdigest(),
            }
            for i, blob in enumerate(patches)
        ],
    }


def encoded(document: object) -> bytes:
    return json.dumps(document,sort_keys=True,separators=(",", ":"),ensure_ascii=True,allow_nan=False).encode("ascii")


def cli(payload: bytes, *args: str) -> tuple[int, dict]:
    done = subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(SCRIPT), *args],
        input=payload, capture_output=True, timeout=8, check=False,
    )
    if done.stderr:
        raise AssertionError("CLI leaked stderr")
    return done.returncode, json.loads(done.stdout.decode("utf-8"))


class ReviewBytesTests(unittest.TestCase):
    def hold(self, blob: bytes) -> None:
        self.assertEqual(reviewer.evaluate(blob), reviewer.HOLD)

    def test_canonical_complete_review_only_not_pass(self):
        result = reviewer.evaluate(encoded(document(GOOD, UTF, MISSING_NL)))
        self.assertEqual(result, reviewer.REVIEW_ONLY)
        self.assertNotEqual(result, 0)

    def test_healthy_valid_utf8_and_tabs(self):
        specimens = (
            b"@@ -1,2 +1,2 @@\n context\t\n-old\n+new",
            b"@@ -0,0 +1 @@\n+first",
            b"@@ -1 +0,0 @@\n-removed",
            b"@@ -1,2 +1,2 @@\n context\n-old\n+new",
            b"@@ -1 +1 @@ def calculate():\n-x = 1\n+x = 2",
            "@@ -1 +1 @@\n-# intact\n+# naïve café".encode(),
            b"@@ -1 +1 @@\n-old\n+new",
            MISSING_NL,
        )
        for raw in specimens:
            with self.subTest(raw=raw[:40]):
                self.assertTrue(reviewer.check_patch(raw))

    def test_bad_utf8_and_replacement_are_refused(self):
        for raw in (
            b"@@ -1 +1 @@\n-old\n+\xff",
            b"@@ -1 +1 @@\n-old\n+\xfe",
            b"@@ -1 +1 @@\n-old\n+\xc3(",
            b"@@ -1 +1 @@\n-old\n+\xed\xa0\x80",
            "@@ -1 +1 @@\n-old\n+�".encode("utf-8"),
        ):
            with self.subTest(raw=raw):
                self.hold(encoded(document(raw)))

    def test_bidi_invisible_and_unicode_line_separators_hold(self):
        for symbol in ("\u202e", "\u2066", "\u200b", "\u200d", "\u2028", "\u2029", "\ufeff", "\x1b", "\x00", "\r", "\x7f"):
            with self.subTest(symbol=repr(symbol)):
                candidate = ("@@ -1 +1 @@\n-old\n+new" + symbol).encode("utf-8")
                self.hold(encoded(document(candidate)))

    def test_invisible_unicode_format_and_spacing_glyphs_are_held(self):
        # These printable Unicode categories can look empty to a human even
        # though the original changed Git patch contains extra UTF-8 bytes.
        ambiguous = ("\u034f", "\ufe0f", "\ufe00", "\u2800", "\u3164",
                     "\u115f", "\u1160", "\uffa0", "\u00a0", "\u2007",
                     "\u202f", "\u0301")
        for symbol in ambiguous:
            with self.subTest(char=repr(symbol)):
                raw = ("@@ -1 +1 @@\n-old\n+new" + symbol).encode("utf-8")
                self.hold(encoded(document(raw)))

    def test_positive_visible_precomposed_unicode_remains_review_only(self):
        raw = "@@ -1 +1 @@\n-# cafe\n+# café 日本語 한글".encode("utf-8")
        self.assertEqual(reviewer.evaluate(encoded(document(raw))), reviewer.REVIEW_ONLY)

    def test_git_hunk_numbers_are_canonical_without_leading_zeros(self):
        for header in (
            b"@@ -01 +1 @@", b"@@ -1 +01 @@", b"@@ -1,01 +1 @@",
            b"@@ -1 +1,01 @@", b"@@ -0001,1 +1,1 @@",
            b"@@ -1,1 +001,1 @@",
        ):
            with self.subTest(header=header):
                self.hold(encoded(document(header + b"\n-old\n+new")))

    def test_many_structurally_inconsistent_numeric_counts_hold(self):
        for old_count in range(0,12):
            for new_count in range(0,12):
                if (old_count,new_count)==(1,1):
                    continue
                header = f"@@ -1,{old_count} +1,{new_count} @@".encode("ascii")
                with self.subTest(old_count=old_count,new_count=new_count):
                    self.assertFalse(reviewer.check_patch(header+b"\n-old\n+new"))

    def test_wrong_hunk_line_counts_hold(self):
        for raw in (
            b"@@ -1 +1 @@\n-old",
            b"@@ -1 +1 @@\n-old\n+new\n+extra",
            b"@@ -1 +1,2 @@\n-old\n+new",
            b"@@ -1 +1 @@\n?old\n+new",
            b"@@ -1 +1 @@\n-old\n new",
            b"@@ -1 +1 @@\n-old\n+new\nextra",
            b"@@ -1 +1 @@\n-old\n+new\n",
            b"@@ -1 +1 @@\n-old\n+new\n@@ -2 +2 @@\n-old",
            b"@@ -1 +1 @@\n-old\n+new\n@@ -1 +1 @@\n-old\n+new",
            b"@@ -1 +1 @@\n-old\n+new\n@@ -99999999 +1 @@\n-z\n+a",
        ):
            with self.subTest(raw=raw[:32]):
                self.assertFalse(reviewer.check_patch(raw))

    def test_context_only_or_zero_line_hunks_cannot_claim_a_change(self):
        for raw in (
            b"@@ -1 +1 @@\n unchanged",
            b"@@ -0,0 +0,0 @@",
            b"@@ -1,2 +1,2 @@\n a\n b",
        ):
            with self.subTest(raw=raw):
                self.assertFalse(reviewer.check_patch(raw))

    def test_only_exact_no_newline_marker_allowed(self):
        for raw in (
            b"@@ -1 +1 @@\n\\ No newline at end of file\n-old\n+new",
            b"@@ -1 +1 @@\n-old\n+new\n\\ No newline at end of file\n\\ No newline at end of file",
            b"@@ -1 +1 @@\n-old\n+new\n\\ Unknown marker",
        ):
            with self.subTest(raw=raw):
                self.assertFalse(reviewer.check_patch(raw))

    def test_git_no_newline_markers_cannot_claim_middle_of_file(self):
        invalid = (
            b"@@ -1,2 +1,2 @@\n-old\n\\ No newline at end of file\n context\n+new",
            b"@@ -1,2 +1,2 @@\n-old\n+new\n\\ No newline at end of file\n context",
            b"@@ -1,2 +1,2 @@\n context\n\\ No newline at end of file\n-old\n+new",
        )
        for raw in invalid:
            with self.subTest(raw=raw[:65]):
                self.hold(encoded(document(raw)))

    def test_git_no_newline_end_of_file_cannot_precede_later_hunks(self):
        for first_hunk in (
            b"@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new",
            b"@@ -1 +1 @@\n-old\n+new\n\\ No newline at end of file",
        ):
            fake = first_hunk + b"\n@@ -10 +10 @@\n-before\n+after"
            with self.subTest(first=first_hunk[:45]):
                self.hold(encoded(document(fake)))

    def test_noncanonical_base64_and_digest_holds(self):
        for changed in ("patch_b64", "sha256"):
            specimen = document(GOOD)
            specimen["patches"][0][changed] = "!!notvalid!!" if changed == "patch_b64" else "0"*64
            self.hold(encoded(specimen))
        specimen = document(GOOD)
        specimen["patches"][0]["patch_b64"] += "===="
        self.hold(encoded(specimen))
        specimen = document(GOOD)
        specimen["patches"][0]["sha256"] = specimen["patches"][0]["sha256"].upper()
        self.hold(encoded(specimen))

    def test_duplicate_ids_and_fields_hold(self):
        specimen = document(GOOD, GOOD)
        specimen["patches"][1]["path_id"] = specimen["patches"][0]["path_id"]
        self.hold(encoded(specimen))
        self.hold(b'{"patches":[],"schema":"a","schema":"b"}')
        self.hold(b'{"patches":[{"path_id":"x","path_id":"y"}],"schema":"a"}')

    def test_schema_extras_and_authority_like_fields_hold(self):
        for where in ("top", "patch"):
            for name in ("approved", "grant", "release_allowed", "client_token"):
                specimen = document(GOOD)
                target = specimen if where == "top" else specimen["patches"][0]
                target[name] = False
                with self.subTest(where=where, name=name):
                    self.hold(encoded(specimen))
        specimen = document(GOOD)
        del specimen["patches"][0]["sha256"]
        self.hold(encoded(specimen))

    def test_canonical_json_only(self):
        original = encoded(document(GOOD))
        self.hold(b" " + original)
        self.hold(original + b" ")
        self.hold(json.dumps(document(GOOD)).encode())
        self.hold(original.replace(b'"schema"',b'"sch\\u0065ma"'))
        self.hold(b"NaN")
        self.hold(b"Infinity")
        self.hold(b"\xff")
        self.hold(b"")
        self.hold(b"{}{}")

    def test_invalid_types_at_all_levels_hold(self):
        for specimen in ([], False, True, None, 11, "string", {}, {"schema":reviewer.SCHEMA,"patches":{}}, {"schema":reviewer.SCHEMA,"patches":[]}):
            with self.subTest(specimen=repr(specimen)):
                self.hold(encoded(specimen))
        for key, value in (("path_id",1), ("patch_b64",1), ("sha256",1), ("path_id","ç"), ("path_id","../x"), ("patch_b64",True), ("sha256",False)):
            specimen = document(GOOD)
            specimen["patches"][0][key] = value
            self.hold(encoded(specimen))

    def test_size_hunk_and_count_limits_hold(self):
        self.hold(b" " * (reviewer.MAX_STDIN + 1))
        self.hold(encoded(document(b"@@ -1 +1 @@\n-old\n+" + b"a" * reviewer.MAX_PATCH)))
        self.hold(encoded(document(*([GOOD] * (reviewer.MAX_PATCHES + 1)))))
        self.assertFalse(reviewer.check_patch(b"@@ -1,9999 +1,9999 @@\n-old\n+new"))
        self.assertFalse(reviewer.check_patch(b"@@ -1 +1 @@\n-old\n+" + b"x" * 8200))

    def test_source_is_unwired_without_network_or_subprocess_imports(self):
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        modules = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.extend(item.name.split(".")[0] for item in node.names)
            if isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module.split(".")[0])
        self.assertEqual(set(modules), {
            "__future__", "base64", "binascii", "hashlib", "json",
            "re", "sys", "unicodedata",
        })

    def test_workflow_is_hosted_only_and_pins_current_pr_head(self):
        source = (ROOT / ".github" / "workflows" / "scope1545-patch-bytes.yml").read_text(encoding="utf-8")
        self.assertIn("actions/checkout@v5", source)
        self.assertIn("actions/setup-python@v6", source)
        self.assertIn("permissions:\n  contents: read", source)
        self.assertIn("ref: ${{ github.event.pull_request.head.sha }}", source)
        self.assertIn("runs-on: ubuntu-24.04", source)
        self.assertNotIn("self-hosted", source)
        self.assertNotIn("workflow_dispatch:", source)

    def test_cli_canonical_exit_three_and_all_flags_false(self):
        code, receipt = cli(encoded(document(GOOD, UTF)))
        self.assertEqual(code, 3)
        self.assertEqual(receipt["status"], "REVIEW_ONLY")
        self.assertEqual(receipt["basis"], "untrusted_synthetic_patch_bytes_only")
        for flag in reviewer.FLAGS:
            self.assertIs(receipt[flag], False)

    def test_cli_invalid_exit_two_and_privacy_minimal(self):
        bad = b"@@ -1 +1 @@\n-old\n+\xffSECRET_PATH"
        code, receipt = cli(encoded(document(bad)))
        self.assertEqual(code, 2)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertNotIn("SECRET_PATH", json.dumps(receipt))
        for flag in reviewer.FLAGS:
            self.assertIs(receipt[flag], False)

    def test_cli_arguments_never_override_admission(self):
        code, receipt = cli(encoded(document(GOOD)), "--release")
        self.assertEqual(code, 2)
        self.assertEqual(receipt["status"], "HOLD")

    def test_stdin_failure_is_atomic_hold(self):
        class BadReader:
            def read(self, _n):
                raise OSError("private synthetic error")
        mock_input = type("Input", (), {"buffer": BadReader()})()
        output = io.StringIO()
        with patch.object(reviewer.sys,"stdin",mock_input), patch.object(reviewer.sys,"stdout",output), patch.object(reviewer.sys,"argv",[str(SCRIPT)]):
            self.assertEqual(reviewer.main(), reviewer.HOLD)
        self.assertEqual(json.loads(output.getvalue())["status"], "HOLD")

    def test_partial_stdout_cannot_return_review_only(self):
        class ShortWriter:
            def write(self,s):
                return len(s)-1
            def flush(self):
                return None
        input_file = type("Input", (), {"buffer": io.BytesIO(encoded(document(GOOD)))})()
        with patch.object(reviewer.sys,"stdin",input_file), patch.object(reviewer.sys,"stdout",ShortWriter()), patch.object(reviewer.sys,"argv",[str(SCRIPT)]):
            self.assertEqual(reviewer.main(), reviewer.HOLD)


class OriginalSourceGitPatchTests(unittest.TestCase):
    """Real no-hook local Git fixtures prove installed source loses patch bytes."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"}
        self.git("init","-q","-b","main")

    def git(self,*args):
        return subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", *args],
            cwd=self.root, env=self.env, capture_output=True, timeout=8,
            check=True,
        ).stdout

    def fixture(self, added: bytes) -> tuple[str, str]:
        (self.root/"fixture.py").write_bytes(b"safe = 1\n")
        self.git("add", "fixture.py")
        self.git("-c","user.name=Synthetic","-c","user.email=synthetic@example.invalid","commit","-qm","base")
        before = self.git("rev-parse","HEAD").decode().strip()
        (self.root/"fixture.py").write_bytes(b"safe = 1\n" + added)
        self.git("add", "fixture.py")
        self.git("-c","user.name=Synthetic","-c","user.email=synthetic@example.invalid","commit","-qm","changed")
        after = self.git("rev-parse","HEAD").decode().strip()
        return before, after

    def test_real_git_utf8_patch_control_is_readable(self):
        sys.path.insert(0,str(ROOT/"src"))
        from lightup.git_changes import collect_git_range
        a,b = self.fixture("# café\n".encode("utf-8"))
        result = collect_git_range(self.root,a,b,merge_base=False,repository="synthetic/fixture")
        patch_text = result.files[0]["patch"]
        self.assertIn("café",patch_text)
        self.assertTrue(reviewer.check_patch(patch_text.encode("utf-8")))

    def test_real_git_two_distant_hunks_preserve_exact_review_shape(self):
        sys.path.insert(0,str(ROOT/"src"))
        from lightup.git_changes import collect_git_range
        original = [f"line_{n} = {n}\n" for n in range(1, 50)]
        (self.root/"fixture.py").write_text("".join(original),encoding="utf-8")
        self.git("add","fixture.py")
        self.git("-c","user.name=Synthetic","-c","user.email=synthetic@example.invalid","commit","-qm","base")
        before=self.git("rev-parse","HEAD").decode().strip()
        changed=list(original)
        changed[2]="line_3 = 300\n"
        changed[41]="line_42 = 4200\n"
        (self.root/"fixture.py").write_text("".join(changed),encoding="utf-8")
        self.git("add","fixture.py")
        self.git("-c","user.name=Synthetic","-c","user.email=synthetic@example.invalid","commit","-qm","changed")
        after=self.git("rev-parse","HEAD").decode().strip()
        got=collect_git_range(self.root,before,after,merge_base=False,repository="synthetic/fixture")
        patch_text=got.files[0]["patch"]
        self.assertEqual(patch_text.count("@@ -"),2)
        self.assertTrue(reviewer.check_patch(patch_text.encode("utf-8")))
        self.assertEqual(reviewer.evaluate(encoded(document(patch_text.encode()))),reviewer.REVIEW_ONLY)

    def test_real_git_valid_final_hunk_no_newline_after_earlier_change(self):
        sys.path.insert(0,str(ROOT/"src"))
        from lightup.git_changes import collect_git_range
        lines=[f"sample_{n}\n" for n in range(1, 54)]
        (self.root/"fixture.py").write_text("".join(lines),encoding="utf-8")
        self.git("add","fixture.py")
        self.git("-c","user.name=Synthetic","-c","user.email=synthetic@example.invalid","commit","-qm","base")
        before=self.git("rev-parse","HEAD").decode().strip()
        updated=list(lines)
        updated[2]="sample_3_modified\n"
        updated[-1]="sample_53_modified"
        (self.root/"fixture.py").write_text("".join(updated),encoding="utf-8")
        self.git("add","fixture.py")
        self.git("-c","user.name=Synthetic","-c","user.email=synthetic@example.invalid","commit","-qm","changed")
        after=self.git("rev-parse","HEAD").decode().strip()
        data=collect_git_range(self.root,before,after,merge_base=False,repository="synthetic/fixture")
        raw=data.files[0]["patch"].encode("utf-8")
        self.assertEqual(raw.count(b"@@ -"),2)
        self.assertIn(b"\\ No newline at end of file",raw)
        self.assertTrue(reviewer.check_patch(raw))
        self.assertEqual(reviewer.evaluate(encoded(document(raw))),reviewer.REVIEW_ONLY)

    def test_actual_raw_invalid_utf8_patch_is_lossily_decoded(self):
        sys.path.insert(0,str(ROOT/"src"))
        from lightup.git_changes import collect_git_range
        a,b = self.fixture(b"# \xff invalid synthetic UTF8\n")
        raw_diff = self.git("diff","-U3",a,b)
        self.assertIn(b"\xff",raw_diff)
        result = collect_git_range(self.root,a,b,merge_base=False,repository="synthetic/fixture")
        patch_text = result.files[0]["patch"]
        self.assertIn("\ufffd",patch_text)
        self.assertFalse(reviewer.check_patch(patch_text.encode("utf-8")))

    def test_disposable_strict_git_decoder_rehearsal_denies_invalid_patch(self):
        # An in-memory patch, never written into source owner code/branch.
        sys.path.insert(0,str(ROOT/"src"))
        from lightup import git_changes
        a,b = self.fixture(b"# \xff invalid synthetic UTF8\n")
        original = git_changes._git
        def strict(repo, *args, check=True):
            raw = git_changes._git_bytes(repo, *args, check=check)
            try:
                return raw.decode("utf-8", "strict")
            except UnicodeDecodeError:
                raise git_changes.GitChangeError("undecodable textual Git evidence") from None
        with patch.object(git_changes, "_git", strict):
            with self.assertRaises(git_changes.GitChangeError):
                git_changes.collect_git_range(self.root,a,b,merge_base=False,repository="synthetic/fixture")
        self.assertIs(git_changes._git, original)

    def test_disposable_strict_git_decoder_keeps_unicode_intact(self):
        sys.path.insert(0,str(ROOT/"src"))
        from lightup import git_changes
        a,b = self.fixture("# café naïve\n".encode("utf-8"))
        original = git_changes._git
        def strict(repo, *args, check=True):
            raw = git_changes._git_bytes(repo, *args, check=check)
            try:
                return raw.decode("utf-8", "strict")
            except UnicodeDecodeError:
                raise git_changes.GitChangeError("undecodable textual Git evidence") from None
        with patch.object(git_changes, "_git", strict):
            result = git_changes.collect_git_range(self.root,a,b,merge_base=False,repository="synthetic/fixture")
            self.assertIn("café naïve", result.files[0]["patch"])
            self.assertTrue(reviewer.check_patch(result.files[0]["patch"].encode("utf-8")))
        self.assertIs(git_changes._git, original)

    @unittest.expectedFailure
    def test_source_owner_eventually_rejects_invalid_patch_bytes_before_review(self):
        sys.path.insert(0,str(ROOT/"src"))
        from lightup.git_changes import GitChangeError, collect_git_range
        a,b = self.fixture(b"# \xff invalid synthetic UTF8\n")
        with self.assertRaises(GitChangeError):
            collect_git_range(self.root,a,b,merge_base=False,repository="synthetic/fixture")


if __name__ == "__main__":
    unittest.main()
