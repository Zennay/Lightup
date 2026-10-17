"""Scope #1547: source-characterization and bounded fictional status-stream gate."""
from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "review_scope_git_status_synthetic_1547.py"
spec = importlib.util.spec_from_file_location("scope1547_synthetic", SCRIPT)
review = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(review)


def packet(stream: bytes) -> bytes:
    return json.dumps(
        {"schema": review.SCHEMA,
         "name_status_b64": base64.b64encode(stream).decode("ascii")},
        sort_keys=True, separators=(",", ":"),
    ).encode("ascii")


class SyntheticGate(unittest.TestCase):
    def test_ordinary_types(self):
        for status in (b"A", b"M", b"D", b"T", b"R0", b"R1", b"R99",
                       b"R100", b"C0", b"C50", b"C100"):
            with self.subTest(status=status):
                stream = status + b"\0" + (b"old.py\0" if status[:1] in b"RC" else b"") + b"new.py\0"
                self.assertEqual(review.review_packet(packet(stream)), 1)

    def test_mixed_valid_records(self):
        self.assertEqual(review.review_stream(
            b"A\0src/a.py\0M\0src/b.py\0R100\0old.py\0new.py\0"), 3)

    def test_invalid_statuses_atomically_hold(self):
        invalid = (b"Q", b"U", b"X", b"Mgarbage", b"R", b"C",
                   b"Rnotanumber", b"R001", b"C00", b"R101", b"C999",
                   b"M1", b"r100", b"R-1", b"R+1", b"R1.0", b"R\xff")
        for item in invalid:
            with self.subTest(item=item):
                stream = item + b"\0old.py\0new.py\0" if item[:1] in b"RC" else item + b"\0new.py\0"
                with self.assertRaises(review.StatusHold):
                    review.review_stream(stream)

    def test_status_boundary_truncation(self):
        for stream in (
            b"", b"M\0file.py", b"M\0", b"M\0file.py\0\0",
            b"R100\0old.py\0", b"R100\0old.py\0new.py",
            b"R100\0old.py\0new.py\0extra", b"M\0file.py\0Q\0other.py\0",
            b"M\0file.py\0R100\0old.py\0",
        ):
            with self.subTest(stream=stream):
                with self.assertRaises(review.StatusHold):
                    review.review_stream(stream)

    def test_path_encoding_identity_and_collisions(self):
        invalid = (b"\xff.py", b"", b"../a.py", b"/root.py",
                   b"src//a.py", b"src\\a.py", b"./a.py", b"src/../a.py",
                   b"e\xcc\x81.py", b"\xef\xbf\xbd.py", b"hi\n.py")
        for path in invalid:
            with self.subTest(path=path):
                with self.assertRaises(review.StatusHold):
                    review.review_stream(b"M\0" + path + b"\0")
        for stream in (
            b"A\0src/A.py\0D\0src/a.py\0",
            b"R100\0file.py\0file.py\0",
            b"A\0file.py\0A\0file.py\0",
        ):
            with self.assertRaises(review.StatusHold):
                review.review_stream(stream)

    def test_unicode_control_remains_acceptable(self):
        self.assertEqual(review.review_stream(b"M\0caf\xc3\xa9.py\0"), 1)

    def test_resource_boundaries(self):
        stream = b"".join(b"A\0x%02d.py\0" % i for i in range(64))
        self.assertEqual(review.review_stream(stream), 64)
        with self.assertRaises(review.StatusHold):
            review.review_stream(stream + b"A\0overflow.py\0")
        with self.assertRaises(review.StatusHold):
            review.review_stream(b"M\0" + b"x" * 1025 + b"\0")
        with self.assertRaises(review.StatusHold):
            review.review_stream(b"M\0x.py\0" + b"\0" * review.MAX_STREAM)

    def test_json_canonical_and_denial_of_authority_fields(self):
        good = packet(b"M\0file.py\0")
        self.assertEqual(review.review_packet(good), 1)
        rejects = (
            b" " + good, good + b"\n",
            good.replace(b'"schema":', b'"schema" :'),
            good[:-1] + b',"authorized":true}',
            b'{"schema":"x","schema":"y","name_status_b64":"TQA="}',
            b'{"schema":"x","name_status_b64":1}',
            b'{"schema":"x","name_status_b64":"!!!!"}',
            b'{"schema":"x","name_status_b64":"TR////8="}',
            b'[]', b'null', b'\xff', b"x" * (review.MAX_INPUT + 1),
        )
        for obj in rejects:
            with self.subTest(obj=obj[:70]):
                with self.assertRaises(review.StatusHold):
                    review.review_packet(obj)

    def test_cli_exit_codes_and_no_authority(self):
        for stream, expected, decision in (
            (b"M\0file.py\0", 3, "REVIEW_ONLY"),
            (b"Q\0file.py\0", 2, "HOLD"),
            (b"Mgarbage\0file.py\0", 2, "HOLD"),
            (b"Rnotanumber\0old.py\0new.py\0", 2, "HOLD"),
        ):
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-B", str(SCRIPT)],
                input=packet(stream), capture_output=True, timeout=8, check=False,
            )
            self.assertEqual(result.returncode, expected)
            self.assertEqual(result.stderr, b"")
            obj = json.loads(result.stdout)
            self.assertEqual(obj.pop("decision"), decision)
            self.assertTrue(obj.pop("not_authorization"))
            self.assertEqual(obj.pop("schema"), review.SCHEMA)
            self.assertTrue(obj)
            self.assertEqual(set(obj), set(review._FLAGS))
            self.assertTrue(all(value is False for value in obj.values()))
            self.assertNotIn(b"file.py", result.stdout)

    def test_real_disposable_git_zero_delimited_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def git(*args):
                return subprocess.run(
                    ["git", "-c", "core.hooksPath=/dev/null", "-C", str(root), *args],
                    capture_output=True, check=True, timeout=8,
                ).stdout
            git("init", "-q")
            (root / "old.py").write_text("hello\n", encoding="utf-8")
            git("add", "old.py")
            git("-c", "user.email=fixture@example.invalid",
                "-c", "user.name=Fixture", "commit", "-qm", "base")
            git("mv", "old.py", "new.py")
            git("-c", "user.email=fixture@example.invalid",
                "-c", "user.name=Fixture", "commit", "-qam", "rename")
            stream = git("diff", "--name-status", "-z", "HEAD~1", "HEAD")
            self.assertIn(b"R100\0old.py\0new.py\0", stream)
            self.assertEqual(review.review_stream(stream), 1)


class OriginalOwnerContract(unittest.TestCase):
    """Expected RED documents original owner code, never patches it here."""
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ROOT / "src"))
        from lightup.git_changes import GitChangeError, _parse_name_status, _parse_numstat
        cls.GitChangeError = GitChangeError
        cls.parse_status = staticmethod(_parse_name_status)
        cls.parse_numstat = staticmethod(_parse_numstat)

    @unittest.expectedFailure
    def test_owner_rejects_malformed_modify_status(self):
        with self.assertRaises(self.GitChangeError):
            self.parse_status(b"Mgarbage\0src/a.py\0")

    @unittest.expectedFailure
    def test_owner_rejects_unknown_status(self):
        with self.assertRaises(self.GitChangeError):
            self.parse_status(b"Q\0src/a.py\0")

    @unittest.expectedFailure
    def test_owner_rejects_malformed_similarity(self):
        with self.assertRaises(self.GitChangeError):
            self.parse_status(b"Rnotanumber\0old.py\0new.py\0")

    @unittest.expectedFailure
    def test_owner_requires_terminator(self):
        with self.assertRaises(self.GitChangeError):
            self.parse_status(b"M\0src/a.py")

    @unittest.expectedFailure
    def test_owner_numstat_requires_terminator(self):
        with self.assertRaises(self.GitChangeError):
            self.parse_numstat(b"1\t0\tsrc/a.py")


if __name__ == "__main__":
    unittest.main()
