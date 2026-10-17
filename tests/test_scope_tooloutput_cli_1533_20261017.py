"""Offline native CLI contract for #1533; no real targets or handler execution."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_scope_offline_cli_native_io_alias_20261014 import _NATIVE_ALIAS_TRIPWIRE

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/review_scope_tooloutput_synthetic_1533.py"
SCHEMA = "lightup.scope1533.synthetic.v1"
FALSE_KEYS = (
    "authorization_verified", "consent_verified", "permit_issued",
    "dispatch_allowed", "execution_enabled", "merge_approved", "release_approved",
)


def _envelope(items):
    return {"schema": SCHEMA, "synthetic_only": True, "items": items}


def _row(summary="synthetic fixture", kind="note", payload_hex="ff00"):
    return {"summary": summary, "kind": kind, "payload_hex": payload_hex}


class OfflineToolOutputCliTests(unittest.TestCase):
    def run_cli(self, data: bytes, *args: str, expected: str):
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(SCRIPT), *args],
            cwd=ROOT, input=data, capture_output=True, timeout=8, check=False,
        )
        self.assertEqual(result.returncode, 3 if expected == "REVIEW_ONLY" else 2, result.stderr)
        self.assertEqual(result.stderr, b"", "never leak parse errors or input")
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertLess(len(result.stdout), 300)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["schema"], "lightup.scope1533.receipt.v1")
        self.assertEqual(receipt["status"], expected)
        self.assertEqual(set(receipt), {"schema", "status", *FALSE_KEYS})
        for name in FALSE_KEYS:
            self.assertIs(receipt[name], False)
        self.assertNotIn(b"synthetic fixture", result.stdout)
        return receipt



    def test_stream_read_oserrors_fail_closed_without_traceback(self):
        # Inject a broken stdin source in an isolated interpreter, preserving
        # the real CLI's entrypoint rather than replacing production checks.
        program = """import runpy,sys
class BrokenStream:
    def read(self, _limit):
        raise OSError('SYNTHETIC_STDIN_SECRET_NEVER_LEAK')
class BrokenStdin:
    buffer = BrokenStream()
entry = runpy.run_path('scripts/review_scope_tooloutput_synthetic_1533.py')
sys.stdin = BrokenStdin()
raise SystemExit(entry['main']([]))
"""
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", program],
            cwd=ROOT, input=b"", capture_output=True, timeout=8, check=False,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stderr, b"", "stdin failure should not expose traceback")
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["status"], "HOLD")
        for flag in FALSE_KEYS:
            self.assertIs(receipt[flag], False)


    def test_missing_stdin_buffer_is_generic_hold_not_traceback(self):
        program = """import runpy,sys
entry=runpy.run_path('scripts/review_scope_tooloutput_synthetic_1533.py')
class MissingBuffer: pass
sys.stdin=MissingBuffer()
raise SystemExit(entry['main']([]))
"""
        child = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", program],
            cwd=ROOT, input=b"", capture_output=True, timeout=8,
        )
        self.assertEqual(child.returncode, 2, child.stderr)
        self.assertEqual(child.stderr, b"")
        receipt = json.loads(child.stdout)
        self.assertEqual(receipt["status"], "HOLD")
        for field in FALSE_KEYS:
            self.assertIs(receipt[field], False)

    def test_broken_receipt_output_has_nonzero_exit_and_no_error_leak(self):
        # A failed reply channel cannot produce an accurate JSON receipt.
        # Never fall back to stdout/stderr traceback or a success exit.
        program = """import runpy,sys
entry=runpy.run_path('scripts/review_scope_tooloutput_synthetic_1533.py')
class BrokenOutput:
    def write(self, message):
        raise BrokenPipeError('SYNTHETIC_RESPONSE_SECRET_NEVER_LEAK')
original=sys.stdout
try:
    sys.stdout=BrokenOutput()
    code=entry['main'](['--unsupported'])
finally:
    sys.stdout=original
raise SystemExit(code)
"""
        child = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", program],
            cwd=ROOT, input=b"", capture_output=True, timeout=8,
        )
        self.assertEqual(child.returncode, 2, child.stderr)
        self.assertEqual(child.stderr, b"")
        self.assertEqual(child.stdout, b"", "no output channel means no receipt")


    def test_delayed_receipt_flush_error_does_not_exit_success(self):
        # CPython may buffer stdout: write() can return normally even when
        # the final flush cannot deliver the receipt. No authority or 0 exit.
        program = """import runpy,sys
entry=runpy.run_path('scripts/review_scope_tooloutput_synthetic_1533.py')
class LateBrokenOutput:
    def write(self, payload):
        return len(payload)
    def flush(self):
        raise BrokenPipeError('SYNTHETIC_FLUSH_SECRET_NEVER_LEAK')
sys.stdout=LateBrokenOutput()
raise SystemExit(entry['main'](['--unsupported']))
"""
        child = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", program],
            cwd=ROOT, input=b"", capture_output=True, timeout=8,
        )
        self.assertEqual(child.returncode, 2, child.stderr)
        self.assertEqual(child.stderr, b"", "flush failure must not leak tracebacks")
        self.assertEqual(child.stdout, b"")

    def test_real_cli_under_original_native_no_io_tripwire(self):
        # Reuse the existing owner's unchanged guard fixture. This is a
        # Python-level interposition test, not a kernel sandbox or consent.
        with tempfile.TemporaryDirectory(prefix="scope1533-synthetic-io-") as tmp:
            sandbox = Path(tmp)
            sitecustomize = sandbox / "sitecustomize.py"
            sitecustomize.write_text(_NATIVE_ALIAS_TRIPWIRE, encoding="utf-8")
            before = hashlib.sha256(sitecustomize.read_bytes()).hexdigest()
            env = os.environ.copy()
            env["PYTHONPATH"] = os.pathsep.join(
                (str(sandbox), str(ROOT / "src"), str(ROOT))
            )
            env["PYTHONNOUSERSITE"] = "1"
            env.pop("PYTHONPYCACHEPREFIX", None)
            env["LIGHTUP_SCOPE_BOOTSTRAP_SCRIPT"] = str(SCRIPT)
            env["LIGHTUP_SCOPE_SOURCE_ROOT"] = str(ROOT / "src/lightup")
            env["LIGHTUP_SCOPE_SCRIPTS_ROOT"] = str(ROOT / "scripts")
            for items, expected in [
                ([_row(kind="http-baseline-observation")], "REVIEW_ONLY"),
                ([_row(kind="not/allowed")], "HOLD"),
                ([_row(), _row(kind="INVALID")], "HOLD"),
            ]:
                with self.subTest(outcome=expected, item_count=len(items)):
                    child = subprocess.run(
                        [sys.executable, "-B", str(SCRIPT)],
                        cwd=sandbox, input=json.dumps(_envelope(items)).encode(),
                        env=env, capture_output=True, timeout=8, check=False,
                    )
                    self.assertEqual(child.returncode, 3 if expected == "REVIEW_ONLY" else 2,
                                     "native tripwire unexpectedly denied the CLI")
                    self.assertEqual(child.stderr, b"")
                    receipt = json.loads(child.stdout)
                    self.assertEqual(receipt["status"], expected)
                    for key in FALSE_KEYS:
                        self.assertIs(receipt[key], False)
                    self.assertEqual(
                        {p.name for p in sandbox.iterdir()}, {"sitecustomize.py"},
                        "offline CLI must never create files",
                    )
                    self.assertEqual(
                        hashlib.sha256(sitecustomize.read_bytes()).hexdigest(),
                        before,
                        "offline CLI must never modify its import guard",
                    )

    def test_single_and_max_batch_do_not_grant_authority(self):
        for count in (1, 2, 16, 32):
            with self.subTest(count=count):
                data = json.dumps(_envelope([_row()] * count)).encode()
                self.run_cli(data, expected="REVIEW_ONLY")

    def test_rejected_input_forms_have_identical_privacy_minimal_receipt(self):
        valid = _envelope([_row()])
        bad = [
            b"", b"\xff", b"null", b"[]", b"{}", b"NaN", b"Infinity",
            b'{"schema":"lightup.scope1533.synthetic.v1","synthetic_only":true,"items":[]}',
            json.dumps(_envelope([_row()] * 33)).encode(),
            json.dumps({**valid, "synthetic_only": False}).encode(),
            json.dumps({**valid, "synthetic_only": "true"}).encode(),
            json.dumps({**valid, "unknown": "injected"}).encode(),
            json.dumps(_envelope([_row(payload_hex="0")])).encode(),
            json.dumps(_envelope([_row(payload_hex="AA")])).encode(),
            json.dumps(_envelope([_row(payload_hex="ff ff")])).encode(),
            json.dumps(_envelope([_row(kind="note\\nmalicious")])).encode(),
            json.dumps(_envelope([_row(summary="synthetic\u202e")])).encode(),
            json.dumps(_envelope([{"summary": "a", "kind": "note", "payload_hex": "ff", "extra": "x"}])).encode(),
            b'{"schema":"lightup.scope1533.synthetic.v1","synthetic_only":true,"items":[{"summary":"s","kind":"note","kind":"note","payload_hex":""}]}',
            b'{"schema":"lightup.scope1533.synthetic.v1","synthetic_only":true,"items":[{"summary":"s","kind":"note","payload_hex":""}],"items":[]}',
            json.dumps(_envelope([_row(payload_hex="0" * 65537)])).encode(),
            b"{" * 64 + b"}" * 64,
            b'{"schema":"lightup.scope1533.synthetic.v1","synthetic_only":true,"items":[1]}',
            json.dumps(_envelope([_row(summary=123)])).encode(),
        ]
        golden = None
        for candidate in bad:
            with self.subTest(case=candidate[:45]):
                receipt = self.run_cli(candidate, expected="HOLD")
                if golden is None:
                    golden = receipt
                self.assertEqual(receipt, golden)

    def test_one_invalid_item_holds_entire_synthetic_batch(self):
        for position in range(32):
            items = [_row()] * 32
            items[position] = _row(kind="not/allowed")
            self.run_cli(json.dumps(_envelope(items)).encode(), expected="HOLD")

    def test_no_args_and_bounded_stdin(self):
        good = json.dumps(_envelope([_row()])).encode()
        self.run_cli(good, "--activate", expected="HOLD")
        self.run_cli(good + b" " * 66_000, expected="HOLD")
        self.run_cli(good + b" trailing", expected="HOLD")

    def test_false_review_cannot_contain_payload_or_summary_even_with_sensitive_looking_input(self):
        secret = "SHOULD_NEVER_APPEAR_IN_RECEIPT"
        self.run_cli(json.dumps(_envelope([_row(summary=secret)])).encode(), expected="REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
