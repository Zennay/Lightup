"""W50: independent subprocess RSS / Python allocation characterization (#1221).

Synthetic opt-in only, using the real optional W31 renderer. Deliberately
NOT proof of installed Markdown-to-HTML safety, total system memory
guarantees, tenancy, or production authorization.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


# A fresh interpreter per sample avoids carrying resource.ru_maxrss from
# earlier test cases. No external program, target, network, or client data.
_CHILD = r'''
import copy
import gc
import hashlib
import json
import resource
import sys
import tracemalloc
from unittest.mock import patch

import lightup.finding_markdown_escaped_optin_w31 as renderer
from lightup.models import Finding, RetestStatus, Severity

scenario = sys.argv[1]
secret = "SYNTHETIC-DO-NOT-EXPORT"
def row(identifier, references=None):
    return Finding(
        finding_id="w50:" + identifier,
        title="Synthetic " + identifier,
        severity=Severity.INFO,
        target="offline.synthetic",
        evidence=["ref:base"] if references is None else references,
        remediation="Review authorized evidence offline",
        retest_status=RetestStatus.NOT_TESTED,
        metadata={"private": {"token": secret}},
    )
def snapshot(rows):
    return [
        (x.finding_id, x.title, x.target, x.remediation, x.severity,
         x.retest_status, copy.deepcopy(x.evidence), copy.deepcopy(x.metadata))
        for x in rows
    ]

if scenario == "accepted":
    rows = [row("accepted", [
        f"ref:{i:03d}:" + "<>&*_" * 2400 for i in range(40)
    ])]
elif scenario == "output_overflow":
    rows = [row("output_overflow", [
        f"ref:{i:03d}:" + "<>&*_" * 3000 for i in range(50)
    ])]
elif scenario == "late_refusal":
    rows = [row("before", [
        f"ref:{i:03d}:" + "z" * 4096 for i in range(80)
    ]), row("after")]
    rows[-1].remediation = "q" * 16385
elif scenario == "huge_scalar":
    rows = [row("huge")]
    rows[0].title = "x" * 1000000
elif scenario == "duplicate":
    rows = [row("duplicate", ["ref:identical", "ref:identical"])]
elif scenario == "unicode":
    rows = [row("unicode", ["ref:café", "ref:🔒️"])]
elif scenario == "empty":
    rows = []
else:
    raise AssertionError("unknown synthetic case")

original = snapshot(rows)
gc.collect()
rss_before_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
tracemalloc.start()
call_count = [0]
real_escape = renderer._escape_literal
def counted_escape(value):
    call_count[0] += 1
    return real_escape(value)
try:
    with patch.object(renderer, "_escape_literal", side_effect=counted_escape):
        try:
            report = renderer.render_escaped_evidence_markdown_optin_w31(rows)
            status = "accepted"
            err_type = None
            err_message = None
        except Exception as exc:
            report = None
            status = "refused"
            err_type = type(exc).__name__
            err_message = str(exc)
    peak_bytes = tracemalloc.get_traced_memory()[1]
finally:
    tracemalloc.stop()
rss_after_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
unchanged = snapshot(rows) == original
print(json.dumps({
    "scenario": scenario,
    "status": status,
    "exception_type": err_type,
    "exception_message": err_message,
    "no_partial_result": report is None if status == "refused" else True,
    "immutable_input": unchanged,
    "private_metadata_absent": secret not in report if report is not None else True,
    "escape_calls": call_count[0],
    "output_bytes": len(report.encode("utf-8")) if report is not None else None,
    "sha256": hashlib.sha256(report.encode("utf-8")).hexdigest() if report is not None else None,
    "peak_tracked_bytes": peak_bytes,
    "rss_before_kib": rss_before_kib,
    "rss_peak_kib": rss_after_kib,
    "rss_increment_kib": max(0, rss_after_kib - rss_before_kib),
}))
'''


@unittest.skipUnless(sys.platform.startswith("linux"), "resource.ru_maxrss is Linux KiB here")
class IsolatedMarkdownMemoryCharacterizationW50(unittest.TestCase):
    # Generous environment-specific CI lab tripwires, not memory SLAs.
    MAX_PYTHON_TRACKED_PEAK = 32 * 1024 * 1024
    MAX_PROCESS_RSS_KIB = 512 * 1024
    INTEGRITY_ERROR = "invalid finding markdown evidence integrity"

    def _case(self, name: str) -> dict:
        env = os.environ.copy()
        root = Path(__file__).resolve().parents[1]
        env["PYTHONPATH"] = str(root / "src") + os.pathsep + env.get("PYTHONPATH", "")
        completed = subprocess.run(
            [sys.executable, "-c", _CHILD, name],
            cwd=root,
            env=env,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr[-3000:])
        result = json.loads(completed.stdout)
        self.assertEqual(result["scenario"], name)
        self.assertTrue(result["immutable_input"])
        self.assertTrue(result["private_metadata_absent"])
        self.assertTrue(result["no_partial_result"])
        self.assertGreater(result["rss_peak_kib"], 0)
        self.assertGreaterEqual(result["rss_increment_kib"], 0)
        self.assertLess(result["rss_peak_kib"], self.MAX_PROCESS_RSS_KIB)
        self.assertLess(result["peak_tracked_bytes"], self.MAX_PYTHON_TRACKED_PEAK)
        return result

    def test_accepted_large_escaped_output_measures_fresh_process(self):
        result = self._case("accepted")
        self.assertEqual(result["status"], "accepted")
        self.assertGreater(result["escape_calls"], 40)
        self.assertGreater(result["output_bytes"], 1_000_000)
        self.assertLessEqual(result["output_bytes"], 2_097_152)

    def test_large_output_refusal_is_atomic_after_escape(self):
        result = self._case("output_overflow")
        self.assertEqual(result["status"], "refused")
        self.assertGreater(result["escape_calls"], 0)
        self.assertIsNone(result["output_bytes"])
        self.assertEqual(result["exception_type"], "ValueError")
        self.assertEqual(result["exception_message"], self.INTEGRITY_ERROR)

    def test_late_row_and_huge_scalar_refuse_prior_to_any_escape(self):
        for scenario in ("late_refusal", "huge_scalar", "duplicate"):
            with self.subTest(scenario=scenario):
                result = self._case(scenario)
                self.assertEqual(result["status"], "refused")
                self.assertEqual(result["escape_calls"], 0)
                self.assertEqual(result["exception_type"], "ValueError")
                self.assertEqual(result["exception_message"], self.INTEGRITY_ERROR)

    def test_unicode_and_empty_controls(self):
        for scenario in ("unicode", "empty"):
            with self.subTest(scenario=scenario):
                result = self._case(scenario)
                self.assertEqual(result["status"], "accepted")
                self.assertGreater(result["output_bytes"], 0)
                self.assertIsNotNone(result["sha256"])

    def test_independent_processes_produce_same_report(self):
        first = self._case("unicode")
        second = self._case("unicode")
        self.assertEqual(first["sha256"], second["sha256"])
        self.assertEqual(first["output_bytes"], second["output_bytes"])


if __name__ == "__main__":
    unittest.main()
