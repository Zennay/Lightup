"""W59 synthetic opt-in HTML reviewer allocation/RSS subprocess characterization.

Never evaluates a real Markdown engine, browser, tenant record, customer finding,
target or installed renderer. Lab tripwires are NOT process memory guarantees.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

_REPO = Path(__file__).resolve().parents[1]
_ERROR = "invalid downstream finding html integrity"
# Conservative diagnostic tripwire for tracked Python allocations only.
_LAB_PEAK_BYTES = 128 * 1024 * 1024

_CHILD = r"""
import hashlib
import json
import resource
import sys
import tracemalloc

from tests.markdown_html_downstream_contract_w51 import check_conservative_html_fragment

mode = sys.argv[1]
if mode == "escaped":
    fragment = "<pre>W51 " + ("&amp;" * 280000) + "</pre>"
elif mode == "many_tags":
    fragment = "<ul>" + ("<li>W51</li>" * 25000) + "</ul>"
elif mode == "late_reject":
    fragment = "<p>W51 " + ("x" * 500000) + "</p><br / >"
elif mode == "over_ceiling":
    fragment = "<pre>W51" + ("x" * (4 * 1024 * 1024)) + "</pre>"
elif mode == "unicode":
    fragment = "<pre>W51 東京 café 👩\u200d💻</pre>"
elif mode == "surrogate_reject":
    fragment = "<pre>W51\ud800</pre>"
else:
    raise RuntimeError("invalid synthetic mode")

source = fragment.encode("utf-8", "surrogatepass")
before_sha = hashlib.sha256(source).hexdigest()
before_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
tracemalloc.start()
try:
    check_conservative_html_fragment(fragment, expected_text="W51")
    result = "accepted"
except ValueError as error:
    if str(error) != "invalid downstream finding html integrity":
        raise
    result = "rejected"
finally:
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
after_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
assert before_sha == hashlib.sha256(fragment.encode("utf-8", "surrogatepass")).hexdigest()
print(json.dumps({
    "mode": mode,
    "result": result,
    "peak_tracked_bytes": peak,
    "rss_highwater_before_kib": before_rss,
    "rss_highwater_after_kib": after_rss,
    "source_bytes": len(source),
    "input_unchanged": True,
}, sort_keys=True))
"""


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux ru_maxrss only")
class HtmlReviewerMemoryW59(unittest.TestCase):
    def _run(self, mode: str, expected: str) -> dict:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(_REPO / "src") + os.pathsep + env.get("PYTHONPATH", "")
        child = subprocess.run(
            [sys.executable, "-c", _CHILD, mode],
            cwd=_REPO,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=45,
        )
        self.assertEqual(child.returncode, 0, (child.stderr or "")[-2000:])
        self.assertFalse(child.stderr.strip(), child.stderr)
        record = json.loads(child.stdout.strip())
        self.assertEqual(record["mode"], mode)
        self.assertEqual(record["result"], expected)
        self.assertTrue(record["input_unchanged"])
        self.assertGreater(record["source_bytes"], 0)
        self.assertGreaterEqual(record["peak_tracked_bytes"], 0)
        self.assertLess(record["peak_tracked_bytes"], _LAB_PEAK_BYTES)
        self.assertGreater(record["rss_highwater_before_kib"], 0)
        self.assertGreaterEqual(
            record["rss_highwater_after_kib"], record["rss_highwater_before_kib"]
        )
        print("W59_SYNTHETIC_METRIC " + json.dumps(record, sort_keys=True))
        return record

    def test_escaped_near_megabyte_html_accepted_with_tracked_budget(self) -> None:
        row = self._run("escaped", "accepted")
        self.assertGreater(row["source_bytes"], 1024 * 1024)

    def test_many_html_nodes_accepted_without_unbounded_python_growth(self) -> None:
        row = self._run("many_tags", "accepted")
        self.assertGreater(row["source_bytes"], 200000)

    def test_late_bad_start_tag_rejected_without_partial_success(self) -> None:
        row = self._run("late_reject", "rejected")
        self.assertGreater(row["source_bytes"], 500000)

    def test_html_source_ceiling_rejects_before_downstream_parse(self) -> None:
        row = self._run("over_ceiling", "rejected")
        self.assertGreater(row["source_bytes"], 4 * 1024 * 1024)

    def test_unicode_and_emoji_positive_control(self) -> None:
        self._run("unicode", "accepted")

    def test_surrogate_utf8_refusal_control(self) -> None:
        self._run("surrogate_reject", "rejected")


if __name__ == "__main__":
    unittest.main()
