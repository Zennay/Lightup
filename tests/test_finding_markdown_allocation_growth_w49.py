"""W49 independent incremental Python-allocation characterization.

Opt-in synthetic-only descendants of W48 (#1224). This does not establish
total RSS, hard memory/time limits, HTML security or tenant authorization.
"""
from __future__ import annotations

import gc
import tracemalloc
import unittest
from unittest.mock import patch

import lightup.finding_markdown_escaped_optin_w31 as renderer
from lightup.models import Finding, RetestStatus, Severity


def _finding(name: str, evidence: list[str]) -> Finding:
    return Finding(
        finding_id="w49:" + name,
        title="Offline " + name,
        severity=Severity.INFO,
        target="offline.synthetic",
        evidence=evidence,
        remediation="Synthetic review only",
        retest_status=RetestStatus.NOT_TESTED,
        metadata={"secret": "W49_PRIVATE_NEVER_OUTPUT"},
    )


def _peak(call):
    # Input objects are intentionally prepared before tracing. Characterize
    # only extra Python-tracked allocations made by this renderer invocation.
    gc.collect()
    tracemalloc.start()
    try:
        result = call()
        peak = tracemalloc.get_traced_memory()[1]
        return result, peak
    finally:
        tracemalloc.stop()


class MarkdownIncrementalGrowthW49(unittest.TestCase):
    LAB_PEAK_LIMIT = 32 * 1024 * 1024
    LAB_EXTRA_GROWTH_LIMIT = 24 * 1024 * 1024

    def test_large_valid_escaped_report_has_conservative_incremental_growth(self):
        # 12 KiB of raw data per distinct reference, HTML-entity and Markdown
        # escape heavy; both 8- and 40-reference reports remain under 1 MiB
        # source and 2 MiB escaped output limits.
        def rows(count):
            return [_finding(
                f"distinct-{count}",
                [f"ref:{i:03d}:" + "<>&*_" * 2400 for i in range(count)],
            )]

        small_rows = rows(8)
        large_rows = rows(40)
        small_original = tuple(small_rows[0].evidence)
        large_original = tuple(large_rows[0].evidence)

        small_text, small_peak = _peak(
            lambda: renderer.render_escaped_evidence_markdown_optin_w31(small_rows)
        )
        large_text, large_peak = _peak(
            lambda: renderer.render_escaped_evidence_markdown_optin_w31(large_rows)
        )

        self.assertGreater(len(large_text.encode("utf-8")), len(small_text.encode("utf-8")))
        self.assertLessEqual(len(large_text.encode("utf-8")), 2_097_152)
        self.assertLess(small_peak, self.LAB_PEAK_LIMIT)
        self.assertLess(large_peak, self.LAB_PEAK_LIMIT)
        self.assertLessEqual(large_peak - small_peak, self.LAB_EXTRA_GROWTH_LIMIT)
        self.assertEqual(tuple(small_rows[0].evidence), small_original)
        self.assertEqual(tuple(large_rows[0].evidence), large_original)
        self.assertNotIn("W49_PRIVATE_NEVER_OUTPUT", large_text)

    def test_one_million_character_field_refuses_before_unicode_walk(self):
        row = _finding("oversized", ["ref:ok"])
        row.title = "X" * 1_000_000
        original_title = row.title
        original_evidence = tuple(row.evidence)

        real_category = renderer.unicodedata.category
        real_normalize = renderer.unicodedata.normalize

        def category(character):
            if character == "X":
                raise AssertionError("oversized field was scanned")
            return real_category(character)

        def normalize(form, character):
            if character == "X":
                raise AssertionError("oversized field was normalized")
            return real_normalize(form, character)

        with (
            patch.object(renderer.unicodedata, "category", side_effect=category),
            patch.object(renderer.unicodedata, "normalize", side_effect=normalize),
            patch.object(renderer, "_escape_literal") as escape,
        ):
            gc.collect()
            tracemalloc.start()
            try:
                with self.assertRaises(ValueError) as raised:
                    renderer.render_escaped_evidence_markdown_optin_w31([row])
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
            escape.assert_not_called()

        self.assertIs(type(raised.exception), ValueError)
        self.assertEqual(str(raised.exception), "invalid finding markdown evidence integrity")
        self.assertLess(peak, self.LAB_PEAK_LIMIT)
        self.assertEqual(row.title, original_title)
        self.assertEqual(tuple(row.evidence), original_evidence)


if __name__ == "__main__":
    unittest.main()
