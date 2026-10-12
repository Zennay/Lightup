"""W48 independent synthetic memory/byte-boundary tests for W46 opt-in Markdown.

These tests do not assert process RSS, real Markdown-to-HTML safety,
tenant authorization, or production readiness. No network or live data.
"""
from __future__ import annotations

import copy
import gc
import tracemalloc
import unittest
from unittest.mock import patch

import lightup.finding_markdown_escaped_optin_w31 as renderer
from lightup.models import Finding, RetestStatus, Severity


def _row(name: str, references: list[str] | None = None) -> Finding:
    return Finding(
        finding_id="w48:" + name,
        title="Synthetic " + name,
        severity=Severity.INFO,
        target="offline.synthetic",
        evidence=["ref:base"] if references is None else references,
        remediation="Review authorized evidence offline",
        retest_status=RetestStatus.NOT_TESTED,
        metadata={"private": {"token": "SYNTHETIC-DO-NOT-EXPORT"}},
    )


def _snapshot(rows: list[Finding]) -> list[tuple]:
    """Snapshot caller-owned mutable data without invoking the renderer."""
    return [
        (
            row.finding_id, row.title, row.target, row.remediation,
            row.severity, row.retest_status,
            copy.deepcopy(row.evidence), copy.deepcopy(row.metadata),
        )
        for row in rows
    ]


def _measured(call):
    """Peak Python-tracked *incremental* allocations, not RSS."""
    gc.collect()
    tracemalloc.start()
    try:
        result = call()
        peak = tracemalloc.get_traced_memory()[1]
        return result, peak
    finally:
        tracemalloc.stop()


class IndependentMarkdownAllocationBoundariesW48(unittest.TestCase):
    # Laboratory regression tripwire only; never a memory safety guarantee.
    LAB_TRACKED_PEAK_BYTES = 32 * 1024 * 1024
    ERROR = "invalid finding markdown evidence integrity"

    def _must_refuse(self, rows: list[Finding], *, no_escape: bool = False) -> int:
        original = _snapshot(rows)
        gc.collect()
        tracemalloc.start()
        try:
            if no_escape:
                with patch.object(renderer, "_escape_literal") as escape:
                    with self.assertRaises(ValueError) as caught:
                        renderer.render_escaped_evidence_markdown_optin_w31(rows)
                    escape.assert_not_called()
            else:
                with self.assertRaises(ValueError) as caught:
                    renderer.render_escaped_evidence_markdown_optin_w31(rows)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertIs(type(caught.exception), ValueError)
        self.assertEqual(str(caught.exception), self.ERROR)
        self.assertEqual(_snapshot(rows), original)
        self.assertLess(peak, self.LAB_TRACKED_PEAK_BYTES)
        return peak

    def test_distinct_large_escaped_references_are_accepted(self):
        # Unlike a repeated reference, every id here is unique. Both source
        # (~480 KiB) and escaped output (~1.56 MiB) remain under their caps.
        references = [f"ref:{i:03d}:" + "<>&*_" * 2400 for i in range(40)]
        rows = [_row("unique", references)]
        original = _snapshot(rows)
        markdown, peak = _measured(
            lambda: renderer.render_escaped_evidence_markdown_optin_w31(rows)
        )
        self.assertIn("### Remediation", markdown)
        self.assertEqual(markdown.count("&lt;"), 40 * 2400)
        self.assertNotIn("SYNTHETIC-DO-NOT-EXPORT", markdown)
        self.assertLessEqual(len(markdown.encode("utf-8")), 2_097_152)
        self.assertLess(peak, self.LAB_TRACKED_PEAK_BYTES)
        self.assertEqual(_snapshot(rows), original)

    def test_identical_references_refuse_before_escaping(self):
        # W43 duplicate integrity rule must not be weakened to satisfy an
        # allocation benchmark with accidental duplicate evidence.
        rows = [_row("duplicate", ["<>&*_" * 1000] * 2)]
        self._must_refuse(rows, no_escape=True)

    def test_exact_field_utf8_bytes_are_accepted_and_plus_one_refuses(self):
        permitted = [_row("utf8", ["é" * 8192])]
        output, peak = _measured(
            lambda: renderer.render_escaped_evidence_markdown_optin_w31(permitted)
        )
        self.assertIn("é" * 40, output)
        self.assertLess(peak, self.LAB_TRACKED_PEAK_BYTES)
        self._must_refuse([_row("utf8-too-large", ["é" * 8193])], no_escape=True)
        self._must_refuse([_row("ascii-too-large", ["a" * 16385])], no_escape=True)

    def test_million_character_input_refuses_without_escape(self):
        row = _row("very-large")
        row.title = "x" * 1_000_000
        self._must_refuse([row], no_escape=True)

    def test_source_batch_overrun_refuses_prior_to_render(self):
        # 65 unique 16 KiB references are individually valid, but exceed
        # the 1 MiB cumulative source limit (even before the row fields).
        references = [
            f"ref:{i:03d}:" + "a" * (16_384 - len(f"ref:{i:03d}:"))
            for i in range(65)
        ]
        self._must_refuse([_row("source-ceiling", references)], no_escape=True)

    def test_late_row_refusal_prevents_early_row_render(self):
        first = _row(
            "early", [f"ref:{i:03d}:" + "z" * 4096 for i in range(80)]
        )
        last = _row("late")
        last.remediation = "q" * 16385
        self._must_refuse([first, last], no_escape=True)

    def test_escaped_output_exceeding_two_mib_refuses_atomically(self):
        # Source ~733 KiB; escaped output >2 MiB. No partial report is
        # returned despite partial internal line assembly.
        references = [f"ref:{i:03d}:" + "<>&*_" * 3000 for i in range(50)]
        self.assertLess(sum(len(r.encode("utf-8")) for r in references), 1_048_576)
        self._must_refuse([_row("output-ceiling", references)])

    def test_empty_and_normal_unicode_remain_private_and_deterministic(self):
        empty, empty_peak = _measured(
            lambda: renderer.render_escaped_evidence_markdown_optin_w31([])
        )
        self.assertIn("No findings recorded", empty)
        self.assertLess(empty_peak, self.LAB_TRACKED_PEAK_BYTES)
        rows = [_row("unicode", ["ref:café", "ref:🔒️"])]
        before = _snapshot(rows)
        output, peak = _measured(
            lambda: renderer.render_escaped_evidence_markdown_optin_w31(rows)
        )
        self.assertIn("café", output)
        self.assertNotIn("SYNTHETIC-DO-NOT-EXPORT", output)
        self.assertEqual(output, renderer.render_escaped_evidence_markdown_optin_w31(rows))
        self.assertEqual(_snapshot(rows), before)
        self.assertLess(peak, self.LAB_TRACKED_PEAK_BYTES)


if __name__ == "__main__":
    unittest.main()
