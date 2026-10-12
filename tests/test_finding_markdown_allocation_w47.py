"""W47 synthetic allocation characterization of the uninstalled W31 renderer.

These tests do not claim a process-RSS bound, downstream HTML safety or
production acceptance. Run offline with Python's standard library only.
"""
from __future__ import annotations

import gc
import tracemalloc
import unittest
from unittest.mock import patch

import lightup.finding_markdown_escaped_optin_w31 as renderer
from lightup.models import Finding, RetestStatus, Severity


def finding(name: str, *, evidence: list[str] | None = None) -> Finding:
    return Finding(
        finding_id="synthetic:" + name,
        title="Synthetic " + name,
        severity=Severity.INFO,
        target="offline.synthetic",
        evidence=["ref:a"] if evidence is None else evidence,
        remediation="Review offline evidence",
        retest_status=RetestStatus.NOT_TESTED,
        metadata={"private": "never export"},
    )


def measured(call):
    gc.collect()
    tracemalloc.start()
    try:
        result = call()
        _, peak = tracemalloc.get_traced_memory()
        return result, peak
    finally:
        tracemalloc.stop()


class MarkdownAllocationCharacterizationW47(unittest.TestCase):
    # This is a generous diagnostic regression threshold, not a memory SLA.
    LAB_PEAK_LIMIT = 32 * 1024 * 1024

    def test_near_limit_escaped_evidence_allocation(self):
        row = finding("large", evidence=["<>&*_" * 2800 for _ in range(40)])
        before = tuple(row.evidence)
        output, peak = measured(
            lambda: renderer.render_escaped_evidence_markdown_optin_w31([row])
        )
        self.assertIn("### Remediation", output)
        self.assertNotIn("never export", output)
        self.assertLess(peak, self.LAB_PEAK_LIMIT)
        self.assertEqual(tuple(row.evidence), before)

    def test_many_evidence_references_allocation(self):
        rows = [
            finding(str(i), evidence=[f"ref:{i}:{j}" for j in range(128)])
            for i in range(64)
        ]
        output, peak = measured(
            lambda: renderer.render_escaped_evidence_markdown_optin_w31(rows)
        )
        self.assertIn("synthetic\\:63", output)
        self.assertLess(peak, self.LAB_PEAK_LIMIT)
        self.assertEqual(len(rows[0].evidence), 128)

    def test_oversized_field_fails_before_escape(self):
        row = finding("oversized")
        row.title = "x" * 1_000_000
        with patch.object(renderer, "_escape_literal") as escape:
            with self.assertRaisesRegex(ValueError, "evidence integrity"):
                _, peak = measured(
                    lambda: renderer.render_escaped_evidence_markdown_optin_w31([row])
                )
            escape.assert_not_called()

    def test_late_rejection_prevents_any_render(self):
        early, late = finding("early"), finding("late")
        late.evidence.append("x" * 1_000_000)
        original = tuple(late.evidence)
        with patch.object(renderer, "_escape_literal") as escape:
            with self.assertRaisesRegex(ValueError, "evidence integrity"):
                renderer.render_escaped_evidence_markdown_optin_w31([early, late])
            escape.assert_not_called()
        self.assertEqual(tuple(late.evidence), original)

    def test_empty_and_unicode_controls(self):
        self.assertIn("No findings recorded", renderer.render_escaped_evidence_markdown_optin_w31([]))
        row = finding("unicode", evidence=["ref:🔒️", "ref:café"])
        output = renderer.render_escaped_evidence_markdown_optin_w31([row])
        self.assertIn("café", output)
        self.assertNotIn("never export", output)


if __name__ == "__main__":
    unittest.main()
