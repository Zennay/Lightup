from __future__ import annotations

from pathlib import Path
import re
import unittest


GATE_DOC = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "st5-evidence-remediation-persisted-consumer-gate.md"
)

EXPECTED_CONSUMERS = {
    "Evidence collection request": "#136",
    "Freshness constraints": "#131",
    "Freshness admission": "#141",
    "Freshness coverage": "#128",
    "Metadata-contract review": "#145",
    "Sufficiency-review request": "#148",
    "Sufficiency verifier preflight": "#150",
    "Sufficiency attestation": "#154",
    "Classification-review request": "#109",
}

FORBIDDEN_POSITIVE_AUTHORITIES = (
    "classification_selected=true",
    "transition_resolution_created=true",
    "collection_authorized=true",
    "tool_call_created=true",
    "execution_allowed=true",
    "target_interaction_allowed=true",
    "remediation_authoring_allowed=true",
    "future_state_retest_allowed=true",
    "deployment_authorized=true",
    "attack_path_mutation_allowed=true",
)


class PersistedEvidenceRemediationGateContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = GATE_DOC.read_text(encoding="utf-8")

    def _covered_boundary_rows(self) -> dict[str, str]:
        section = self.text.split("## Covered boundaries", 1)[1].split(
            "## Merge-order gate", 1
        )[0]
        rows: dict[str, str] = {}
        for line in section.splitlines():
            if not line.startswith("|") or "---" in line or "Persisted boundary" in line:
                continue
            columns = [column.strip() for column in line.strip("|").split("|")]
            self.assertEqual(5, len(columns), line)
            boundary, _handoff, consumer, _hosted, _canonical = columns
            self.assertNotIn(boundary, rows, f"duplicate covered boundary: {boundary}")
            rows[boundary] = consumer
        return rows

    def test_covered_boundary_set_and_consumers_are_exact(self) -> None:
        rows = self._covered_boundary_rows()
        self.assertEqual(set(EXPECTED_CONSUMERS), set(rows))
        for boundary, consumer in EXPECTED_CONSUMERS.items():
            self.assertIn(consumer, rows[boundary], boundary)

    def test_non_bypassable_consumer_stage_order_is_explicit(self) -> None:
        invariant = self.text.split(
            "## Non-bypassable persisted-consumer invariant", 1
        )[1].split("## Ownership / non-overlap", 1)[0]
        stages = (
            "Duplicate-key-safe JSON decode",
            "Exact strict parser",
            "Immediate live validator",
        )
        positions = [invariant.index(stage) for stage in stages]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("must not receive a parsed object", invariant)
        self.assertIn("all applicable stages pass", invariant)

    def test_semantic_stop_line_stays_fail_closed(self) -> None:
        stop_line = self.text.split("## Semantic stop line", 1)[1]
        self.assertRegex(
            stop_line,
            re.compile(
                r"classification-review \*\*request\*\*.*does not perform that\s+review",
                re.IGNORECASE | re.DOTALL,
            ),
        )
        for required in (
            "classification_selected=false",
            "transition_resolution_created=false",
            "future_semantics=unresolved",
            "security_verdict=not_evaluated",
        ):
            self.assertIn(required, stop_line)

        compact = re.sub(r"\s+", "", self.text.lower())
        for forbidden in FORBIDDEN_POSITIVE_AUTHORITIES:
            self.assertNotIn(forbidden, compact)

    def test_operational_and_parallel_lane_ownership_remains_separate(self) -> None:
        ownership = self.text.split("## Ownership / non-overlap", 1)[1].split(
            "## Covered boundaries", 1
        )[0]
        self.assertIn("Issue #157", ownership)
        self.assertIn("#60", ownership)
        self.assertIn("future-state retest/authorization", ownership)


if __name__ == "__main__":
    unittest.main()
