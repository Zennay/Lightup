from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from lightup.future_remediation_implementation_plan import _parse_model_content


RAW_IMPLEMENTATION_PLAN_RESPONSE_CHAR_LIMIT = 65_536


class ImplementationPlannerRawResponseBoundAcceptanceTest(unittest.TestCase):
    def _canonical_raw(self) -> str:
        return json.dumps(
            {
                "summary": "Apply the smallest defensive change and verify it.",
                "plan_items": [
                    {
                        "plan_item_id": "plan-1",
                        "change_area": "configuration",
                        "intent": "Tighten the affected defensive control.",
                        "verification_intent": "Verify the intended control state.",
                        "rollback_intent": "Restore the prior configuration if needed.",
                    }
                ],
                "assumptions": [],
                "unresolved_questions": [],
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def test_canonical_planner_response_remains_green(self) -> None:
        raw = self._canonical_raw()

        summary, items, assumptions, unresolved = _parse_model_content(raw)

        self.assertEqual(
            summary,
            "Apply the smallest defensive change and verify it.",
        )
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].plan_item_id, "plan-1")
        self.assertEqual(assumptions, ())
        self.assertEqual(unresolved, ())
        self.assertLessEqual(
            len(raw),
            RAW_IMPLEMENTATION_PLAN_RESPONSE_CHAR_LIMIT,
        )

    def test_oversized_raw_response_fails_before_json_parser(self) -> None:
        # JSON permits leading whitespace, so this is semantically the same
        # canonical response after decoding. The aggregate raw envelope alone is
        # what must fail closed before any parser work.
        raw = (
            " " * RAW_IMPLEMENTATION_PLAN_RESPONSE_CHAR_LIMIT
            + self._canonical_raw()
        )
        self.assertGreater(
            len(raw),
            RAW_IMPLEMENTATION_PLAN_RESPONSE_CHAR_LIMIT,
        )

        with patch(
            "lightup.future_remediation_implementation_plan.json.loads",
            side_effect=AssertionError("oversized response reached json.loads"),
        ) as loads:
            with self.assertRaisesRegex(
                ValueError,
                "planner response|raw response|response size|bounded response",
            ):
                _parse_model_content(raw)

        loads.assert_not_called()


if __name__ == "__main__":
    unittest.main()
