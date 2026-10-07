from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_text_revision_review_handoff as handoff_tests


class _PersistedTextSubclass(str):
    """Producer-impossible polymorphic persisted JSON text."""


class _PersistedObjectSubclass(dict):
    """Producer-impossible polymorphic persisted JSON object."""


class FutureRemediationTextRevisionReviewConsumerSubclassTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextRevisionReviewHandoffTest(
            "test_approved_review_round_trips_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _state_dump(self) -> str:
        with self.base.base.base.base.base.base.base.base.base.state.connect() as con:
            return "\n".join(con.iterdump())

    def test_exact_builtin_persisted_forms_remain_green(self):
        raw = self.base.review.to_json()
        payload = json.loads(raw)

        self.assertIs(type(raw), str)
        self.assertIs(type(payload), dict)
        self.assertEqual(self.base._load(persisted=raw), self.base.review)
        self.assertEqual(self.base._load(persisted=payload), self.base.review)

    def test_equal_content_str_subclass_fails_closed_without_mutation(self):
        persisted = _PersistedTextSubclass(self.base.review.to_json())
        before_value = str(persisted)
        before_state = self._state_dump()

        with self.assertRaises(ValueError):
            self.base._load(persisted=persisted)

        self.assertIs(type(persisted), _PersistedTextSubclass)
        self.assertEqual(str(persisted), before_value)
        self.assertEqual(self._state_dump(), before_state)

    def test_equal_content_dict_subclass_fails_closed_without_mutation(self):
        persisted = _PersistedObjectSubclass(
            json.loads(self.base.review.to_json())
        )
        before_value = copy.deepcopy(persisted)
        before_state = self._state_dump()

        with self.assertRaises(ValueError):
            self.base._load(persisted=persisted)

        self.assertIs(type(persisted), _PersistedObjectSubclass)
        self.assertEqual(persisted, before_value)
        self.assertEqual(self._state_dump(), before_state)


if __name__ == "__main__":
    unittest.main()
