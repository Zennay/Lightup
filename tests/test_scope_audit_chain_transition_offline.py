"""Real API and stdin subprocess tests for anchored fictional export transitions."""

from __future__ import annotations

from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from lightup.scope_audit_chain_offline import (
    SCHEMA as CHAIN_SCHEMA,
    ZERO_HASH,
    compute_event_hash,
)
from lightup.scope_audit_chain_transition_offline import (
    MAX_TRANSITION_BYTES, SCHEMA, verify_transition,
)


def chain(kinds=("REVIEW_OPENED", "REVIEW_NOTE")):
    previous = ZERO_HASH
    events = []
    for index, kind in enumerate(kinds):
        body = {
            "seq": index,
            "kind": kind,
            "at": (datetime(2026, 10, 17, 12) + timedelta(seconds=index)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "scope_sha256": "a" * 64,
            "previous_sha256": previous,
        }
        previous = compute_event_hash(body)
        events.append({**body, "sha256": previous})
    return {"schema": CHAIN_SCHEMA, "events": events}, previous


def transition(before=("REVIEW_OPENED",), after=("REVIEW_OPENED", "REVIEW_NOTE")):
    old, old_tip = chain(before)
    new, new_tip = chain(after)
    return {"schema": SCHEMA, "before": old, "after": new}, old_tip, new_tip


def encode(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


class ScopeAuditTransitionTests(unittest.TestCase):
    def assert_hold(self, obj, old_tip, new_tip):
        raw = obj if type(obj) is bytes else encode(obj)
        result = verify_transition(raw, old_tip, new_tip)
        self.assertEqual("HOLD", result["status"])
        self.assertEqual("TRANSITION_INVALID", result["reason"])
        self.assertEqual(0, result["previous_records"])
        self.assertEqual(0, result["proposed_records"])
        self.assertEqual(0, result["new_records"])
        for key in ("consent_verified", "authorization_granted", "release_approved"):
            self.assertIs(result[key], False)

    def assert_review(self, obj, old_tip, new_tip, previous, proposed):
        result = verify_transition(encode(obj), old_tip, new_tip)
        self.assertEqual("REVIEW_ONLY", result["status"])
        self.assertEqual("FICTIONAL_APPEND_ONLY", result["reason"])
        self.assertEqual(previous, result["previous_records"])
        self.assertEqual(proposed, result["proposed_records"])
        self.assertEqual(proposed - previous, result["new_records"])
        for key in ("consent_verified", "authorization_granted", "release_approved"):
            self.assertIs(result[key], False)

    def test_one_record_added(self):
        obj, old_tip, new_tip = transition()
        self.assert_review(obj, old_tip, new_tip, 1, 2)

    def test_multiple_record_append_with_terminal_withdrawal(self):
        obj, old_tip, new_tip = transition(
            ("REVIEW_OPENED", "REVIEW_NOTE"),
            ("REVIEW_OPENED", "REVIEW_NOTE", "REVIEW_NOTE", "REVIEW_WITHDRAWN"),
        )
        self.assert_review(obj, old_tip, new_tip, 2, 4)

    def test_same_export_replay_is_hold(self):
        obj, old_tip, _ = transition()
        obj["after"] = obj["before"]
        self.assert_hold(obj, old_tip, old_tip)

    def test_truncated_candidate_holds(self):
        obj, old_tip, new_tip = transition(
            ("REVIEW_OPENED", "REVIEW_NOTE"),
            ("REVIEW_OPENED",),
        )
        self.assert_hold(obj, old_tip, new_tip)

    def test_mismatched_independent_anchors_hold(self):
        obj, old_tip, new_tip = transition()
        self.assert_hold(obj, "f" * 64, new_tip)
        self.assert_hold(obj, old_tip, "f" * 64)
        self.assert_hold(obj, old_tip, "F" * 64)
        self.assert_hold(obj, None, new_tip)
        self.assert_hold(obj, True, new_tip)

    def test_rewritten_prefix_fails_even_if_new_tip_recomputed(self):
        obj, old_tip, _ = transition(
            ("REVIEW_OPENED", "REVIEW_NOTE"),
            ("REVIEW_OPENED", "REVIEW_NOTE", "REVIEW_NOTE"),
        )
        new_events = obj["after"]["events"]
        old_event = new_events[1]
        body = {k: v for k, v in old_event.items() if k != "sha256"}
        body["at"] = "2026-10-17T12:00:05Z"
        new_events[1] = {**body, "sha256": compute_event_hash(body)}
        tail = {k: v for k, v in new_events[2].items() if k != "sha256"}
        tail["at"] = "2026-10-17T12:00:06Z"
        tail["previous_sha256"] = new_events[1]["sha256"]
        new_events[2] = {**tail, "sha256": compute_event_hash(tail)}
        self.assert_hold(obj, old_tip, new_events[-1]["sha256"])

    def test_rehashed_truncated_old_export_fails_trusted_old_anchor(self):
        obj, old_tip, new_tip = transition(
            ("REVIEW_OPENED", "REVIEW_NOTE"),
            ("REVIEW_OPENED", "REVIEW_NOTE", "REVIEW_NOTE"),
        )
        obj["before"]["events"] = obj["before"]["events"][:1]
        self.assert_hold(obj, old_tip, new_tip)

    def test_existing_withdrawal_cannot_be_extended(self):
        obj, old_tip, new_tip = transition(
            ("REVIEW_OPENED", "REVIEW_WITHDRAWN"),
            ("REVIEW_OPENED", "REVIEW_WITHDRAWN", "REVIEW_NOTE"),
        )
        self.assert_hold(obj, old_tip, new_tip)

    def test_reopened_review_after_withdrawal_fails(self):
        obj, old_tip, new_tip = transition(
            ("REVIEW_OPENED", "REVIEW_WITHDRAWN"),
            ("REVIEW_OPENED", "REVIEW_WITHDRAWN", "REVIEW_OPENED"),
        )
        self.assert_hold(obj, old_tip, new_tip)

    def test_scope_switch_with_new_valid_chain_holds(self):
        obj, old_tip, _ = transition()
        after = obj["after"]
        previous = ZERO_HASH
        for event in after["events"]:
            body = {k: v for k, v in event.items() if k != "sha256"}
            body["scope_sha256"] = "b" * 64
            body["previous_sha256"] = previous
            previous = compute_event_hash(body)
            event.update({**body, "sha256": previous})
        self.assert_hold(obj, old_tip, previous)

    def test_forged_authority_fields_at_every_layer_hold(self):
        for location in ("root", "before", "after", "event"):
            with self.subTest(location=location):
                obj, old_tip, new_tip = transition()
                if location == "root":
                    obj["release_approved"] = True
                elif location == "event":
                    obj["after"]["events"][0]["consent_verified"] = True
                else:
                    obj[location]["authorization_granted"] = True
                self.assert_hold(obj, old_tip, new_tip)

    def test_schema_downgrade_and_alias_hold(self):
        for key, value in (
            ("schema", "LIGHTUP-FICTIONAL-SCOPE-AUDIT-TRANSITION-V0"),
            ("before", []),
            ("after", False),
        ):
            with self.subTest(key=key):
                obj, old_tip, new_tip = transition()
                obj[key] = value
                self.assert_hold(obj, old_tip, new_tip)

    def test_duplicate_keys_unsafe_json_numbers_invalid_utf8(self):
        obj, old_tip, new_tip = transition()
        raw = encode(obj)
        self.assert_hold(raw.replace(b'"schema":', b'"schema":"wrong","schema":', 1),
                         old_tip, new_tip)
        self.assert_hold(raw.replace(b'"seq":0', b'"seq":NaN', 1), old_tip, new_tip)
        self.assert_hold(raw.replace(b'"seq":0', b'"seq":Infinity', 1), old_tip, new_tip)
        self.assert_hold(raw + b"\xff", old_tip, new_tip)

    def test_bounded_input(self):
        obj, old_tip, new_tip = transition()
        self.assert_hold(encode(obj) + b" " * MAX_TRANSITION_BYTES, old_tip, new_tip)
        self.assert_hold(b"", old_tip, new_tip)
        self.assert_hold("not bytes", old_tip, new_tip)
        self.assert_hold(b"[]", old_tip, new_tip)

    def test_bool_float_seq_rejected_on_recheck(self):
        for bad in (True, 0.0, "0"):
            with self.subTest(bad=bad):
                obj, old_tip, new_tip = transition()
                obj["after"]["events"][0]["seq"] = bad
                self.assert_hold(obj, old_tip, new_tip)

    def test_nonmonotonic_timestamps(self):
        obj, old_tip, _ = transition()
        old_event = obj["after"]["events"][1]
        body = {k: v for k, v in old_event.items() if k != "sha256"}
        body["at"] = "2026-10-17T12:00:00Z"
        obj["after"]["events"][1] = {**body, "sha256": compute_event_hash(body)}
        self.assert_hold(obj, old_tip, obj["after"]["events"][1]["sha256"])

    def _cli(self, raw, old_tip, new_tip, flag=True):
        root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root / "src")
        cmd = [
            sys.executable, "-m", "lightup.scope_audit_chain_transition_offline",
            "--expected-old-tip", old_tip,
            "--expected-new-tip", new_tip,
        ]
        if flag:
            cmd.append("--synthetic-only")
        return subprocess.run(cmd, input=raw, capture_output=True, cwd=root,
                              env=env, timeout=10)

    def test_cli_isolated_positive_exit_3(self):
        obj, old_tip, new_tip = transition()
        p = self._cli(encode(obj), old_tip, new_tip)
        self.assertEqual(3, p.returncode, p.stderr.decode())
        self.assertEqual("REVIEW_ONLY", json.loads(p.stdout)["status"])
        self.assertNotIn(("a" * 64).encode(), p.stdout)
        self.assertNotIn(old_tip.encode(), p.stdout)
        self.assertNotIn(new_tip.encode(), p.stdout)

    def test_cli_missing_explicit_flag_holds(self):
        obj, old_tip, new_tip = transition()
        p = self._cli(encode(obj), old_tip, new_tip, flag=False)
        self.assertEqual(2, p.returncode)
        self.assertEqual("HOLD", json.loads(p.stdout)["status"])

    def test_cli_tamper_privacy_generic_hold(self):
        obj, old_tip, new_tip = transition()
        obj["after"]["events"][1]["kind"] = "APPROVED"
        p = self._cli(encode(obj), old_tip, new_tip)
        self.assertEqual(2, p.returncode)
        receipt = json.loads(p.stdout)
        self.assertEqual("HOLD", receipt["status"])
        self.assertNotIn(b"APPROVED", p.stdout)
        self.assertNotIn(b"2026-10-17", p.stdout)

    def test_cli_duplicate_keys_hold(self):
        obj, old_tip, new_tip = transition()
        raw = encode(obj).replace(b'"schema":', b'"schema":"fake","schema":', 1)
        p = self._cli(raw, old_tip, new_tip)
        self.assertEqual(2, p.returncode)
        self.assertEqual("HOLD", json.loads(p.stdout)["status"])


if __name__ == "__main__":
    unittest.main()
