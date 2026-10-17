"""Negative offline regressions for externally anchored fictional checkpoints."""

from __future__ import annotations

from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from lightup.scope_audit_chain_offline import (
    MAX_EVENTS, SCHEMA as CHAIN_SCHEMA, ZERO_HASH, compute_event_hash, verify_chain,
)
from lightup.scope_audit_chain_checkpoints_offline import (
    MAX_CHECKPOINTS, MAX_INPUT_BYTES, SCHEMA, verify_checkpoints,
)


def snapshot(length, *, scope="a" * 64, withdraw=False):
    rows = []
    last = ZERO_HASH
    for index in range(length):
        kind = "REVIEW_OPENED" if index == 0 else "REVIEW_NOTE"
        if withdraw and index == length - 1:
            kind = "REVIEW_WITHDRAWN"
        body = {
            "seq": index,
            "kind": kind,
            "at": (
                datetime(2026, 10, 17, 12) + timedelta(seconds=index)
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scope_sha256": scope,
            "previous_sha256": last,
        }
        last = compute_event_hash(body)
        rows.append({**body, "sha256": last})
    return {"schema": CHAIN_SCHEMA, "events": rows}, last


def bundle(lengths, *, withdraw_last=False):
    snapshots = []
    tips = []
    for index, count in enumerate(lengths):
        obj, tip = snapshot(
            count, withdraw=withdraw_last and index == len(lengths) - 1
        )
        snapshots.append(obj)
        tips.append(tip)
    return {"schema": SCHEMA, "snapshots": snapshots}, tuple(tips)


def encode(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class CheckpointAcceptanceTests(unittest.TestCase):
    def hold(self, obj, tips):
        raw = obj if type(obj) is bytes else encode(obj)
        result = verify_checkpoints(raw, tips)
        self.assertEqual("HOLD", result["status"])
        self.assertEqual("CHECKPOINTS_INVALID", result["reason"])
        for name in ("checkpoints", "initial_records", "final_records", "appended_records"):
            self.assertEqual(0, result[name])
        for name in ("consent_verified", "authorization_granted", "release_approved"):
            self.assertIs(result[name], False)

    def accepted(self, obj, tips, counts):
        receipt = verify_checkpoints(encode(obj), tips)
        self.assertEqual("REVIEW_ONLY", receipt["status"])
        self.assertEqual("FICTIONAL_CHECKPOINT_CONTINUITY", receipt["reason"])
        self.assertEqual(tuple(counts), (
            receipt["checkpoints"], receipt["initial_records"],
            receipt["final_records"], receipt["appended_records"],
        ))
        for field in ("consent_verified", "authorization_granted", "release_approved"):
            self.assertIs(receipt[field], False)

    def test_exact_two_snapshot_minimum(self):
        obj, tips = bundle([1, 2])
        self.accepted(obj, tips, (2, 1, 2, 1))

    def test_three_snapshot_continuity(self):
        obj, tips = bundle([1, 3, 6])
        self.accepted(obj, tips, (3, 1, 6, 5))

    def test_all_eight_checkpoints(self):
        obj, tips = bundle([1, 2, 3, 4, 5, 6, 7, 8])
        self.accepted(obj, tips, (MAX_CHECKPOINTS, 1, 8, 7))

    def test_bound_64_records_last_checkpoint(self):
        obj, tips = bundle([1, 32, MAX_EVENTS])
        self.accepted(obj, tips, (3, 1, 64, 63))

    def test_capacity_eight_checkpoints_with_64_final_records(self):
        lengths = [1, 2, 3, 4, 8, 16, 32, 64]
        obj, tips = bundle(lengths)
        self.accepted(obj, tips, (8, 1, 64, 63))

    def test_forked_individually_valid_reanchored_history_holds(self):
        obj, tips = bundle([2, 3, 4])
        last = obj["snapshots"][-1]["events"]
        previous = ZERO_HASH
        for record in last:
            body = {key: value for key, value in record.items() if key != "sha256"}
            old = datetime.strptime(body["at"], "%Y-%m-%dT%H:%M:%SZ")
            body["at"] = (old + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            body["previous_sha256"] = previous
            previous = compute_event_hash(body)
            record.update({**body, "sha256": previous})
        # Individually coherent SHA does not allow rewriting prior checkpoints.
        self.assertEqual(
            "REVIEW_ONLY", verify_chain(encode(obj["snapshots"][-1]), previous)["status"]
        )
        self.hold(obj, tips[:-1] + (previous,))

    def test_all_trusted_anchors_in_correct_order_required(self):
        obj, tips = bundle([1, 2, 3, 4])
        self.hold(obj, tips[::-1])
        self.hold(obj, tips[:-1])
        self.hold(obj, tips + ("f" * 64,))

    def test_withdrawal_can_end_last_checkpoint(self):
        obj, tips = bundle([1, 2, 3], withdraw_last=True)
        self.accepted(obj, tips, (3, 1, 3, 2))

    def test_only_one_checkpoint_rejected(self):
        obj, tips = bundle([1])
        self.hold(obj, tips)

    def test_nine_checkpoints_rejected(self):
        obj, tips = bundle([1, 2, 3, 4, 5, 6, 7, 8, 9])
        self.hold(obj, tips)

    def test_missing_middle_checkpoint_with_all_pins_rejected(self):
        obj, tips = bundle([1, 2, 4, 6])
        obj["snapshots"].pop(1)
        self.hold(obj, tips)

    def test_missing_first_checkpoint_with_all_pins_rejected(self):
        obj, tips = bundle([1, 2, 4])
        obj["snapshots"].pop(0)
        self.hold(obj, tips)

    def test_missing_final_checkpoint_with_all_pins_rejected(self):
        obj, tips = bundle([1, 2, 4])
        obj["snapshots"].pop()
        self.hold(obj, tips)

    def test_extra_checkpoint_without_pin_rejected(self):
        obj, tips = bundle([1, 2])
        obj["snapshots"].append(snapshot(3)[0])
        self.hold(obj, tips)

    def test_repeated_checkpoint_replay_rejected(self):
        obj, tips = bundle([1, 2, 3])
        obj["snapshots"][2] = obj["snapshots"][1]
        self.hold(obj, tips[:2] + (tips[1],))

    def test_checkpoint_order_swap_rejected(self):
        obj, tips = bundle([1, 2, 3])
        obj["snapshots"][0], obj["snapshots"][1] = (
            obj["snapshots"][1], obj["snapshots"][0]
        )
        self.hold(obj, tips)

    def test_checkpoint_rollback_with_matching_alternative_tip_rejected(self):
        obj, tips = bundle([1, 2, 3])
        obj["snapshots"][2] = snapshot(1)[0]
        self.hold(obj, tips[:2] + (tips[0],))

    def test_wrong_tip_each_position(self):
        obj, tips = bundle([1, 2, 3, 4, 5, 6, 7, 8])
        for index in range(len(tips)):
            with self.subTest(tip=index):
                wrong = list(tips)
                wrong[index] = "f" * 64
                self.hold(obj, tuple(wrong))

    def test_prefix_rewrite_with_reanchored_tip_fails(self):
        obj, tips = bundle([2, 3, 4])
        mutated = obj["snapshots"][2]["events"]
        original = mutated[1]
        body = {k: v for k, v in original.items() if k != "sha256"}
        body["at"] = "2026-10-17T12:00:01Z"
        body["scope_sha256"] = "b" * 64
        mutated[1] = {**body, "sha256": compute_event_hash(body)}
        previous = mutated[1]["sha256"]
        for index in range(2, len(mutated)):
            body = {k: v for k, v in mutated[index].items() if k != "sha256"}
            body["previous_sha256"] = previous
            body["scope_sha256"] = "b" * 64
            previous = compute_event_hash(body)
            mutated[index] = {**body, "sha256": previous}
        self.hold(obj, tips[:2] + (previous,))

    def test_legacy_withdrawal_then_new_record_holds(self):
        obj, tips = bundle([2, 3])
        original, old_tip = snapshot(2, withdraw=True)
        obj["snapshots"][0] = original
        self.hold(obj, (old_tip, tips[1]))

    def test_unknown_schema_and_extra_authority_holds(self):
        obj, tips = bundle([1, 2])
        for key, value in (("schema", "V0"), ("authorization_granted", True)):
            with self.subTest(field=key):
                other = json.loads(encode(obj))
                other[key] = value
                self.hold(other, tips)

    def test_type_confused_or_extra_checkpoint_fields_holds(self):
        obj, tips = bundle([1, 2])
        obj["snapshots"][0]["consent_verified"] = True
        self.hold(obj, tips)
        obj, tips = bundle([1, 2])
        obj["snapshots"][0]["events"][0]["release_approved"] = True
        self.hold(obj, tips)

    def test_external_pins_must_be_exact_tuple_and_lowercase(self):
        obj, tips = bundle([1, 2])
        for bad in (list(tips), " ".join(tips), None, True, tuple(),
                    (tips[0], "F" * 64), (tips[0], True), (tips[0], 0)):
            with self.subTest(bad=repr(bad)[:35]):
                self.hold(obj, bad)

    def test_duplicate_keys_invalid_utf8_and_nonfinite_hold(self):
        obj, tips = bundle([1, 2])
        raw = encode(obj)
        self.hold(raw.replace(b'"schema":', b'"schema":"fake","schema":', 1), tips)
        self.hold(raw.replace(b'"seq":0', b'"seq":NaN', 1), tips)
        self.hold(raw + b"\xff", tips)

    def test_oversized_and_empty_input_holds(self):
        obj, tips = bundle([1, 2])
        self.hold(encode(obj) + b" " * MAX_INPUT_BYTES, tips)
        self.hold(b"", tips)
        self.hold("not bytes", tips)

    def test_oversized_single_snapshot_holds(self):
        obj, tips = bundle([1, 2])
        obj["snapshots"][1]["unexpected"] = "X" * 40000
        self.hold(obj, tips)

    def test_nested_json_recursion_fail_closed(self):
        obj, tips = bundle([1, 2])
        self.hold(b"[" * 1100 + b"0" + b"]" * 1100, tips)

    def _cli(self, obj, tips, *, opt_in=True):
        root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root / "src")
        args = [sys.executable, "-m", "lightup.scope_audit_chain_checkpoints_offline"]
        for tip in tips:
            args += ["--expected-tip", tip]
        if opt_in:
            args.append("--synthetic-only")
        return subprocess.run(args, input=encode(obj), cwd=root, env=env,
                              capture_output=True, timeout=10)

    def test_cli_three_checkpoint_approval_never_true(self):
        obj, tips = bundle([1, 2, 3])
        p = self._cli(obj, tips)
        self.assertEqual(3, p.returncode, p.stderr.decode())
        receipt = json.loads(p.stdout)
        self.assertEqual("REVIEW_ONLY", receipt["status"])
        self.assertEqual(3, receipt["checkpoints"])
        for name in ("consent_verified", "authorization_granted", "release_approved"):
            self.assertIs(receipt[name], False)
        for sensitive in (b"scope_sha256", b"2026-10-17", tips[-1].encode()):
            self.assertNotIn(sensitive, p.stdout)

    def test_cli_requires_explicit_synthetic_flag(self):
        obj, tips = bundle([1, 2])
        p = self._cli(obj, tips, opt_in=False)
        self.assertEqual(2, p.returncode)
        self.assertEqual("HOLD", json.loads(p.stdout)["status"])

    def test_cli_dropped_middle_checkpoint_holds(self):
        obj, tips = bundle([1, 2, 3])
        obj["snapshots"].pop(1)
        p = self._cli(obj, tips)
        self.assertEqual(2, p.returncode)
        self.assertEqual("HOLD", json.loads(p.stdout)["status"])


if __name__ == "__main__":
    unittest.main()
