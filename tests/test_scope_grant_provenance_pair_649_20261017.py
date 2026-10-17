"""#649 atomic fictional before/after issuance-provenance comparisons only.

No production code, no source-owner modification, no client consent, no scan.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
PAIR_CLI = SCRIPTS / "review_scope_grant_provenance_pair_synthetic_649.py"
sys.path.insert(0, str(SCRIPTS))

import review_scope_grant_provenance_pair_synthetic_649 as pair
import review_scope_grant_provenance_synthetic_649 as base


def record(approved_by="Synthetic Operator", reference="SYNTH-649"):
    return {"approved_by": approved_by, "reference": reference}


def packet(pairs=None):
    if pairs is None:
        pairs = [{"before": record(), "after": record()}]
    return {"schema": pair.PAIR_SCHEMA, "synthetic_only": True, "pairs": pairs}


def encode(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


class _HostileKey:
    def __init__(self, collide):
        self.collision = hash(collide)
        self.armed = False

    def __hash__(self):
        if self.armed:
            raise AssertionError("foreign hash called")
        return self.collision

    def __eq__(self, other):
        if self.armed:
            raise AssertionError("foreign equality called")
        return self is other


class _HostileText(str):
    def strip(self):
        raise AssertionError("untrusted strip invoked")

    def __eq__(self, other):
        raise AssertionError("untrusted equality invoked")


class PairReview649Tests(unittest.TestCase):
    def test_exact_fictional_pair_can_only_produce_falsy_review(self):
        result = pair.review_pair_batch(packet())
        self.assertIs(result.status, base.ReviewStatus.REVIEW_ONLY)
        self.assertFalse(result)
        self.assertFalse(result.status)
        self.assertEqual(
            (result.authorization_verified, result.consent_verified,
             result.permit_issued, result.dispatch_allowed, result.execution_enabled,
             result.merge_approved, result.release_approved),
            (False,) * 7,
        )

    def test_two_snapshot_slots_must_not_be_same_python_object(self):
        # If both fields point at a single mutable object, no independent
        # before/after snapshots were actually represented.
        one = record()
        raw = packet([{"before": one, "after": one}])
        self.assertIs(pair.review_pair_batch(raw).status, base.ReviewStatus.HOLD)
        self.assertIs(
            pair.review_pair_batch(packet([{"before": dict(one), "after": dict(one)}])).status,
            base.ReviewStatus.REVIEW_ONLY,
        )

    def test_shared_records_across_entries_are_not_independent(self):
        before = record()
        first = {"before": before, "after": record()}
        second = {"before": before, "after": record()}
        self.assertIs(
            pair.review_pair_batch(packet([first, second])).status, base.ReviewStatus.HOLD
        )
        self.assertIs(
            pair.review_pair_batch(packet([first, first])).status, base.ReviewStatus.HOLD
        )

    def test_actual_issuance_double_strip_shape_mismatch_holds(self):
        # Synthetic, not a DB read or evidence of an actual client.
        for before, after in (
            (record(reference="SYNTH-649"), record(reference="")),
            (record(approved_by="Synthetic Operator"), record(approved_by="")),
            (record(reference="REF-A"), record(reference="REF-B")),
            (record(approved_by="Operator A"), record(approved_by="Operator B")),
        ):
            with self.subTest(before=before, after=after):
                self.assertIs(
                    pair.review_pair_batch(packet([{"before": before, "after": after}])).status,
                    base.ReviewStatus.HOLD,
                )

    def test_edited_provenance_on_other_pair_holds_entire_batch(self):
        items = [{"before": record(reference=f"SYNTH-{i}"),
                  "after": record(reference=f"SYNTH-{i}")} for i in range(32)]
        self.assertIs(pair.review_pair_batch(packet(items)).status, base.ReviewStatus.REVIEW_ONLY)
        for index in (0, 1, 15, 31):
            changed = json.loads(json.dumps(items))
            changed[index]["after"]["reference"] += "-CHANGED"
            self.assertIs(pair.review_pair_batch(packet(changed)).status, base.ReviewStatus.HOLD)

    def test_reject_empty_oversize_or_nonlist_pairs(self):
        for value in ([], [{}] * 33, tuple([{"before": record(), "after": record()}]),
                      "not a list", 0, None, {}):
            with self.subTest(type=type(value).__name__):
                raw = packet()
                raw["pairs"] = value
                self.assertIs(pair.review_pair_batch(raw).status, base.ReviewStatus.HOLD)

    def test_reject_untrusted_fields_or_forged_synthetic_marker(self):
        for value in (None, False, 1, "true", [], {}):
            changed = packet()
            changed["synthetic_only"] = value
            self.assertIs(pair.review_pair_batch(changed).status, base.ReviewStatus.HOLD)
        changed = packet()
        changed["schema"] = "lightup.scope649.provenance_pair.synthetic.v0"
        self.assertIs(pair.review_pair_batch(changed).status, base.ReviewStatus.HOLD)
        for name in ("consent", "signature", "grant_id", "authorized"):
            changed = packet()
            changed[name] = "not trusted"
            self.assertIs(pair.review_pair_batch(changed).status, base.ReviewStatus.HOLD)

    def test_reject_nested_unknown_missing_and_cross_role_fields(self):
        for level in ("pair", "before", "after"):
            for operation in ("unknown", "remove"):
                raw = packet()
                obj = raw["pairs"][0]
                if level != "pair":
                    obj = obj[level]
                if operation == "unknown":
                    obj["authorized"] = True
                else:
                    obj.pop(next(iter(obj)))
                with self.subTest(level=level, operation=operation):
                    self.assertIs(pair.review_pair_batch(raw).status, base.ReviewStatus.HOLD)

    def test_reject_ambiguous_scalar_types_before_any_foreign_methods(self):
        for invalid in (_HostileText("abc"), None, False, 7, 1.2, [], {}, b"abc"):
            for phase in ("before", "after"):
                for field in ("reference", "approved_by"):
                    raw = packet()
                    raw["pairs"][0][phase][field] = invalid
                    with self.subTest(type=type(invalid).__name__, phase=phase, field=field):
                        self.assertIs(pair.review_pair_batch(raw).status, base.ReviewStatus.HOLD)

    def test_hash_collision_keys_are_rejected_without_foreign_equality(self):
        # Exact built-in dict can contain a foreign key, even after intake.
        for level, collision in (
            ("root", "schema"), ("pair", "after"),
            ("before", "reference"), ("after", "approved_by"),
        ):
            raw = packet()
            owner = raw if level == "root" else raw["pairs"][0]
            if level in ("before", "after"):
                owner = owner[level]
            key = _HostileKey(collision)
            owner[key] = owner.pop(collision)
            key.armed = True
            with self.subTest(level=level):
                self.assertIs(pair.review_pair_batch(raw).status, base.ReviewStatus.HOLD)

    def test_valid_unicode_but_not_confusables(self):
        valid = packet([{"before": record("Élodie", "SYNTH-É"),
                         "after": record("Élodie", "SYNTH-É")}])
        self.assertIs(pair.review_pair_batch(valid).status, base.ReviewStatus.REVIEW_ONLY)
        for invalid in ("X\n", "X\x00Y", "A\u202eB", "e\u0301", " X", "X "):
            raw = packet()
            raw["pairs"][0]["after"]["reference"] = invalid
            self.assertIs(pair.review_pair_batch(raw).status, base.ReviewStatus.HOLD)

    def test_exact_duplicate_json_key_and_nonfinite_rejection(self):
        valid = encode(packet())
        bad = (
            b'{"schema":"x","schema":"y"}',
            valid.replace(b'"approved_by":"Synthetic Operator"',
                          b'"approved_by":"Synthetic Operator","approved_by":"duplicated"', 1),
            valid.replace(b'true', b'NaN', 1),
            valid.replace(b'true', b'Infinity', 1),
            b'\xff',
            b'',
            valid + b'0',
            valid + b' ' * (pair.MAX_INPUT + 1),
        )
        for raw in bad:
            with self.subTest(raw=raw[:32]):
                self.assertIs(pair.parse_and_compare(raw).status, base.ReviewStatus.HOLD)
        self.assertIs(pair.parse_and_compare(valid).status, base.ReviewStatus.REVIEW_ONLY)

    def test_every_proper_prefix_is_hold(self):
        valid = encode(packet())
        for pos in range(len(valid)):
            self.assertIs(pair.parse_and_compare(valid[:pos]).status, base.ReviewStatus.HOLD)

    def test_cli_exits_nonzero_never_echoes_values(self):
        marker = "SYNTHETIC_PRIVATE_LABEL_NO_ECHO"
        values = packet([{"before": record(reference=marker),
                          "after": record(reference=marker)}])
        raw = encode(values)
        for value, expected_code, expected_status in (
            (raw, 3, "REVIEW_ONLY"), (b"{}", 2, "HOLD"),
            (raw.replace(marker.encode(), b"VOID", 1), 2, "HOLD"),
            (raw + b"0" * pair.MAX_INPUT, 2, "HOLD"),
        ):
            with self.subTest(status=expected_status, length=len(value)):
                done = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", str(PAIR_CLI)],
                    input=value, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=False, timeout=10,
                )
                self.assertEqual(done.returncode, expected_code)
                self.assertEqual(done.stderr, b"")
                self.assertNotIn(marker.encode(), done.stdout)
                payload = json.loads(done.stdout)
                self.assertEqual(payload["status"], expected_status)
                self.assertEqual(set(payload)-{"status"}, {
                    "authorization_verified", "consent_verified", "permit_issued",
                    "dispatch_allowed", "execution_enabled", "merge_approved",
                    "release_approved",
                })
                self.assertTrue(all(v is False for k,v in payload.items() if k!="status"))

    def test_all_single_bit_mutations_of_minimal_fictional_pair_hold(self):
        # The exact chosen minimal fixture contains no ignorable whitespace.
        # This is a deterministic regression oracle, not an authenticity proof:
        # semantically equivalent JSON spellings can legitimately exist.
        pristine = encode(packet())
        self.assertIs(pair.parse_and_compare(pristine).status, base.ReviewStatus.REVIEW_ONLY)
        seen = 0
        for offset in range(len(pristine)):
            for bit in range(8):
                damaged = bytearray(pristine)
                damaged[offset] ^= 1 << bit
                actual = pair.parse_and_compare(bytes(damaged)).status
                with self.subTest(offset=offset, bit=bit):
                    self.assertIs(actual, base.ReviewStatus.HOLD)
                seen += 1
        self.assertGreater(seen, 1200)

    def test_every_batch_slot_uses_atomic_hold_not_partial_success(self):
        initial = [{"before": record(reference=f"SYNTH-{i}"),
                    "after": record(reference=f"SYNTH-{i}")} for i in range(32)]
        self.assertIs(pair.review_pair_batch(packet(initial)).status, base.ReviewStatus.REVIEW_ONLY)
        for index in range(32):
            changed = json.loads(json.dumps(initial))
            changed[index]["after"]["approved_by"] = "Different Fictional Reviewer"
            with self.subTest(index=index):
                receipt = pair.review_pair_batch(packet(changed))
                self.assertIs(receipt.status, base.ReviewStatus.HOLD)
                self.assertFalse(receipt)
                self.assertFalse(receipt.authorization_verified)
                self.assertFalse(receipt.dispatch_allowed)

    def test_actual_cli_waits_for_fragmented_stdin_until_eof(self):
        # Separate real OS writes exercise bounded buffered reader behavior,
        # not a mocked in-memory input. No network, no real authorization.
        data = encode(packet())
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", "-B", str(PAIR_CLI)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            assert process.stdin is not None
            for chunk in (data[:1], data[1:8], data[8:37], data[37:]):
                process.stdin.write(chunk)
                process.stdin.flush()
            process.stdin.close()
            assert process.stdout is not None and process.stderr is not None
            output = process.stdout.read()
            errors = process.stderr.read()
            exit_code = process.wait(timeout=10)
            self.assertEqual(exit_code, 3)
            self.assertEqual(errors, b"")
            self.assertEqual(json.loads(output)["status"], "REVIEW_ONLY")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)

    def test_stdin_error_or_broken_output_is_hold(self):
        class BadStdin:
            class buffer:
                @staticmethod
                def read(n):
                    raise OSError("SYNTHETIC_SECRET")
        with patch.object(pair.sys, "stdin", BadStdin()):
            with patch.object(pair.os, "write", return_value=len(base._HOLD)) as w:
                self.assertEqual(pair.main(), 2)
                self.assertEqual(w.call_args.args[1], base._HOLD)
                self.assertNotIn(b"SYNTHETIC_SECRET", w.call_args.args[1])
        class GoodStdin:
            class buffer:
                @staticmethod
                def read(n):
                    return encode(packet())
        with patch.object(pair.sys, "stdin", GoodStdin()):
            for r in (0, 1, True, None):
                with patch.object(pair.os, "write", return_value=r):
                    self.assertEqual(pair.main(), 2)
            with patch.object(pair.os, "write", side_effect=BrokenPipeError("SECRET")):
                self.assertEqual(pair.main(), 2)

    def test_no_prod_import_network_db_or_scan(self):
        text = PAIR_CLI.read_text()
        for banned in ("from lightup", "import lightup", "socket.", "requests.",
                       "sqlite3.", "subprocess.", "urllib.", "http.client"):
            self.assertNotIn(banned, text)


if __name__ == "__main__":
    unittest.main()
