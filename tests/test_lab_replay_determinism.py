"""Regression coverage for deterministic loopback replay receipts and exact ledger sets."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lightup.lab_replay import _build_replay, _canonical, _sha, _verify_database_lineage


class ReplayDeterminismContract(unittest.TestCase):
    def test_independent_replays_produce_identical_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            receipt_a, receipt_bytes_a, digest_a = _build_replay(Path(first))
            receipt_b, receipt_bytes_b, digest_b = _build_replay(Path(second))

            self.assertEqual(receipt_a, receipt_b)
            self.assertEqual(receipt_bytes_a, receipt_bytes_b)
            self.assertEqual(digest_a, digest_b)
            self.assertEqual(digest_a, _sha(receipt_bytes_a))
            self.assertEqual(digest_b, _sha(receipt_bytes_b))
            self.assertEqual(receipt_a["outcome"], "PASS")
            self.assertFalse(receipt_a["policy"]["external_target_contacted"])
            self.assertFalse(receipt_a["policy"]["live_remediation_performed"])

    def test_replay_rejects_an_unreferenced_receipt_row(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            receipt, _receipt_bytes, _digest = _build_replay(bundle)
            extra_receipt = _canonical({"unexpected": "extra"})
            extra_json = extra_receipt.decode("utf-8")
            extra_digest = _sha(extra_receipt)

            with sqlite3.connect(bundle / "replay-ledger.sqlite3") as ledger:
                ledger.execute(
                    "INSERT INTO replay_receipts(receipt_sha256,receipt_json) VALUES(?,?)",
                    (extra_digest, extra_json),
                )

            with self.assertRaisesRegex(RuntimeError, "receipt set mismatch"):
                _verify_database_lineage(bundle, receipt)


if __name__ == "__main__":
    unittest.main()
