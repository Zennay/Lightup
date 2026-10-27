"""Offline deterministic acceptance for UNTRUSTED lab-inventory checksum chains."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.check_scope_lab_inventory_chain_offline import review_chain

SCRIPT = ROOT / "scripts" / "check_scope_lab_inventory_chain_offline.py"
FIELDS = ("authorization_verified", "permit_issued", "execution_enabled",
          "merge_approved", "release_approved")
DOMAIN = b"LIGHTUP-OFFLINE-LAB-CHAIN-V1\x00"


def calculate_checksum(version, literals, previous_digest):
    # Independent serializer fixture; does not invoke implementation checksum.
    canonical = json.dumps({
        "lab_literals": sorted(literals),
        "previous_digest": previous_digest,
        "version": version,
    }, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode("ascii")
    return hashlib.sha256(DOMAIN + canonical).hexdigest()


def fixture(versions=None):
    if versions is None:
        versions = [["127.0.0.1", "10.1.2.3", "fd00::1"],
                    ["127.0.0.1", "10.1.2.3"],
                    ["10.1.2.3"]]
    rows = []
    parent = None
    for version, values in enumerate(versions, 1):
        checksum = calculate_checksum(version, values, parent)
        rows.append({"version": version, "lab_literals": values[:],
                     "previous_digest": parent, "digest": checksum})
        parent = checksum
    return {"schema_version": 1, "revisions": rows}


class LabInventoryChainTests(unittest.TestCase):
    def assertNonauthorizing(self, receipt):
        self.assertEqual(set(receipt), {"schema_version", "status", "reason", *FIELDS})
        self.assertEqual(receipt["schema_version"], 1)
        self.assertTrue(all(receipt[field] is False for field in FIELDS))
        self.assertNotIn("10.1.2.3", json.dumps(receipt))

    def assertHold(self, document, reason=None):
        result = review_chain(document)
        self.assertEqual(result["status"], "HOLD", result)
        self.assertNonauthorizing(result)
        if reason is not None:
            self.assertEqual(result["reason"], reason)

    def test_valid_two_version_checksum_chain_is_review_only(self):
        result = review_chain(fixture([["10.1.2.3", "10.1.2.4"], ["10.1.2.3"]]))
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNonauthorizing(result)

    def test_valid_three_version_chain_only_shape_review(self):
        result = review_chain(fixture())
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNonauthorizing(result)

    def test_valid_four_versions_order_independent_literals(self):
        doc = fixture([["10.1.2.3", "127.0.0.1", "fd00::1"],
                       ["fd00::1", "127.0.0.1", "10.1.2.3"],
                       ["10.1.2.3", "127.0.0.1"],
                       ["10.1.2.3"]])
        self.assertEqual(review_chain(doc)["status"], "REVIEW_ONLY")

    def test_tampered_address_without_digest_update_holds(self):
        doc = fixture()
        doc["revisions"][1]["lab_literals"] = ["127.0.0.1"]
        self.assertHold(doc, "CHECKSUM_MISMATCH")

    def test_tampered_digest_holds(self):
        doc = fixture()
        doc["revisions"][1]["digest"] = "0" * 64
        self.assertHold(doc, "CHECKSUM_MISMATCH")

    def test_wrong_parent_link_holds(self):
        doc = fixture()
        doc["revisions"][1]["previous_digest"] = "a" * 64
        self.assertHold(doc, "BROKEN_DIGEST_LINK")

    def test_root_requires_exact_null_parent(self):
        for value in ("", "0" * 64, False, 0, [], {}):
            with self.subTest(value=value):
                doc = fixture()
                doc["revisions"][0]["previous_digest"] = value
                self.assertHold(doc, "INVALID_CHAIN_ROOT")

    def test_sequence_cannot_skip_or_duplicate_revision_numbers(self):
        for values in ((1, 3, 4), (1, 1, 3), (2, 3, 4), (1, True, 3),
                       (1, "2", 3), (1, 2.0, 3)):
            with self.subTest(values=values):
                doc = fixture()
                for row, version in zip(doc["revisions"], values):
                    row["version"] = version
                self.assertHold(doc, "NONCONTIGUOUS_REVISION")

    def test_swap_revision_order_detected(self):
        doc = fixture()
        doc["revisions"][0], doc["revisions"][1] = (
            doc["revisions"][1], doc["revisions"][0])
        self.assertHold(doc, "NONCONTIGUOUS_REVISION")

    def test_delete_intermediate_revision_detected(self):
        doc = fixture()
        del doc["revisions"][1]
        self.assertHold(doc, "NONCONTIGUOUS_REVISION")

    def test_transient_widening_then_revert_holds_even_with_valid_checksums(self):
        doc = fixture([["10.1.2.3"], ["10.1.2.3", "10.1.2.4"], ["10.1.2.3"]])
        self.assertHold(doc, "TRANSIENT_SCOPE_WIDENING")

    def test_recomputed_checksum_after_widening_still_holds(self):
        doc = fixture([["10.1.2.3"], ["10.1.2.3", "10.1.2.4"]])
        self.assertHold(doc, "TRANSIENT_SCOPE_WIDENING")

    def test_recomputed_self_declared_clean_chain_is_never_authorization(self):
        doc = fixture([["10.1.2.3", "10.1.2.4"], ["10.1.2.3"]])
        # This proves the caller controls both payload and checksums.
        result = review_chain(doc)
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNonauthorizing(result)

    def test_uppercase_bad_length_and_nonhex_checksum_holds(self):
        for value in ("A" * 64, "z" * 64, "0" * 63, "0" * 65, True,
                      None, "", 1, b"0" * 64):
            with self.subTest(value=str(value)[:10]):
                doc = fixture()
                doc["revisions"][0]["digest"] = value
                self.assertHold(doc, "INVALID_DIGEST_FORMAT")

    def test_extra_revision_fields_cannot_smuggle_authorization(self):
        for field in ("owner", "tenant", "permit_issued", "authorization",
                      "approved_by", "timestamp"):
            doc = fixture()
            doc["revisions"][1][field] = True
            self.assertHold(doc, "INVALID_REVISION_SHAPE")

    def test_extra_root_fields_cannot_smuggle_authorization(self):
        for field in ("permit_issued", "scan_enabled", "consent"):
            doc = fixture()
            doc[field] = True
            self.assertHold(doc, "INVALID_CHAIN_SHAPE")

    def test_incorrect_revision_object_and_missing_keys_hold(self):
        for replacement in (None, True, "x", [], 42, {},
                            {"version": 2}):
            doc = fixture()
            doc["revisions"][1] = replacement
            self.assertHold(doc, "INVALID_REVISION_SHAPE")

    def test_version_count_is_exactly_two_to_four(self):
        for versions in ([], [["10.1.2.3"]], [["10.1.2.3"]] * 5):
            doc = fixture(versions)
            self.assertHold(doc, "INVALID_CHAIN_LENGTH")
        for bad in (None, True, 2, "versions", {}, ()):
            doc = fixture()
            doc["revisions"] = bad
            self.assertHold(doc, "INVALID_CHAIN_LENGTH")

    def test_malformed_intermediate_address_never_ignored(self):
        for value in ("8.8.8.8", "169.254.1.1", "fe80::1", "fd00::1%eth0",
                      "::ffff:10.1.2.3", "10.1.2.3/8",
                      "FD00::1", "fd00:0:0:0:0:0:0:1", "127.0.0.1:80"):
            with self.subTest(value=value):
                doc = fixture([["10.1.2.3"], [value], ["10.1.2.3"]])
                self.assertHold(doc, "INVALID_LAB_LITERAL")

    def test_empty_duplicate_and_too_long_intermediate_list_holds(self):
        for values in ([], ["10.1.2.3", "10.1.2.3"],
                       ["10.1.2.3"] * 33, "10.1.2.3", None):
            doc = fixture()
            doc["revisions"][1]["lab_literals"] = values
            self.assertHold(doc, "INVALID_LAB_LITERAL")

    def test_wrong_schema_type_and_root_shape_holds(self):
        for version in (True, False, 1.0, "1", None, 0):
            doc = fixture()
            doc["schema_version"] = version
            self.assertHold(doc, "INVALID_CHAIN_SHAPE")
        for doc in (None, [], True, 123, "{}", {"schema_version": 1}):
            self.assertHold(doc, "INVALID_CHAIN_SHAPE")

    def test_repeated_checks_do_not_mutate_input_or_cache_state(self):
        doc = fixture()
        before = copy.deepcopy(doc)
        original = review_chain(doc)
        self.assertEqual(original, review_chain(doc))
        self.assertEqual(doc, before)
        doc["revisions"][1]["digest"] = "0" * 64
        self.assertHold(doc, "CHECKSUM_MISMATCH")
        self.assertEqual(review_chain(before), original)

    def test_no_dns_or_network_depends_on_review(self):
        with patch.object(socket, "socket", side_effect=AssertionError("socket")):
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")):
                self.assertNonauthorizing(review_chain(fixture()))
                self.assertNonauthorizing(review_chain(fixture(
                    [["10.1.2.3"], ["10.1.2.3", "10.1.2.4"]])))

    def _cli(self, raw, *extra):
        data = raw if type(raw) is bytes else json.dumps(raw).encode("ascii")
        return subprocess.run([sys.executable, str(SCRIPT), *extra],
                              input=data, capture_output=True, check=False, timeout=6)

    def test_cli_review_only_is_nonzero(self):
        p = self._cli(fixture())
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertNonauthorizing(json.loads(p.stdout))

    def test_cli_failed_digest_is_nonzero_and_does_not_echo(self):
        private = "SECRET-ASSET-NEVER-ECHO"
        doc = fixture()
        doc["revisions"][1]["lab_literals"] = [private]
        p = self._cli(doc)
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertNotIn(private.encode(), p.stdout + p.stderr)
        self.assertNonauthorizing(json.loads(p.stdout))

    def test_cli_duplicate_keys_nonascii_and_large_payload_holds(self):
        for raw in (b'{"schema_version":1,"schema_version":1}',
                    b'{"revisions":[{"a":1,"a":2}]}',
                    b"\xff\xfe", b"x" * 8193):
            with self.subTest(raw=raw[:20]):
                p = self._cli(raw)
                self.assertEqual(p.returncode, 2, p.stderr)
                self.assertNonauthorizing(json.loads(p.stdout))

    def test_cli_argv_denies_any_flag(self):
        p = self._cli(fixture(), "--permit")
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertNonauthorizing(json.loads(p.stdout))

    def test_shell_chain_never_reaches_following_command(self):
        cmd = f"{sys.executable} {SCRIPT} && echo SHOULD_NOT_RUN"
        p = subprocess.run(["sh", "-c", cmd],
                           input=json.dumps(fixture()).encode("ascii"),
                           capture_output=True, check=False, timeout=6)
        self.assertEqual(p.returncode, 3)
        self.assertNotIn(b"SHOULD_NOT_RUN", p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
