"""Synthetic fail-closed checks for comparisons of two UNTRUSTED lab chains."""
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
from scripts.check_scope_lab_inventory_chain_extension_offline import review_extension

SCRIPT = ROOT / "scripts" / "check_scope_lab_inventory_chain_extension_offline.py"
DOMAIN = b"LIGHTUP-OFFLINE-LAB-CHAIN-V1\x00"
FLAGS = ("authorization_verified", "permit_issued", "execution_enabled",
         "merge_approved", "release_approved")


def chain(sets):
    previous, rows = None, []
    for index, literals in enumerate(sets, 1):
        canonical = json.dumps(
            {"version": index, "lab_literals": sorted(literals),
             "previous_digest": previous},
            sort_keys=True, ensure_ascii=True, separators=(",", ":"),
        ).encode("ascii")
        digest = hashlib.sha256(DOMAIN + canonical).hexdigest()
        rows.append({"version": index, "lab_literals": list(literals),
                     "previous_digest": previous, "digest": digest})
        previous = digest
    return {"schema_version": 1, "revisions": rows}


FIRST = ["127.0.0.1", "10.1.2.3", "fd00::1"]
SECOND = ["127.0.0.1", "10.1.2.3"]
THIRD = ["10.1.2.3"]
FOURTH = ["10.1.2.3"]


def packet(previous=None, candidate=None):
    return {"schema_version": 1,
            "previous_chain": chain([FIRST, SECOND]) if previous is None else previous,
            "candidate_chain": chain([FIRST, SECOND, THIRD])
            if candidate is None else candidate}


class LabChainExtensionTests(unittest.TestCase):
    def assertNoAuthority(self, result):
        self.assertEqual(set(result), {"schema_version", "status", "reason", *FLAGS})
        self.assertTrue(all(result[k] is False for k in FLAGS))
        self.assertNotIn("10.1.2.3", json.dumps(result))

    def assertHold(self, payload, reason=None):
        output = review_extension(payload)
        self.assertEqual(output["status"], "HOLD", output)
        self.assertNoAuthority(output)
        if reason is not None:
            self.assertEqual(output["reason"], reason)

    def test_new_third_revision_is_only_reviewable(self):
        result = review_extension(packet())
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNoAuthority(result)

    def test_new_two_revisions_can_append_two(self):
        result = review_extension(packet(candidate=chain([FIRST, SECOND, THIRD, FOURTH])))
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNoAuthority(result)

    def test_three_revision_prior_can_extend_to_four(self):
        result = review_extension(packet(
            previous=chain([FIRST, SECOND, THIRD]),
            candidate=chain([FIRST, SECOND, THIRD, FOURTH]),
        ))
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNoAuthority(result)

    def test_stale_same_chain_is_not_new_evidence(self):
        base = chain([FIRST, SECOND])
        self.assertHold(packet(previous=base, candidate=copy.deepcopy(base)),
                        "STALE_OR_ROLLED_BACK_CHAIN")

    def test_shortened_candidate_is_denied(self):
        self.assertHold(packet(
            previous=chain([FIRST, SECOND, THIRD]),
            candidate=chain([FIRST, SECOND])),
            "STALE_OR_ROLLED_BACK_CHAIN")

    def test_rewritten_prefix_even_if_candidate_valid_is_denied(self):
        candidate = chain([["10.1.2.3", "fd00::1"], ["10.1.2.3"], THIRD])
        self.assertHold(packet(candidate=candidate), "REWRITTEN_CHAIN_PREFIX")

    def test_reordered_literals_with_same_checksum_still_change_prefix(self):
        reordered = list(reversed(FIRST))
        candidate = chain([reordered, SECOND, THIRD])
        self.assertHold(packet(candidate=candidate), "REWRITTEN_CHAIN_PREFIX")

    def test_modified_middle_revision_then_recomputed_digest_is_denied(self):
        candidate = chain([FIRST, ["10.1.2.3"], THIRD])
        self.assertHold(packet(candidate=candidate), "REWRITTEN_CHAIN_PREFIX")

    def test_deleted_middle_record_fails_candidate_consistency(self):
        candidate = chain([FIRST, SECOND, THIRD])
        del candidate["revisions"][1]
        self.assertHold(packet(candidate=candidate), "INVALID_CANDIDATE_CHAIN")

    def test_inserted_extra_address_is_denied_even_with_valid_digests(self):
        candidate = chain([FIRST, SECOND, ["10.1.2.3", "10.1.2.4"]])
        self.assertHold(packet(candidate=candidate), "INVALID_CANDIDATE_CHAIN")

    def test_reverted_widening_also_denied(self):
        candidate = chain([FIRST, SECOND, ["10.1.2.3", "10.1.2.4"], THIRD])
        self.assertHold(packet(candidate=candidate), "INVALID_CANDIDATE_CHAIN")

    def test_untrusted_corrupted_prior_never_blesses_candidate(self):
        old = chain([FIRST, SECOND])
        old["revisions"][1]["digest"] = "0" * 64
        self.assertHold(packet(previous=old), "INVALID_PREVIOUS_CHAIN")

    def test_untrusted_corrupt_candidate_never_blessed(self):
        proposed = chain([FIRST, SECOND, THIRD])
        proposed["revisions"][1]["previous_digest"] = "0" * 64
        self.assertHold(packet(candidate=proposed), "INVALID_CANDIDATE_CHAIN")

    def test_forged_consent_and_permission_metadata_refused(self):
        for field in ("authorization_verified", "permit_issued", "client",
                      "consent", "release_approved", "approval_reference"):
            doc = packet()
            doc[field] = True
            self.assertHold(doc, "INVALID_COMPARISON_SHAPE")

    def test_wrong_schema_boolean_float_and_version_holds(self):
        for value in (True, False, None, "1", 1.0, 0, 2):
            doc = packet()
            doc["schema_version"] = value
            self.assertHold(doc, "INVALID_COMPARISON_SHAPE")

    def test_missing_keys_and_non_dict_payloads_hold(self):
        for bad in (None, True, 1, "x", [], {},
                    {"schema_version": 1},
                    {"schema_version": 1, "candidate_chain": chain([FIRST, SECOND])}):
            self.assertHold(bad, "INVALID_COMPARISON_SHAPE")

    def test_noncanonical_special_use_and_mapped_ip_proposed_holds(self):
        for address in ("8.8.8.8", "fe80::1", "::ffff:10.1.2.3",
                        "FD00::1", "10.1.2.3/8", "127.0.0.1:123"):
            with self.subTest(address=address):
                proposed = chain([FIRST, SECOND, [address]])
                self.assertHold(packet(candidate=proposed), "INVALID_CANDIDATE_CHAIN")

    def test_repeated_review_is_pure_and_rewrite_flips_to_hold(self):
        doc = packet()
        before = copy.deepcopy(doc)
        first = review_extension(doc)
        self.assertEqual(first, review_extension(doc))
        self.assertEqual(doc, before)
        doc["candidate_chain"] = chain([["fd00::1", "10.1.2.3"],
                                        ["10.1.2.3"], THIRD])
        self.assertHold(doc, "REWRITTEN_CHAIN_PREFIX")
        self.assertEqual(review_extension(before), first)

    def test_no_network_or_dns_even_for_invalid_candidate(self):
        with patch.object(socket, "socket", side_effect=AssertionError("socket")):
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")):
                self.assertNoAuthority(review_extension(packet()))
                self.assertNoAuthority(review_extension(packet(candidate=chain(
                    [FIRST, SECOND, ["8.8.8.8"]]))))

    def _cli(self, doc, *args):
        raw = doc if type(doc) is bytes else json.dumps(doc).encode("ascii")
        return subprocess.run([sys.executable, str(SCRIPT), *args],
                              input=raw, capture_output=True, check=False, timeout=6)

    def test_cli_valid_shape_uses_nonzero_review_exit(self):
        p = self._cli(packet())
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertNoAuthority(json.loads(p.stdout))

    def test_cli_private_input_is_never_echoed(self):
        marker = "PRIVATE-CUSTOMER-IDENTITY-MARKER"
        doc = packet()
        doc["candidate_chain"]["revisions"][2]["lab_literals"] = [marker]
        p = self._cli(doc)
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertNotIn(marker.encode(), p.stdout + p.stderr)
        self.assertNoAuthority(json.loads(p.stdout))

    def test_cli_duplicate_json_keys_bad_encoding_and_overlimit_holds(self):
        for raw in (b'{"schema_version":1,"schema_version":1}',
                    b'{"previous_chain":{"x":1,"x":2}}', b"\xff", b"x" * 8193):
            p = self._cli(raw)
            self.assertEqual(p.returncode, 2, p.stderr)
            self.assertNoAuthority(json.loads(p.stdout))

    def test_cli_unexpected_arguments_never_enable_authority(self):
        p = self._cli(packet(), "--permit")
        self.assertEqual(p.returncode, 2)
        self.assertNoAuthority(json.loads(p.stdout))

    def test_shell_chain_cannot_treat_check_as_permission(self):
        cmd = f"{sys.executable} {SCRIPT} && echo MUST_NOT_RUN"
        p = subprocess.run(["sh", "-c", cmd], input=json.dumps(packet()).encode("ascii"),
                           capture_output=True, check=False, timeout=6)
        self.assertEqual(p.returncode, 3)
        self.assertNotIn(b"MUST_NOT_RUN", p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
