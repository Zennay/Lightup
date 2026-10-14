"""Cross-binding of six independently non-authorizing offline scope reviewers."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.check_scope_lab_dossier_offline import review_dossier
from scripts.check_scope_lab_inventory_chain_offline import record_digest

SCRIPT = ROOT / "scripts" / "check_scope_lab_dossier_offline.py"
FLAGS = ("authorization_verified", "permit_issued", "execution_enabled",
         "merge_approved", "release_approved")


def make_chain(versions):
    rows, parent = [], None
    for n, values in enumerate(versions, 1):
        digest = record_digest(n, set(values), parent)
        rows.append({"version": n, "lab_literals": values[:],
                     "previous_digest": parent, "digest": digest})
        parent = digest
    return {"schema_version": 1, "revisions": rows}


def dossier(versions=None):
    versions = versions if versions is not None else [
        ["127.0.0.1", "10.1.2.3", "fd00::1"],
        ["127.0.0.1", "10.1.2.3"],
        ["10.1.2.3"],
    ]
    return {
        "schema_version": 1,
        "literal": "10.1.2.3",
        "inventory": {
            "schema_version": 1,
            "declared_lab_literals": versions[0][:],
            "proposed_literals": versions[-1][:],
        },
        "narrowing": {
            "schema_version": 1,
            "previous_lab_literals": versions[-2][:],
            "proposed_lab_literals": versions[-1][:],
        },
        "history": {"schema_version": 1, "lab_literal_versions":
                    [version[:] for version in versions]},
        "chain": make_chain(versions),
        "extension": {
            "schema_version": 1,
            "previous_chain": make_chain(versions[:-1]),
            "candidate_chain": make_chain(versions),
        },
    }


class DossierReviewTests(unittest.TestCase):
    def assertNoAuthority(self, r):
        self.assertEqual(set(r), {"schema_version", "status", "reason", *FLAGS})
        self.assertTrue(all(r[k] is False for k in FLAGS))
        self.assertNotIn("10.1.2.3", json.dumps(r))

    def assertHold(self, payload, reason=None):
        result = review_dossier(payload)
        self.assertEqual(result["status"], "HOLD", result)
        self.assertNoAuthority(result)
        if reason is not None:
            self.assertEqual(result["reason"], reason)

    def test_three_revision_complete_dossier_is_review_only(self):
        result = review_dossier(dossier())
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNoAuthority(result)

    def test_four_revision_complete_dossier_is_review_only(self):
        versions = [["127.0.0.1", "10.1.2.3", "fd00::1"],
                    ["127.0.0.1", "10.1.2.3"],
                    ["10.1.2.3"], ["10.1.2.3"]]
        result = review_dossier(dossier(versions))
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNoAuthority(result)

    def test_same_submitted_data_in_different_order_not_granted(self):
        d = dossier()
        d["inventory"]["declared_lab_literals"].reverse()
        self.assertEqual(review_dossier(d)["status"], "REVIEW_ONLY")
        self.assertNoAuthority(review_dossier(d))

    def test_unrelated_valid_literal_cannot_be_swapped(self):
        d = dossier()
        d["literal"] = "127.0.0.1"
        self.assertHold(d, "DOSSIER_MISMATCH")

    def test_inventory_positive_but_proposed_not_equal_transition_holds(self):
        d = dossier()
        d["inventory"]["proposed_literals"] = ["127.0.0.1"]
        self.assertHold(d, "DOSSIER_MISMATCH")

    def test_previous_transition_must_match_penultimate_history_version(self):
        d = dossier()
        d["narrowing"]["previous_lab_literals"] = ["10.1.2.3"]
        self.assertHold(d, "DOSSIER_MISMATCH")

    def test_syntactically_valid_different_history_refused(self):
        d = dossier()
        d["history"]["lab_literal_versions"][0].remove("fd00::1")
        self.assertHold(d, "DOSSIER_MISMATCH")

    def test_candidate_extension_must_be_exact_chain_not_another_valid_one(self):
        d = dossier()
        d["chain"] = make_chain([["127.0.0.1", "10.1.2.3"],
                                  ["10.1.2.3"], ["10.1.2.3"]])
        self.assertHold(d, "DOSSIER_MISMATCH")

    def test_false_cross_reference_never_blended_from_individual_reviews(self):
        d = dossier()
        d["inventory"]["proposed_literals"] = ["127.0.0.1", "10.1.2.3"]
        self.assertHold(d, "DOSSIER_MISMATCH")

    def test_missing_revision_in_chain_even_with_valid_other_surfaces_holds(self):
        d = dossier()
        d["chain"] = make_chain([
            ["127.0.0.1", "10.1.2.3", "fd00::1"],
            ["10.1.2.3"],
        ])
        self.assertHold(d, "DOSSIER_MISMATCH")

    def test_self_declared_chain_with_bad_digest_is_held(self):
        d = dossier()
        d["chain"]["revisions"][1]["digest"] = "0" * 64
        self.assertHold(d, "INPUT_REVIEW_HELD")

    def test_scope_widening_in_middle_is_held(self):
        versions = [["10.1.2.3"], ["10.1.2.3", "10.1.2.4"],
                    ["10.1.2.3"]]
        d = dossier(versions)
        self.assertHold(d, "INPUT_REVIEW_HELD")

    def test_private_or_reserved_literal_is_held(self):
        for value in ("8.8.8.8", "169.254.1.1", "fe80::1",
                      "::ffff:10.1.2.3", "0.0.0.0", "FD00::1"):
            d = dossier()
            d["literal"] = value
            self.assertHold(d, "INPUT_REVIEW_HELD")

    def test_fake_authority_fields_in_root_refused(self):
        for field in ("permit_issued", "authorization_verified", "owner",
                      "tenant", "consent", "release_approved"):
            d = dossier()
            d[field] = True
            self.assertHold(d, "INVALID_DOSSIER_SHAPE")

    def test_falsy_root_schema_type_fails_closed(self):
        for value in (True, False, "1", 1.0, None, 0, 2):
            d = dossier()
            d["schema_version"] = value
            self.assertHold(d, "INVALID_DOSSIER_SHAPE")

    def test_missing_fields_and_non_object_shapes_fail(self):
        for value in (None, True, [], 0, {}, {"schema_version": 1}):
            self.assertHold(value, "INVALID_DOSSIER_SHAPE")
        d = dossier()
        del d["extension"]
        self.assertHold(d, "INVALID_DOSSIER_SHAPE")

    def test_invalid_subdocuments_deny_entire_dossier(self):
        for key in ("inventory", "narrowing", "history", "chain", "extension"):
            d = dossier()
            d[key] = {"schema_version": 1}
            self.assertHold(d, "INPUT_REVIEW_HELD")

    def test_input_is_not_mutated_and_repeatable(self):
        d = dossier()
        original = copy.deepcopy(d)
        result = review_dossier(d)
        self.assertEqual(d, original)
        self.assertEqual(review_dossier(d), result)
        d["literal"] = "8.8.8.8"
        self.assertHold(d)
        self.assertEqual(review_dossier(original), result)

    def test_no_socket_or_dns_depends_on_dossier_review(self):
        with patch.object(socket, "socket", side_effect=AssertionError("socket")):
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")):
                self.assertNoAuthority(review_dossier(dossier()))
                d = dossier()
                d["literal"] = "8.8.8.8"
                self.assertNoAuthority(review_dossier(d))

    def _cli(self, item, *args):
        raw = item if type(item) is bytes else json.dumps(item).encode("ascii")
        return subprocess.run([sys.executable, str(SCRIPT), *args],
                              input=raw, capture_output=True, check=False, timeout=6)

    def test_cli_positive_shape_exits_nonzero_three(self):
        p = self._cli(dossier())
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertNoAuthority(json.loads(p.stdout))

    def test_cli_denial_never_echoes_private_identifier(self):
        marker = "PRIVATE-CUSTOMER-SCOPE-SECRET"
        d = dossier()
        d["literal"] = marker
        p = self._cli(d)
        self.assertEqual(p.returncode, 2)
        self.assertNotIn(marker.encode(), p.stdout + p.stderr)
        self.assertNoAuthority(json.loads(p.stdout))

    def test_cli_oversize_nonascii_and_duplicate_keys_deny(self):
        for raw in (b"x" * 8193, b"\xff\xfe",
                    b'{"schema_version":1,"schema_version":1}'):
            p = self._cli(raw)
            self.assertEqual(p.returncode, 2)
            self.assertNoAuthority(json.loads(p.stdout))

    def test_cli_unrecognized_approval_arguments_denied(self):
        p = self._cli(dossier(), "--authorize")
        self.assertEqual(p.returncode, 2)
        self.assertNoAuthority(json.loads(p.stdout))

    def test_shell_chain_cannot_issue_consent_from_review_only(self):
        p = subprocess.run(["sh", "-c",
                            f"{sys.executable} {SCRIPT} && echo MUST_NOT_RUN"],
                           input=json.dumps(dossier()).encode("ascii"),
                           capture_output=True, check=False, timeout=6)
        self.assertEqual(p.returncode, 3)
        self.assertNotIn(b"MUST_NOT_RUN", p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
