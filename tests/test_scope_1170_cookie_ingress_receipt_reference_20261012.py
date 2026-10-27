"""Offline acceptance tests for the non-authorizing #1170 cookie ingress receipt.

No HTTP client, server, Nginx, Gunicorn, state store, or real cookies used.
"""
import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from scope_1170_cookie_ingress_receipt_reference import (  # noqa: E402
    DENIED, SCENARIOS, review_cookie_ingress_receipt,
)

COMMIT = "1" * 40
CONFIG = "2" * 64
CAPTURE = "3" * 64


def sample():
    pins = {
        "repository_commit": COMMIT,
        "nginx_config_sha256": CONFIG,
        "backend_capture_sha256": CAPTURE,
    }
    rows = []
    for name, wire in SCENARIOS.items():
        denied = name in DENIED
        rows.append({
            "scenario": name,
            "wire_cookie_fields": list(wire),
            "edge_status": 400 if denied else 200,
            "backend_cookie_fields": [] if denied else list(wire),
            "backend_reached": not denied,
            "application_session_lookups": 0,
            "persistent_writes": 0,
            "set_cookie": False,
            "no_store": True,
            "authenticated": False,
            "second_request_admitted": False,
        })
    receipt = {
        **pins,
        "case_observations": rows,
        "fixture_only": True,
    }
    return receipt, pins


class CookieIngressReceiptReferenceTests(unittest.TestCase):
    def assert_rejected(self, mutate):
        receipt, pins = sample()
        mutate(receipt, pins)
        self.assertFalse(review_cookie_ingress_receipt(receipt, pins))

    def test_good_synthetic_shape_only(self):
        receipt, pins = sample()
        before = copy.deepcopy(receipt)
        self.assertTrue(review_cookie_ingress_receipt(receipt, pins))
        self.assertEqual(receipt, before)

    def test_every_required_case_is_present_exactly_once(self):
        for idx in range(len(SCENARIOS)):
            with self.subTest(missing=idx):
                self.assert_rejected(lambda r, p: r["case_observations"].pop(idx))
        self.assert_rejected(lambda r, p: r["case_observations"].__setitem__(
            -1, copy.deepcopy(r["case_observations"][0])
        ))

    def test_case_spoofing_or_unsupported_extra_field(self):
        self.assert_rejected(lambda r, p: r["case_observations"][0].__setitem__(
            "scenario", "fake"
        ))
        self.assert_rejected(lambda r, p: r["case_observations"][0].__setitem__(
            "operator_approved", True
        ))
        self.assert_rejected(lambda r, p: r.__setitem__("release_approved", True))

    def test_exact_wire_case_cannot_be_forged_as_clean(self):
        for name in DENIED:
            with self.subTest(scenario=name):
                self.assert_rejected(lambda r, p: next(
                    row for row in r["case_observations"]
                    if row["scenario"] == name
                )["wire_cookie_fields"].clear())

    def test_denial_must_happen_before_session_lookup_and_write(self):
        for name in DENIED:
            for field, value in (
                ("application_session_lookups", 1),
                ("persistent_writes", 1),
                ("authenticated", True),
                ("set_cookie", True),
                ("second_request_admitted", True),
                ("no_store", False),
                ("edge_status", 200),
            ):
                with self.subTest(case=name, field=field):
                    self.assert_rejected(lambda r, p: next(
                        row for row in r["case_observations"]
                        if row["scenario"] == name
                    ).__setitem__(field, value))

    def test_positive_controls_do_not_grant_privilege(self):
        for name in SCENARIOS:
            if name in DENIED:
                continue
            for field, value in (
                ("authenticated", True), ("persistent_writes", 1),
                ("set_cookie", True), ("second_request_admitted", True),
                ("backend_reached", False),
            ):
                with self.subTest(case=name, field=field):
                    self.assert_rejected(lambda r, p: next(
                        row for row in r["case_observations"]
                        if row["scenario"] == name
                    ).__setitem__(field, value))

    def test_backend_cannot_silently_normalize_ambiguous_wire(self):
        self.assert_rejected(lambda r, p: next(
            row for row in r["case_observations"]
            if row["scenario"] == "duplicate_wire_headers"
        ).update({
            "backend_reached": True,
            "backend_cookie_fields": [SCENARIOS["single_session"][0]],
        }))
        self.assert_rejected(lambda r, p: r["case_observations"][0].update({
            "backend_reached": False,
            "backend_cookie_fields": ["forged"],
        }))

    def test_backend_observation_cannot_be_python_subclass(self):
        class PretendStr(str):
            pass
        class PretendList(list):
            pass
        self.assert_rejected(lambda r, p: r["case_observations"][0].__setitem__(
            "backend_cookie_fields", PretendList([])
        ))
        self.assert_rejected(lambda r, p: r["case_observations"][0].__setitem__(
            "wire_cookie_fields", [PretendStr("x")]
        ))

    def test_numeric_and_boolean_polymorphism_rejected(self):
        self.assert_rejected(lambda r, p: r["case_observations"][0].__setitem__(
            "persistent_writes", False
        ))
        self.assert_rejected(lambda r, p: r["case_observations"][0].__setitem__(
            "edge_status", True
        ))
        self.assert_rejected(lambda r, p: r["case_observations"][0].__setitem__(
            "no_store", 1
        ))

    def test_external_pins_are_required_and_exact(self):
        for key in ("repository_commit", "nginx_config_sha256", "backend_capture_sha256"):
            with self.subTest(key=key):
                self.assert_rejected(lambda r, p: p.__setitem__(key, "f" * len(p[key])))
                self.assert_rejected(lambda r, p: r.__setitem__(key, "G" * len(r[key])))
        self.assert_rejected(lambda r, p: p.pop("nginx_config_sha256"))

    def test_fixture_marker_cannot_be_used_as_installed_proof(self):
        self.assert_rejected(lambda r, p: r.__setitem__("fixture_only", False))
        self.assert_rejected(lambda r, p: r.__setitem__("fixture_only", 1))

    def test_malformed_collections_fail_closed(self):
        self.assertFalse(review_cookie_ingress_receipt(None, None))
        self.assertFalse(review_cookie_ingress_receipt({}, {}))
        self.assert_rejected(lambda r, p: r.__setitem__(
            "case_observations", tuple(r["case_observations"])
        ))
        self.assert_rejected(lambda r, p: r["case_observations"][0].__setitem__(
            "wire_cookie_fields", tuple()
        ))

    def test_exact_status_bounds(self):
        for bad in (-1, 0, 300, 399, 500, 999):
            with self.subTest(code=bad):
                self.assert_rejected(lambda r, p: next(
                    row for row in r["case_observations"]
                    if row["scenario"] == "duplicate_semicolon"
                ).__setitem__("edge_status", bad))


if __name__ == "__main__":
    unittest.main()
