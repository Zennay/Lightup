"""Installed legacy source, fictional-only post-issuance quarantine (#1484).

Runs the actual ActivationGate only for localhost/LAB_ONLY under fixed
synthetic clocks; no network, grants, handlers, or production source edits.
"""
from __future__ import annotations

from datetime import datetime, timezone
import socket
import sqlite3
import subprocess
import unittest
from unittest.mock import patch

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.models import Target
from lightup.scope import ScopePolicy
from lightup.permit_claim_review_1484 import review_fictional_permit_claim_batch

T = datetime(2026, 10, 16, 10, 0, tzinfo=timezone.utc)

def lab_gate():
    return ActivationGate(ScopePolicy(),
                          ActivationPolicy(mode=ActivationMode.LAB_ONLY))

def review(*permits):
    return review_fictional_permit_claim_batch(tuple(permits), review_cutoff=T)

class InstalledFictionalPermit1484Tests(unittest.TestCase):
    def test_original_gate_issues_synthetic_lab_record_but_review_cannot_authorize(self):
        with patch("lightup.activation.token_urlsafe", return_value="a" * 32), \
             patch("lightup.activation.datetime") as clock:
            clock.now.return_value = T
            permit = lab_gate().issue(Target("localhost"), "lab.review")
        self.assertEqual(permit.issued_at, T)
        self.assertEqual(permit.mode, ActivationMode.LAB_ONLY)
        self.assertEqual(permit.target, "localhost")
        result = review(permit)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertFalse(result.execution_allowed)
        self.assertFalse(result.release_allowed)

    def test_same_real_gate_permit_repeated_in_batch_is_rejected(self):
        with patch("lightup.activation.token_urlsafe", return_value="a" * 32), \
             patch("lightup.activation.datetime") as clock:
            clock.now.return_value = T
            permit = lab_gate().issue(Target("localhost"), "lab.review")
        self.assertEqual(review(permit, permit).status, "HOLD")

    def test_two_real_gate_permits_different_ids_remain_review_only(self):
        with patch("lightup.activation.token_urlsafe", side_effect=["a" * 32, "b" * 32]), \
             patch("lightup.activation.datetime") as clock:
            clock.now.return_value = T
            gate = lab_gate()
            first = gate.issue(Target("localhost"), "lab.review")
            second = gate.issue(Target("127.0.0.1"), "lab.review")
        result = review(first, second)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(result.inspected, 2)
        self.assertIs(result.execution_allowed, False)

    def test_original_gate_plan_only_denies_even_loopback(self):
        gate = ActivationGate(ScopePolicy(), ActivationPolicy())
        with self.assertRaises(PermissionError):
            gate.issue(Target("localhost"), "lab.review")

    def test_original_gate_lab_mode_denies_explicit_synthetic_public(self):
        gate = ActivationGate(
            ScopePolicy(explicit_hosts=frozenset({"review.example.test"}),
                        require_authorization_for_public=False),
            ActivationPolicy(mode=ActivationMode.LAB_ONLY),
        )
        with self.assertRaises(PermissionError):
            gate.issue(Target("review.example.test"), "lab.review")

    def test_issuer_record_with_injected_authorized_marker_is_not_accepted(self):
        with patch("lightup.activation.token_urlsafe", return_value="a" * 32), \
             patch("lightup.activation.datetime") as clock:
            clock.now.return_value = T
            permit = lab_gate().issue(Target("localhost"), "lab.review")
        object.__setattr__(permit, "authorized", True)
        result = review(permit)
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.inspected, 0)
        self.assertFalse(result.execution_allowed)

    def test_actual_fictional_issuer_and_reviewer_do_not_use_io(self):
        with patch.object(socket, "socket", side_effect=AssertionError("socket")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")), \
             patch.object(sqlite3, "connect", side_effect=AssertionError("database")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")), \
             patch("lightup.activation.token_urlsafe", return_value="a" * 32), \
             patch("lightup.activation.datetime") as clock:
            clock.now.return_value = T
            permit = lab_gate().issue(Target("localhost"), "lab.review")
            self.assertEqual(review(permit).status, "REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
