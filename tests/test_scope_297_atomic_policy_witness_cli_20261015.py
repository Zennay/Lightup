"""Deterministic controls for the offline-only #297 HOLD diagnostic CLI."""

from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
import os
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import scope_297_atomic_policy_witness_20261015 as witness


class Issue297OfflineWitnessTests(unittest.TestCase):
    def test_all_eight_original_installed_source_cases_are_actual_unsafe_allow(self):
        receipt = witness.evaluate()
        self.assertEqual(receipt["case_count"], 8)
        self.assertEqual(receipt["unsafe_allow_count"], 8)
        self.assertEqual(receipt["denied_review_count"], 0)
        self.assertEqual(receipt["error_review_count"], 0)
        self.assertEqual(receipt["network_blocked_review_count"], 0)
        self.assertEqual(
            {x["classification"] for x in receipt["observations"]},
            {"UNSAFE_ALLOW"},
        )

    def test_case_ids_unique_and_only_documentation_targets(self):
        cases = witness.CASES
        self.assertEqual(len(cases), len({case.case_id for case in cases}))
        self.assertEqual(len(cases), 8)
        self.assertTrue(
            all(
                "example.test" in case.target or case.target == "198.51.100.42"
                for case in cases
            )
        )

    def test_all_real_authority_flags_always_false(self):
        receipt = witness.evaluate()
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(
            receipt["permissions"], witness.FROZEN_FALSE_PERMISSIONS
        )
        self.assertFalse(any(receipt["permissions"].values()))
        self.assertFalse(receipt["is_real_grant"])
        self.assertFalse(receipt["is_real_target_assessment"])

    def test_plain_cli_is_readable_nl_and_returns_hold_2(self):
        buf = StringIO()
        with redirect_stdout(buf):
            result = witness.main([])
        self.assertEqual(result, 2)
        output = buf.getvalue()
        self.assertIn("UITKOMST: HOLD", output)
        self.assertIn("Onveilige toestemmingen gezien: 8", output)
        self.assertIn("host_bytes_to_network: UNSAFE_ALLOW", output)

    def test_json_cli_returns_machine_readable_hold_2(self):
        buf = StringIO()
        with redirect_stdout(buf):
            result = witness.main(["--json"])
        self.assertEqual(result, 2)
        receipt = json.loads(buf.getvalue())
        self.assertEqual(receipt, witness.evaluate())
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["unsafe_allow_count"], 8)

    def test_no_case_target_or_fake_grant_identifier_leaks_in_output(self):
        buf = StringIO()
        with redirect_stdout(buf):
            witness.main([])
            witness.main(["--json"])
        rendered = buf.getvalue()
        self.assertNotIn("SYNTHETIC-NOT-A-REAL-GRANT", rendered)
        self.assertNotIn("security.example.test", rendered)
        self.assertNotIn("198.51.100.42", rendered)

    def test_unsupported_external_target_input_rejected(self):
        with patch("sys.stderr", new=StringIO()):
            with self.assertRaises(SystemExit) as err:
                witness.main(["--target", "other.example.test"])
        self.assertEqual(err.exception.code, 2)

    def test_source_witness_uses_socket_and_dns_tripwires(self):
        # Outer tripwires remain uncalled: actual source does pure parsing only.
        with (
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("NO_DNS")) as dns,
            patch.object(socket, "socket", side_effect=AssertionError("NO_SOCKETS")) as sock,
        ):
            self.assertEqual(witness.evaluate()["unsafe_allow_count"], 8)
            dns.assert_not_called()
            sock.assert_not_called()

    def test_source_repair_does_not_auto_authorize_or_mark_green(self):
        class StrictPolicy:
            def __init__(self, **_):
                pass

            def decide(self, _target):
                return witness.ScopeDecision(
                    False, None, witness.ScopeReason.OUT_OF_SCOPE
                )

        # A hypothetical future owner source fix is still only a HOLD review.
        with patch.object(witness, "ScopePolicy", StrictPolicy):
            receipt = witness.evaluate()
        self.assertEqual(receipt["unsafe_allow_count"], 0)
        self.assertEqual(receipt["denied_review_count"], 8)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertFalse(any(receipt["permissions"].values()))

    def test_source_exception_is_privacy_minimal_review_not_success(self):
        class UnexpectedPolicy:
            def __init__(self, **_):
                pass

            def decide(self, _target):
                raise RuntimeError("PRIVATE-SECRET-SHOULD-NOT-LEAK")

        with patch.object(witness, "ScopePolicy", UnexpectedPolicy):
            receipt = witness.evaluate()
            rendered = witness.render_dutch(receipt)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["error_review_count"], 8)
        self.assertEqual(receipt["unsafe_allow_count"], 0)
        self.assertNotIn("PRIVATE-SECRET", json.dumps(receipt) + rendered)

    def test_future_constructor_rejection_is_generic_hold_not_crash(self):
        class RejectsMalformedAtConstruction:
            def __init__(self, **_):
                raise ValueError("PRIVATE-ISSUER-DATA-MUST-NOT-LEAK")

        with patch.object(witness, "ScopePolicy", RejectsMalformedAtConstruction):
            receipt = witness.evaluate()
            text_report = witness.render_dutch(receipt)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["error_review_count"], 8)
        self.assertEqual(receipt["unsafe_allow_count"], 0)
        self.assertFalse(any(receipt["permissions"].values()))
        self.assertNotIn(
            "PRIVATE-ISSUER-DATA",
            json.dumps(receipt) + text_report,
        )

    def test_fake_source_socket_attempt_is_blocked_and_reported(self):
        class NetworkAttemptPolicy:
            def __init__(self, **_):
                pass

            def decide(self, _target):
                # Must hit the socket tripwire, not an actual system socket.
                socket.socket()
                raise AssertionError("unreachable")

        with patch.object(witness, "ScopePolicy", NetworkAttemptPolicy):
            receipt = witness.evaluate()
            human = witness.render_dutch(receipt)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["network_blocked_review_count"], 8)
        self.assertEqual(receipt["unsafe_allow_count"], 0)
        self.assertIn("Gestopte netwerkpogingen voor review: 8", human)
        self.assertFalse(any(receipt["permissions"].values()))

    def test_fake_source_dns_attempt_is_blocked_and_reported(self):
        class DNSAttemptPolicy:
            def __init__(self, **_):
                pass

            def decide(self, _target):
                socket.getaddrinfo("example.test", 443)
                raise AssertionError("unreachable")

        with patch.object(witness, "ScopePolicy", DNSAttemptPolicy):
            receipt = witness.evaluate()
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["network_blocked_review_count"], 8)
        self.assertEqual(receipt["error_review_count"], 0)
        self.assertEqual(receipt["unsafe_allow_count"], 0)
        self.assertFalse(any(receipt["permissions"].values()))

    def test_suppressed_socket_exception_still_counts_as_network_attempt(self):
        class SwallowsSocketFailure:
            def __init__(self, **_):
                pass

            def decide(self, _target):
                try:
                    socket.socket()
                except witness.NetworkAttemptBlocked:
                    pass
                return witness.ScopeDecision(
                    True, None, witness.ScopeReason.EXPLICIT_HOST
                )

        with patch.object(witness, "ScopePolicy", SwallowsSocketFailure):
            receipt = witness.evaluate()
        self.assertEqual(receipt["network_blocked_review_count"], 8)
        self.assertEqual(receipt["unsafe_allow_count"], 0)
        self.assertEqual(receipt["other_allow_review_count"], 0)
        self.assertFalse(any(receipt["permissions"].values()))

    def test_suppressed_dns_exception_still_counts_as_network_attempt(self):
        class SwallowsResolverFailure:
            def __init__(self, **_):
                pass

            def decide(self, _target):
                try:
                    socket.getaddrinfo("example.test", 443)
                except witness.NetworkAttemptBlocked:
                    pass
                return witness.ScopeDecision(
                    False, None, witness.ScopeReason.OUT_OF_SCOPE
                )

        with patch.object(witness, "ScopePolicy", SwallowsResolverFailure):
            receipt = witness.evaluate()
        self.assertEqual(receipt["network_blocked_review_count"], 8)
        self.assertEqual(receipt["denied_review_count"], 0)
        self.assertFalse(any(receipt["permissions"].values()))

    def test_independent_attempt_counters_do_not_mark_later_cases(self):
        class OneBadCase:
            calls = 0

            def __init__(self, **_):
                pass

            def decide(self, _target):
                type(self).calls += 1
                if type(self).calls == 1:
                    try:
                        socket.socket()
                    except witness.NetworkAttemptBlocked:
                        pass
                return witness.ScopeDecision(
                    False, None, witness.ScopeReason.OUT_OF_SCOPE
                )

        with patch.object(witness, "ScopePolicy", OneBadCase):
            receipt = witness.evaluate()
        self.assertEqual(receipt["network_blocked_review_count"], 1)
        self.assertEqual(receipt["denied_review_count"], 7)
        self.assertEqual(receipt["case_count"], 8)
        self.assertEqual(receipt["status"], "HOLD")

    def test_bypass_resolver_helpers_are_independently_tripped(self):
        attempts = (
            ("gethostbyname", ("example.test",)),
            ("gethostbyname_ex", ("example.test",)),
            ("gethostbyaddr", ("198.51.100.42",)),
            ("getnameinfo", (("198.51.100.42", 443), 0)),
            ("getfqdn", ("example.test",)),
        )
        for api, args in attempts:
            with self.subTest(api=api):
                with witness.disconnected() as guard:
                    with self.assertRaises(witness.NetworkAttemptBlocked):
                        getattr(socket, api)(*args)
                    self.assertEqual(guard.attempts, 1)
        self.assertEqual(witness.evaluate()["network_blocked_review_count"], 0)

    def test_socket_helper_functions_and_pair_are_tripped(self):
        attempts = (
            ("create_connection", (("198.51.100.42", 443),)),
            ("create_server", (("127.0.0.1", 0),)),
            ("socketpair", ()),
        )
        for api, args in attempts:
            with self.subTest(api=api):
                with witness.disconnected() as guard:
                    with self.assertRaises(witness.NetworkAttemptBlocked):
                        getattr(socket, api)(*args)
                    self.assertEqual(guard.attempts, 1)

    def test_tripwire_restores_original_socket_apis(self):
        names = ("socket", "create_connection", "getaddrinfo", "gethostbyname")
        original = {name: getattr(socket, name) for name in names}
        with witness.disconnected() as guard:
            for name in names:
                with self.assertRaises(witness.NetworkAttemptBlocked):
                    getattr(socket, name)()
            self.assertEqual(guard.attempts, len(names))
        for name in names:
            self.assertIs(getattr(socket, name), original[name])

    def test_cli_does_not_write_any_files(self):
        # The implementation is pure reporting with no cwd, os.open or tempfile.
        with (
            patch("builtins.open", side_effect=AssertionError("NO_FILE_WRITES")) as opened,
            patch("os.system", side_effect=AssertionError("NO_SHELL")) as shell,
        ):
            self.assertEqual(witness.main(["--json"]), 2)
            opened.assert_not_called()
            shell.assert_not_called()


if __name__ == "__main__":
    unittest.main()
