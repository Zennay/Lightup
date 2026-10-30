"""The M1 scorer sandbox refuses non-fixed socket operations before OS I/O."""
from __future__ import annotations

import io
import json
import socket
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from lightup import lab_canary, lab_service_score, lab_tls_score, lab_web_score
from lightup.lab_socket_guard import (
    LabSocketBoundaryError, fixed_loopback_socket_boundary,
)


class FixedLoopbackSocketBoundaryTests(unittest.TestCase):
    def test_non_loopback_connect_bind_send_and_name_resolution_denied(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            with patch.object(socket.socket, "connect") as underlying_connect, patch.object(
                socket.socket, "connect_ex"
            ) as underlying_connect_ex, patch.object(
                socket.socket, "bind"
            ) as underlying_bind, patch.object(
                socket.socket, "sendto"
            ) as underlying_send:
                with fixed_loopback_socket_boundary():
                    for action in (
                        lambda: sock.connect(("203.0.113.1", 443)),
                        lambda: sock.connect_ex(("203.0.113.1", 443)),
                        lambda: sock.bind(("0.0.0.0", 0)),
                        lambda: sock.sendto(b"sample", ("203.0.113.1", 53)),
                        lambda: socket.getaddrinfo("example.invalid", 443),
                        lambda: sock.connect(("localhost", 443)),
                        lambda: sock.bind(("127.0.0.2", 0)),
                    ):
                        with self.subTest(action=repr(action)), self.assertRaises(
                            LabSocketBoundaryError
                        ):
                            action()
                underlying_connect.assert_not_called()
                underlying_connect_ex.assert_not_called()
                underlying_bind.assert_not_called()
                underlying_send.assert_not_called()

    def test_non_getaddrinfo_dns_and_reverse_dns_are_blocked(self):
        resolver_names = (
            "gethostbyname", "gethostbyname_ex", "gethostbyaddr",
            "getnameinfo", "getfqdn",
        )
        calls = (
            lambda: socket.gethostbyname("external.invalid"),
            lambda: socket.gethostbyname_ex("external.invalid"),
            lambda: socket.gethostbyaddr("203.0.113.9"),
            lambda: socket.getnameinfo(("203.0.113.9", 443), 0),
            lambda: socket.getfqdn("external.invalid"),
        )
        originals = {name: getattr(socket, name) for name in resolver_names}
        with fixed_loopback_socket_boundary():
            self.assertEqual(socket.getfqdn("127.0.0.1"), "127.0.0.1")
            for name, action in zip(resolver_names, calls):
                with self.subTest(api=name), self.assertRaises(LabSocketBoundaryError):
                    action()
        for name, original in originals.items():
            self.assertIs(getattr(socket, name), original)

    def test_each_installed_scorer_api_enforces_socket_gate_on_its_own(self):
        cases = (
            (lab_service_score, "run_lab_service_inventory_score"),
            (lab_tls_score, "run_lab_tls_baseline_score"),
            (lab_web_score, "run_lab_web_baseline_score"),
        )
        def forbidden_work(_db):
            # DNS must fail before any external connection can be attempted.
            return socket.create_connection(("example.invalid", 443))
        for mod, api in cases:
            with self.subTest(api=api):
                with patch.object(mod, "_unprotected_" + api,
                                  side_effect=forbidden_work):
                    with self.assertRaises(LabSocketBoundaryError):
                        getattr(mod, api)("synthetic.db")

    def test_each_installed_scorer_api_runs_valid_fixed_fixture(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path
        with TemporaryDirectory() as d:
            for mod, api, count in (
                (lab_service_score, "run_lab_service_inventory_score", 1),
                (lab_tls_score, "run_lab_tls_baseline_score", 1),
                (lab_web_score, "run_lab_web_baseline_score", 5),
            ):
                with self.subTest(api=api):
                    result = getattr(mod, api)(Path(d) / (api + ".db"))
                    self.assertIs(result["passed"], True)
                    self.assertEqual(result["evaluation"]["metrics"]["valid_findings"], count)

    def test_all_three_direct_clis_reject_forged_success_evaluations(self):
        from copy import deepcopy
        from tempfile import TemporaryDirectory
        from pathlib import Path
        with TemporaryDirectory() as directory:
            for mod, api in (
                (lab_service_score, "run_lab_service_inventory_score"),
                (lab_tls_score, "run_lab_tls_baseline_score"),
                (lab_web_score, "run_lab_web_baseline_score"),
            ):
                with self.subTest(api=api):
                    valid = getattr(mod, api)(Path(directory) / (api + ".db"))
                    self.assertIs(valid["passed"], True)
                    forged = deepcopy(valid)
                    forged["evaluation"]["metrics"]["false_positive_rate"] = 0.75
                    forged["evaluation"]["run_id"] = "forged-canonical-run"
                    for attack in ("fpr_and_run", "scenario_swap"):
                        bad = deepcopy(forged)
                        if attack == "scenario_swap":
                            bad["evaluation"]["metrics"]["false_positive_rate"] = 0.0
                            bad["evaluation"]["run_id"] = valid["run_id"]
                            bad["scenario_id"] = "forged-lab-scenario"
                            bad["evaluation"]["scenario_id"] = "forged-lab-scenario"
                        with self.subTest(attack=attack), patch.object(
                            mod, api, return_value=bad
                        ):
                            with redirect_stdout(io.StringIO()) as receipt:
                                exit_code = mod.main(["--db", "fictional.db"])
                            self.assertEqual(exit_code, 2)
                            self.assertEqual(json.loads(receipt.getvalue()), {
                                "passed": False, "error": "offline fixture denied or unavailable"
                            })

    def test_all_three_installed_clis_hide_failure_paths(self):
        for mod, api in (
            (lab_service_score, "run_lab_service_inventory_score"),
            (lab_tls_score, "run_lab_tls_baseline_score"),
            (lab_web_score, "run_lab_web_baseline_score"),
        ):
            with self.subTest(api=api):
                with patch.object(mod, api,
                                  side_effect=PermissionError("/tmp/PRIVATE-credential.db")):
                    with redirect_stdout(io.StringIO()) as out:
                        code = mod.main(["--db", "/tmp/PRIVATE-credential.db"])
                self.assertEqual(code, 2)
                self.assertEqual(json.loads(out.getvalue()), {
                    "passed": False, "error": "offline fixture denied or unavailable"
                })
                self.assertNotIn("PRIVATE", out.getvalue())

    def test_direct_clis_do_not_echo_rejected_argument_values(self):
        from contextlib import redirect_stderr
        for mod, api in (
            (lab_service_score, "run_lab_service_inventory_score"),
            (lab_tls_score, "run_lab_tls_baseline_score"),
            (lab_web_score, "run_lab_web_baseline_score"),
        ):
            with self.subTest(api=api):
                with patch.object(mod, api) as scorer:
                    with redirect_stderr(io.StringIO()) as err:
                        with self.assertRaises(SystemExit) as raised:
                            mod.main(["--target", "https://PRIVATE.example/secret"])
                self.assertEqual(raised.exception.code, 2)
                self.assertNotIn("PRIVATE", err.getvalue())
                scorer.assert_not_called()

    def test_valid_fixed_loopback_scorer_run_works_and_restores_socket(self):
        original = socket.socket.connect
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(lab_canary.main([]), 0)
        result = json.loads(out.getvalue())
        self.assertTrue(result["fixed_loopback_socket_boundary_enforced"])
        self.assertTrue(result["temporary_state_removed"])
        self.assertIs(socket.socket.connect, original)

    def test_scoring_failure_restores_socket_and_emits_private_hold(self):
        original = socket.socket.connect
        with patch("lightup.lab_canary.run_lab_service_inventory_score",
                   side_effect=RuntimeError("PRIVATE error text")):
            with redirect_stdout(io.StringIO()) as out:
                self.assertEqual(lab_canary.main([]), 2)
        self.assertEqual(json.loads(out.getvalue())["status"], "HOLD")
        self.assertNotIn("PRIVATE", out.getvalue())
        self.assertIs(socket.socket.connect, original)


if __name__ == "__main__":
    unittest.main()
