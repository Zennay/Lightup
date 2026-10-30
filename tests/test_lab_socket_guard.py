"""The M1 scorer sandbox refuses non-fixed socket operations before OS I/O."""
from __future__ import annotations

import io
import json
import socket
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from lightup import lab_canary
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
