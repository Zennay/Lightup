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

    def test_preconnected_socket_send_paths_refuse_non_loopback_peer(self):
        # Synthetic peer only: never open a real external connection.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            with patch.object(socket.socket, "getpeername", return_value=("203.0.113.5", 443)):
                with patch.object(socket.socket, "send", return_value=1) as raw_send, patch.object(
                    socket.socket, "sendall", return_value=None
                ) as raw_sendall, patch.object(
                    socket.socket, "sendfile", return_value=1
                ) as raw_sendfile:
                    with fixed_loopback_socket_boundary():
                        for action in (
                            lambda: sock.send(b"x"),
                            lambda: sock.sendall(b"x"),
                            lambda: sock.sendfile(io.BytesIO(b"x")),
                        ):
                            with self.subTest(action=repr(action)), self.assertRaises(
                                LabSocketBoundaryError
                            ):
                                action()
                    raw_send.assert_not_called()
                    raw_sendall.assert_not_called()
                    raw_sendfile.assert_not_called()

    def test_preconnected_loopback_peer_send_paths_remain_usable(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            with patch.object(socket.socket, "getpeername", return_value=("127.0.0.1", 53111)):
                with patch.object(socket.socket, "send", return_value=1) as raw_send, patch.object(
                    socket.socket, "sendall", return_value=None
                ) as raw_sendall, patch.object(
                    socket.socket, "sendfile", return_value=1
                ) as raw_sendfile:
                    with fixed_loopback_socket_boundary():
                        self.assertEqual(sock.send(b"x"), 1)
                        self.assertIsNone(sock.sendall(b"x"))
                        self.assertEqual(sock.sendfile(io.BytesIO(b"x")), 1)
                    raw_send.assert_called_once()
                    raw_sendall.assert_called_once()
                    raw_sendfile.assert_called_once()

    def test_preconnected_tls_socket_overrides_refuse_external_peer(self):
        # SSL overrides socket.send/sendall/sendfile and can write directly.
        # Use only a synthetic peer; never dial an external endpoint.
        import ssl
        from types import SimpleNamespace
        fake = SimpleNamespace(family=socket.AF_INET,
                               getpeername=lambda: ("203.0.113.5", 443))
        names = ("send", "sendall", "sendfile", "write")
        for name in names:
            with self.subTest(api=name), patch.object(
                ssl.SSLSocket, name, return_value=1
            ) as underlying:
                with fixed_loopback_socket_boundary():
                    with self.assertRaises(LabSocketBoundaryError):
                        getattr(ssl.SSLSocket, name)(fake, b"fixture")
                underlying.assert_not_called()

    def test_preconnected_tls_loopback_socket_writes_still_allowed(self):
        import ssl
        from types import SimpleNamespace
        fake = SimpleNamespace(family=socket.AF_INET,
                               getpeername=lambda: ("127.0.0.1", 53111))
        for name in ("send", "sendall", "sendfile", "write"):
            with self.subTest(api=name), patch.object(
                ssl.SSLSocket, name, return_value=1
            ) as underlying:
                with fixed_loopback_socket_boundary():
                    self.assertEqual(getattr(ssl.SSLSocket, name)(fake, b"x"), 1)
                underlying.assert_called_once()

    def test_tls_connect_override_rejects_external_address(self):
        import ssl
        from types import SimpleNamespace
        fake = SimpleNamespace(family=socket.AF_INET)
        for name in ("connect", "connect_ex"):
            with self.subTest(api=name), patch.object(
                ssl.SSLSocket, name, return_value=0
            ) as underlying:
                with fixed_loopback_socket_boundary():
                    with self.assertRaises(LabSocketBoundaryError):
                        getattr(ssl.SSLSocket, name)(fake, ("203.0.113.5", 443))
                    self.assertEqual(
                        getattr(ssl.SSLSocket, name)(fake, ("127.0.0.1", 443)), 0
                    )
                underlying.assert_called_once()

    def test_tls_wrap_and_handshake_cannot_use_preconnected_external_peer(self):
        import ssl
        from types import SimpleNamespace
        external = SimpleNamespace(family=socket.AF_INET,
                                   getpeername=lambda: ("203.0.113.5", 443))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with patch.object(ssl.SSLContext, "wrap_socket", return_value="wrapped") as underlying:
            with fixed_loopback_socket_boundary():
                with self.assertRaises(LabSocketBoundaryError):
                    ssl.SSLContext.wrap_socket(context, external, server_hostname="example.invalid")
            underlying.assert_not_called()
        for method in ("do_handshake", "unwrap"):
            with self.subTest(method=method), patch.object(
                ssl.SSLSocket, method, return_value=None
            ) as underlying:
                with fixed_loopback_socket_boundary():
                    with self.assertRaises(LabSocketBoundaryError):
                        getattr(ssl.SSLSocket, method)(external)
                underlying.assert_not_called()

    def test_tls_wrap_and_handshake_allow_preconnected_loopback_peer(self):
        import ssl
        from types import SimpleNamespace
        loopback = SimpleNamespace(family=socket.AF_INET,
                                   getpeername=lambda: ("127.0.0.1", 53111))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with patch.object(ssl.SSLContext, "wrap_socket", return_value="wrapped"):
            with fixed_loopback_socket_boundary():
                self.assertEqual(ssl.SSLContext.wrap_socket(context, loopback), "wrapped")
        for method in ("do_handshake", "unwrap"):
            with self.subTest(method=method), patch.object(
                ssl.SSLSocket, method, return_value="ok"
            ):
                with fixed_loopback_socket_boundary():
                    self.assertEqual(getattr(ssl.SSLSocket, method)(loopback), "ok")

    def test_unapproved_child_process_paths_are_blocked(self):
        import os
        import subprocess
        # All launch primitives are mocked: never run a real external command.
        with patch.object(subprocess, "Popen", return_value="launched") as popen, patch.object(
            os, "system", return_value=0
        ) as system, patch.object(os, "popen", return_value="shell") as ospopen, patch.object(
            os, "posix_spawn", return_value=42
        ) as spawn, patch.object(os, "posix_spawnp", return_value=42) as spawnp:
            with fixed_loopback_socket_boundary():
                attempts = (
                    lambda: subprocess.Popen(["curl", "https://example.invalid"]),
                    lambda: subprocess.Popen("openssl req -x509", shell=True),
                    lambda: os.system("echo TEST-SYNTHETIC"),
                    lambda: os.popen("echo TEST-SYNTHETIC"),
                    lambda: os.posix_spawn("/bin/echo", ["echo", "TEST-SYNTHETIC"], {}),
                    lambda: os.posix_spawnp("echo", ["echo", "TEST-SYNTHETIC"], {}),
                )
                for action in attempts:
                    with self.subTest(action=repr(action)), self.assertRaises(
                        LabSocketBoundaryError
                    ):
                        action()
            for original in (popen, system, ospopen, spawn, spawnp):
                original.assert_not_called()

    def test_direct_exec_spawn_and_forkpty_paths_are_blocked(self):
        import os
        with patch.object(os, "execve", return_value=None) as execve, patch.object(
            os, "spawnv", return_value=0
        ) as spawnv, patch.object(os, "forkpty", return_value=(42, 1)) as forkpty:
            with fixed_loopback_socket_boundary():
                for launch in (
                    lambda: os.execve("/bin/echo", ["echo", "synthetic"], {}),
                    lambda: os.spawnv(os.P_WAIT, "/bin/echo", ["echo", "synthetic"]),
                    lambda: os.forkpty(),
                ):
                    with self.subTest(launch=repr(launch)), self.assertRaises(
                        LabSocketBoundaryError
                    ):
                        launch()
            execve.assert_not_called()
            spawnv.assert_not_called()
            forkpty.assert_not_called()

    def test_only_pinned_local_certificate_subprocess_is_admitted(self):
        import shutil
        import subprocess
        from pathlib import Path
        from tempfile import TemporaryDirectory
        openssl = shutil.which("openssl")
        if openssl is None:
            self.skipTest("TLS fixture requires installed openssl")
        with TemporaryDirectory(prefix="lightup-tls-lab-") as folder:
            valid = [
                openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(Path(folder) / "fixture-key.pem"),
                "-out", str(Path(folder) / "fixture-cert.pem"), "-days", "1",
                "-subj", "/CN=127.0.0.1", "-addext",
                "subjectAltName=IP:127.0.0.1", "-addext",
                "basicConstraints=critical,CA:FALSE",
            ]
            with patch.object(subprocess, "Popen", return_value="allowed") as original:
                with fixed_loopback_socket_boundary():
                    self.assertEqual(subprocess.Popen(valid), "allowed")
                    for index, value in ((1, "s_client"), (7, "/tmp/PRIVATE-key.pem"),
                                         (15, "subjectAltName=DNS:public.example"),
                                         (17, "basicConstraints=CA:TRUE")):
                        attempt = list(valid)
                        attempt[index] = value
                        with self.subTest(index=index), self.assertRaises(LabSocketBoundaryError):
                            subprocess.Popen(attempt)
                    with self.assertRaises(LabSocketBoundaryError):
                        subprocess.Popen(valid, shell=True)
                original.assert_called_once_with(valid)

    def test_preconnected_socket_receive_paths_check_peer_before_io(self):
        # Synthetic peer identities; no public socket ever opened.
        from types import SimpleNamespace
        fake = SimpleNamespace(family=socket.AF_INET,
                               getpeername=lambda: ("203.0.113.5", 443))
        for method, args in (
            ("recv", (1,)), ("recv_into", (bytearray(2),)),
            ("recvfrom", (1,)), ("recvfrom_into", (bytearray(2),)),
            ("recvmsg", (1,)), ("recvmsg_into", ([bytearray(2)],)),
        ):
            if not hasattr(socket.socket, method):
                continue
            with self.subTest(method=method), patch.object(
                socket.socket, method, return_value=b"x"
            ) as underlying:
                with fixed_loopback_socket_boundary():
                    with self.assertRaises(LabSocketBoundaryError):
                        getattr(socket.socket, method)(fake, *args)
                underlying.assert_not_called()

    def test_preconnected_tls_read_paths_check_peer_before_io(self):
        import ssl
        from types import SimpleNamespace
        fake = SimpleNamespace(family=socket.AF_INET,
                               getpeername=lambda: ("203.0.113.5", 443))
        for method, args in (("recv", (1,)), ("recv_into", (bytearray(2),)),
                             ("read", (1,))):
            with self.subTest(method=method), patch.object(
                ssl.SSLSocket, method, return_value=b"x"
            ) as underlying:
                with fixed_loopback_socket_boundary():
                    with self.assertRaises(LabSocketBoundaryError):
                        getattr(ssl.SSLSocket, method)(fake, *args)
                underlying.assert_not_called()

    def test_exact_openssl_cannot_be_spawned_directly_outside_validated_popen(self):
        # A forged environment and direct spawn must not inherit the Popen grant.
        import os
        import shutil
        from pathlib import Path
        from tempfile import TemporaryDirectory
        openssl = shutil.which("openssl")
        if openssl is None:
            self.skipTest("openssl not installed")
        with TemporaryDirectory(prefix="lightup-tls-lab-") as d:
            cmd = [openssl, "req", "-x509", "-newkey", "rsa:2048",
                   "-nodes", "-keyout", str(Path(d) / "fixture-key.pem"),
                   "-out", str(Path(d) / "fixture-cert.pem"), "-days", "1",
                   "-subj", "/CN=127.0.0.1", "-addext",
                   "subjectAltName=IP:127.0.0.1", "-addext",
                   "basicConstraints=critical,CA:FALSE"]
            with patch.object(os, "posix_spawn", return_value=100) as raw, patch.object(
                os, "posix_spawnp", return_value=100
            ) as rawp:
                with fixed_loopback_socket_boundary():
                    for name in ("posix_spawn", "posix_spawnp"):
                        with self.subTest(name=name), self.assertRaises(
                            LabSocketBoundaryError
                        ):
                            getattr(os, name)(openssl, cmd,
                                              {"OPENSSL_CONF": "/tmp/untrusted.conf"})
                raw.assert_not_called()
                rawp.assert_not_called()

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
                    for attack in (
                        "fpr_and_run", "scenario_swap", "missing_evidence",
                        "duplicated_evidence", "untrusted_engine", "model_binding",
                    ):
                        bad = deepcopy(valid if attack not in ("fpr_and_run",) else forged)
                        if attack == "scenario_swap":
                            bad["scenario_id"] = "forged-lab-scenario"
                            bad["evaluation"]["scenario_id"] = "forged-lab-scenario"
                        elif attack == "missing_evidence":
                            bad["evaluation"]["evidence_ids"] = []
                        elif attack == "duplicated_evidence":
                            ids = bad["evaluation"]["evidence_ids"]
                            bad["evaluation"]["evidence_ids"] = [ids[0]] * len(ids)
                        elif attack == "untrusted_engine":
                            bad["evaluation"]["engine_version"] = "untrusted-lab-producer"
                        elif attack == "model_binding":
                            bad["evaluation"]["model_bindings"] = ["unknown-model"]
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

    def test_canary_rejects_silent_socket_guard_failure(self):
        # All fixtures are fixed 127.0.0.1; no external socket is used.
        from contextlib import nullcontext
        with patch.object(lab_canary, "fixed_loopback_socket_boundary",
                          return_value=nullcontext()):
            with redirect_stdout(io.StringIO()) as output:
                code = lab_canary.main([])
        self.assertEqual(code, 2, "unchecked boundary must not report PASS")
        self.assertEqual(json.loads(output.getvalue()), {
            "status": "HOLD", "passed": False, "lab_only": True,
            "external_target_authorized": False, "deployment_authorized": False,
            "failure_stage": "setup",
        })

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
