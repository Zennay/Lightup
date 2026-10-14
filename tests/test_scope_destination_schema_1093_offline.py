"""Synthetic and subprocess acceptance for the non-authorizing #1093 reviewer."""
from __future__ import annotations

import json
import itertools
import os
import pathlib
import pty
import socket
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "review_scope_destination_schema_1093_offline.py"
sys.path.insert(0, str(ROOT / "scripts"))
from review_scope_destination_schema_1093_offline import (  # noqa: E402
    DENIAL, MAX_INPUT_BYTES, _read_private_pipe, _seal_receipt,
    review_bytes, review_schema,
)


def fixture():
    return {"tools": [
        {"tool_id": "lab-http-baseline", "parameters": [
            {"name": "url", "kind": "string", "role": "endpoint", "required": True}]},
        {"tool_id": "lab-tls-baseline", "parameters": [
            {"name": "host", "kind": "string", "role": "host", "required": True},
            {"name": "port", "kind": "integer", "role": "port", "required": True}]},
        {"tool_id": "lab-service-inventory", "parameters": [
            {"name": "host", "kind": "string", "role": "host", "required": True},
            {"name": "ports", "kind": "string", "role": "port_set", "required": True}]},
    ]}


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


class ReviewTests(unittest.TestCase):
    def assert_denied(self, value, status):
        self.assertEqual(value["status"], status)
        self.assertEqual(set(value), {"status", "claimed_tool_count",
                                     "claimed_parameter_count", *DENIAL})
        for key in DENIAL:
            self.assertIs(value[key], False)
        for key in ("claimed_tool_count", "claimed_parameter_count"):
            self.assertIs(type(value[key]), int)

    def test_three_distinct_real_worker_shapes_structural_only(self):
        value = review_bytes(encoded(fixture()))
        self.assert_denied(value, "REVIEW_ONLY")
        self.assertEqual((value["claimed_tool_count"], value["claimed_parameter_count"]), (3, 5))

    def test_claims_pin_actual_installed_lab_parameter_shapes(self):
        # Source-shaped comparison only: no registry registration, handler,
        # credentials, real target, DNS, socket, dispatch, or authorization.
        sys.path.insert(0, str(ROOT / "src"))
        from lightup.workers.http_baseline import HTTP_BASELINE_TOOL
        from lightup.workers.tls_baseline import TLS_BASELINE_TOOL
        from lightup.workers.service_inventory import SERVICE_INVENTORY_TOOL

        installed = (HTTP_BASELINE_TOOL, TLS_BASELINE_TOOL,
                     SERVICE_INVENTORY_TOOL)
        claimed = fixture()["tools"]
        self.assertEqual(len(installed), len(claimed))
        for definition, claim in zip(installed, claimed):
            with self.subTest(tool_id=definition.tool_id):
                self.assertEqual(definition.tool_id, claim["tool_id"])
                self.assertEqual(
                    [(parameter.name, parameter.kind.value,
                      parameter.required)
                     for parameter in definition.parameters],
                    [(parameter["name"], parameter["kind"],
                      parameter["required"])
                     for parameter in claim["parameters"]],
                )
                # Roles are presently *absent* from ToolDefinition; claims
                # cannot assert trusted role ownership for production.
                self.assert_denied(review_schema({"tools": [claim]}),
                                   "REVIEW_ONLY")

    def test_real_lab_handlers_route_exact_arguments_to_mock_producers(self):
        """Observe argument mapping without invoking any target transport."""
        sys.path.insert(0, str(ROOT / "src"))
        from lightup.ai.orchestration import RunContext
        from lightup.workers import http_baseline as http
        from lightup.workers import tls_baseline as tls
        from lightup.workers import service_inventory as svc

        context = RunContext.for_lab("synthetic-destination-flow")
        url = "http://127.0.0.1:18080/fixture"
        host = "127.0.0.1"
        http_observation = http.BaselineObservation(
            url=url, status=200, headers=(), issues=())
        tls_observation = tls.TlsObservation(
            host=host, port=10443, protocol="TLSv1.3",
            cipher="TLS_AES_128_GCM_SHA256", chain_trusted=True, issues=())

        # Defense in depth: every intended producer is mocked AND the
        # transport entry points raise before any actual connection.
        with (
            mock.patch("socket.socket",
                       side_effect=AssertionError("no socket allowed")) as raw_socket,
            mock.patch("socket.create_connection",
                       side_effect=AssertionError("no TCP allowed")) as tcp,
            mock.patch.object(http, "HTTPConnection",
                              side_effect=AssertionError("no HTTP allowed")) as raw_http,
            mock.patch.object(http, "observe",
                              return_value=http_observation) as http_producer,
            mock.patch.object(tls, "observe",
                              return_value=tls_observation) as tls_producer,
            mock.patch.object(svc, "inventory",
                              return_value={80: False, 443: True}) as svc_producer,
        ):
            h = http.run_http_baseline(context, {"url": url})
            t = tls.run_tls_baseline(context, {"host": host, "port": 10443})
            i = svc.run_service_inventory(
                context, {"host": host, "ports": "80,443"})
            http_producer.assert_called_once_with(url)
            tls_producer.assert_called_once_with(host, 10443)
            svc_producer.assert_called_once_with(host, (80, 443))
            self.assertEqual(json.loads(h.evidence_payload)["url"], url)
            self.assertEqual(json.loads(t.evidence_payload)["port"], 10443)
            self.assertEqual(json.loads(i.evidence_payload)["host"], host)
            self.assertEqual(json.loads(i.evidence_payload)["results"],
                             {"80": False, "443": True})
            raw_socket.assert_not_called()
            tcp.assert_not_called()
            raw_http.assert_not_called()

    def test_real_lab_handlers_deny_nonlab_context_before_any_producer(self):
        """Lab handler defense-in-depth is independent of claimed metadata."""
        from dataclasses import replace
        sys.path.insert(0, str(ROOT / "src"))
        from lightup.ai.orchestration import RunContext
        from lightup.labeval import LabIsolationError
        from lightup.workers import http_baseline as http
        from lightup.workers import tls_baseline as tls
        from lightup.workers import service_inventory as svc

        context = replace(RunContext.for_lab("synthetic-denial"),
                          is_lab=False)
        handlers = (
            (http.run_http_baseline, {"url": "http://127.0.0.1:18080/"}),
            (tls.run_tls_baseline, {"host": "127.0.0.1", "port": 10443}),
            (svc.run_service_inventory,
             {"host": "127.0.0.1", "ports": "80,443"}),
        )
        with (
            mock.patch.object(http, "observe") as h_observe,
            mock.patch.object(tls, "observe") as t_observe,
            mock.patch.object(svc, "inventory") as s_inventory,
            mock.patch("socket.create_connection",
                       side_effect=AssertionError("no network")) as tcp,
            mock.patch("socket.socket",
                       side_effect=AssertionError("no raw socket")) as raw_socket,
            mock.patch.object(http, "HTTPConnection",
                              side_effect=AssertionError("no HTTP")) as raw_http,
        ):
            for handler, arguments in handlers:
                with self.subTest(handler=handler.__name__):
                    with self.assertRaises(LabIsolationError):
                        handler(context, arguments)
            h_observe.assert_not_called()
            t_observe.assert_not_called()
            s_inventory.assert_not_called()
            tcp.assert_not_called()
            raw_socket.assert_not_called()
            raw_http.assert_not_called()

    def test_known_lab_role_claims_follow_actual_handler_parameter_contract(self):
        """Test-side fixed expectations; NOT trusted production role metadata."""
        sys.path.insert(0, str(ROOT / "src"))
        from lightup.workers.http_baseline import HTTP_BASELINE_TOOL
        from lightup.workers.tls_baseline import TLS_BASELINE_TOOL
        from lightup.workers.service_inventory import SERVICE_INVENTORY_TOOL

        known = {
            "lab-http-baseline": (("url", "endpoint"),),
            "lab-tls-baseline": (("host", "host"), ("port", "port")),
            "lab-service-inventory": (
                ("host", "host"), ("ports", "port_set")),
        }
        installed = (
            HTTP_BASELINE_TOOL, TLS_BASELINE_TOOL, SERVICE_INVENTORY_TOOL
        )
        self.assertEqual(set(known), {definition.tool_id for definition in installed})
        for definition, claim in zip(installed, fixture()["tools"]):
            with self.subTest(tool_id=definition.tool_id):
                expected = known[definition.tool_id]
                # Do not assert the absence of a future trusted registry
                # role field: the production owner must be free to add it.
                self.assertEqual(
                    tuple((parameter["name"], parameter["role"])
                          for parameter in claim["parameters"]), expected)
                self.assertEqual(
                    tuple(parameter.name for parameter in definition.parameters),
                    tuple(name for name, _ in expected))

    def test_no_source_truth_can_be_inferred(self):
        fake = fixture()
        fake["tools"][0]["tool_id"] = "unknown_but_well_formed"
        self.assert_denied(review_schema(fake), "REVIEW_ONLY")

    def test_reject_role_kind_cross_product(self):
        for role, wrong_kind in (("port", "string"), ("port_set", "integer"),
                                 ("host", "integer"), ("endpoint", "array")):
            with self.subTest(role=role):
                sample = fixture()
                sample["tools"][0]["parameters"][0].update(role=role, kind=wrong_kind)
                self.assert_denied(review_schema(sample), "HOLD")

    def test_destination_role_grammar_all_four_valid_shapes(self):
        endpoint = {"name": "url", "kind": "string", "role": "endpoint", "required": True}
        host = {"name": "host", "kind": "string", "role": "host", "required": True}
        port = {"name": "port", "kind": "integer", "role": "port", "required": True}
        port_set = {"name": "ports", "kind": "string", "role": "port_set", "required": True}
        metadata = {"name": "trace_id", "kind": "string", "role": "none", "required": True}
        for params in ([endpoint], [host], [host, port], [host, port_set]):
            for variant in (params, list(reversed(params)), params + [metadata]):
                with self.subTest(roles=tuple(p["role"] for p in variant)):
                    packet = {"tools": [{"tool_id": "shape_only",
                                          "parameters": variant}]}
                    original = encoded(packet)
                    self.assert_denied(review_schema(packet), "REVIEW_ONLY")
                    self.assert_denied(review_bytes(original), "REVIEW_ONLY")
                    self.assertEqual(encoded(packet), original)

    def test_destination_role_grammar_rejects_ambiguous_selectors_atomically(self):
        def field(name, kind, role):
            return {"name": name, "kind": kind, "role": role, "required": True}

        host = field("host", "string", "host")
        port = field("port", "integer", "port")
        ports = field("ports", "string", "port_set")
        endpoint = field("url", "string", "endpoint")
        metadata = field("note", "boolean", "none")
        malformed = (
            [port],
            [ports],
            [metadata],
            [host, field("alternate_host", "string", "host")],
            [endpoint, field("backup_url", "string", "endpoint")],
            [host, endpoint],
            [endpoint, port],
            [endpoint, ports],
            [host, port, ports],
            [host, port, field("backup_port", "integer", "port")],
            [host, ports, field("fallback_ports", "string", "port_set")],
            [host, endpoint, port],
            [port, ports],
        )
        valid = fixture()["tools"][0]
        for bad in malformed:
            with self.subTest(roles=tuple(p["role"] for p in bad)):
                forged = {"tool_id": "ambiguous", "parameters": bad}
                for tools in ([forged], [valid, forged], [forged, valid]):
                    packet = {"tools": tools}
                    baseline = encoded(packet)
                    denied = review_schema(packet)
                    self.assert_denied(denied, "HOLD")
                    self.assertEqual(denied["claimed_tool_count"], 0)
                    self.assertEqual(denied["claimed_parameter_count"], 0)
                    self.assert_denied(review_bytes(baseline), "HOLD")
                    self.assertEqual(encoded(packet), baseline)

    def test_cli_bad_role_composition_refuses_to_echo_claims(self):
        bad_shapes = (
            [{"name": "port", "kind": "integer", "role": "port", "required": True}],
            [{"name": "url", "kind": "string", "role": "endpoint", "required": True},
             {"name": "ports", "kind": "string", "role": "port_set", "required": True}],
            [{"name": "host", "kind": "string", "role": "host", "required": True},
             {"name": "url", "kind": "string", "role": "endpoint", "required": True}],
        )
        for parameters in bad_shapes:
            with self.subTest(roles=tuple(p["role"] for p in parameters)):
                body = encoded({"tools": [
                    {"tool_id": "synthetic_customer_secret_marker",
                     "parameters": parameters}]})
                process = subprocess.run(
                    [sys.executable, str(SCRIPT), "--stdin-json"],
                    input=body, capture_output=True, timeout=6)
                self.assertEqual(process.returncode, 2)
                self.assertFalse(process.stderr)
                self.assertNotIn(b"synthetic_customer_secret_marker", process.stdout)
                self.assertEqual(process.stdout.count(b"\n"), 1)
                self.assert_denied(json.loads(process.stdout), "HOLD")

    def test_exhaustive_destination_role_grammar_up_to_four_parameters(self):
        """Enumerate the entire bounded role vocabulary, not only examples.

        Independent allowlist oracle intentionally avoids the reviewer's
        branch structure. NONE can add metadata but cannot create authority.
        The 5^1+5^2+5^3+5^4 = 780 packets stay wholly synthetic and offline.
        """
        role_kinds = {
            "endpoint": "string", "host": "string", "port": "integer",
            "port_set": "string", "none": "boolean",
        }
        valid_destinations = {
            ("endpoint",), ("host",), ("host", "port"),
            ("host", "port_set"),
        }
        allowed_sorted = {tuple(sorted(value)) for value in valid_destinations}
        reviewed = held = 0
        for size in (1, 2, 3, 4):
            for roles in itertools.product(role_kinds, repeat=size):
                params = [
                    {"name": "p_" + str(i), "kind": role_kinds[role],
                     "role": role, "required": role != "none"}
                    for i, role in enumerate(roles)
                ]
                packet = {"tools": [
                    {"tool_id": "synthetic_role_matrix",
                     "parameters": params}]}
                destinations = tuple(sorted(
                    role for role in roles if role != "none"
                ))
                expected = (
                    "REVIEW_ONLY"
                    if destinations in allowed_sorted else "HOLD"
                )
                result = review_schema(packet)
                self.assert_denied(result, expected)
                if expected == "REVIEW_ONLY":
                    reviewed += 1
                    self.assertEqual(result["claimed_tool_count"], 1)
                    self.assertEqual(result["claimed_parameter_count"], size)
                else:
                    held += 1
                    self.assertEqual(result["claimed_tool_count"], 0)
                    self.assertEqual(result["claimed_parameter_count"], 0)
        self.assertEqual(reviewed + held, 780)
        self.assertGreater(reviewed, 0)
        self.assertGreater(held, 0)

    def test_destination_must_be_explicitly_required_and_bool_exact(self):
        for field_name in ("required",):
            for forged in (False, None, 0, 1, "true", [], {}, 1.0):
                with self.subTest(forged=str(forged)):
                    packet = fixture()
                    packet["tools"][1]["parameters"][0][field_name] = forged
                    self.assert_denied(review_schema(packet), "HOLD")
                    self.assert_denied(review_bytes(encoded(packet)), "HOLD")
            missing = fixture()
            del missing["tools"][1]["parameters"][0][field_name]
            self.assert_denied(review_schema(missing), "HOLD")
            self.assert_denied(review_bytes(encoded(missing)), "HOLD")

        allowed = fixture()
        allowed["tools"][0]["parameters"].append(
            {"name": "trace_id", "kind": "string", "role": "none",
             "required": False})
        self.assert_denied(review_schema(allowed), "REVIEW_ONLY")
        self.assert_denied(review_bytes(encoded(allowed)), "REVIEW_ONLY")
        allowed["tools"][0]["parameters"][-1]["required"] = 0
        self.assert_denied(review_schema(allowed), "HOLD")

    def test_required_metadata_cannot_be_omitted_or_renamed(self):
        for mutation in ("missing", "renamed", "optional_port", "optional_set"):
            with self.subTest(mutation=mutation):
                packet = fixture()
                tls = packet["tools"][1]["parameters"]
                if mutation == "missing":
                    del tls[0]["required"]
                elif mutation == "renamed":
                    tls[0]["is_required"] = tls[0].pop("required")
                elif mutation == "optional_port":
                    tls[1]["required"] = False
                else:
                    packet["tools"][2]["parameters"][1]["required"] = False
                self.assert_denied(review_schema(packet), "HOLD")
                self.assert_denied(review_bytes(encoded(packet)), "HOLD")

    def test_reject_untrusted_structure(self):
        for change in (
            lambda v: v.update(approved=True),
            lambda v: v["tools"][0].update(approved=True),
            lambda v: v["tools"][0]["parameters"][0].update(approved=True),
            lambda v: v["tools"].append(v["tools"][0]),
            lambda v: v["tools"][0]["parameters"].append(v["tools"][0]["parameters"][0]),
            lambda v: v["tools"][0]["parameters"][0].update(role="authorized"),
            lambda v: v["tools"][0]["parameters"][0].update(name="Url"),
            lambda v: v["tools"][0]["parameters"][0].update(kind=True),
            lambda v: v["tools"][0].update(tool_id="HTTP-Baseline"),
            lambda v: v["tools"][0].update(parameters=[]),
            lambda v: v["tools"][0]["parameters"][0].update(role="none"),
        ):
            with self.subTest(case=str(change)):
                sample = fixture()
                change(sample)
                self.assert_denied(review_schema(sample), "HOLD")

    def test_real_lab_worker_id_hyphens_are_allowed_but_parameter_hyphens_denied(self):
        sample = fixture()
        self.assert_denied(review_schema(sample), "REVIEW_ONLY")
        sample["tools"][0]["parameters"][0]["name"] = "bad-parameter"
        self.assert_denied(review_schema(sample), "HOLD")

    def test_current_paramkind_enum_is_closed_world(self):
        for kind in ("array", "object", "map", "STRING", "float"):
            with self.subTest(kind=kind):
                sample = fixture()
                sample["tools"][1]["parameters"][1]["kind"] = kind
                self.assert_denied(review_schema(sample), "HOLD")

    def test_non_destination_metadata_does_not_supply_authority(self):
        sample = fixture()
        sample["tools"][0]["parameters"].append(
            {"name": "max_retries", "kind": "integer", "role": "none", "required": True})
        self.assert_denied(review_schema(sample), "REVIEW_ONLY")
        sample["tools"][0]["parameters"][0]["role"] = "none"
        self.assert_denied(review_schema(sample), "HOLD")

    def test_duplicate_decoded_keys_rejected(self):
        for raw in (
            b'{"tools":[],"tools":[]}',
            b'{"tools":[{"tool_id":"a","tool_id":"b","parameters":[]}]}',
            b'{"tools":[],"\\u0074ools":[]}',
            b'{"tools":NaN}',
            b'{"tools":Infinity}',
            b'{"tools":1e9999}',
            b'{"tools":[] }{}',
            b'\xff',
            b'',
            b' ' * (MAX_INPUT_BYTES + 1),
        ):
            with self.subTest(raw=raw[:30]):
                self.assert_denied(review_bytes(raw), "HOLD")

    def test_reject_polymorphic_in_memory_claims(self):
        class Text(str):
            pass
        class Items(list):
            pass
        for value in (Items(fixture()["tools"]),):
            self.assert_denied(review_schema({"tools": value}), "HOLD")
        sample = fixture()
        sample["tools"][0]["tool_id"] = Text("lab-http-baseline")
        self.assert_denied(review_schema(sample), "HOLD")
        sample = fixture()
        sample["tools"][0]["parameters"][0]["role"] = Text("endpoint")
        self.assert_denied(review_schema(sample), "HOLD")

    def test_polymorphic_field_name_aliases_hold_at_every_level(self):
        # Type identity applies to dictionary keys, not just values. A str
        # subclass compares equal to an official key, but is NOT a canonical
        # JSON parser-created field name at this direct-Python API boundary.
        class Alias(str):
            pass

        sample = fixture()
        for depth in ("packet", "tool", "parameter"):
            with self.subTest(depth=depth):
                payload = fixture()
                if depth == "packet":
                    payload = {Alias("tools"): payload["tools"]}
                elif depth == "tool":
                    tool = payload["tools"][0]
                    tool[Alias("tool_id")] = tool.pop("tool_id")
                else:
                    param = payload["tools"][1]["parameters"][0]
                    param[Alias("name")] = param.pop("name")
                self.assert_denied(review_schema(payload), "HOLD")
        # Canonical built-in strings still work; this additional API guard
        # cannot accidentally deny real JSON decoded by the strict reader.
        self.assert_denied(review_schema(sample), "REVIEW_ONLY")
        self.assert_denied(review_bytes(encoded(sample)), "REVIEW_ONLY")

    def test_poisoned_key_hash_never_invoked_during_field_validation(self):
        # If a future refactor calls set(mapping) before checking exact key
        # identity, an attacker-supplied string subclass gets a code path.
        class UntrustedKey(str):
            armed = False

            def __hash__(self):
                if self.armed:
                    raise AssertionError("untrusted key rehashed")
                return str.__hash__(self)

            def __eq__(self, other):
                if self.armed:
                    raise AssertionError("untrusted key compared")
                return str.__eq__(self, other)

        for depth in ("packet", "tool", "parameter", "receipt"):
            with self.subTest(depth=depth):
                name = {"packet": "tools", "tool": "parameters",
                        "parameter": "required", "receipt": "status"}[depth]
                key = UntrustedKey(name)
                sample = fixture()
                if depth == "packet":
                    container = sample
                elif depth == "tool":
                    container = sample["tools"][0]
                elif depth == "parameter":
                    container = sample["tools"][0]["parameters"][0]
                else:
                    container = review_schema(sample)
                value = container.pop(name)
                container[key] = value  # insertion precedes arming
                key.armed = True
                if depth == "receipt":
                    self.assertIsNone(_seal_receipt(container))
                else:
                    self.assert_denied(review_schema(sample), "HOLD")

    def test_max_structural_cardinality(self):
        data = fixture()["tools"][0]
        many = {"tools": [{"tool_id": "tool_" + str(i), "parameters":
                 [{"name": "host", "kind": "string", "role": "host", "required": True}]}
                for i in range(8)]}
        self.assert_denied(review_schema(many), "REVIEW_ONLY")
        many["tools"].append(data)
        self.assert_denied(review_schema(many), "HOLD")
        many = {"tools": [{"tool_id": "one", "parameters":
                 [{"name": "host", "kind": "string", "role": "host", "required": True}]
                 + [{"name": "p_" + str(i), "kind": "string", "role": "none", "required": True}
                    for i in range(15)]}]}
        self.assert_denied(review_schema(many), "REVIEW_ONLY")
        many["tools"][0]["parameters"].append(data["parameters"][0])
        self.assert_denied(review_schema(many), "HOLD")

    def test_cli_unclosed_pipe_forces_finite_atomic_hold(self):
        for payload in (b'{"tools":[', encoded(fixture())):
            with self.subTest(length=len(payload)):
                proc = subprocess.Popen(
                    [sys.executable, str(SCRIPT), "--stdin-json"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)
                try:
                    proc.stdin.write(payload)
                    proc.stdin.flush()  # deliberately do NOT send EOF
                    self.assertEqual(proc.wait(timeout=6), 2)
                    stdout = proc.stdout.read()
                    stderr = proc.stderr.read()
                    self.assertFalse(stderr)
                    self.assertEqual(stdout.count(b"\n"), 1)
                    self.assert_denied(json.loads(stdout), "HOLD")
                    self.assertNotIn(payload, stdout)
                finally:
                    proc.stdin.close()
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait(timeout=3)
                    proc.stdout.close()
                    proc.stderr.close()

    def test_ready_fifo_drained_by_peer_retries_eagain_without_blocking(self):
        # Fully synthetic race: select reports readable, a peer drains the
        # FIFO, read gets EAGAIN, then another writer supplies EOF.
        with (
            mock.patch("review_scope_destination_schema_1093_offline.os.fstat",
                       return_value=types.SimpleNamespace(st_mode=stat.S_IFIFO)),
            mock.patch("review_scope_destination_schema_1093_offline.os.get_blocking",
                       return_value=True),
            mock.patch("review_scope_destination_schema_1093_offline.os.set_blocking")
                as set_blocking,
            mock.patch("review_scope_destination_schema_1093_offline.select.select",
                       return_value=([0], [], [])),
            mock.patch("review_scope_destination_schema_1093_offline.os.read",
                       side_effect=[BlockingIOError(), b'{"tools":[]}', b""])
        ):
            self.assertEqual(_read_private_pipe(), b'{"tools":[]}')
            self.assertEqual(set_blocking.call_args_list,
                             [mock.call(0, False), mock.call(0, True)])

    def test_cli_stdin_pipe_restores_parent_blocking_state(self):
        # A subprocess duplicates fd0 but shares its POSIX open-file-description.
        # Both accepted EOF and HOLD must leave the parent's mode unchanged.
        for initially_blocking in (False, True):
            for valid in (False, True):
                with self.subTest(initially_blocking=initially_blocking, valid=valid):
                    read_fd, write_fd = os.pipe()
                    try:
                        os.set_blocking(read_fd, initially_blocking)
                        if valid:
                            os.write(write_fd, encoded(fixture()))
                        os.close(write_fd)
                        write_fd = None
                        result = subprocess.run(
                            [sys.executable, str(SCRIPT), "--stdin-json"],
                            stdin=read_fd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=6)
                        self.assertEqual(result.returncode, 3 if valid else 2)
                        self.assertFalse(result.stderr)
                        self.assertIs(os.get_blocking(read_fd), initially_blocking)
                        self.assert_denied(json.loads(result.stdout),
                                           "REVIEW_ONLY" if valid else "HOLD")
                    finally:
                        os.close(read_fd)
                        if write_fd is not None:
                            os.close(write_fd)

    def test_cli_rejects_regular_file_stdin_without_reading_it(self):
        with tempfile.TemporaryFile() as stream:
            stream.write(encoded(fixture()))
            stream.flush()
            stream.seek(0)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--stdin-json"],
                stdin=stream, capture_output=True, timeout=6)
            self.assertEqual(result.returncode, 2)
            self.assert_denied(json.loads(result.stdout), "HOLD")
            self.assertEqual(stream.tell(), 0)
            self.assertFalse(result.stderr)

    def test_receipt_seal_blocks_forged_authority_and_type_confusion(self):
        good = review_schema(fixture())
        self.assert_denied(good, "REVIEW_ONLY")
        self.assertLess(len(_seal_receipt(good)), 512)
        for key, forged in (
            ("authorization_verified", True),
            ("permit_issued", 1),
            ("dispatch_enabled", "false"),
            ("merge_approved", True),
            ("deploy_approved", True),
            ("release_approved", True),
            ("authenticated_registry", True),
            ("claimed_tool_count", True),
            ("claimed_parameter_count", 1.0),
            ("status", "APPROVED"),
        ):
            with self.subTest(key=key):
                changed = dict(good)
                changed[key] = forged
                self.assertIsNone(_seal_receipt(changed))
        changed = dict(good)
        changed["client_secret"] = "never-echo"
        self.assertIsNone(_seal_receipt(changed))
        changed = dict(good)
        del changed["release_approved"]
        self.assertIsNone(_seal_receipt(changed))
        changed = dict(good, status="HOLD")
        self.assertIsNone(_seal_receipt(changed))
        self.assertIsNone(_seal_receipt(b"raw-secret"))

    def test_cli_rejects_regular_file_stdout_without_writing(self):
        with tempfile.TemporaryFile() as output:
            output.write(b"original-data")
            output.flush()
            output.seek(0, os.SEEK_END)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--stdin-json"],
                input=encoded(fixture()), stdout=output,
                stderr=subprocess.PIPE, timeout=6)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(result.stderr)
            output.seek(0)
            self.assertEqual(output.read(), b"original-data")

    def test_cli_rejects_inherited_unix_socket_stdout_without_writing(self):
        # socketpair returns a tuple, not a tuple context manager. Manage
        # both sockets individually on CPython 3.11 and 3.14.
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--stdin-json"],
                input=encoded(fixture()), stdout=child,
                stderr=subprocess.PIPE, timeout=6)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(result.stderr)
            child.close()
            parent.settimeout(1)
            self.assertEqual(parent.recv(512), b"")
        finally:
            child.close()
            parent.close()

    def test_cli_real_pty_receipt_stays_denial_only(self):
        master_fd, slave_fd = pty.openpty()
        try:
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--stdin-json"],
                input=encoded(fixture()), stdout=slave_fd,
                stderr=subprocess.PIPE, timeout=6)
            self.assertEqual(result.returncode, 3)
            self.assertFalse(result.stderr)
            receipt = os.read(master_fd, 512)
            self.assertEqual(receipt.count(b"\n"), 1)
            self.assertLess(len(receipt), 512)
            self.assert_denied(json.loads(receipt), "REVIEW_ONLY")
        finally:
            os.close(slave_fd)
            os.close(master_fd)

    def test_cli_broken_stdout_pipe_no_traceback(self):
        read_fd, write_fd = os.pipe()
        try:
            os.close(read_fd)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--stdin-json"],
                input=encoded(fixture()), stdout=write_fd,
                stderr=subprocess.PIPE, timeout=6)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(result.stderr)
        finally:
            os.close(write_fd)

    def test_cli_stdout_device_denies_without_receipt(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--stdin-json"],
            input=encoded(fixture()), stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, timeout=6)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(result.stderr)

    def test_cli_full_stdout_pipe_cannot_hang_or_leak_fd_blocking(self):
        for initially_blocking in (False, True):
            with self.subTest(initially_blocking=initially_blocking):
                read_fd, write_fd = os.pipe()
                try:
                    os.set_blocking(write_fd, False)
                    while True:
                        try:
                            os.write(write_fd, b"x" * 1024)
                        except BlockingIOError:
                            break
                    os.set_blocking(write_fd, initially_blocking)
                    result = subprocess.run(
                        [sys.executable, str(SCRIPT), "--stdin-json"],
                        input=encoded(fixture()), stdout=write_fd,
                        stderr=subprocess.PIPE, timeout=6)
                    self.assertEqual(result.returncode, 2)
                    self.assertFalse(result.stderr)
                    self.assertIs(os.get_blocking(write_fd), initially_blocking)
                finally:
                    os.close(write_fd)
                    os.close(read_fd)

    def test_cli_real_process_never_exits_success_and_never_echoes_claims(self):
        sample = fixture()
        sample["tools"][0]["tool_id"] = "private_customer_token"
        for raw, argv, status, code in (
            (encoded(sample), ["--stdin-json"], "REVIEW_ONLY", 3),
            (b'{"tools":"SECRET-NEVER-ECHO"}', ["--stdin-json"], "HOLD", 2),
            (encoded(sample), ["--approved"], "HOLD", 2),
            (encoded(sample), ["--stdin-json", "--release"], "HOLD", 2),
        ):
            with self.subTest(status=status):
                result = subprocess.run([sys.executable, str(SCRIPT), *argv],
                                        input=raw, capture_output=True, timeout=6)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertFalse(result.stderr)
                self.assertEqual(result.stdout.count(b"\n"), 1)
                self.assertLess(len(result.stdout), 512)
                self.assertNotIn(b"private_customer_token", result.stdout)
                self.assertNotIn(b"SECRET-NEVER-ECHO", result.stdout)
                self.assert_denied(json.loads(result.stdout), status)


if __name__ == "__main__":
    unittest.main()
