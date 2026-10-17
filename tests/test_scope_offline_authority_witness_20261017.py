"""Regression controls for the wholly offline, non-authorizing witness (#1565)."""
from __future__ import annotations

import json
import io
import os
import importlib.util
import marshal
import struct
import shutil
import tempfile
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone, timedelta
import re
import socket
import signal
import time
import threading
import subprocess
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import scope_offline_authority_witness_20261017 as witness  # noqa: E402

FLAGS = tuple(witness.FALSE_AUTHORITY)


class OfflineAuthorityWitnessTests(unittest.TestCase):
    def assert_no_authority(self, receipt):
        self.assertEqual(receipt["schema"], witness.SCHEMA)
        for key in FLAGS:
            self.assertIs(receipt[key], False, key)
        self.assertNotIn("target", receipt)
        self.assertNotIn("authorization", receipt)
        self.assertNotIn("token", receipt)

    def test_untrusted_authority_metadata_cannot_widen_any_receipt(self):
        forged = {key: True for key in witness.FALSE_AUTHORITY}
        forged["fictional_release_proof"] = True
        with patch.object(witness, "FALSE_AUTHORITY", forged):
            review = witness.evaluate()
            hold = witness._receipt("HOLD", "artificial_test")
        self.assertEqual(review["status"], "REVIEW_ONLY")
        self.assertEqual(hold["status"], "HOLD")
        for result in (review, hold):
            for key in FLAGS:
                self.assertIs(result[key], False, key)
            self.assertNotIn("fictional_release_proof", result)

    def test_authority_flag_constants_are_immutable(self):
        with self.assertRaises(TypeError):
            witness.FALSE_AUTHORITY["release_allowed"] = True
        self.assertIs(witness.FALSE_AUTHORITY["release_allowed"], False)

    def _isolated_source_child(self, corrupt_name, payload, *, prepend=False):
        # Each source-integrity mutation executes in a fresh *fictional* temp
        # checkout so no shared or original working file is ever changed.
        with tempfile.TemporaryDirectory(prefix="lightup-source-witness-") as tmp:
            base = Path(tmp)
            scripts = base / "scripts"
            source = base / "src" / "lightup"
            scripts.mkdir(parents=True)
            source.mkdir(parents=True)
            script = scripts / "scope_offline_authority_witness_20261017.py"
            shutil.copyfile(ROOT / "scripts" / script.name, script)
            for name in ("__init__.py", "models.py", "scope.py"):
                shutil.copyfile(ROOT / "src" / "lightup" / name, source / name)
            tampered = source / corrupt_name
            previous = tampered.read_text(encoding="utf-8")
            tampered.write_text(payload + previous if prepend else previous + payload, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(script), "--offline-lab-only"],
                capture_output=True, text=True, timeout=12, check=False,
            )

    def test_modified_scope_module_is_rejected_before_import_side_effect(self):
        # The marker may never be created: hashing must happen BEFORE Python
        # executes the modified scope module's top-level body.
        with tempfile.TemporaryDirectory(prefix="lightup-never-created-") as tmp:
            marker = Path(tmp) / "should-not-exist"
            injected = f"from pathlib import Path\nPath({str(marker)!r}).write_text('imported', encoding='utf8')\n"
            done = self._isolated_source_child("scope.py", injected, prepend=True)
            self.assertFalse(marker.exists(), "tampered source executed before verification")
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertEqual(done.stderr, "")
        parsed = json.loads(done.stdout)
        self.assertEqual(parsed["status"], "HOLD")
        self.assertEqual(parsed["reason"], "offline_witness_source_drift")
        self.assert_no_authority(parsed)

    def test_modified_models_module_is_rejected_before_import(self):
        done = self._isolated_source_child("models.py", "\n# fictional extra model revision\n")
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertEqual(done.stderr, "")
        parsed = json.loads(done.stdout)
        self.assertEqual(parsed["status"], "HOLD")
        self.assertEqual(parsed["reason"], "offline_witness_source_drift")
        self.assert_no_authority(parsed)

    def test_modified_package_initializer_never_executes_side_effect(self):
        with tempfile.TemporaryDirectory(prefix="lightup-init-marker-") as tmp:
            marker = Path(tmp) / "imported-marker"
            injected = (
                "\nfrom pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('imported',encoding='utf8')\n"
            )
            done = self._isolated_source_child("__init__.py", injected)
            self.assertFalse(marker.exists(), "modified package __init__ executed")
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertEqual(done.stderr, "")
        result = json.loads(done.stdout)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "offline_witness_source_drift")
        self.assert_no_authority(result)

    def test_symlink_policy_source_is_rejected_before_import(self):
        with tempfile.TemporaryDirectory(prefix="lightup-symlink-") as tmp:
            base = Path(tmp)
            scripts = base / "scripts"
            source = base / "src" / "lightup"
            scripts.mkdir(parents=True)
            source.mkdir(parents=True)
            script = scripts / "scope_offline_authority_witness_20261017.py"
            shutil.copyfile(ROOT / "scripts" / script.name, script)
            for name in ("__init__.py", "models.py"):
                shutil.copyfile(ROOT / "src" / "lightup" / name, source / name)
            alternate = base / "fictional-scope-copy.py"
            shutil.copyfile(ROOT / "src" / "lightup" / "scope.py", alternate)
            (source / "scope.py").symlink_to(alternate)
            done = subprocess.run(
                [sys.executable, str(script), "--offline-lab-only"],
                capture_output=True, text=True, timeout=12, check=False,
            )
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertEqual(done.stderr, "")
        result = json.loads(done.stdout)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "offline_witness_source_drift")
        self.assert_no_authority(result)

    def test_unchanged_source_cli_attests_both_real_sources_without_leaking_paths(self):
        expected = {
            "src/lightup/__init__.py": "24b02c39a8fe5041da81517a9aace8ba27161c5e020611d222755a6a6f429b01",
            "src/lightup/models.py": "f84779b55f193c2d0a143418cf569c3539ee2bdb92e76a542ffda39643d3b541",
            "src/lightup/scope.py": "1bf081d0b85490466fbb4ad95b2d12917882ed51d05627139bdd5abf110018c0",
        }
        result = witness.evaluate()
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertEqual(result["source_sha256"], expected)
        self.assert_no_authority(result)
        self.assertNotIn(str(ROOT), json.dumps(result))

    def test_preloaded_noncanonical_policy_module_cannot_look_like_current_checkout(self):
        # Even if source files match SHA, Python can satisfy imports from
        # sys.modules. An already-cached module outside the pinned checkout
        # must return HOLD before the real evaluator is used.
        source = str(ROOT / "src")
        script = str(ROOT / "scripts" / "scope_offline_authority_witness_20261017.py")
        snippet = (
            f"import sys,runpy;sys.path.insert(0,{source!r});"
            "import lightup.scope as cached;"
            "cached.__file__='/fictional/cached/scope.py';"
            f"sys.argv=[{script!r},'--offline-lab-only'];"
            f"runpy.run_path({script!r},run_name='__main__')"
        )
        done = subprocess.run([sys.executable,"-c",snippet],capture_output=True,text=True,timeout=12,check=False)
        self.assertEqual(done.returncode,2,done.stderr)
        self.assertEqual(done.stderr,"")
        body = json.loads(done.stdout)
        self.assertEqual(body["status"],"HOLD")
        self.assertEqual(body["reason"],"offline_witness_source_drift")
        self.assert_no_authority(body)

    def test_changed_source_after_first_attestation_must_hold_before_positive_receipt(self):
        # Race simulation: the entry hash matches, but just before an
        # affirmative receipt the second source check detects a change.
        first = witness._trusted_source_hashes
        calls = []
        def simulate_source_update():
            calls.append(True)
            return first() if len(calls) == 1 else None
        with patch.object(witness, "_trusted_source_hashes", simulate_source_update):
            result = witness.evaluate()
        self.assertGreaterEqual(len(calls), 2)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "offline_witness_source_drift")
        self.assertNotIn("source_sha256", result)
        self.assert_no_authority(result)

    def test_loaded_module_identity_change_during_decide_is_not_approved(self):
        # A source module's metadata might change between initial admission
        # and final receipt; the witness cannot accept stale import evidence.
        source_mod = sys.modules[witness.ScopePolicy.__module__]
        saved = source_mod.__file__
        decide = witness.ScopePolicy.decide
        def alter_origin(self, target):
            answer = decide(self, target)
            source_mod.__file__ = "/fictional/foreign/scope.py"
            return answer
        try:
            with patch.object(witness.ScopePolicy, "decide", alter_origin):
                result = witness.evaluate()
        finally:
            source_mod.__file__ = saved
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "offline_witness_source_drift")
        self.assert_no_authority(result)
        self.assertEqual(witness.evaluate()["status"], "REVIEW_ONLY")

    def test_forged_bytecode_cache_is_rejected_before_import(self):
        # A timestamp-matching .pyc can have different executable bytes
        # while all pinned .py source SHA-256 digests remain unchanged.
        with tempfile.TemporaryDirectory(prefix="lightup-bytecode-test-") as tmp:
            root = Path(tmp)
            pkg = root / "src" / "lightup"
            scripts = root / "scripts"
            scripts.mkdir()
            pkg.mkdir(parents=True)
            script = scripts / "scope_offline_authority_witness_20261017.py"
            shutil.copyfile(ROOT / "scripts" / script.name, script)
            for filename in ("__init__.py", "models.py", "scope.py"):
                shutil.copyfile(ROOT / "src" / "lightup" / filename, pkg / filename)
            scope_source = pkg / "scope.py"
            marker = root / "evil-pyc-imported"
            fake_contents = (
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
                + scope_source.read_text(encoding="utf-8")
            )
            code = compile(fake_contents, str(scope_source), "exec")
            current = scope_source.stat()
            cache = Path(importlib.util.cache_from_source(str(scope_source)))
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_bytes(
                importlib.util.MAGIC_NUMBER
                + struct.pack("<III", 0, int(current.st_mtime), current.st_size)
                + marshal.dumps(code)
            )
            done = subprocess.run(
                [sys.executable, str(script), "--offline-lab-only"],
                capture_output=True, text=True, timeout=12, check=False,
            )
            self.assertFalse(marker.exists(), "a forged .pyc executed before source admission")
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertEqual(done.stderr, "")
        result = json.loads(done.stdout)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "offline_witness_source_drift")
        self.assert_no_authority(result)

    def test_canonical_matrix_is_review_only_not_execution_permission(self):
        result = witness.evaluate()
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertEqual(result["checked"], 17)
        self.assertRegex(result["synthetic_matrix_sha256"], r"^[0-9a-f]{64}$")
        self.assert_no_authority(result)

    def test_receipt_digest_is_deterministic(self):
        one = witness.evaluate()
        two = witness.evaluate()
        self.assertEqual(one, two)
        self.assertEqual(one["status"], "REVIEW_ONLY")

    def test_no_target_host_or_synthetic_consent_text_is_exposed(self):
        rendered = json.dumps(witness.evaluate(), sort_keys=True)
        for text in ("127.0.0.1", "8.8.8.8", "fixture.example.test", "SYNTHETIC-NOT-CONSENT"):
            self.assertNotIn(text, rendered)

    def test_policy_drift_to_allow_denied_case_fails_closed(self):
        def allow_all(self, target):
            return witness.ScopeDecision(True, "127.0.0.1", witness.ScopeReason.LOOPBACK)
        with patch.object(witness.ScopePolicy, "decide", allow_all):
            result = witness.evaluate()
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "scope_policy_contract_drift")
        self.assert_no_authority(result)

    def test_reason_drift_fails_closed(self):
        original = witness.ScopePolicy.decide
        def different_reason(self, target):
            found = original(self, target)
            return witness.ScopeDecision(found.allowed, found.normalized_host, witness.ScopeReason.OUT_OF_SCOPE)
        with patch.object(witness.ScopePolicy, "decide", different_reason):
            result = witness.evaluate()
        self.assertEqual(result["status"], "HOLD")
        self.assert_no_authority(result)

    def test_host_normalization_drift_fails_closed(self):
        original = witness.ScopePolicy.decide
        def different_host(self, target):
            found = original(self, target)
            return witness.ScopeDecision(found.allowed, "unexpected.example.test", found.reason)
        with patch.object(witness.ScopePolicy, "decide", different_host):
            result = witness.evaluate()
        self.assertEqual(result["status"], "HOLD")
        self.assert_no_authority(result)

    def test_non_boolean_allowed_flag_fails_closed(self):
        with patch.object(witness.ScopePolicy, "decide", return_value=witness.ScopeDecision(1, "127.0.0.1", witness.ScopeReason.LOOPBACK)):
            result = witness.evaluate()
        self.assertEqual(result["reason"], "invalid_decision_shape")
        self.assert_no_authority(result)

    def test_evaluator_exception_is_generic_hold_without_leakage(self):
        with patch.object(witness.ScopePolicy, "decide", side_effect=RuntimeError("DONT-LEAK-PRIVATE")):
            result = witness.evaluate()
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "offline_witness_evaluation_failed")
        self.assertNotIn("DONT-LEAK-PRIVATE", json.dumps(result))
        self.assert_no_authority(result)

    def test_duplicate_and_noncanonical_case_identity_fail_closed(self):
        cases = witness.canonical_cases()
        for tampered in (
            (cases[0],) + (cases[0],) + cases[2:],
            (replace(cases[0], case_id="bad-Σ"),) + cases[1:],
            cases[:-1],
        ):
            with self.subTest(tampered=tampered[0].case_id, size=len(tampered)):
                result = witness.evaluate(tampered)
                self.assertEqual(result["status"], "HOLD")
                self.assert_no_authority(result)

    def test_fake_expected_acceptance_fails_closed(self):
        cases = witness.canonical_cases()
        changed = (replace(cases[4], expected_allowed=True),)
        result = witness.evaluate(cases[:4] + changed + cases[5:])
        self.assertEqual(result["status"], "HOLD")
        self.assert_no_authority(result)

    def test_polymorphic_target_value_is_rejected_before_normalization(self):
        calls = []
        class SpoofedValue(str):
            def strip(self, *args, **kwargs):
                calls.append("strip")
                raise AssertionError("untrusted target normalization executed")
        cases = witness.canonical_cases()
        evil = (replace(cases[0], target=witness.Target(SpoofedValue("127.0.0.1"))),) + cases[1:]
        result = witness.evaluate(evil)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "invalid_witness_matrix")
        self.assertEqual(calls, [])
        self.assert_no_authority(result)

    def test_polymorphic_policy_and_authorization_are_rejected_before_decide(self):
        cases = witness.canonical_cases()
        class SpoofedSet(frozenset):
            def __iter__(self):
                raise AssertionError("untrusted policy iteration executed")
        class SpoofedAuthorization(witness.Authorization):
            def is_current(self, now=None):
                raise AssertionError("untrusted authorization evaluated")
        altered_policy = replace(cases[0], policy=witness.ScopePolicy(explicit_hosts=SpoofedSet({"fixture.example.test"})))
        altered_auth = replace(
            cases[6],
            target=witness.Target("fixture.example.test", authorization=SpoofedAuthorization("fake", "not-consent")),
        )
        for changed_index, changed in ((0, altered_policy), (6, altered_auth)):
            with self.subTest(case_index=changed_index):
                scenarios = list(cases)
                scenarios[changed_index] = changed
                result = witness.evaluate(tuple(scenarios))
                self.assertEqual(result["status"], "HOLD")
                self.assertEqual(result["reason"], "invalid_witness_matrix")
                self.assert_no_authority(result)

    def test_time_bound_authorization_and_no_auth_policy_are_distinct_controls(self):
        cases = {case.case_id: case for case in witness.canonical_cases()}
        for identity in ("explicit-host-expired", "explicit-host-not-yet", "explicit-cidr-expired"):
            with self.subTest(case=identity):
                original = cases[identity]
                self.assertFalse(original.expected_allowed)
                self.assertIs(original.expected_reason, witness.ScopeReason.AUTHORIZATION_EXPIRED)
        bypass = cases["explicit-host-no-auth-policy"]
        self.assertTrue(bypass.expected_allowed)
        self.assertIs(bypass.policy.require_authorization_for_public, False)
        self.assertIsNone(bypass.target.authorization)
        self.assertEqual(witness.evaluate()["status"], "REVIEW_ONLY")

    def test_time_bound_alias_or_non_utc_metadata_is_denied_before_policy(self):
        cases = witness.canonical_cases()
        original = cases[11]
        class DeceptiveDatetime(datetime):
            def __lt__(self, other):
                raise AssertionError("untrusted date comparison executed")
        inputs = (
            DeceptiveDatetime(2000, 1, 1, tzinfo=timezone.utc),
            datetime(2000, 1, 1),
            datetime(2000, 1, 1, tzinfo=timezone(timedelta(hours=1))),
            "2000-01-01",
        )
        for bound in inputs:
            with self.subTest(bound_type=type(bound).__name__, bound_tz=str(getattr(bound, "tzinfo", None))):
                auth = witness.Authorization(owner="fictional-reviewer", reference="SYNTHETIC-EXPIRED", valid_until=bound)
                alternate = replace(original, target=witness.Target(original.target.value, authorization=auth))
                result = witness.evaluate(cases[:11] + (alternate,) + cases[12:])
                self.assertEqual(result["status"], "HOLD")
                self.assertEqual(result["reason"], "invalid_witness_matrix")
                self.assert_no_authority(result)

    def test_expiry_policy_bypass_or_reason_mutation_is_detected(self):
        cases = witness.canonical_cases()
        original_decide = witness.ScopePolicy.decide
        def ignore_expiry(self, target):
            decision = original_decide(self, target)
            if decision.reason is witness.ScopeReason.AUTHORIZATION_EXPIRED:
                return witness.ScopeDecision(True, decision.normalized_host, witness.ScopeReason.EXPLICIT_HOST)
            return decision
        with patch.object(witness.ScopePolicy, "decide", ignore_expiry):
            result = witness.evaluate()
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "scope_policy_contract_drift")
        self.assert_no_authority(result)

    def test_pinned_both_fixture_and_observed_digests(self):
        result = witness.evaluate()
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertEqual(result["checked"], 17)
        self.assertEqual(result["synthetic_fixture_sha256"], witness.REFERENCE_FIXTURE_SHA256)
        self.assertEqual(result["synthetic_matrix_sha256"], witness.REFERENCE_BEHAVIOR_SHA256)
        self.assert_no_authority(result)

    def test_semantically_equivalent_but_modified_fixture_holds_before_policy_call(self):
        cases = witness.canonical_cases()
        # Both values still normalize to the same host. An output-only hash
        # would not reveal this input mutation; the fixture pin must catch it.
        new_target = witness.Target("localhost")
        # Construct exactly 17 cases, with the changed case in original slot 1.
        modified = cases[:1] + (replace(cases[1], target=new_target),) + cases[2:]
        with patch.object(witness.ScopePolicy, "decide", side_effect=AssertionError("policy was called")) as decision:
            result = witness.evaluate(modified)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "reference_fixture_drift")
        self.assertNotIn("synthetic_fixture_sha256", result)
        decision.assert_not_called()
        self.assert_no_authority(result)

    def test_corpus_reorder_and_synthetic_consent_provenance_drift_hold_pre_eval(self):
        cases = witness.canonical_cases()
        reordered = cases[1:2] + cases[:1] + cases[2:]
        changed_auth = witness.Authorization("different-fictional-reviewer", "SYNTHETIC-NOT-CONSENT")
        changed = cases[:6] + (
            replace(cases[6], target=witness.Target(cases[6].target.value, authorization=changed_auth)),
        ) + cases[7:]
        for altered in (reordered, changed):
            with self.subTest(case=altered[0].case_id):
                with patch.object(witness.ScopePolicy, "decide", side_effect=AssertionError("called")) as decision:
                    result = witness.evaluate(altered)
                self.assertEqual(result["status"], "HOLD")
                self.assertEqual(result["reason"], "reference_fixture_drift")
                decision.assert_not_called()
                self.assert_no_authority(result)

    def test_behavior_digest_pin_rejects_changed_reference_without_positive_receipt(self):
        with patch.object(witness, "REFERENCE_BEHAVIOR_SHA256", "0" * 64):
            result = witness.evaluate()
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "reference_behavior_drift")
        self.assertNotIn("synthetic_fixture_sha256", result)
        self.assertNotIn("synthetic_matrix_sha256", result)
        self.assert_no_authority(result)

    def test_python_network_file_and_process_attempts_hold_during_witness(self):
        original = witness.ScopePolicy.decide
        def policy_with_io(self, target, which):
            if which == "socket":
                with socket.socket():
                    pass
            elif which == "file":
                Path(__file__).read_text(encoding="utf-8")
            elif which == "process":
                subprocess.run([sys.executable, "-c", "print('fictional')"], check=True)
            return original(self, target)
        for which in ("socket", "file", "process"):
            with self.subTest(kind=which):
                with patch.object(
                    witness.ScopePolicy, "decide",
                    lambda self, target: policy_with_io(self, target, which),
                ):
                    result = witness.evaluate()
                self.assertEqual(result["status"], "HOLD")
                self.assertEqual(result["reason"], "offline_witness_evaluation_failed")
                self.assert_no_authority(result)
                self.assertNotIn("synthetic_matrix_sha256", result)
                # A blocked operation must never poison a subsequent clean review.
                self.assertEqual(witness.evaluate()["status"], "REVIEW_ONLY")

    def test_python_audit_arguments_are_never_reflected_to_receipt(self):
        def policy_with_private_audit(self, target):
            sys.audit("socket.connect", "private-operator-context")
            raise AssertionError("must not reach this point")
        with patch.object(witness.ScopePolicy, "decide", policy_with_private_audit):
            receipt = witness.evaluate()
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["reason"], "offline_witness_evaluation_failed")
        self.assertNotIn("private-operator-context", json.dumps(receipt))
        self.assert_no_authority(receipt)

    def test_evaluator_stdout_and_stderr_attempts_hold_without_private_echo(self):
        for channel in ("stdout", "stderr"):
            with self.subTest(channel=channel):
                def noisy_policy(self, target):
                    if channel == "stdout":
                        sys.stdout.write("PRIVATE-SCOPE-OUTPUT")
                    else:
                        sys.stderr.write("PRIVATE-SCOPE-OUTPUT")
                    raise AssertionError("unexpected continued execution")
                out, err = io.StringIO(), io.StringIO()
                with patch.object(witness.ScopePolicy, "decide", noisy_policy):
                    with redirect_stdout(out), redirect_stderr(err):
                        receipt = witness.evaluate()
                self.assertEqual(receipt["status"], "HOLD")
                self.assertEqual(receipt["reason"], "offline_witness_evaluation_failed")
                self.assertEqual(out.getvalue(), "")
                self.assertEqual(err.getvalue(), "")
                self.assertNotIn("PRIVATE-SCOPE-OUTPUT", json.dumps(receipt))
                self.assert_no_authority(receipt)
                self.assertEqual(witness.evaluate()["status"], "REVIEW_ONLY")

    def test_stalled_scope_decision_has_bounded_wall_clock_and_hold(self):
        # A buggy in-process evaluator must not hang offline review forever.
        if not hasattr(signal, "setitimer") or threading.current_thread() is not threading.main_thread():
            self.skipTest("POSIX main-thread alarm required")
        if signal.getsignal(signal.SIGALRM) != signal.SIG_DFL or any(signal.getitimer(signal.ITIMER_REAL)):
            self.skipTest("external alarm is active")
        def stuck(self, target):
            time.sleep(7)
            raise AssertionError("deadline was not enforced")
        before = time.monotonic()
        with patch.object(witness.ScopePolicy, "decide", stuck):
            result = witness.evaluate()
        elapsed = time.monotonic() - before
        self.assertLess(elapsed, 4.5)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "offline_witness_time_budget_exceeded")
        self.assert_no_authority(result)
        self.assertEqual(witness.evaluate()["status"], "REVIEW_ONLY")

    def test_external_signal_handler_and_alarm_are_never_overwritten(self):
        if not hasattr(signal, "setitimer") or threading.current_thread() is not threading.main_thread():
            self.skipTest("POSIX main-thread alarm required")
        if signal.getsignal(signal.SIGALRM) != signal.SIG_DFL or any(signal.getitimer(signal.ITIMER_REAL)):
            self.skipTest("external alarm is active")
        calls = []
        def external_handler(sig, frame):
            calls.append(sig)
        def forbidden_decide(self, target):
            calls.append("decision")
            raise AssertionError("conflicting alarm must deny before policy call")
        signal.signal(signal.SIGALRM, external_handler)
        try:
            with patch.object(witness.ScopePolicy, "decide", forbidden_decide):
                result = witness.evaluate()
            self.assertEqual(result["status"], "HOLD")
            self.assertEqual(result["reason"], "offline_witness_time_fence_unavailable")
            self.assertEqual(calls, [])
            self.assertIs(signal.getsignal(signal.SIGALRM), external_handler)
        finally:
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
        self.assert_no_authority(result)
        self.assertEqual(witness.evaluate()["status"], "REVIEW_ONLY")

    def test_worker_thread_without_exclusive_alarm_returns_hold(self):
        outputs = []
        def worker():
            outputs.append(witness.evaluate())
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(2)
        self.assertFalse(t.is_alive(), "worker must never wait for an unavailable timer")
        self.assertEqual(len(outputs), 1)
        self.assertEqual(outputs[0]["status"], "HOLD")
        self.assertEqual(outputs[0]["reason"], "offline_witness_time_fence_unavailable")
        self.assert_no_authority(outputs[0])

    def test_preexisting_alarm_timer_is_not_stolen_or_discharged(self):
        if not hasattr(signal, "setitimer") or threading.current_thread() is not threading.main_thread():
            self.skipTest("POSIX main-thread alarm required")
        if signal.getsignal(signal.SIGALRM) != signal.SIG_DFL or any(signal.getitimer(signal.ITIMER_REAL)):
            self.skipTest("external alarm is active")
        # A genuine external timer (without a custom handler) must be detected
        # before the scope policy is invoked. Disarm during cleanup.
        observed = []
        def forbidden(self, target):
            observed.append("executed")
            raise AssertionError("must not execute with someone else's alarm")
        signal.setitimer(signal.ITIMER_REAL, 12)
        try:
            with patch.object(witness.ScopePolicy, "decide", forbidden):
                result = witness.evaluate()
            remainder, repeat = signal.getitimer(signal.ITIMER_REAL)
            self.assertGreater(remainder, 10)
            self.assertEqual(repeat, 0)
            self.assertEqual(observed, [])
            self.assertEqual(result["status"], "HOLD")
            self.assertEqual(result["reason"], "offline_witness_time_fence_unavailable")
            self.assert_no_authority(result)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        self.assertEqual(witness.evaluate()["status"], "REVIEW_ONLY")

    def test_nested_witness_does_not_rearm_or_gain_positive_verdict(self):
        original = witness.ScopePolicy.decide
        nested_receipts = []
        def nested_decide(self, target):
            nested_receipts.append(witness.evaluate())
            return original(self, target)
        with patch.object(witness.ScopePolicy, "decide", nested_decide):
            outer = witness.evaluate()
        self.assertEqual(outer["status"], "REVIEW_ONLY")
        self.assertEqual(len(nested_receipts), 17)
        for result in nested_receipts:
            self.assertEqual(result["status"], "HOLD")
            self.assertEqual(result["reason"], "offline_witness_time_fence_unavailable")
            self.assert_no_authority(result)

    def test_scope_crash_restores_alarm_and_subsequent_review_works(self):
        if not hasattr(signal, "setitimer") or threading.current_thread() is not threading.main_thread():
            self.skipTest("POSIX main-thread alarm required")
        if signal.getsignal(signal.SIGALRM) != signal.SIG_DFL or any(signal.getitimer(signal.ITIMER_REAL)):
            self.skipTest("external alarm is active")
        before_handler = signal.getsignal(signal.SIGALRM)
        before_timer = signal.getitimer(signal.ITIMER_REAL)
        with patch.object(witness.ScopePolicy, "decide", side_effect=ValueError("private failure")):
            result = witness.evaluate()
        self.assertEqual(result["status"], "HOLD")
        self.assert_no_authority(result)
        self.assertEqual(signal.getsignal(signal.SIGALRM), before_handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), before_timer)
        self.assertEqual(witness.evaluate()["status"], "REVIEW_ONLY")

    def test_clean_evaluation_does_not_keep_or_change_global_alarm(self):
        if not hasattr(signal, "setitimer") or threading.current_thread() is not threading.main_thread():
            self.skipTest("POSIX main-thread alarm required")
        if signal.getsignal(signal.SIGALRM) != signal.SIG_DFL or any(signal.getitimer(signal.ITIMER_REAL)):
            self.skipTest("external alarm is active")
        old_handler = signal.getsignal(signal.SIGALRM)
        old_timer = signal.getitimer(signal.ITIMER_REAL)
        self.assertEqual(witness.evaluate()["status"], "REVIEW_ONLY")
        self.assertEqual(signal.getsignal(signal.SIGALRM), old_handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), old_timer)

    def test_policy_cannot_mutate_target_after_returning_matching_decision(self):
        original = witness.ScopePolicy.decide
        def tampering_policy(self, target):
            result = original(self, target)
            object.__setattr__(target, "value", "changed.fixture.example.test")
            return result
        with patch.object(witness.ScopePolicy, "decide", tampering_policy):
            result = witness.evaluate()
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "offline_witness_fixture_mutated")
        self.assert_no_authority(result)
        self.assertEqual(witness.evaluate()["status"], "REVIEW_ONLY")

    def test_mutated_fictional_authorization_provenance_must_hold(self):
        original = witness.ScopePolicy.decide
        def tampering_policy(self, target):
            result = original(self, target)
            if target.authorization is not None:
                object.__setattr__(target.authorization, "reference", "SYNTHETIC-ALTERED")
            return result
        with patch.object(witness.ScopePolicy, "decide", tampering_policy):
            result = witness.evaluate()
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "offline_witness_fixture_mutated")
        self.assert_no_authority(result)

    def test_mutating_future_fixture_stops_before_next_policy_call(self):
        scenarios = witness.canonical_cases()
        original = witness.ScopePolicy.decide
        calls = []
        def tampering_policy(self, target):
            calls.append(target.value)
            result = original(self, target)
            if len(calls) == 1:
                object.__setattr__(scenarios[-1], "expected_host", "altered.example.test")
            return result
        with patch.object(witness.ScopePolicy, "decide", tampering_policy):
            result = witness.evaluate(scenarios)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "offline_witness_fixture_mutated")
        self.assertEqual(len(calls), 1)
        self.assert_no_authority(result)

    def test_policy_object_state_mutation_after_matching_decision_holds(self):
        original = witness.ScopePolicy.decide
        def tampering_policy(self, target):
            result = original(self, target)
            object.__setattr__(self, "allow_private_lab", False)
            return result
        with patch.object(witness.ScopePolicy, "decide", tampering_policy):
            result = witness.evaluate()
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "offline_witness_fixture_mutated")
        self.assert_no_authority(result)

    def test_unexpected_target_attribute_during_policy_is_fixture_mutation(self):
        original = witness.ScopePolicy.decide
        def inject(self, target):
            result = original(self, target)
            object.__setattr__(target, "fictional_hidden_permit", True)
            return result
        with patch.object(witness.ScopePolicy, "decide", inject):
            result = witness.evaluate()
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "offline_witness_fixture_mutated")
        self.assert_no_authority(result)

    def test_unexpected_fictional_authorization_attribute_fails_closed(self):
        original = witness.ScopePolicy.decide
        def inject(self, target):
            result = original(self, target)
            if target.authorization is not None:
                object.__setattr__(target.authorization, "fake_provenance", "not-approved")
            return result
        with patch.object(witness.ScopePolicy, "decide", inject):
            result = witness.evaluate()
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "offline_witness_fixture_mutated")
        self.assert_no_authority(result)

    def test_unexpected_policy_and_case_attributes_are_rejected(self):
        cases = witness.canonical_cases()
        original = witness.ScopePolicy.decide
        def inject(self, target):
            result = original(self, target)
            object.__setattr__(self, "fictional_external_scope", True)
            object.__setattr__(cases[-1], "fictional_exception", True)
            return result
        with patch.object(witness.ScopePolicy, "decide", inject):
            result = witness.evaluate(cases)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "offline_witness_fixture_mutated")
        self.assert_no_authority(result)

    def test_unexpected_decision_attribute_is_invalid_shape(self):
        original = witness.ScopePolicy.decide
        def inject(self, target):
            result = original(self, target)
            object.__setattr__(result, "fake_dispatch_allowed", True)
            return result
        with patch.object(witness.ScopePolicy, "decide", inject):
            result = witness.evaluate()
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "invalid_decision_shape")
        self.assert_no_authority(result)

    def test_os_environment_side_effect_attempt_must_hold_without_leak(self):
        original = witness.ScopePolicy.decide
        key = "LIGHTUP_SCOPE_1565_SYNTHETIC_AUDIT_TEST"
        def env_policy(self, target):
            result = original(self, target)
            os.putenv(key, "SYNTHETIC-NOT-CONSENT")
            return result
        try:
            with patch.object(witness.ScopePolicy, "decide", env_policy):
                result = witness.evaluate()
        finally:
            # Contain the deliberate RED test in the disposable process.
            os.unsetenv(key)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "offline_witness_evaluation_failed")
        self.assertNotIn(key, json.dumps(result))
        self.assert_no_authority(result)

    def test_chdir_and_copy_audit_attempts_must_hold(self):
        original = witness.ScopePolicy.decide
        for name in ("os.chdir", "shutil.copyfile"):
            with self.subTest(name=name):
                def mutated_policy(self, target):
                    result = original(self, target)
                    if name == "os.chdir":
                        os.chdir(os.getcwd())  # Same directory; only audit side effect.
                    else:
                        sys.audit("shutil.copyfile", "fictional-source", "fictional-dest")
                    return result
                with patch.object(witness.ScopePolicy, "decide", mutated_policy):
                    receipt = witness.evaluate()
                self.assertEqual(receipt["status"], "HOLD")
                self.assertEqual(receipt["reason"], "offline_witness_evaluation_failed")
                self.assert_no_authority(receipt)

    def test_evaluator_must_not_escape_through_baseexception_variants(self):
        for failure in (SystemExit(0), SystemExit(3), KeyboardInterrupt(), GeneratorExit()):
            with self.subTest(name=type(failure).__name__, status=getattr(failure, "code", None)):
                with patch.object(witness.ScopePolicy, "decide", side_effect=failure):
                    try:
                        receipt = witness.evaluate()
                    except BaseException as escaped:
                        self.fail(f"{type(escaped).__name__} escaped the offline HOLD boundary")
                self.assertEqual(receipt["status"], "HOLD")
                self.assertEqual(receipt["reason"], "offline_witness_evaluation_failed")
                self.assert_no_authority(receipt)
                self.assertEqual(witness.evaluate()["status"], "REVIEW_ONLY")

    def test_real_python_child_cannot_exit_zero_via_policy_systemexit(self):
        script_dir = str(ROOT / "scripts")
        program = (
            f"import sys; sys.path.insert(0, {script_dir!r}); "
            "import scope_offline_authority_witness_20261017 as w; "
            "w.ScopePolicy.decide=lambda self,target: "
            "(_ for _ in ()).throw(SystemExit(0)); "
            "raise SystemExit(w.main(['--offline-lab-only']))"
        )
        done = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True, text=True, timeout=12, check=False,
        )
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertEqual(done.stderr, "")
        receipt = json.loads(done.stdout)
        self.assertEqual(receipt["status"], "HOLD")
        self.assert_no_authority(receipt)

    def test_swallowed_timeout_signal_cannot_yield_review_only(self):
        if not hasattr(signal, "setitimer") or threading.current_thread() is not threading.main_thread():
            self.skipTest("POSIX main-thread alarm required")
        if signal.getsignal(signal.SIGALRM) != signal.SIG_DFL or any(signal.getitimer(signal.ITIMER_REAL)):
            self.skipTest("external alarm in use")
        original = witness.ScopePolicy.decide
        first_case = [True]
        def policy_swallows_deadline(self, target):
            if first_case[0]:
                first_case[0] = False
                try:
                    time.sleep(witness.EVALUATION_DEADLINE_SECONDS + 0.6)
                except BaseException:
                    # Swallow the ONE-SHOT SIGALRM, then return a valid
                    # first result. Later cases stay fast and deterministic.
                    pass
            return original(self, target)
        started = time.monotonic()
        with patch.object(witness.ScopePolicy, "decide", policy_swallows_deadline):
            result = witness.evaluate()
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, witness.EVALUATION_DEADLINE_SECONDS - 0.1)
        self.assertLess(elapsed, witness.EVALUATION_DEADLINE_SECONDS + 1.5)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "offline_witness_time_budget_exceeded")
        self.assert_no_authority(result)
        self.assertEqual(witness.evaluate()["status"], "REVIEW_ONLY")

    def test_no_network_socket_or_dns_is_necessary(self):
        with (patch.object(socket, "socket", side_effect=AssertionError("network invoked")),
              patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns invoked"))):
            result = witness.evaluate()
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assert_no_authority(result)

    def test_main_refuses_missing_or_invalid_opt_in(self):
        for args in ([], ["--json"], ["--offline-lab-only", "--anything"], "bad", [object()], ["--offline-lab-only", 1]):
            with self.subTest(args=repr(args)):
                with patch("builtins.print") as report:
                    code = witness.main(args)
                self.assertEqual(code, 2)
                body = json.loads(report.call_args.args[0])
                self.assertEqual(body["status"], "HOLD")
                self.assert_no_authority(body)

    def test_cli_refuses_str_subclass_and_list_subclass(self):
        class FakeStr(str):
            def __eq__(self, other):
                raise AssertionError("untrusted equality invoked")
        class FakeList(list):
            def __iter__(self):
                raise AssertionError("untrusted iterator invoked")
        for argv in ([FakeStr("--offline-lab-only")], FakeList(["--offline-lab-only"])):
            with patch("builtins.print") as report:
                code = witness.main(argv)
            self.assertEqual(code, 2)
            body = json.loads(report.call_args.args[0])
            self.assert_no_authority(body)

    def test_real_python_child_requires_exact_opt_in_and_never_exits_zero(self):
        script = ROOT / "scripts" / "scope_offline_authority_witness_20261017.py"
        for args, expected_code, expected_status in (
            ([], 2, "HOLD"),
            (["--offline-lab-only"], 3, "REVIEW_ONLY"),
        ):
            with self.subTest(args=args):
                done = subprocess.run([sys.executable, str(script), *args], capture_output=True, text=True, timeout=15, check=False)
                self.assertEqual(done.returncode, expected_code, done.stderr)
                self.assertEqual(done.stderr, "")
                result = json.loads(done.stdout)
                self.assertEqual(result["status"], expected_status)
                self.assert_no_authority(result)


if __name__ == "__main__":
    unittest.main()
