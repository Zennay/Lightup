#!/usr/bin/env python3
"""Offline canonical ScopePolicy witness. A REVIEW_ONLY receipt never grants authority.

Only the built-in, deterministic, synthetic case matrix is admitted by the CLI.
No user targets, network I/O, grants, handlers, or production state are read/written.
"""
from __future__ import annotations

import hashlib
import json
import re
import signal
import threading
import sys
from contextvars import ContextVar
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType

# Import the installed checkout's real evaluator, not a lookalike test implementation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from lightup.models import Authorization, Target  # noqa: E402
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason  # noqa: E402

# A per-review 2.5-second real-time deadline on POSIX/Linux prevents a
# stalled installed evaluator from denying a bounded offline HOLD receipt.
# Refuse, rather than overwrite, any alarm already owned by another component.
EVALUATION_DEADLINE_SECONDS = 2.5


class _WitnessTimeLimit(BaseException):
    """Out-of-band timer exception that ordinary Exception handlers cannot swallow."""


def _witness_alarm(_signum: int, _frame: object) -> None:
    raise _WitnessTimeLimit()


SCHEMA = "lightup.scope-offline-decision-witness.v1"
# These hashes attest only the fictional fixtures and observed classifications.
# They are not source signatures, real consent, or release/merge authority.
REFERENCE_FIXTURE_SHA256 = "b7f7d7595f7afc56605410fc3dce434da8ff2bad6900672a9890cc3cc176071a"
REFERENCE_BEHAVIOR_SHA256 = "075c7598f4a01809cd19ef8a02d9380a2bdbde01e2a22fd8dfc940475386dcb1"
# A context-local audit fence catches ordinary Python network/file/process I/O
# accidentally added to ScopePolicy.decide(). Not an OS sandbox or defense against
# native-code bypass: the witness remains PLAN/LAB ONLY, non-authorizing.
_WITNESS_EVALUATION_ACTIVE: ContextVar[bool] = ContextVar("scope1565_audit", default=False)
# Deny *categories*, not a small incomplete list of operations:
# process env/chdir/unlink/rename etc. are audited as os.* but do not necessarily
# open files, and shutil.* can perform independent filesystem effects.
_DENIED_AUDIT_EVENTS = frozenset({
    "open", "sys.addaudithook", "sys.settrace", "sys.setprofile",
})
_DENIED_AUDIT_PREFIXES = ("socket.", "subprocess.", "os.", "shutil.", "ctypes.")


def _deny_witness_io(event: str, args: tuple[object, ...]) -> None:
    if _WITNESS_EVALUATION_ACTIVE.get() and (
        event in _DENIED_AUDIT_EVENTS
        or event.startswith(_DENIED_AUDIT_PREFIXES)
    ):
        # Never include audit arguments, paths, secrets or evaluator state.
        raise PermissionError("offline witness policy evaluation forbids Python I/O")


sys.addaudithook(_deny_witness_io)


class _DenyPolicyOutput:
    """Keep Python-level scope-evaluator output out of machine receipts."""

    def write(self, payload: str) -> int:
        raise PermissionError("offline witness disallows policy stdout or stderr")

    def flush(self) -> None:
        return None


_DENY_OUTPUT = _DenyPolicyOutput()

# Immutable public metadata for callers; actual receipts hard-code these seven
# false fields independently so reassignment cannot forge authority.
FALSE_AUTHORITY = MappingProxyType({
    "client_consent_verified": False,
    "operator_consent_verified": False,
    "authorization_granted": False,
    "dispatch_allowed": False,
    "scan_allowed": False,
    "deployment_allowed": False,
    "release_allowed": False,
})

@dataclass(frozen=True)
class WitnessCase:
    case_id: str
    target: Target
    policy: ScopePolicy
    expected_allowed: bool
    expected_host: str | None
    expected_reason: ScopeReason


def canonical_cases() -> tuple[WitnessCase, ...]:
    # Reserved synthetic hostname and local policy-only address strings. No DNS.
    sample_auth = Authorization(owner="fictional-reviewer", reference="SYNTHETIC-NOT-CONSENT")
    expired_auth = Authorization(owner="fictional-reviewer", reference="SYNTHETIC-EXPIRED", valid_until=datetime(2000, 1, 1, tzinfo=timezone.utc))
    future_auth = Authorization(owner="fictional-reviewer", reference="SYNTHETIC-NOT-YET", valid_from=datetime(2100, 1, 1, tzinfo=timezone.utc))
    host = "fixture.example.test"
    hosts = frozenset({host})
    cidrs = ("8.8.8.0/24",)
    return (
        WitnessCase("loopback-ip", Target("127.0.0.1"), ScopePolicy(), True, "127.0.0.1", ScopeReason.LOOPBACK),
        WitnessCase("loopback-name", Target("LOCALHOST."), ScopePolicy(), True, "localhost", ScopeReason.LOOPBACK),
        WitnessCase("private-lab", Target("10.22.33.44"), ScopePolicy(), True, "10.22.33.44", ScopeReason.PRIVATE_LAB),
        WitnessCase("private-disabled", Target("10.22.33.44"), ScopePolicy(allow_private_lab=False), False, "10.22.33.44", ScopeReason.OUT_OF_SCOPE),
        WitnessCase("unknown-public", Target("8.8.8.8"), ScopePolicy(), False, "8.8.8.8", ScopeReason.OUT_OF_SCOPE),
        WitnessCase("explicit-host-no-consent", Target("HTTPS://FIXTURE.EXAMPLE.TEST/path"), ScopePolicy(explicit_hosts=hosts), False, host, ScopeReason.AUTHORIZATION_MISSING),
        WitnessCase("explicit-host-synthetic-control", Target(host, authorization=sample_auth), ScopePolicy(explicit_hosts=hosts), True, host, ScopeReason.EXPLICIT_HOST),
        WitnessCase("explicit-network-no-consent", Target("8.8.8.8"), ScopePolicy(explicit_networks=cidrs), False, "8.8.8.8", ScopeReason.AUTHORIZATION_MISSING),
        WitnessCase("explicit-network-synthetic-control", Target("8.8.8.8", authorization=sample_auth), ScopePolicy(explicit_networks=cidrs), True, "8.8.8.8", ScopeReason.EXPLICIT_NETWORK),
        WitnessCase("host-removed-denies", Target(host, authorization=sample_auth), ScopePolicy(), False, host, ScopeReason.OUT_OF_SCOPE),
        WitnessCase("blank-target-denies", Target(" "), ScopePolicy(), False, None, ScopeReason.INVALID_TARGET),
        WitnessCase("explicit-host-expired", Target(host, authorization=expired_auth), ScopePolicy(explicit_hosts=hosts), False, host, ScopeReason.AUTHORIZATION_EXPIRED),
        WitnessCase("explicit-host-not-yet", Target(host, authorization=future_auth), ScopePolicy(explicit_hosts=hosts), False, host, ScopeReason.AUTHORIZATION_EXPIRED),
        WitnessCase("explicit-cidr-expired", Target("8.8.8.8", authorization=expired_auth), ScopePolicy(explicit_networks=cidrs), False, "8.8.8.8", ScopeReason.AUTHORIZATION_EXPIRED),
        WitnessCase("explicit-host-no-auth-policy", Target(host), ScopePolicy(explicit_hosts=hosts, require_authorization_for_public=False), True, host, ScopeReason.EXPLICIT_HOST),
        WitnessCase("cidr-removed-denies", Target("8.8.8.8", authorization=sample_auth), ScopePolicy(), False, "8.8.8.8", ScopeReason.OUT_OF_SCOPE),
        WitnessCase("loopback-lab-disabled", Target("127.0.0.1"), ScopePolicy(allow_private_lab=False), True, "127.0.0.1", ScopeReason.LOOPBACK),
    )


def _receipt(status: str, reason: str, checked: int = 0, digest: str | None = None) -> dict[str, object]:
    result: dict[str, object] = {
        "schema": SCHEMA,
        "status": status,
        "reason": reason,
        "checked": checked,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "authorization_granted": False,
        "dispatch_allowed": False,
        "scan_allowed": False,
        "deployment_allowed": False,
        "release_allowed": False,
    }
    if digest is not None:
        result["synthetic_matrix_sha256"] = digest
    return result


# Python frozen dataclasses can still acquire extra instance keys through
# object.__setattr__. Such shadow fields must not silently enter a positive
# review, even if all declared fields and classifications remain unchanged.
_CASE_KEYS = frozenset({"case_id", "target", "policy", "expected_allowed", "expected_host", "expected_reason"})
_TARGET_KEYS = frozenset({"value", "authorization", "labels"})
_AUTH_KEYS = frozenset({"owner", "reference", "valid_from", "valid_until"})
_POLICY_KEYS = frozenset({"allow_private_lab", "explicit_hosts", "explicit_networks", "require_authorization_for_public"})
_DECISION_KEYS = frozenset({"allowed", "normalized_host", "reason"})


def _exact_fields(instance: object, expected: frozenset[str]) -> bool:
    fields = vars(instance)
    return type(fields) is dict and fields.keys() == expected


def _hash_canonical_rows(rows: list[list[object]]) -> str:
    raw = json.dumps(rows, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _fixture_snapshot(fixtures: object) -> list[list[object]] | None:
    """Validate every fictional case before calling any policy method."""
    if type(fixtures) is not tuple or len(fixtures) != 17:
        return None
    seen: set[str] = set()
    rows: list[list[object]] = []
    for case in fixtures:
        if (
            type(case) is not WitnessCase
            or not _exact_fields(case, _CASE_KEYS)
            or type(case.case_id) is not str
            or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", case.case_id) is None
            or case.case_id in seen
            or type(case.target) is not Target
            or not _exact_fields(case.target, _TARGET_KEYS)
            or type(case.target.value) is not str
            or len(case.target.value) > 512
            or not case.target.value.isascii()
            or type(case.target.labels) is not tuple
            or len(case.target.labels) > 16
            or any(type(label) is not str or len(label) > 128 for label in case.target.labels)
            or type(case.policy) is not ScopePolicy
            or not _exact_fields(case.policy, _POLICY_KEYS)
            or type(case.policy.allow_private_lab) is not bool
            or type(case.policy.require_authorization_for_public) is not bool
            or type(case.policy.explicit_hosts) is not frozenset
            or len(case.policy.explicit_hosts) > 16
            or any(type(item) is not str or len(item) > 253 for item in case.policy.explicit_hosts)
            or type(case.policy.explicit_networks) is not tuple
            or len(case.policy.explicit_networks) > 16
            or any(type(item) is not str or len(item) > 64 for item in case.policy.explicit_networks)
            or type(case.expected_allowed) is not bool
            or (case.expected_host is not None and type(case.expected_host) is not str)
            or type(case.expected_reason) is not ScopeReason
        ):
            return None
        authorization = case.target.authorization
        if authorization is not None:
            if (
                type(authorization) is not Authorization
                or not _exact_fields(authorization, _AUTH_KEYS)
                or type(authorization.owner) is not str
                or len(authorization.owner) > 128
                or type(authorization.reference) is not str
                or len(authorization.reference) > 128
            ):
                return None
            for bound in (authorization.valid_from, authorization.valid_until):
                if bound is not None and (
                    type(bound) is not datetime or bound.tzinfo is not timezone.utc
                ):
                    return None
        rows.append([
            case.case_id, case.target.value, list(case.target.labels),
            None if authorization is None else [
                authorization.owner, authorization.reference,
                None if authorization.valid_from is None else authorization.valid_from.isoformat(),
                None if authorization.valid_until is None else authorization.valid_until.isoformat(),
            ],
            case.policy.allow_private_lab,
            sorted(case.policy.explicit_hosts),
            list(case.policy.explicit_networks),
            case.policy.require_authorization_for_public,
            case.expected_allowed, case.expected_host, case.expected_reason.value,
        ])
        seen.add(case.case_id)
    return rows


def _evaluate_pinned_cases(fixtures: tuple[WitnessCase, ...], fixture_digest: str, snapshot: list[list[object]]) -> dict[str, object]:
    """Called only under the exclusive deadline and after fixture-pin admission."""
    observed: list[list[object]] = []
    for case in fixtures:
        token = _WITNESS_EVALUATION_ACTIVE.set(True)
        try:
            with redirect_stdout(_DENY_OUTPUT), redirect_stderr(_DENY_OUTPUT):
                decision = case.policy.decide(case.target)
        finally:
            _WITNESS_EVALUATION_ACTIVE.reset(token)
        # Frozen dataclasses are not immutable against object.__setattr__.
        # A matching decision can conceal changes to the current or a FUTURE
        # fictional target, authorization, scope policy, or expected verdict.
        # Check the *entire* fixed corpus after each policy call, not only
        # after the last case, so a mutation stops further evaluation.
        if _fixture_snapshot(fixtures) != snapshot:
            return _receipt("HOLD", "offline_witness_fixture_mutated")
        if (
            type(decision) is not ScopeDecision
            or not _exact_fields(decision, _DECISION_KEYS)
            or type(decision.allowed) is not bool
            or (decision.normalized_host is not None and type(decision.normalized_host) is not str)
            or type(decision.reason) is not ScopeReason
        ):
            return _receipt("HOLD", "invalid_decision_shape")
        if (
            decision.allowed is not case.expected_allowed
            or decision.normalized_host != case.expected_host
            or decision.reason is not case.expected_reason
        ):
            return _receipt("HOLD", "scope_policy_contract_drift")
        observed.append([case.case_id, decision.allowed, decision.normalized_host, decision.reason.value])
    digest = _hash_canonical_rows(observed)
    if digest != REFERENCE_BEHAVIOR_SHA256:
        return _receipt("HOLD", "reference_behavior_drift")
    receipt = _receipt("REVIEW_ONLY", "canonical_synthetic_matrix_matches", len(fixtures), digest)
    receipt["synthetic_fixture_sha256"] = fixture_digest
    return receipt


def evaluate(cases: tuple[WitnessCase, ...] | None = None) -> dict[str, object]:
    """Only pin-matched, bounded fictional evaluation may yield REVIEW_ONLY."""
    try:
        fixtures = canonical_cases() if cases is None else cases
        snapshot = _fixture_snapshot(fixtures)
        if snapshot is None:
            return _receipt("HOLD", "invalid_witness_matrix")
        fixture_digest = _hash_canonical_rows(snapshot)
        if fixture_digest != REFERENCE_FIXTURE_SHA256:
            return _receipt("HOLD", "reference_fixture_drift")
        # Never steal an existing process-level SIGALRM timer, silently run
        # without the deadline, or execute a policy on a worker thread.
        if (
            threading.current_thread() is not threading.main_thread()
            or not hasattr(signal, "setitimer")
            or not hasattr(signal, "SIGALRM")
            or _WITNESS_EVALUATION_ACTIVE.get()
            or signal.getsignal(signal.SIGALRM) is not signal.SIG_DFL
            or any(signal.getitimer(signal.ITIMER_REAL))
        ):
            return _receipt("HOLD", "offline_witness_time_fence_unavailable")
        prior_handler = signal.getsignal(signal.SIGALRM)
        try:
            signal.signal(signal.SIGALRM, _witness_alarm)
            signal.setitimer(signal.ITIMER_REAL, EVALUATION_DEADLINE_SECONDS)
            return _evaluate_pinned_cases(fixtures, fixture_digest, snapshot)
        finally:
            # Restore both resources even if the policy crashed, returned
            # early or exceeded the wall-clock budget.
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, prior_handler)
    except _WitnessTimeLimit:
        return _receipt("HOLD", "offline_witness_time_budget_exceeded")
    except BaseException:
        # The offline CLI MUST NEVER emit an accidental success exit 0 through
        # a scope callback raising SystemExit(0), KeyboardInterrupt or
        # GeneratorExit. This intentionally differs from normal application
        # interrupt propagation: no non-HOLD path may escape this witness.
        # No potentially sensitive input, error, or exception is echoed.
        return _receipt("HOLD", "offline_witness_evaluation_failed")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    # Exact built-in admission happens before any caller-controlled equality/iteration.
    if type(args) is not list or len(args) != 1 or type(args[0]) is not str or args[0] != "--offline-lab-only":
        receipt = _receipt("HOLD", "explicit_offline_opt_in_required")
    else:
        receipt = evaluate()
    print(json.dumps(receipt, sort_keys=True, ensure_ascii=True, separators=(",", ":")))
    return 3 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
