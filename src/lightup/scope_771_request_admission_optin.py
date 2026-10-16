"""Opt-in fail-closed admission for canonical ExecutionRequest envelopes (#771).

This module is not imported by the default application or tool executor.
The original source owner controls any future integration into production.
No permission is issued and no network-capable handler is called.
"""

from __future__ import annotations

from .execution_policy import ExecutionPolicy, ExecutionRequest, PolicyDecision


def decide_exact_execution_request(
    policy: object, request: object,
) -> PolicyDecision:
    """Evaluate only exact immutable owner request/policy types.

    Reject *before* accessing any untrusted member or dispatching an
    overridden policy method. Legitimate requests delegate to the existing
    owner logic unchanged; a downstream allow remains just a plan-only
    policy decision and is never an execution permit.
    """
    if type(policy) is not ExecutionPolicy:
        return PolicyDecision(False, "canonical ExecutionPolicy object required")
    if type(request) is not ExecutionRequest:
        return PolicyDecision(False, "canonical ExecutionRequest object required")
    return policy.decide(request)
