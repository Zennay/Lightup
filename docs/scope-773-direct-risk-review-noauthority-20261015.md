# LightUp #773 — isolated direct grant risk claim inspection

**Posture: INCUBATE M3/M7, PLAN/LAB ONLY, DRAFT/HOLD. This is NOT authorization.**
This additive follow-up is separate from the older #773 branch, and edits none
of its files. It does not take ownership of installed authorization code.

## Problem witnessed on current `main`

`ExecutionPolicy.decide()` compares `requested_risk > grant.scope.max_risk`
without first proving that `ScopeDefinition.max_risk` is an exact `RiskLevel`.
An in-memory `ScopeDefinition(max_risk=99)` can therefore let a
`TARGET_ACTIVE` request through even though 99 is not a defined risk.
The dedicated test marks that **installed source gap expected RED**: it must
not be represented as a passing production fix. Source-owner review is needed.

## Additive, non-authorizing sidecar

- `scripts/review_scope_direct_risk_claim_773.py` exports
  `inspect_direct_scope_risk(scope, requested_risk)` for in-memory,
  **synthetic** review only. It neither opens nor reads external files,
  performs DNS or network access, imports an executor, nor mutates grants.
- Exact built-in `ScopeDefinition` identity and exact `RiskLevel` types
  are prerequisites. Plain integers, booleans, floats, foreign `IntEnum`,
  polymorphic objects and foreign scope subclasses are **HOLD**.
- Requests above the canonical risk ceiling, and any destructive-lab tier
  in this direct-target risk-only comparison, are **HOLD**.
- Matching canonical limits are merely **REVIEW_ONLY**. The typed immutable
  receipt exposes six literal-false read-only booleans. Its constructor accepts
  only status and reason, **never** authority flags; fresh `to_dict()` outputs
  cannot mutate the underlying tuple or elevate a later receipt. The flags: `authorized`, `may_scan`,
  `may_dispatch`, `may_issue_grant`, `release_ready`, `may_deploy`.
- This intentionally does **not** inspect asset membership, exclusions,
  capabilities, requester identity, grant signatures, consent, timestamps,
  revocation, network destination, ingress, or runtime identity. It therefore
  **cannot** be composed as sufficient evidence to authorize or release.
- The API receives only in-memory objects. No command-line entrypoint is
  provided. Never substitute this reviewer for the actual installed
  `ExecutionPolicy`, `ActivationGate` and per-dispatch grant resolver.

## Bounded validation

```sh
PYTHONPATH=src python -m unittest discover -s tests \
  -p 'test_scope_direct_risk_claim_review_773.py' -v
```

The unit suite checks the full five-by-five canonical risk matrix,
invalid raw types, spoofed enum/numeric forms, foreign scope subclasses,
destructive-tier denial, monotonicity, all-six-false receipt invariants,
secret non-reflection, constructor-forgery rejection, immutable fresh snapshot
outputs, live mocked file/network/subprocess denial tripwires, an AST import
allowlist canary, and one `expectedFailure`
for the *installed* direct-int-99 policy gap.

An expected failure on the installed policy is a documented **RED**,
not a fix, a green authorization decision, or authorization to touch targets.
If the installed owner closes #773, remove the test's expected-failure
marker and require exact-head tests to pass normally before discussing
promotion. No release evidence is implied by any CI result here.

## Ownership and release gates

Only three newly added paths are owned on this branch: the sidecar, its
dedicated test and this contract. No change to main's `src/lightup/`
authorization implementations, `DomainStore`, web ingress, workflows,
runner, existing tests, other workers' branches, or deployments.

Remain **DRAFT/HOLD** until independent evidence for original-request
provenance (#177), real operator/customer consent, live revocation (#347),
target/destination binding, installed ingress/registered VPS, privacy/security
review, and explicit human release. No real grants, scans, dispatches, merge
or deployment on this receipt.
