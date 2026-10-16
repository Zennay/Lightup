# Legacy permit / scope-decision consistency — #1491 (offline)

**INCUBATE M3/M7 — PLAN/LAB ONLY — DRAFT/HOLD. Not authorization or release evidence.**

## Exact installed-source observation
On unchanged main `e73b7445c87ad239bdb03c50a99078ef93163b02`,
`ScopePolicy.decide(Target)` returns a frozen `ScopeDecision`, while
`ActivationGate.issue()` writes an `ExecutionPermit` without the decision
reason or authenticated policy snapshot. Matching two caller-supplied objects
does **not** prove they were paired when the permit was minted.

## New isolated working helper
`src/lightup/permit_decision_review_1491.py` performs *only* deterministic,
bounded **post-issuance consistency review**, with no trust upgrade:

- Exact original `ExecutionPermit` and `ScopeDecision` dataclass identity
  and full exact instance-field sets (rejects missing/forged fields).
- Strict literal `allowed is True`, real `ScopeReason` and `ActivationMode`.
- LAB_ONLY only; plausible canonical loopback/RFC1918/ULA identity and decision
  reason, exact target match. Special-use and IPv6 zone-suffixed addresses HOLD.
- Bounded built-in permit/capability/reference string syntax, expected
  (but **caller-asserted**) `LAB-...` string, exact canonical UTC timestamp.
- **All results** immutable `HOLD` or `REVIEW_ONLY`; four literal false
  `authorized`, `consent_verified`, `dispatch_allowed`,
  `release_allowed`. No user-controlled values in result reasons.
- No grant writer, adapter, scanner, DNS, HTTP, SQLite, shell or ambient clock.

Run (offline and only synthetic fixtures):
```bash
PYTHONPATH=src python -m unittest tests.test_scope_permit_decision_review_1491_20261016 -v
```

Includes actual original `ActivationGate.issue` loopback fixture under mocked
token generation and PLAN_ONLY negative, adversarial malformed records, swapped
decision, claimed LAB reference, timestamp, subclasses, incomplete/extra fields,
parallel-review-equivalent repeated results, and no-I/O guards.

## Limitations — explicit original owner handoff
`REVIEW_ONLY` says merely that two unauthenticated legacy *claims* have
plausible compatible shapes. The helper is **unwired**. Caller can fabricate
both objects or supply their own expected reference. It **does not** verify
issued permit ID uniqueness, provenance signature, real policy binding, actor,
tenant, asset approval, capability consent, revocation, trusted time, executor
dispatch authorization or replay protection. A real grant must be independently
bound to a durable, authenticated scope-decision/consent snapshot *before*
issuance and revalidated at handler dispatch. Existing real source owners
#1482/#1484/#1480/#1476/#1487 must coordinate any production adoption.
Nothing about this module makes the legacy ActivationGate safe to expose.

For promotion: source-owner design review, authentic client/operator consent,
independent security/privacy, exact-head hosted and registered permanent VPS
CI on `vps-bb300bba`, **and explicit human GO**. Until then no merge,
deployment, real target, active scan, permit dispatch or production wiring.
