# #1517 — post-scope Target identity drift: source-owner acceptance

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. NOT A PERMIT.**

## Exact original source boundary

The immutable original main baseline inspected on 2026-10-16 was
`e73b7445c87ad239bdb03c50a99078ef93163b02`.

`src/lightup/activation.py:ActivationGate.issue` calls
`scope_policy.decide(target)`, then re-reads `target.authorization`
and `target.authorization.is_current()` before stamping the synthetic
`ExecutionPermit`. This sequence does not bind the _same_ target
authorization identity across the two operations. Python frozen dataclasses
do **not** prevent trusted in-process code using `object.__setattr__`
to replace fields. One source reproducer uses a temporary `unittest.mock.patch`
wrapper; a second exercises both original installed source methods using a
fictional in-process `Authorization` subclass. Neither uses real targets,
external callbacks, traffic or active tools.

This is a reproducible *synthetic in-process state-integrity regression*, **not
a demonstrated externally reachable exploit**.

## Deliverables isolated from source owners

- `src/lightup/scope_target_binding_review_1517.py` — independent, unwired,
  pure stdlib review of two exact built-in tuples: canonical reserved fictional
  asset `*.example.test`, owner, grant reference, integer revision. All changed,
  malformed, polymorphic, non-fictional or aliased identities return generic
  `HOLD`; exact matching fictional values yield `REVIEW_ONLY` **only**.
- `review_target_binding_batch_1517` — strict 1–64-item exact built-in tuple cohort, every pair canonical and equal, rejects repeated fictional asset/grant IDs and any individual mismatch **atomically** with HOLD, never partial permissions.
- `tests/test_scope_target_binding_review_1517.py` — source reproduction and
  deterministic isolated reviewer tests. The two original-source rejection contracts
  use `@unittest.expectedFailure` while original activation lacks the binding
  guard. A clean expected failure **is not** a repaired source.
- `.github/workflows/scope-target-binding-review-1517.yml` — separate,
  opt-in/no-secrets hosted test lane; never uses the permanent named VPS runner.

No existing original activation/models/scope/grant/consent/handler/CI/VPS
source modified. #1476, #1480, #1482, #1491 and their current draft PR
owners remain independent.

## Locally reproducible offline acceptance

```bash
PYTHONPATH=src python -W error::ResourceWarning -m unittest discover \
  -s tests -p 'test_scope_target_binding_review_1517.py' -v
```

The only successful result acceptable is ordinary tests PASS with *two*
deliberately original-source expected failures. The optional diagnostic
`REVIEW_ONLY` result never grants source provenance, identity attestation,
actual consent, execution, runtime safety, a scan or release authority.
Every receipt returns literal False for `authorized`, `consent_verified`,
`dispatch_allowed`, `release_allowed`. Results are freshly constructed
rather than cross-request shared. Untrusted input is not echoed by diagnostic.

## Original source-owner handoff

A future source-owned fix should take an immutable strict canonical target
and authorization snapshot prior to scope decision, compare the same identity
and version after that decision, ensure all at-use revocation checks, and
issue a permit only if the current decision and authorization are still bound
to that snapshot. Any mismatch must abort atomically. Only then should the
existing expectedFailures be converted into normal passing regressions by
the owner of original source. Avoid interpreting any source-only test wrapper
as deployed protection.

**Independent release fences:** actual separately authenticated client and
operator consent; durable revocation checked at dispatch; source-owned
production fix; independent security/privacy; full exact-head original hosted
and actual permanently registered named `vps-bb300bba` runner GREEN;
explicit human GO. Historical original #301 date-fixture CI failure remains
with independent draft #1452. No merge, deploy, scans, grants, handlers,
production targets or release on this draft.
