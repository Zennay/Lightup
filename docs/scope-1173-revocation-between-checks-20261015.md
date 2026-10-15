# Scope authorization #1173 — approval mutation between checks

**15 October 2026 · INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**

## Source ownership and exact pin

Independent tests-only acceptance branch **stacked on the existing source-owner PR #1172**, pinned to immutable head `292e13fb7de08d7c6be625ef71749c8eaffa702e`. This PR adds only a new test module and this documentation; it does not modify `src/lightup/destructive_lab_step_up.py`, the owner's existing tests, default `ToolExecutor`, any other worker branch, workflow, runner, deployment, or real target.

## Confirmed source-level check/use ordering

Current opt-in `DestructiveLabStepUpExecutor.execute()` reads one trusted approval from `approval_resolver`, checks its scope/revocation/time, then independently calls `isolation_verifier`, checks the registered tool again, and delegates to `ToolExecutor.execute()`. **It does not re-check the *live* approval after the isolation callback and before handler dispatch.**

A deterministic, entirely synthetic callback can revoke, expire or rescope the approval in this gap. This is a synchronous controlled in-memory interleaving **not proof of a real deployed race or reachable attacker**. The actual production transaction and revocation authority are still future work. Rechecking the resolver after callback would narrow this deterministic window but would **not** alone provide atomic revocation/dispatch under concurrent processes; a shared transactional/lease boundary and owner review are required.

## Acceptance implemented

The independent real-source test `tests/test_scope_1173_revocation_between_checks_20261015.py` runs the actual owner opt-in adapter against a disposable SQLite evidence ledger, with a no-op registered handler and socket-creation tripwire.

- Four **intentional installed-source expected RED** tests require denial if trusted approval is revoked, expired or reassigned after first approval read but during isolation verification, including **one truly concurrent deterministic two-thread revocation** while a lab verification callback is held at a synchronization barrier. This is a controlled lab-only in-memory reproduction, not a claim about network-exposed concurrency. The source currently dispatches nonetheless.
- Three **ordinary green controls** verify already-revoked approvals deny before isolation, false lab isolation denies before handler, and an unmodified synthetic approval+fixture verifier allows only the inert local handler.
- A fourth **ordinary green RED-integrity witness** calls all four failing bodies directly, verifies the exact missing-denial assertion, callback ordering, handler invocation and temporary SQLite evidence; it rejects masked setup/network exceptions, unrelated failure, and false green.

No real customer consent, trusted human approval, actual isolation attestation, outgoing network access, scanning, destructive payload, external actor, or deployment is involved. `isolation_verifier=lambda: True` is **strictly a synthetic test fixture** and cannot authorize real use.

## Owner closure and proof

1. #1172 / #107 owners decide and implement atomic operator revocation/approval consumption bound to exact run, tenant, engagement, asset, capability, tool and current clock, while preserving denial-before-handler and evidence.
2. Persisted operator issuance/revocation, real lab isolation and network egress must be independently verified; callback-only revalidation is not enough for concurrent processes.
3. Convert the four expected REDs to ordinary PASS **only on actual repaired source**, update the witness, retain valid synthetic controls; no masking of a red as a generic expected failure.
4. Exact-head Python 3.11/3.14 offline unit and real producer-integrations, registered permanent VPS runner, independent security/privacy review and explicit human release are separate mandatory gates.

Run offline only:
`PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_1173_revocation_between_checks_20261015.py' -v`

**DRAFT/HOLD. NO MERGE, SCAN, REAL APPROVAL, ACTIVATION OR DEPLOY.**
