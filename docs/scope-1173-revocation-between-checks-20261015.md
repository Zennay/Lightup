# Scope authorization #1173 — approval mutation between checks

**15 October 2026 · INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**

## Source ownership and exact pin

Independent tests-only acceptance branch **stacked on the existing source-owner PR #1172**, pinned to immutable head `292e13fb7de08d7c6be625ef71749c8eaffa702e`. This PR adds only a new test module and this documentation; it does not modify `src/lightup/destructive_lab_step_up.py`, the owner's existing tests, default `ToolExecutor`, any other worker branch, workflow, runner, deployment, or real target.

## Confirmed source-level check/use ordering

Current opt-in `DestructiveLabStepUpExecutor.execute()` reads one trusted approval from `approval_resolver`, checks its scope/revocation/time, then independently calls `isolation_verifier`, checks the registered tool again, and delegates to `ToolExecutor.execute()`. **It does not re-check the *live* approval after the isolation callback and before handler dispatch.**

A deterministic, entirely synthetic callback can revoke, expire or rescope the approval in this gap. This is a synchronous controlled in-memory interleaving **not proof of a real deployed race or reachable attacker**. The actual production transaction and revocation authority are still future work. Rechecking the resolver after callback would narrow this deterministic window but would **not** alone provide atomic revocation/dispatch under concurrent processes; a shared transactional/lease boundary and owner review are required.

## Acceptance implemented

The independent real-source test `tests/test_scope_1173_revocation_between_checks_20261015.py` runs the actual owner opt-in adapter against a disposable SQLite evidence ledger, with a no-op registered handler and socket-creation tripwire.

- **Nine deliberately expected source REDs** document open fail-closed gaps: four approval changes after trusted resolver read (revoked, expired, rescope and deterministic concurrent revoke), one swapped inert handler after final registry check, one capability-ID reassignment after that check, one risk-level metadata reassignment after that check, and two postapproval changes to frozen run/client or call/asset objects from an in-process callback. These are **not repaired** by expected-failure annotations.
- **Eight ordinary PASS controls and direct RED integrity witnesses** verify already-revoked denial before callbacks, false lab isolation denial, genuine inert low-effect positive dispatch, pre-final-check handler swap denial, and four independent exact-error/invocation/SQLite witnesses (approval-change REDs, swapped-handler RED, and capability/risk REDs). None treats a generic exception, socket tripwire failure, timeout or accidental pass as an expected vulnerability result.

No real customer consent, trusted human approval, actual isolation attestation, outgoing network access, scanning, destructive payload, external actor, or deployment is involved. `isolation_verifier=lambda: True` is **strictly a synthetic test fixture** and cannot authorize real use.


## Final registry snapshot versus handler dispatch (new independent gate)

In the same source-owner adapter, the second registry lookup validates the original
definition and handler identity, **then** delegates to the unwrapped
`ToolExecutor.execute`, which performs its own third lookup. The identity
validated before dispatch is not locked or passed atomically to raw execution.

Three extra entirely synthetic real-source tests distinguish:

1. **Expected RED:** a worker thread pauses the final registry lookup after
   capturing the validated handler tuple; a second thread replaces the exact
   registered handler with another inert fake. The final snapshot check sees
   the old handler, while raw dispatch sees and invokes the new one.
2. **Ordinary green:** a tool substitution made during the isolation callback
   *before* the second lookup is already correctly denied by the adapter.
3. **Ordinary green witness:** verifies that the new RED is a precise missing
   `ToolDenied` assertion with the replacement handler called and synthetic
   SQLite evidence written; setup errors, barrier timeouts or unexpected green
   cannot masquerade as the intended failure.

These tests distinguish the **existing early identity check working correctly**
from the remaining **post-check to raw-dispatch** mutable-registry gap. They are
not an instruction to swap a live registry or proof of an externally reachable
race. Owner closure requires stable registered-tool identity through atomic
authorization + handler dispatch, without turning the experimental wrapper into
production authorization.


## Capability and risk binding through the same final dispatch boundary

The same registry check/use gap also affects the **authorization identity
metadata**, not only which inert handler object is called. Two additional
installed-source expected REDs modify the registered tool's `capability_id`
(`web-baseline` → `api-baseline`) or `min_risk` (destructive risk 5 →
elevated risk 4) immediately *after* the second approved lookup, before the
raw executor's third registry read. The original approved tool and callback
remain otherwise unchanged. The source currently writes synthetic evidence
for the modified capability or dispatches using the modified risk without
a new, correctly bound approval.

An ordinary source-RED witness demands the exact missing-denial assertion,
the synchronized post-check substitution event, one inert handler call,
one disposable SQLite evidence row, and the **actual policy request risk and
capability** matching what the unwrapped executor was handed. This prevents
an unrelated failure from being disguised as a security regression.

The source owner must bind capability, interaction, risk, handler and approval
through **one atomic admission-to-dispatch boundary**. Merely revalidating
the registry before a separately mutable executor read is not sufficient.
No persistent approval, external target, network, DNS, operator action, or
live handler is used by these fixtures.


## Frozen envelope mutation is not an operator attestation

`RunContext` and `ToolCall` are Python frozen dataclasses, which prevents
ordinary assignment but does not protect an object from an in-process trusted
callback using `object.__setattr__`. In the installed opt-in admission, those
same objects are passed to `isolation_verifier` **after** the approval is
validated and **before** raw dispatch. No immutable, previously matched
run/client/engagement/asset snapshot is bound to raw execution.

Two additional independent installed-source expected REDs simulate in-memory
postapproval mutation of `call.asset` or `context.client_id` using a fixture
callback and then demand `ToolDenied` **before** an inert handler or evidence.
The current implementation permits the synthetic handler. One ordinary strict
witness verifies the expected missing-denial assertion, actual handler call,
disposable SQLite evidence and changed asset/client metadata, ruling out
masked setup failures.

This is a trusted in-process callback abuse scenario, **not an externally
proven attack path**; source owners should snapshot or seal matched envelope
identities and make them immutable through final dispatch. Neither a frozen
dataclass annotation nor additional pre-callback checks establishes this.
No real tenant, target, client, network or grant is accessed.

## Owner closure and proof

1. #1172 / #107 owners decide and implement atomic operator revocation/approval consumption bound to exact run, tenant, engagement, asset, capability, tool and current clock, while preserving denial-before-handler and evidence.
2. Persisted operator issuance/revocation, real lab isolation and network egress must be independently verified; callback-only revalidation is not enough for concurrent processes.
3. Convert the nine expected REDs to ordinary PASS **only on actual repaired source**, update the witness, retain valid synthetic controls; no masking of a red as a generic expected failure.
4. Exact-head Python 3.11/3.14 offline unit and real producer-integrations, registered permanent VPS runner, independent security/privacy review and explicit human release are separate mandatory gates.

Run offline only:
`PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_1173_revocation_between_checks_20261015.py' -v`

**DRAFT/HOLD. NO MERGE, SCAN, REAL APPROVAL, ACTIVATION OR DEPLOY.**
