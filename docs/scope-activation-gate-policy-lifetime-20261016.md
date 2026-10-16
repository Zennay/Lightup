# ActivationGate policy lifetime: source-bound review (#1476)

**State: DRAFT/HOLD · LightUp INCUBATE M3/M7 · PLAN/LAB ONLY.** This is a deliberately non-authorizing, offline acceptance pack. No public security testing, scan, durable grant, handler, deployment or merge.

## Original source boundary

On `main`, `src/lightup/activation.py` validates `ActivationPolicy` only in `ActivationGate.__init__`. The gate stores `self.activation_policy` and `self.scope_policy` as ordinary writable instance fields. Its `issue()` method dereferences both afresh.

An immutable `ActivationPolicy` dataclass prevents changing *fields on that object*, but does not prevent replacing the *entire object on the gate*. Likewise `ScopePolicy` is frozen but `gate.scope_policy` is replaceable.

The synthetic installed-source examples show distinct hazards:

1. A gate constructed under PLAN_ONLY can be rebound to LAB_ONLY, after which `issue()` returns an in-memory localhost permit.
2. An invalid AUTHORIZED policy missing its required `activation_reference` is rejected by the constructor but is accepted as a replacement, bypassing the one-time `validate()`; with fabricated legacy `Target.authorization`, `issue()` returns an in-memory permit whose reference falls back to the fictional target authorization.
3. An AUTHORIZED gate whose original scope excludes the fictional DNS name can be rebound to a broader explicit host policy; `issue()` then returns an in-memory permit.

These are in-process object-lifetime discrepancies. **No proof** exists here that arbitrary external users can replace Python attributes; the deployed caller graph, genuine consent, durable grants, live revocation and actual tool dispatch remain unverified. A local `ExecutionPermit` is **not** permission to scan anything. Positive witness tests are kept so an accidentally skipped or vacuous expected-RED is detectable.

## Strict original-source acceptance

`tests/test_scope_activation_gate_policy_rebinding_red_20261016.py` imports the *installed original* `ActivationGate`, `ActivationPolicy`, `ScopePolicy` and `Target`, never a copy of the policy logic. The dedicated suite includes normal PLAN_ONLY deny, valid LAB_ONLY control, constructor validation denial, frozen-policy control, original narrow scope deny, and three successful counterexample witnesses. Exactly **three** `@unittest.expectedFailure` tests express a desired non-rebindable lifetime contract:

- PLAN_ONLY object cannot later issue LAB_ONLY permits merely because a policy field was replaced;
- a policy replacement cannot bypass the original validation contract;
- an original restricted scope cannot be widened through an instance-attribute assignment.

`expectedFailure` is a **known OPEN defect**; a successful overall test run does not close any RED. When a reviewed source fix lands, remove each marker and prove the exact test passes normally. Any surprising XPASS must be investigated and cannot automatically count as proof of source repair. All target names use `.example.test` and the loopback literal. Tests use no real customer data, external IO, sockets or handlers.

Run offline with `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_activation_gate_policy_rebinding_red_20261016.py' -v`. On the isolated file, intended current-source outcome is **11 tests, eight ordinary PASS and three expected failures**.

## Review ownership and safety gates

- Original `activation.py` and `scope.py` remain unchanged. Their existing source owners decide the source fix. A safer contract may use a sealed gate instance, constructor-only immutable snapshot, or explicit verified reconfiguration that **cannot promote** risk/scope. A naive `__setattr__` patch or shallow freeze is not sufficient if input collections or nested references remain mutable.
- Scope admissibility, typed capabilities, immutable/tenant-bound grants, revocation, risk, activation mode, evidence-before-handler and approved assessments must still be checked when the real dispatch is eventually wired. The simple legacy `Target.authorization` object in these tests is **fictional** and cannot stand in for durable authorization.
- No source owners' tests, production runtime paths, pre-existing tests, workflows, build runners, PR branches or deployment config were edited.
- Before any promotion: actual exact-head hosted tests on both supported interpreters, genuine independently registered VPS execution, separate security/privacy and original-owner review, verified client and operator authorization, human GO. This PR remains **DRAFT/HOLD**, not release or dispatch authority.

Issue: https://github.com/Zennay/Lightup/issues/1476

## W2: opt-in actual source review implementation (unwired and non-authorizing)

A separate **new production-tree module**, `src/lightup/activation_gate_lifetime_review_1476.py`, implements an intentionally **unwired observation-only** boundary. It is imported by its own new tests only, not by `ActivationGate.issue`, a server, a scanner, the policy stack, CI, or deployment.

- `pin_gate_for_offline_review(gate)` accepts **exact original class identities** for the gate and both policy objects. It conservatively checks exact booleans, enum values, immutable collection types, exact built-in text entries, and bounded metadata (256 collection items, 2,048 characters per entry).
- A snapshot holds strong references to the **original** gate, scope and activation policy objects and records the exact field values without DNS lookup, network, subprocess, grant, policy decision, or permit issuance. The snapshot is not a token, an unforgeable lock or a future authorization.
- `review_gate_lifetime(gate, pin)` checks gate identity, both original policy-object identities, exact structural field snapshots and input types. Replacing policies **even with equal values** or mutating frozen dataclasses via `object.__setattr__` yields generic `HOLD`. An unchanged snapshot yields `REVIEW_ONLY`, **never an allow**.
- Both receipt types always have six literal `False` flags for permission/grant issuance, dispatch, scanning, deployment and release. No target, client, real grant ID, scope string, approval reference or other metadata is returned in a receipt. A snapshot's printable representation also hides its internal references and values.
- No consumer must use the result as a check-then-execute permit: independent running code can change immediately after this observation, and in-process callers can forge Python objects. Only a source-owner-integrated atomic authority mechanism with durable live grant/revoke checks can settle that race.

`tests/test_scope_activation_gate_lifetime_review_1476.py` adds **21 ordinary tests** including all three valid policy modes remaining non-authorizing; identity and same-value swaps; bypassing frozen field protections; mutable aliases and invalid booleans/types; exact enum/str-subclass refusal; bound thresholds; wrong gate and snapshot; no original `issue()` or external-effect calls; and absence of metadata in `repr`.

These **21 tests are ordinary tests, not expected failures**: any failure is a problem with this new reference code, not an intentional production-source RED. The three pre-existing original-source REDs in the separate file remain OPEN and the real source owners still own remediation. Before considering a source-side adoption, owners should remove the RED markers only after those tests actually pass against unchanged normal tests.
