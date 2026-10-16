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

`tests/test_scope_activation_gate_lifetime_review_1476.py` adds **27 ordinary tests** including all three valid policy modes remaining non-authorizing; identity and same-value swaps; bypassing frozen field protections; mutable aliases and invalid booleans/types; exact enum/str-subclass refusal; bound thresholds; wrong gate and snapshot; no original `issue()` or external-effect calls; and absence of metadata in `repr`.

These **21 tests are ordinary tests, not expected failures**: any failure is a problem with this new reference code, not an intentional production-source RED. The three pre-existing original-source REDs in the separate file remain OPEN and the real source owners still own remediation. Before considering a source-side adoption, owners should remove the RED markers only after those tests actually pass against unchanged normal tests.

## W3 fail-closed corruption controls

A reviewed input may be a partially constructed exact `ActivationGate` (via `object.__new__`) or its `__dict__`/frozen nested policy fields can be deleted after the original review. Both pinning and review now catch only the expected shape errors (`AttributeError`, `TypeError`, `ValueError`) and return `None` or a generic **HOLD** receipt rather than accidentally leaking an exception or reporting REVIEW_ONLY. Three extra ordinary installed-source regression methods check an uninitialized source gate, deleted top-level activation policy, and deleted nested scope fields. **Total new opt-in reviewer tests: 27**, separate from 11 original-source tests (8 ordinary controls and 3 OPEN expected failures).

## W4: exact original hosted failure repaired in isolation

On immutable W3 HEAD `48d0c8582dc95e92b6794fae5648406aa7d96fea`, hosted [#38862921746](https://github.com/Zennay/Lightup/actions/runs/38862921746) actually ran both Python versions. Raw logs: 1,272 tests each, **3 unexpected failures** (two subcases in our newly added `test_deleted_nested_fields_hold_without_exception`, plus unchanged foreign #301 fixed-date fixture) and 26 expected source failures. All other 23 lifetime tests, all 8 original ordinary controls and all 3 expected REDs behaved as designed. Producer integrations SKIPPED. No green falsely claimed.

The two *owned* failures were a real flaw in our conservative reference: Python frozen dataclasses can fall back to class-level defaults after `object.__delattr__` removes an instance field, so direct attribute reads may incorrectly report an unchanged policy. W4 now explicitly checks the **exact instance `vars(...)` field set** for source gate and both policy objects before inspecting values; deleted or extra injected fields fail closed. Three additional ordinary regressions cover missing enum field, extra policy keys, and extra gate keys. New **27 ordinary tests**, plus 11 older original-source methods = **38 total own tests (35 expected PASS and 3 open expected-RED)**. The real original source is unchanged, and any next-head CI needs its own job log verification.

## W5: bounded all-or-nothing multi-gate offline review

Own new module `src/lightup/activation_gate_cohort_review_1476.py` composes the **existing real installed-source gate observer** without any runtime wiring. `pin_gate_cohort_for_offline_review` accepts only a tuple of **1–64 distinct exact `ActivationGate` objects**; each is independently pinned with the original safe metadata checks. One corrupted input, duplicate identity, subclass, oversized batch or malformed gate causes the **whole pin to fail** rather than returning partial success.

`review_gate_cohort_offline` checks the same tuple of gates in its original identity order. Any changed, missing, substituted, repeated or corrupted item produces one generic **HOLD** receipt for the *entire* cohort. All items unchanged produce **REVIEW_ONLY** only. Both statuses have six literal `False` dispatch/grant/permit/scan/deploy/release flags; no per-gate verdicts, target names, references or approval data leak into receipt text. It does not issue grants, permissions, call handlers, open sockets, query DNS or scan.

The companion **22 ordinary** source-bound tests live only in `tests/test_scope_activation_gate_cohort_review_1476.py`. They exercise exact one/multiple-gate controls, upper bound, duplicates, reordered cohorts, invalid policy/scope, forged/malformed pins, whole-batch refusal, privacy-minimal receipt and no-external-effects canaries. Combined own coverage is now **60 tests** (27 ordinary single-gate reviewer + 22 ordinary cohort + 8 ordinary source witnesses + 3 deliberate OPEN source expected-REDs).

**Limitations:** no actual persistent gate lock; Python objects can be forged inside the process and can be swapped after observation. `REVIEW_ONLY` is not grant approval, an atomic production dispatch fence, customer consent, lab authorization or a basis to enable scans. An unobserved swap-and-restore between separate reviews is NOT detected. The original `ActivationGate.issue` owners still have to implement a genuinely enforceable source-side contract and live grant/revocation/tenant/risk checks, then make the three REDs pass as ordinary tests. All source/CI/workflow/runner and competing worker files remain unchanged; original project posture stays INCUBATE M3/M7 **DRAFT/HOLD**.

## W6: mid-review drift, two bounded passes

The W5 cohort checker was strengthened for a specific non-concurrent but important observation-ordering problem: an earlier gate might be changed by ordinary in-process code while a later gate is being pinned or inspected. The first pass would otherwise finish having stored an already stale earlier snapshot, even though an immediate check would detect the drift.

The batch pin operation now **revalidates every earlier gate's stored identity and exact fields once after collecting all pins** and atomically returns `None` if any changed. The batch review similarly performs **two complete bounded passes** and returns a generic cohort-level HOLD if either pass detects a change. This still is NOT a lock, transaction, cross-thread consistency barrier, ABA/revert detector or dispatch authorization.

Three extra ordinary genuine-source tests simulate deterministic mid-pinning and mid-review mutation with isolated in-process mocks and verify a stable 3-gate cohort incurs exactly six review calls. The checker remains bounded to 64 gates, only returns deny-only receipts and invokes no real tool. **Cumulative own tests: 63** (27 single-gate + 25 cohort + 8 original-source ordinary controls + 3 intentionally OPEN expected source REDs). Original runtime source owners must solve actual atomic authority/check-use/revocation barriers. Any completed hosted/VPS log must be matched to the exact immutable commit, not previous runs.

## W7: explicitly non-authorizing monotone observed-HOLD journal

A separate new pure module, `src/lightup/activation_gate_review_journal_1476.py`, holds a **bounded optional in-process chain** of cohort review results. `begin_offline_cohort_journal(gates)` accepts only the complete original cohort. `advance_offline_cohort_journal(gates, journal)` returns a **new journal plus deny-only receipt**; callers must persist the returned next object if they want the history. Once an actually observed change makes `HOLD`, every later observation using that returned chain stays on HOLD, including if the original policy objects are later restored to identical references. A 1,024-observation cap leads to HOLD instead of unlimited counters.

`tests/test_scope_activation_gate_review_journal_1476.py` adds **14 ordinary original-module tests**: unchanged controls, exact internal types, invalid and malformed journals, 1,024 boundary, changed/restored gate, multiple gate batches, privacy-minimal representation and hard no-IO/no-permit canaries. It ALSO explicitly demonstrates a limitation: reusing a **stale older journal** after a HOLD may report REVIEW_ONLY again. Likewise, an adversarial caller can forge Python objects or change a gate entirely between observations. **Do not imply durable revocation, immutable history, audit authenticity or actual runtime execution safety.** The source owner must design a durable, trusted, atomic authority mechanism separately. Even REVIEW_ONLY is *never permission* and all six receipt flags remain literal false.

Cumulative own test modules now **77 methods** (= 27 single-gate, 25 atomic cohort, 14 offline journal, 8 original-source ordinary, 3 deliberately OPEN original-source expected REDs). All modules are entirely unwired from `ActivationGate.issue`, and no existing CI/workflow, owner source, real grant or target has been changed.

## W8: optional session cursor anti-replay and public AUTHORIZED owner RED

This cycle continues **ONLY** existing own branch #1477, on self-owned source/tests/docs paths. It does not touch original gate source, workflows or parallel workers.

### Material offline reviewer implementation
The existing **unwired** `activation_gate_review_journal_1476.py` now includes `OfflineReviewSession`, `open_offline_review_session` and `advance_offline_review_session`: an **opt-in in-memory cursor** that requires the exact *same Python journal object identity* returned by the previous successful review, so an accidentally reused earlier observation yields a terminal HOLD **within the same session object**. An observed policy change also yields a sticky session HOLD even if policy references return to their old values.

This is deliberately **not trusted audit history, durable revocation, authorization, an unforgeable token, a lock or active dispatch fence**. It is possible to instantiate a fresh session after restoration; callers controlling process memory can forge/mutate the session, and an unobserved swap and restore cannot be detected. Tests explicitly demonstrate the fresh-session limitation and neither permission nor scan is ever issued. Every receipt preserves the six literal false authority flags. No scan adapter/handler or network is connected.

The companion owned `tests/test_scope_activation_gate_review_journal_1476.py` now has **26 ordinary methods**, adding 12 ordinary in-memory cursor regressions: exact original token identity and monotonic two-step success; stale/equal-value cursor latch; observed policy/scope drift; malformed sessions; bounded observation count; metadata privacy; side-effect canaries and the explicitly unsafe fresh-session reset.

### New genuine original-source acceptance gap
The owned `tests/test_scope_activation_gate_policy_rebinding_red_20261016.py` adds a normal original-source **witness** proving PLAN_ONLY→valid AUTHORIZED rebinding on the *same* policy gate with an explicitly fictional public `.example.test` target. It adds a FOURTH intentional `@unittest.expectedFailure` production contract demanding that a gate created PLAN_ONLY must never acquire public AUTHORIZED permit issuance by post-constructor assignment, even when the new policy is independently valid. This is additional source-owner RED evidence, not a source fix, not customer consent, and never a scan.

**W8 own suite count: 91** = 27 single-gate + 25 two-pass cohort + 26 ordinary journal (including 12 session methods) + 9 ordinary original-source controls/witnesses + **4 original-source still OPEN `expectedFailure` tests**. New source changes are only to owned offline journal; original `src/lightup/activation.py` and `scope.py` still require their source owners #122/#126. Independently verify exact immutable W8 hosted jobs before claiming any new PASS.

### Non-release checklist
Original gate immutable policy binding or atomic authorization + tenant/capability/grant/consent/revocation checks remain absent; full preflight has an independently owned old #301 fixed-date fixture problem, and registered self-hosted VPS proof is absent until actual assigned job logs exist. Independent security/privacy and human GO are NOT replaced by synthetic tests. **INCUBATE M3/M7, PLAN/LAB ONLY, DRAFT/HOLD; NEVER deploy, merge, issue a real grant, activate a handler or scan.**

## W9: original live gate decision/use drift, deterministic source acceptance

Four more **genuine original `ActivationGate.issue` test methods** were added to the existing self-owned source acceptance file only, not to runtime. A narrowly patched *original* `ScopePolicy.decide` returns the real source decision but simulates a deterministic mutation immediately at the decision boundary:

1. Original policy **PLAN_ONLY**, synthetic fictional explicitly scoped public target; while source runs `decide`, an in-memory mutation replaces the `activation_policy` with a valid `AUTHORIZED` policy. The ordinary witness confirms original `issue` then returns an in-process permit. An independent sixth-column RED-style `@expectedFailure` invariant requires this unauthorized mid-issue mode promotion to be rejected.
2. Original policy **AUTHORIZED** and fictional scoped target: original source `decide` correctly approves, but before returning the decision the test replaces `gate.scope_policy` with a stricter scope, so the **current** gate now denies the same target. The original source still returns an in-process permit from the stale initial decision. An additional `@expectedFailure` invariant requires a fail-closed denial if the scope has been revoked before the permit is returned.

These tests show deterministic **in-process ordering/TOCTOU windows**, not a demonstrated multithreaded exploit or internet scanning. The synthetic public target is `review.example.test`, with only fictitious authorization data. All sockets, DNS and subprocess effects are banned in ordinary positive witnesses. `ExecutionPermit` is an in-memory object and **not** authority to dispatch real tools. The original runtime owner must decide how to bind an immutable/canonical decision and validate live grants and revocation atomically, while preserving all consent/tenant/risk/capability checks. Do not patch `activation.py`, `scope.py` or issue real permissions from this branch.

**Cumulative own suite now 95 methods**: **89 ordinary source-bound controls/review tests + SIX deliberately OPEN actual-source expected REDs**. The newly added last two REDs must not be promoted to ordinary PASS until the original code is really fixed. Full-GitHub-CI baseline #301 fixture and permanent VPS assignment remain other-owner dependencies. This repo remains **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**.
