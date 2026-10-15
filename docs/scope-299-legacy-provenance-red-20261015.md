# Issue #299 — legacy public authorization provenance: current-main installed RED

**LightUp INCUBATE M3/M7 / PLAN + LAB ONLY / DRAFT/HOLD.** This is a *test-only acceptance contract*, not a permit, client consent, a production repair, a real-target check or release evidence.

## Why this exists

The canonical `Authorization(owner, reference)` is immutable in shape, but the current `Authorization.is_current()` checks only its optional time bounds. The existing `ScopePolicy.decide()` allows an explicit public host or network if this object exists and is current; it does not independently require canonical, nonempty owner/reference provenance. `ActivationGate.issue()` separately accepts an operator activation reference, which must never make missing *client* authorization lineage legitimate. The current `ExecutionPermit` model does not yet carry a separate `authorization_reference`. These are installed-source observations, not evidence of an external exploit.

## Isolated test matrix

New `tests/test_scope_299_legacy_provenance_red_20261015.py` runs real installed `lightup.models.Authorization`, `lightup.scope.ScopePolicy`, and `lightup.activation.ActivationGate` against fictional `review.example.test` and documentation IP `203.0.113.27` without socket/DNS/handler actions. The suite contains **6 ordinary green controls** (canonical host, canonical network, missing grant, expired grant, PLAN_ONLY and LAB_ONLY) and **6 deliberately expected source REDs**:

1. blank client owner with an explicit public host;
2. blank reference with an explicit public network;
3. whitespace-only owner;
4. padded owner and reference;
5. `str`-subclass owner, which cannot count as producer-canonical provenance;
6. `AUTHORIZED` activation with a valid operator marker but blank distinct client provenance.

One **strict RED oracle** replays the twelve cases separately and requires exactly the named six expected failures, six real normal PASS, no skipped/error/unexpected-success cases, and the concrete AssertionError cause. This distinguishes current-source missing rejection from a crashed or silently missing test. The suite counts thirteen *top-level* unittest methods; its private replay is diagnostic, not thirteen additional cases.

## Owner handoff and exact repair conditions

The original #299 source owner, coordinated with #100/#105 and activation owners, must make scope admission fail closed on anything but **exact built-in trimmed nonempty** `Authorization.owner` and `Authorization.reference`; falsy, padded, polymorphic or untrusted provenance must not authorize a public target or reach permit creation. Keep canonical public-host/network, expired/missing, PLAN_ONLY and LAB_ONLY behavior unchanged, and preserve caller-object immutability.

`AUTHORIZED` permits must carry a distinct, nonempty *client authorization* reference and the existing trusted *operator activation* reference. Neither operator approval nor a scope decision alone proves actual customer ownership, current trusted grant, tenancy or operator identity. Repairing only the permit display field would not fix the unsafe scope decision. The source owner should first adopt these failing assertions as ordinary PASS expectations after a narrowly reviewed source fix, then add cross-layer integration assertions for issuance, revocation, tenant/asset/risk/time and actual execution admission.

## Independent gates

- This PR adds only its own **new tests and documentation** to current main; no existing source, other worker paths, workflow, runner, customer records or active adapters are changed.
- No network, DNS, lab execution, real targets, scanning, synthetic grant persistence or permission elevation. `203.0.113.0/24` and `.example.test` are documentation-only identifiers.
- New acceptance tests do **not** claim a source fix or green production authorization. A passing suite with expected REDs is **NOT evidence the source is safe**.
- Before any promotion: exact-head hosted Python 3.11 + 3.14 with original logs, actual canonical registered VPS-run evidence (not an unassigned queue job), independently reviewed security/privacy, trusted customer and operator approval, explicit authorized lab isolation and human release decision.
- **NO MERGE, NO DEPLOY, NO GRANT, NO SCAN, NO REAL TARGET.** Owner-controlled source PRs #100/#105/#107 and existing #301 fixture repair remain separate.
