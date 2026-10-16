# Issue #299 — legacy public authorization provenance: current-main installed RED

**LightUp INCUBATE M3/M7 / PLAN + LAB ONLY / DRAFT/HOLD.** This is a *test-only acceptance contract*, not a permit, client consent, a production repair, a real-target check or release evidence.

## Why this exists

The canonical `Authorization(owner, reference)` is immutable in shape, but the current `Authorization.is_current()` checks only its optional time bounds. The existing `ScopePolicy.decide()` allows an explicit public host or network if this object exists and is current; it does not independently require canonical, nonempty owner/reference provenance. `ActivationGate.issue()` separately accepts an operator activation reference, which must never make missing *client* authorization lineage legitimate. The current `ExecutionPermit` model does not yet carry a separate `authorization_reference`. These are installed-source observations, not evidence of an external exploit.

## Isolated test matrix

New `tests/test_scope_299_legacy_provenance_red_20261015.py` runs real installed `lightup.models.Authorization`, `lightup.scope.ScopePolicy`, and `lightup.activation.ActivationGate` against fictional `review.example.test` and documentation IP `203.0.113.27` with an explicit no-socket/no-DNS monkeypatch on every installed-source case, and without any handler actions. The suite contains **9 ordinary green controls** (canonical host, canonical network, canonical inert AUTHORIZED host permit, canonical network permit, missing grant, expired grant, PLAN_ONLY, LAB_ONLY, and immutable invalid-input review) and **12 deliberately expected source REDs**:

1. blank client owner with an explicit public host;
2. blank reference with an explicit public network;
3. whitespace-only owner;
4. padded owner and reference;
5. `str`-subclass owner, which cannot count as producer-canonical provenance;
6. `AUTHORIZED` activation with a valid operator marker but blank distinct client provenance.

The six additional W3 source REDs cover non-string `None` and numeric owners plus boolean, bytes, list and foreign `str`-subclass references, on both public-host and explicit-network paths. Two additional ordinary green controls verify synthetically issued in-memory public-network permits still carry a distinct operator marker (no real execution) and that review does not mutate even intentionally malformed legacy provenance objects. **The raw source must reject noncanonical values before scope/activation, rather than merely format the resulting permit.**

One **strict RED oracle** replays the twenty-one cases separately and requires exactly the named twelve expected failures, nine real normal PASS, no skipped/error/unexpected-success cases, and the concrete AssertionError cause. This distinguishes current-source missing rejection from a crashed or silently missing test. The suite counts twenty-two *top-level* unittest methods (9 ordinary PASS, 12 expected RED, 1 strict oracle); its private replay is diagnostic, not a second normal discovery.

## Owner handoff and exact repair conditions

The original #299 source owner, coordinated with #100/#105 and activation owners, must make scope admission fail closed on anything but **exact built-in trimmed nonempty** `Authorization.owner` and `Authorization.reference`; falsy, padded, polymorphic or untrusted provenance must not authorize a public target or reach permit creation. Keep canonical public-host/network, expired/missing, PLAN_ONLY and LAB_ONLY behavior unchanged, and preserve caller-object immutability.

`AUTHORIZED` permits must carry a distinct, nonempty *client authorization* reference and the existing trusted *operator activation* reference. Neither operator approval nor a scope decision alone proves actual customer ownership, current trusted grant, tenancy or operator identity. Repairing only the permit display field would not fix the unsafe scope decision. The source owner should first adopt these failing assertions as ordinary PASS expectations after a narrowly reviewed source fix, then add cross-layer integration assertions for issuance, revocation, tenant/asset/risk/time and actual execution admission.

## Independent gates

- This PR adds only its own **new tests and documentation** to current main; no existing source, other worker paths, workflow, runner, customer records or active adapters are changed.
- No network, DNS, lab execution, real targets, scanning, synthetic grant persistence or permission elevation. `203.0.113.0/24` and `.example.test` are documentation-only identifiers.
- New acceptance tests do **not** claim a source fix or green production authorization. A passing suite with expected REDs is **NOT evidence the source is safe**.
- Before any promotion: exact-head hosted Python 3.11 + 3.14 with original logs, actual canonical registered VPS-run evidence (not an unassigned queue job), independently reviewed security/privacy, trusted customer and operator approval, explicit authorized lab isolation and human release decision.
- **NO MERGE, NO DEPLOY, NO GRANT, NO SCAN, NO REAL TARGET.** Owner-controlled source PRs #100/#105/#107 and existing #301 fixture repair remain separate.

## W2 — strict offline provenance-shape review (non-authorizing)

The branch now also owns **only two additional original paths**, `scripts/scope_299_legacy_provenance_review.py` and `tests/test_scope_299_legacy_provenance_review_20261016.py`, which do not install a runtime gate, write a database or touch anyone else's existing code. This deliberately supplements the installed-source REDs with an independent privacy-minimal diagnostic.

### Input / outputs

Run locally with **explicit opt-in** and a **fictional** JSON packet only:

```sh
printf '%s' '{"owner":"fictional-reviewer","reference":"NOT-CONSENT"}' |
  python -B scripts/scope_299_legacy_provenance_review.py --offline-synthetic-only
```

- Reads a maximum of **4,097 stdin bytes** to enforce **4,096-byte input ceiling**, with no pathname argument, file write, DNS, HTTP or socket use. Invalid command-line arguments never parse stdin.
- Enforces an **interpreter-independent JSON lexical nesting limit of 32**, counting brackets outside quoted strings only. This prevents Python 3.11/3.14 parser recursion differences (a 1,500-level array was accepted by one version), while literal brackets/escaped quotes within string values do not count. Full JSON decoding still validates all syntax and bracket types.
- Parses exactly one strict UTF-8 JSON object with exactly the lowercase keys `owner` and `reference`; **duplicate keys at any nesting depth**, extra/missing keys, trailing JSON, NaN/Infinity, bad encoding and oversized packets fail closed as malformed.
- Evaluates only exact built-in, already-trimmed, nonempty printable strings as a **canonical presentation shape**. That is deliberately more conservative than `str.strip()` and does **not** establish the issuer's identity, source-of-truth, tenant, engagement, asset, time, revocation or any other trusted approval.
- On syntactically valid input (canonical OR noncanonical), the CLI emits a bounded one-line `{"status":"HOLD", "reason":...}` receipt and **exit code 2**. Invalid packets/options get fixed reason `invalid_packet` and **exit 3**. It cannot exit zero through its public interface.
- Every receipt has **six permanent boolean false** flags: `can_authorize`, `can_dispatch`, `can_merge`, `can_deploy`, `can_scan`, `can_release`. No caller-owned raw owner, reference, exception or secret is echoed. Even `canonical_shape_only` is **HOLD**, not a result that may be promoted to execution.
- The new test module includes **17 independent top-level test methods**, exercises real synthetic subprocess execution, strict JSON and UTF-8 boundaries, secret non-echo, controls and aliases, subclass traps, fixed false-flag output and an AST-import whitelist. The only accepted imports in the diagnostic are `__future__`, `json` and `sys`.

### Integration / ownership

This diagnostic must **not** be wired into `ScopePolicy`, `ActivationGate`, `ToolExecutor`, the admin UI or customer authorization APIs by this worker. Real issuance and runtime check/use verification belong to source owners #100/#105/#107 and persistently authenticated customer/operator decisions. No synthetic client record or diagnostic claim may create real authority. Dedicated source RED acceptance must become ordinary green source PASS after an independently reviewed fail-closed repair; independent operator/consent, scope/risk/revocation, evidence-before-handler, VPS and security/privacy release gates remain outstanding.

Both new paths are self-owned on this PR. Keep in **INCUBATE M3/M7 / DRAFT/HOLD, no merge/deploy/scanning/grants**.

### Cross-interpreter preflight repair (W4)

Initial exact-head [hosted offline preflight #38827421796](https://github.com/Zennay/Lightup/actions/runs/38827421796) exposed one **own** cross-Python difference: the 1,500-array nesting fixture was rejected by Python 3.11, but Python 3.14's JSON parser accepted it, returning `noncanonical_shape/exit 2` rather than `invalid_packet/exit 3`. This was a **diagnostic input-hardening defect**, not external scan/authorization evidence. All other 36 own cases followed their expected results on 3.11, while 3.14 had this one distinct failure. Entire old hosted suites additionally still failed on unchanged owner #301 elapsed fixture; producer SKIPPED. The diagnostic now rejects depth above 32 **before parsing**, with explicit boundary and escaped-string tests; these fixes require a *new exact-head CI run* before PASS claims. No changes to source owners, existing tests or runners.


## W5 — atomic, non-authorizing fictional provenance-pair review

The single-record diagnostic cannot show whether **legacy client approval provenance has changed between two caller-supplied snapshots**, e.g. an owner/reviewer field or reference is silently replaced. New opt-in `--offline-synthetic-pair-only` adds a strict **before/after identity-drift witness**, still entirely non-installed and not a grant.

Usage with only fictional values:

```sh
printf '%s' '{"before":{"owner":"fictional-owner","reference":"NOT-A-GRANT"},"after":{"owner":"other-fictional-owner","reference":"NOT-A-GRANT"}}' |
  python -B scripts/scope_299_legacy_provenance_review.py --offline-synthetic-pair-only
```

The independent `tests/test_scope_299_legacy_pair_review_20261016.py` adds **18 real top-level subprocess tests**. The original single-record mode remains unchanged and remains separately covered. The pairing accepts *exactly* `before` and `after` dicts, each with *exactly* `owner` and `reference` of canonical syntactic shape. Mixed/missing/extra schema, duplicate JSON keys at any depth, invalid encoding, input exceeding 4,096 bytes and JSON nesting beyond 32 return `invalid_packet` and **exit 3**. Blank, control/whitespace, padded or polymorphic values in **either** snapshot make the entire pair `noncanonical_shape` and **exit 2**; the other half is not approved.

When both purely synthetic shapes are canonical, exact byte-for-byte *decoded string* equality gives `unchanged_shape_only` (exit 2); a different owner or reference gives `provenance_changed` (exit 2). Both results are bounded, deterministic and **always HOLD** with six `false` authority flags; neither is trusted customer consent, authenticated issuer provenance, revocation/current-grant evidence, scope permission, operator step-up or authorization. No raw values, tokens, targets, exception text or file paths are echoed. A matching user-controlled pair cannot prove immutability in the persistent issuer's records.

This W5 scope deliberately does **not** change source-owned `ActivationGate`/`ScopePolicy`/`ToolExecutor`, issue #1433's grant-amendment owner, other workers, CI workflows or runtime deployment. It creates an independent privacy-minimal *legacy owner/reference field* differential diagnostic only. All real authorization closure still belongs to #100/#105/#107 and the independent gate owners. DRAFT/HOLD, no merge, deploy, grant, scan or target interaction.

## W6 — installed-source permit lineage closure and scoped owner handoff

Issue [#299](https://github.com/Zennay/Lightup/issues/299) explicitly requires **distinct client authorization reference** on every `AUTHORIZED` permit and **no client authorization reference** on lab-only permits. The original W1–W5 tests proved public-scope admission defects but did not yet assert those two permit-field invariants directly.

Four additional precisely classified installed-source `@expectedFailure` requirements now cover:
1. `Authorization.is_current()` must fail closed on empty owner, even for otherwise current time windows;
2. `Authorization.is_current()` must fail closed on a dict-typed reference;
3. a synthetic `AUTHORIZED` public-host permit must separately expose `authorization_reference="FICTIONAL-CLIENT-NOT-A-GRANT"`, NOT just the distinct operator `activation_reference`;
4. the same separation must hold for explicitly authorized public networks.

Two additional ordinary controls prove `LAB_ONLY` can issue only an inert **loopback, no-client-authorization** permit without fabricating `authorization_reference`, and prove a canonical client `Authorization` stays current without mutating its fields. **Both modes construct only pure data and never call a handler, target or network**. The strict independent RED replay-oracle is updated from 21 to **27** real source acceptance cases (11 normal PASS + 16 intentional installed-source RED), plus the oracle itself = **28 top-level installed-source methods**. All own cases remain intentionally non-release evidence until source remediations are independently validated.

### Cross-branch source owner evidence (read-only)

Read-only inspection compared the current `main` installed source to active [source-owner PR #100](https://github.com/Zennay/Lightup/pull/100) exact HEAD `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`:
- `main` has no `ExecutionPermit.authorization_reference`, while #100 **already declares it** and passes the client `target.authorization.reference` into its inert `AUTHORIZED` permit; the client/reference *separation* piece is therefore **implemented on the other owner branch but not on main**, **not merged**, and cannot be misreported as a new production fix from this PR.
- Both currently inspected `Authorization.is_current` variants still focus on time (and #100 revocation) without canonical owner/reference validation. This **remaining #299 source rejection defect belongs to #100/#105 owners**.
- #100 adds asset and revocation checks; source-owner acceptance should retain those and not accidentally regress per-asset binding/revocation while adding canonical legacy provenance checks.
- `main` returns loopback scope without client authorization; `LAB_ONLY` issues `authorization_reference=None` on #100 as explicit separate field. Preserve this difference from true `AUTHORIZED` client provenance.
- The separate [#107 source-owner PR](https://github.com/Zennay/Lightup/pull/107) remains OPEN/DRAFT; live grant validity remains a separate time-of-use release prerequisite, even if canonical shape is fixed.
- The acceptance tests on this branch intentionally import **current `main` source**, not unmerged #100, so the `authorization_reference` RED represents **main's integration debt**, whereas the legacy provenance REDs additionally identify #100's unfinished source hardening. Owner should re-run/convert appropriate tests on their exact integrated SHA without rebasing or writing from this worker.

**Owner-only correction checklist:** require exact built-in trimmed, nonempty `owner` and `reference` before any public allow/permit; retain trusted asset/tenant/grant binding, valid-time/revocation and independent operator approval; populate distinct permit references for `AUTHORIZED` and none for lab-only; turn expected REDs into normal PASS only after source fix and log the actual exact-head CI/VPS proof. No real target, consent, grant, deployment, merge or active test is authorized by this document.
