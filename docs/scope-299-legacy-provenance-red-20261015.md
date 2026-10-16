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

## W7 — independent offline installed-source acceptance runner (non-authorizing)

Our current-main safety acceptance now has a **separate opt-in local test launcher**. Its purpose is to help the original source owners distinguish the #299 current-source RED debt from the unrelated, date-expired #301 whole-project CI failure **without falsely claiming the producer/whole CI is green**.

```sh
python -B scripts/scope_299_local_acceptance_receipt_20261016.py --offline-local-suite-only
```

The launcher uses exactly these three **preexisting own modules**, with `unittest.TestResult` but without invoking the entire repository test discovery:

- `test_scope_299_legacy_provenance_red_20261015` — **28** installed-source unit methods (11 ordinary controls PASS, 16 intentional source RED expected failures, one strict independent replay oracle PASS).
- `test_scope_299_legacy_provenance_review_20261016` — **17** hermetic single-record CLI test methods.
- `test_scope_299_legacy_pair_review_20261016` — **18** hermetic before/after CLI test methods.

That is **63 separately discovered methods**. The launcher itself **does not load the new launcher acceptance module**; its own `tests/test_scope_299_local_acceptance_receipt_20261016.py` contains **8 additional independent top-level tests** covering opt-in CLI, fixed HOLD-only and six false authorization flags, exact runner module whitelist and count, privacy non-echo, invalid target/scan/grant/path options and static import boundaries. After W7 the owned repo contains **71 top-level test methods total**, while the launcher verifies precisely the 63 pre-existing source/CLI methods to avoid self-recursive test execution.

All 63 cases run locally without real target interaction. The parent process blocks socket construction and DNS lookups during import/execution; the synthetic subprocess diagnostics themselves have fixed no-network import whitelists. The tool accepts **no source URL, network/target, policy, customer record, grant, input-file, runner, PR or release flag**. It returns exactly one bounded synthetic JSON receipt with `status=HOLD`, `evidence_class=local_untrusted`, and all six `can_*` fields `false`. Expected open source defects produce reason `open_source_reds_observed` and **nonzero exit 2**; missing/skipped/failing/unexpected-success tests or changed RED counts produce `contract_changed` and **nonzero exit 3**; absent or unexpected CLI arguments produce `invalid_command`, exit 3. No filenames, stack traces, identities or exception content are emitted in the receipt. Even an exact match means **16 SOURCE VULNERABILITY EXPECTATIONS REMAIN UNFIXED**, never remediation or permission.

This script performs **no GitHub/VPS/CI attestation**, checks no exact trusted Git SHA, cannot guarantee sandbox isolation against malicious code in local files, and cannot independently establish that a branch was reviewed or approved. It is a local self-review convenience, not cryptographic or durable evidence and not a real scope/approval control. The GitHub-hosted and permanently assigned VPS jobs must be separately checked on the exact new HEAD. The original source owners #100/#105/#107 still own real source repairs and final review.


## W8 — owner-portable installed-source acceptance; preserve #100 binding

The original #299 acceptance only exercised current `main` which lacks the `Authorization.assets` field added by unmerged [source-owner PR #100](https://github.com/Zennay/Lightup/pull/100), exact owner head `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f` at read-only review. Blindly copying the tests to that head **without** a matching fictional assets tuple would cause `AUTHORIZATION_ASSET_MISMATCH` rather than prove the missing legacy provenance check. This is an important source-branch regression-test fidelity gap, not a reason to weaken asset binding or modify their code.

Added entirely independent `tests/test_scope_299_owner_portable_acceptance_20261016.py`. The helper introspects *installed dataclass fields* and passes a synthetic `assets=(exact_target,)` to the legacy `Authorization` constructor **only when the installed branch actually declares that field**. When absent on `main`, no fictional asset-binding claim is made. This makes the **same installed test code** portable across current `main` and the independently maintained #100 source model, without monkeypatching source, bypassing the owner's asset/revocation checks or producing a real customer authorization.

This new pack contains **16 ordinary discoverable test methods**:
- **7 normal positive/negative controls**: exactly matching synthetic explicit public host and documentation network, missing client authorization and expired grant on both branches, inert `LAB_ONLY` loopback without client reference, an inert canonical `AUTHORIZED` permit preserving the distinct operator marker (and `authorization_reference` only when the installed model declares it), and no mutation of the synthetic client grant after inspection.
- **8 intentionally `@expectedFailure` *installed-source* REDs**: blank `owner` / blank `reference`, whitespace `owner` / padded `reference`, `None` owner / boolean reference on explicitly asset-bound public host/network, and direct `Authorization.is_current()` acceptance of empty owner/reference. These remain genuine outstanding #299 client provenance source failures even in the exact asset-bound #100 source shape unless repaired by its owner.
- **1 independent replay oracle** that demands exactly 8 *named* assertion-type source REDs, seven ordinary PASS, zero skipped, zero exceptions, zero unexpected successes; it fails if those source issues are fixed until the owner intentionally converts the expected-RED assertions to real normal green evidence.

All source imports are **current checked-out installed source**. This worker has only inspected #100 source remotely and has **not executed the portable tests on #100's exact Git commit**. A claim of owner-branch compatibility must still be demonstrated by the actual owner branch's own isolated immutable-head CI/VPS job; a green `main` test run is not owner-branch proof. Every fixture is fictional and sockets/DNS are forbidden. No handler or real target is invoked.

The local non-authorizing standalone `scripts/scope_299_local_acceptance_receipt_20261016.py --offline-local-suite-only` now includes this fourth *specific named* test module. Its strict contract is **79 source/synthetic CLI top-level cases**, of which **24 intentionally expected source REDs** (16 earlier + 8 portable), and no errors/skips/unexpected successes. It still returns exactly one synthetic `status=HOLD` / `evidence_class=local_untrusted` receipt with all six authority flags `false`, with nonzero exit code 2 only while the expected source defects remain; contract drift/invalid args yield exit 3. The separate eight dedicated receipt CLI guards remain **outside** this recursive test pack. Hence this branch now owns **87 distinct top-level test methods**, with 79 included in the opt-in local diagnostic and 8 self-checks on that diagnostic.

The owner's repair plan remains unchanged: fail closed on client provenance at current scope/permit gates while preserving actual asset binding, revocation, tenant, time-of-use and operator approval; source-branch owner must explicitly promote REDs after repair. The new portable tests are regression requirements, **not remediation and never permission to scan, grant, deploy or merge**. #301's existing date fixture and #1144 registered runner remain separate external dependencies.

## W9 — source-owner asset/revocation non-regressions before provenance repair

Two extra normal controls in the same **owner-portable** installed-source acceptance module protect the independent safety policies introduced on unmerged [PR #100](https://github.com/Zennay/Lightup/pull/100):

1. If and only if the installed `Authorization` defines `assets`, create one fictional exact-host grant for `review.example.test`, verify that a second fictional but explicitly configured host `other-review.example.test` is **rejected with `AUTHORIZATION_ASSET_MISMATCH`**, while the exact authorized host continues to match. A future #299 provenance fix must **not** widen asset acceptance.
2. If and only if the installed `Authorization` defines `revoked_at`, create a synthetic already-revoked, otherwise canonical grant with an exact asset, verify that both `ScopePolicy.decide()` and `Authorization.is_current()` **deny** despite matching host and client fields. A future #299 fix must **not** undo source-owner revocation.

When the **current main** lacks these owner-branch fields, the controls **explicitly assert the absence of the feature and do not claim that main has asset-binding/revocation safety**; they only become real enforcement assertions if installed source supports it. No skips, mocks of assets/revocation internals, or changes to #100's active source paths.

This raises the portable subset to **18 discoverable methods**: 9 ordinary controls including these two conditional owner safeguards, 8 intentional currently unfixed source REDs, and one strict oracle of exactly 17 real cases. The nonauthorizing local `--offline-local-suite-only` runner now checks **81** named tests (28 current-source +17 single CLI +18 pair CLI +18 portable), expects exactly **24 intentional source REDs**, rejects any error, skipped test or unexpected success; its 8 separate self-checks make **89 total own top-level methods**. Still **HOLD-only**, six hard-false capability flags, never exit 0. The branch on main can prove correct fixture selection and installed-source behavior, while the **specific owner #100 head must still independently execute its own tests** to claim actual asset/revocation branch compatibility.

## W10/W11 — actual independent execution against source-owner #100 immutable code

The earlier W8/W9 portable tests were only verified on `main`; that was insufficient to claim that the new #100 `Authorization.assets`, `revoked_at`, separate client `authorization_reference` and owner-specific `ScopePolicy` actually preserved scope safety.

A **separate one-file-only draft [PR #1469](https://github.com/Zennay/Lightup/pull/1469)** now targets the **existing unmodified owner PR #100 branch** `chatgpt/scope-authorization-revocation-20261006` at exact unchanged parent **`ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`**, without modifying owner files. Its current self-owned test-child commit **`5ecf3ea32dbce0c6df410b2877bcca8a2f069c79`** is **two commits ahead, zero behind and has exactly ONE fully NEW path** `tests/test_scope_299_owner_portable_acceptance_20261016.py` (+283/-0). This file is byte-identical on this standalone proof branch and our main-based #1468 branch. It is a test-only, disposable integration *child*, never a source fix or independent grant.

### Exact-source owner compatibility proven, not guessed

Original GitHub-hosted [offline preflight #38830799622](https://github.com/Zennay/Lightup/actions/runs/38830799622) separately read Python **3.14 job #116748872644** and Python **3.11 job #116748872985**, **on that exact source-owner child commit**. Both full suites report **`Ran 534 tests` + `OK (expected failures=10)`**. The 20 own top-level methods include **9 ordinary PASS controls**, including **ACTUAL owner branch** rejection for different asset, actual revoked grant denial, canonical exact-host/network and public permit lineage, plus **10 intentionally open #299 client provenance source REDs** (now 2 extra direct `AUTHORIZED` permit issue attempts proving operator marker cannot replace blank owner or blank client reference), and **1 strict replay oracle PASS**. These are current source defects, never release-ready authorization. No handler or target is invoked.

An **older** exact child commit `282d621d93341fb902ca937dbdd44cd00712770c`, [hosted run #38830631403](https://github.com/Zennay/Lightup/actions/runs/38830631403), also had both Python 3.11 and 3.14 full **532-test unit preflights SUCCESS with exactly 8 intentionally open source REDs** and separate **86-test producer integration jobs SUCCESS on both**. That older producer proof **does not automatically cover the newer 10-RED child commit**. Newer producer results must be examined independently, and separate registered self-hosted VPS CI is still an unmet exact-head requirement.

This proves the *compatibility of the currently installed #100 source with the portable test pack* and pinpoints real unsafe missing-client-provenance permit paths, **not the safety of issuing a real permit**. An actual remediation belongs entirely to source owner #100/#105/#107, must preserve asset/revocation checks, reject noncanonical `owner`/`reference` **before** public allow and permit issuance, and keep client and operator references separate.

### Separate #1468 current-main branch counters

Two added ordinary negative permit regressions live on both test-only branches and are `@expectedFailure` until source repairs. On this `main` acceptance branch, the independent local **non-authorizing HOLD** runner now checks **83** exact owned tests (28 installed +17 single CLI +18 paired CLI +20 owner-portable), **26 intentionally open source REDs** (16 originally installed +10 portable). Its 8 separate launcher self-checks bring the branch to **91** unique top-level methods. Exit remains **2** for observing expected open defects, **3** for changed/missing tests, six permanent false authority flags, no success exit, real grant, target scan or customer data.

Even if owner #100-hosted CI succeeds, it is **NOT** proof of trusted self-hosted VPS, full cross-branch merge readiness, customer/operator consent, independent security/privacy, threat assessment or explicit human GO. Mainline #301 date-fixture owner PR #1452, permanent LightUp runner #1144, per-tool risk-5 step-up #1172, pre-handler evidence #1454 and actual authorization repairs #299/#100/#105/#107 remain HOLD. No merge, deploy, grant, or active scan.

## W12 — actual owner-branch input-shape attack regressions and LAB isolation

The owner-source proof now also covers **exact legacy provenance byte-shape**, not only blank fields. Updated byte-identical test-only modules are committed independently on [main-derived PR #1468](https://github.com/Zennay/Lightup/pull/1468) and [source-owner-child draft #1469](https://github.com/Zennay/Lightup/pull/1469), with **no changes to source-owner files or base branch**. The extra tests carry precisely **fictional owner and reference fields with the exact public asset attached on #100**:

1. A `str` subclass supplied as `Authorization.owner` is not an exact canonical built-in string and cannot admit the explicit public host (expected source RED).
2. A byte string supplied as the client `reference` cannot admit the explicitly configured public documentation network (expected RED).
3. An **actual runtime embedded LF** within the synthetic owner, with no outer whitespace, must be denied before public host access (expected RED).
4. An **actual runtime embedded NUL** within the client reference must be denied before public documentation network access (expected RED).
5. An ordinary **positive lab-only isolation** control supplies a fictional, untrusted client Authorization to a loopback Target but demands that the inert LAB_ONLY permit still carries `authorization_reference=None` and does not mutate the synthetic client object. This specifically rules out provenance leakage in LAB_ONLY irrespective of optional input data.

The owner-portable installed source pack now has **25 top-level tests (10 ordinary controls, 14 intentional current-source REDs, one strict replay oracle)**. The main-derived nonauthorizing opt-in local receipt runner enumerates **88** exact named tests (28 original installed +17 single-CLI +18 pair-CLI +25 portable), requires **30 intentional source REDs** (16 original +14 portable) and rejects any unexpected source success, crashes, skips or wrong counts. The eight independent launcher self-tests bring the main-derived PR total to **96 unique top-level methods**. Every receipt still permanently reports **HOLD, six false capabilities, exit 2 or 3**. New original hosted exact-SHA and source-owner-hosted CI and separate VPS evidence must be inspected before claiming this W12 set proven.

This is still a test-only DRAFT/HOLD contract, not a real trusted issuer, grant, production source fix, release or permission to scan. #100/#105/#107 own actual source remediation; runner #1144, #301 expired main fixture and independent consent/privacy/security/human GO remain separate.

## W13 — fix own regression and contain local test stdout/stderr

The W12 **main-derived** hosted preflight originally failed at `compileall` **before any test discovery** because a previous scripted edit to our own new `tests/test_scope_299_local_acceptance_receipt_20261016.py` temporarily dropped two closing parentheses in the assertions for 88 tests and 30 source REDs. This was **our own syntax regression**, NOT the unrelated pre-existing #301 expired fixture. The missing parentheses were restored and the test title corrected to reflect four modules. Do not attribute this initial W12 compile failure to #301; only logs from a subsequent exact head can determine any remaining CI failure. Source owner #100's separately executed W12 child was not affected by our main-branch selftest file and had **all four hosted unit+producer jobs SUCCESS** at its own immutable SHA.

Further test-only hardening of the current-main HOLD diagnostic `scripts/scope_299_local_acceptance_receipt_20261016.py`: a bounded, discard-only `_DiscardOutput` stream is installed temporarily as `sys.stdout` and `sys.stderr` **while the local 88-case test suite executes**. This prevents accidental noisy test logs, raw exception details and injected fake JSON lines from leaking alongside the final single-line `status=HOLD` report, including when tests throw. Once the suite is finished, the original streams are restored, and the fixed JSON HOLD receipt is printed by the caller. **No values from test output are stored or echoed**; exceptions are already caught and collapsed to a fixed `contract_changed` failure status, always nonzero.

Two new **independent selftests** deliberately inject a noisy or raising in-process synthetic unittest suite and verify both stdout/stderr are empty and the launcher returns `False` (fail-closed). These selftests do not run inside the 88-case suite, so the standalone selfcheck set now has **10 unique methods** (up from 8), for **98 unique own top-level tests** in the main-derived PR. The opt-in suite still runs precisely **88 named methods with 30 intentional installed-source REDs** and always returns HOLD with six false authority flags, exit 2 or 3; no successful authorization, dispatch, scan, merge or deployment.

Caveat: this best-effort in-process output suppression assumes cooperative local test code, **not an OS-level sandbox**; malicious imported Python could still use raw file descriptors or bypass monkeypatching. It is not cryptographically attested, not a substitute for trusted CI/VPS isolation and never safe to run against arbitrary unreviewed code. The source-owner-test-only [draft #1469](https://github.com/Zennay/Lightup/pull/1469) remains separate and unaffected; no production source changes, merges, deploys or scans.
