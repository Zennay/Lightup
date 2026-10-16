# #1480 — ActivationGate issuance instant vs authorization expiry (source acceptance)

**Status: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This independent source-facing test is not a patch to runtime authorization and does not enable any network action. Original policy owners retain `src/lightup/activation.py`, `models.py`, `scope.py`, plus #1476 policy-lifetime acceptance and #301 time-shape acceptance.

## Verified source contract and why it matters

On immutable `main` commit `e73b7445c87ad239bdb03c50a99078ef93163b02`:

1. `ActivationGate.issue` calls `ScopePolicy.decide(target)`, which can call `Authorization.is_current()`.
2. For `AUTHORIZED`, `ActivationGate.issue` calls `Authorization.is_current()` again.
3. **Only after both checks**, the returned `ExecutionPermit.issued_at` is stamped using another `datetime.now(timezone.utc)`.

A fabricated finite `.example.test` authorization can be valid at step 1 and 2, but already expired at step 3. The permit then records an issuance instant later than the authorization's `valid_until`. This is **not** a claim of a remotely exposed exploit, runtime tool invocation, real customer consent, durable grant existence, or asset interaction. The existing application has other authorization checks; no conclusion is made about external exploitability.

## Independent tests

`tests/test_scope_1480_activation_issuance_instant_20261016.py` uses only stdlib `unittest` and temporary `unittest.mock.patch` of the module-imported `datetime` names, not the system clock, file system, network or running services. `INSIDE` is one second before `valid_until` and `OUTSIDE` one second after.

- Ordinary controls: distinct UTC clock canary; allowed exact authorized public asset within the whole window; inclusivity at exact expiry; expired-at-check denied; PLAN_ONLY denied; LAB_ONLY cannot issue for fictional public target; unknown public asset denied.
- **One deliberately OPEN `expectedFailure`** requires the installed `ActivationGate` to refuse an authorized permit when its eventual `issued_at` is beyond the original grant window. The original implementation currently permits the two-clock case. A source repair should turn this into an ordinary positive test, not leave the known RED disguised as a green release.

The owner should establish a consistent authorization decision/issuance instant, ensure no time-window widening across policy, tenant, engagement, asset, risk and capability gates, and preserve revocation checks when integrating. Simply changing the expected test value, deleting an authorization check, or modifying system time does not satisfy the invariant. Document how issuance and subsequent actual tool dispatch are separately revalidated. The policy-lifetime rebinding issue #1476 and polymorphic/falsy datetime issue #301 are independent.

## Reproduction and promotion

From the exact checkout of this branch, only run:

```bash
PYTHONPATH=src python -m unittest -v tests/test_scope_1480_activation_issuance_instant_20261016.py
```

If unittest package discovery dislikes direct module-path notation, use:

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_1480_activation_issuance_instant_20261016.py' -v
```

An overall process exit of 0 while one test is an **expected failure** demonstrates only the test harness and an **unrepaired source gap**; it is never authorization, approval, or production repair evidence. Check original complete logs for exact head, both Python 3.11 and 3.14 and permanent VPS runner proof independently. Unrelated #301 wallclock fixture can currently fail full hosted suite; its owner #1452 owns that repair. Never silence that failure or claim the full suite passes based on this focused acceptance.

**Release blockers:** original source-owner review and true source fix, all REDs promoted after repair, original client/operator consent, durable live revocation, independent privacy/security review, exact-head full hosted and registered permanent-VPS proof with real hostname/runner, and explicit human GO. **Do not merge, deploy, activate grants/handlers, run scans or access real targets** on this branch.


## W2 — strict opt-in source provenance and non-authorizing result (2026-10-16)

Three additional **self-owned, new** proof paths/runner tests protect this acceptance from accidental false green:

- `scripts/check_scope_1480_source_acceptance_20261016.py` first verifies the installed `src/lightup/activation.py` bytes against original Git **blob SHA `156e94c18d5221b3d55e2c9fff4e393369e0f38e`** without trusting branch metadata or spawning Git. A missing, replaced, symlinked, oversized or unreadable original source -> `HOLD` before any tests. This check is not a signature and cannot attest VPS/consent.
- It then executes **only** the eight original-source acceptance methods and requires exactly seven ordinary successes plus **one explicit original-source expected RED with assertion text** `PermissionError not raised`. Any ordinary failure, error, skipped test, unexpected source repair, or different RED traceback -> `HOLD` and nonzero. JSON `REVIEW_ONLY` is narrow harness validity, **never** production source repair or release authority. All eleven permission/release/scan/CI/consent boolean fields remain false.
- `tests/test_scope_1480_runner_integrity_20261016.py` verifies exact original installed source fingerprint, rejects a deliberately altered fingerprint with zero test execution, and exercises the real strict harness, checking that no flag can grant production authority.

Opt-in targeted reproduction from exact branch:
```bash
python scripts/check_scope_1480_source_acceptance_20261016.py
```

**Do not use the strict harness to bypass the full hosted suite failure under #301 or replace permanent VPS evidence.** Any eventual real owner source fix intentionally invalidates the old pinned blob and must be separately reviewed, then all expected RED markers formally promoted to ordinary PASS before independent full CI and human approval.


## W3 — actual reusable but entirely UNWIRED production-adjacent reviewer

New **separate**, pure module `src/lightup/activation_issuance_window_review_1480.py` provides `review_issuance_window(authorization, issued_at)`: exact built-in `Authorization` and `datetime` identity, explicitly finite original UTC bounds, inclusive chronology and no temporal widening. Missing, non-UTC, polymorphic, inverted, early and late instants all yield immutable **`HOLD`**; canonical within-window returns only **`REVIEW_ONLY`**, *never* `allowed`, execution permits, a grant, dispatch, consent or deployment. It reads only caller-provided values; no `datetime.now`, files, SQLite, sockets or subprocess. It is **not called by the real ActivationGate** and does not fix #1480 until the original source owner integrates a consistently sampled issuance boundary.

New `tests/test_scope_1480_issuance_window_review_20261016.py` has **10 ordinary standalone tests** of finite bounds, exact inclusive edge, expiry/early/inverted/missing/naive/poly types, subclassed auth, immutable nonauthorizing results and mocked socket exclusion. These do not replace the installed original source RED or attest actual consent. No existing runtime or another worker's paths were changed.

A source owner may reuse the pure metadata reviewer only after independently deciding whether strict exact UTC/finiteness constraints match product requirements and adding real installed grant/revocation/tenant/capability tests. Promoting old source RED demands runtime changes and independent human security review, not simply a REVIEW_ONLY output.


## W4 — local original-RED repairability and monotonic two-instant reference

- New self-owned `tests/test_scope_1480_local_source_reference_20261016.py` calls the *actual installed* original `ActivationGate` with fictional identifiers. It observes the unpatched original expired synthetic permit; then a `unittest.mock.patch.object` wrapper exists **only during the test**, uses the pure reviewer to discard such a synthetic permit, and runs the literal original expected-RED body as a **plain PASS**. Canonical in-window issuance and PLAN_ONLY/expired denials still behave normally; patch cleanup verifies original production source restored. This is a controlled repairability witness, **NOT** a production/runtime fix and not a new deployment adapter.
- New strictly non-authorizing `review_issuance_transition(authorization, checked_at, issued_at)` alongside the existing source reviewer verifies **both** exact caller-provided UTC instants fall inside the original bounded grant window, with `issued_at >= checked_at`. It yields only immutable `REVIEW_ONLY` or `HOLD` and never samples a live clock. A caller can spoof these values, so it cannot prove consent, grant ownership, revocation or permission to execute.
- New `tests/test_scope_1480_issuance_transition_20261016.py`: ten ordinary tests for inclusive windows, same-instant controls, false early/late transitions, rollback/reordering, datetime subclasses, missing authorization and read-only input. Pure reference remains completely **UNWIRED** and cannot invoke tools/handlers, issue permits, access real assets, or change authorization.

**Owner adoption contract:** real `ActivationGate.issue` / dispatch owner must choose a trusted, coherent authorization time sampling/linearization point and apply durable revocation / target / tenant / capability checks. Do not turn a supplied REVIEW_ONLY oracle output into authorization. `#1480` expected RED must remain until original installed source is actually repaired; any promotion requires independent safety review, full hosted CI and permanent VPS evidence before human GO.


## W5 — coherent original-bound snapshot across both reviewed instants

The pure `review_issuance_transition` now captures **one** in-memory immutable `Authorization` snapshot of original `valid_from` and `valid_until` before either temporal review. A caller retaining the original frozen dataclass can otherwise force `object.__setattr__` in a synthetic interleaving to widen the second read. The reviewer never lets the second instant see an expanded window even when the original held input is changed mid-review.

A dedicated **race-canary ordinary PASS** mutates the caller-held input after the first helper call, proves the deliberate widening happened only to that object, proves both reviews used the **same independent snapshot**, and still requires `HOLD: issuance_after_approved_window`. This is purely in-process; nothing reads external clocks, customer records, authorization sources or handlers.

New strict opt-in checker now runs **33 own source/reference methods**: 32 ordinary controls + exactly **one original installed-source expected RED**; separate 3 runner integrity tests verify the checker. The checker returns never-authorizing REVIEW_ONLY/HOLD, not a full-suite/CI bypass. **Original ActivationGate remains unchanged and unsafe at the observed narrow issuance race until source owner fixes it.**


## W6 — review verdict structure hardened against frozen-dataclass bypass

The standalone `IssuanceWindowReview` result is now a slotless `NamedTuple` rather than a frozen dataclass: Python's `object.__setattr__` can otherwise forcibly change a frozen-dataclass Boolean despite a normal assignment throwing `FrozenInstanceError`. The owned regression now verifies **both** ordinary assignment and direct `object.__setattr__` reject release-flag rebinding and the review record has no instance `__dict__`. This is just a structural safeguard: any caller may fabricate a new value object, so **even a REVIEW_ONLY result must NEVER be treated as grant/consent/permit/dispatch/release authority**. All owner-consent/revocation and runtime dispatch decisions remain independent; no live handlers/permissions/source owner edits.


## W7 — exact-case manifest + deterministic temporal matrix

The opt-in `scripts/check_scope_1480_source_acceptance_20261016.py` now hard-pins the **full, explicit set of 36 TestCase method IDs**, not just the number of tests. It recursively enumerates loaded unittest suites before executing any test and fails closed with nonzero `HOLD: test_inventory_mismatch` on missing/duplicate/replaced/unexpected cases, even if the total count matches. It also verifies the **exact fully qualified original expected source-RED test ID**, never a substring. The six independent runner-integrity methods include positive loaded-inventory proof; count-preserving method substitution, duplicates and truncation detection; and an in-process tampered manifest proof that rejects before any `TextTestRunner.run` invocation. This remains a local review helper and cannot attest signed CI, production source behavior, or customer authorization.

Additional purely deterministic evidence in existing own modules: **2,500** seeded check-to-stamp combinations spanning before, during and after grant validity; **352** synthetic closed-interval boundary pairs; 12 explicit non-UTC offset cases. Each observes structurally allowed or denied review state and confirms all actual grant/scan/dispatch/release flags stay false. No real assets, live time, sockets or workers.

On this source-acceptance branch the strict CLI target is now **36** methods: 35 ordinary controls and one intentionally OPEN original-source RED. The additional **six** separate runner-integrity controls mean **42 own unittest methods** in a full-suite run. Changes remain restricted to existing eight own branch paths, with original ActivationGate source and other owners untouched. Do not interpret the expected RED as a fixed source or the CLI exit code as any release approval.


## W8 — pin exact original proof bytes, not just unittest names

The review-only CLI now rejects **any** drift in five independent reviewed Git blob objects *before loading/executing tests*: all four exact source/reference test files plus the isolated pure `activation_issuance_window_review_1480.py` source. In addition to pinning original `activation.py` and exact **36 unittest method IDs**, it checks the exact Git SHA-1 blob framing (`b"blob <size>\\0" + original bytes`), rejects symlink/missing/oversized inputs and emits only non-authorizing `HOLD: review_material_blob_mismatch` on a mismatch. Two new normal runner tests verify these five trusted local sources and that substituting a source digest causes early HOLD with **zero** test execution. No direct network, subprocess, customer interaction or runtime permission.

This is an **evidence-drift guard, NOT an adversarial signature or proof of green permanent CI**. A malicious committer able to alter both verifier and manifest can fake local evidence. Review must compare original immutable Git objects externally, inspect hosted CI logs and original registered VPS runner proof. Byte pins must be deliberately updated and reviewed if the true source-under-test changes; never auto-mint approval from a green local runner.

Targeted opt-in checker: `python scripts/check_scope_1480_source_acceptance_20261016.py`. The reviewed workload remains **36** exact methods (**35 ordinary + one still-open expected original-source RED**); eight independent runner-integrity controls now bring ordinary suite coverage to **44 own methods total** (43 ordinary + 1 unresolved source RED). `REVIEW_ONLY` always refuses all 11 release/permit/scan/dispatch/consent/VPS flags.


## W9 — malformed exact authorization objects and atomic caller-field snapshots

The installed `models.Authorization` type is a `@dataclass(frozen=True)`, but CPython permits `object.__new__(Authorization)` without required fields and `object.__delattr__`/ `object.__setattr__` mutations. The earlier entirely unwired reviewer read `authorization.valid_from`, `valid_until`, `owner` or `reference` separately; a malformed exact-class instance therefore raised `AttributeError` instead of a controlled `HOLD`. This is a gap in the **optional pure reviewer**, not evidence of another discovered live `ActivationGate` exploit.

Our own pure `review_issuance_window` now snapshots original `Authorization.__dict__` via `vars(authorization).copy()` once and returns `HOLD: noncanonical_finite_utc_window` for missing bounds. `review_issuance_transition` snapshots the full original owner/reference/from/until field set exactly once before constructing its standalone read-only synthetic authorization and returns `HOLD: check_noncanonical_authorization_fields` if any original field is missing. A single original field snapshot prevents splitting the validity window into two independent property reads; **no trusted wall-clock read, original source modification, network, or permission issuance**.

Six new ordinary regressions cover missing/partially erased date bounds, owner/reference erasure, constructor-free exact-class object, and explicit `Authorization.__getattribute__` traps proving neither reviewer performs separate live bound property reads. Entire 42-case opt-in source check now hard-pins the five current reviewed Git blobs and all 42 exact method IDs: **41 ordinary PASS required, one deliberately OPEN original-source expected RED**. Eight separate strict runner tests bring complete owned test count to **50** (49 ordinary + one source expected RED). Every published verdict remains no-authority.

The source issue remains #1480; original runtime owner #122 must independently select coherent linearization of real authorization check/permit stamp. This fix does not give owner consent, live revocation, capability permission, or release, and expected original `ActivationGate` RED remains.


## W10 — actual original-source lifetime shrink between two authorization checks

The unchanged installed original `ScopePolicy.decide` and `ActivationGate.issue` each calls `Authorization.is_current()` for the same fictional explicit public host. The additional exact-original-source test temporarily patches **only the in-process `Authorization.is_current` method** to force-shrink the held synthetic `Authorization.valid_until` via `object.__setattr__` **immediately AFTER its SECOND successful check**. Both original checks return true, but the original `ActivationGate.issue` then stamps a permit later than its newly expired authorization. This reproduces a distinct post-check mutability/time-of-check window inside the existing #1480 context. It is an intentionally synthetic local mutation; **not a claim that a real unauthenticated remote party can force this state**.

A second normal test holds the same synthetic mutation while applying the already existing temporary **test-only** `ActivationGate.issue` wrapper, confirming the wrapper rejects the now-invalid synthetic permit with `PermissionError` and restores original source afterward. The real original `ActivationGate`, `scope.py`, `models.py`, all other owners' work, handler code and runners remain untouched. The original expected source RED stays unresolved.

The strict local non-authorizing checker requires **44 exact source/reference/pure reviewed method IDs** (43 ordinary expected PASS + **1 still-open original source expectedFailure**) and current five Git blob pins; eight additional runner-integrity methods imply **52 owned unittest methods total** in full suite (51 ordinary expected PASS + one deliberately open source RED). Exact-head original hosted and permanent registered VPS CI evidence is still required. **DRAFT/HOLD, no permission to run real target/handler/scan/grant**.


## W11 — exact installed transitive authorization dependency closure

The original `ActivationGate.issue` doesn't implement all checks alone: `ScopePolicy.decide` in `src/lightup/scope.py` and `Authorization.is_current` in `src/lightup/models.py` are executed as part of its source acceptance. Previously the original `activation.py` blob and the five local reviewed artifacts were pinned, but **silent drift in these two original runtime dependencies** could yield a false locally compatible result. The strict checker now pins exact immutable baseline Git *blob bytes* for both original source dependencies (`scope.py` = `23909917822b5630c76be0cb47c99e1549b30cf8`; `models.py` = `74b96d45a5308d39e2c4c930728e10a2ccc18d2a`) and returns nonzero `HOLD: original_authorization_dependency_blob_mismatch` before tests on any mismatch. It still pins unmodified original `activation.py` = `156e94c18d5221b3d55e2c9fff4e393369e0f38e`, four owned test files and the isolated pure review file. None of these original sources are edited by this branch.

Three extra independent ordinary tests prove the two dependency pins, altered `models.py` or `scope.py` manifest digests produce HOLD with zero test execution, and a missing original dependency path also fails closed. The optional verifier's source/test compatibility result remains **REVIEW_ONLY**, never a trusted signature, permission, consent record or CI success indicator. Registered permanent runner, exact-head hosted source logs, real client+operator approval, live revocation and the original source owner's runtime fix are still mandatory.

**Ownership:** source changes in original `models.py`, `scope.py` or `activation.py` must come through their separate owners; this verifier must hold on any such change until its baseline and source-specific tests are independently revised. The original source expected RED remains deliberately open. Current acceptance suite remains 44 exact source methods (43 ordinary + 1 original unresolved expected source RED), with **11 separate strict harness tests** (was 8): **55 own total**.


## W12 — reproducible, machine-readable local source evidence (non-authorizing)

`python scripts/check_scope_1480_source_acceptance_20261016.py` now emits one deterministic JSON record for operator review whether the run is `HOLD` (nonzero) or narrow `REVIEW_ONLY` (exit 0). Its additional self-reported fields include:
- `original_activation_git_blob`, `original_dependency_git_blobs` (original `models.py` and `scope.py`) and `reviewed_local_git_blobs` (four review tests and the pure reviewer): exact expected original Git blob hashes, **not signatures** and **not independent observed repo attestations**;
- `expected_case_count=44` and `expected_case_manifest_sha256`: a stable SHA-256 digest of the *lexicographically sorted, LF-joined 44 fully qualified test IDs*;
- `evidence_manifest_version=1`, `evidence_self_reported=true`, and **`independent_ci_attestation=false` under EVERY status**;
- unchanged always-false `source_fixed`, `full_suite_green`, `permanent_vps_proven`, `consent_verified`, `revocation_verified`, `may_issue_grants`, `may_dispatch_tools`, `may_scan_targets`, `may_merge`, `may_deploy`, `release_authorized`.

Three additional ordinary tests verify canonical LF digest, source/review manifest content, all non-authorizing flags in REVIEW_ONLY, and HOLD carrying diagnostic provenance without becoming an attestation. This is machine-readable evidence for a human reviewer, not permission for production. The strict source acceptance still executes **44 pinned exact methods**, 43 regular and one intentionally open original runtime expected RED. **14 independent harness integrity tests** (11 existing after W11 plus three here) bring this branch to **58 OWN unittest methods: 57 ordinary controls + one deliberately OPEN source expected RED**. No runtime source or other worker branch changed.

Original source owner must still fix the actual issuance race. Full original hosted CI and permanent registered runner proof must be independently inspected at the **exact final head**; unrelated #301 test-fixture owner and #1144 VPS operator remain distinct. **DRAFT/HOLD.**
