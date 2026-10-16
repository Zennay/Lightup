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
