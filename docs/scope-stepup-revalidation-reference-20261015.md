# #1173 — synthetic snapshot revalidation after an untrusted isolation probe

**State: DRAFT/HOLD · INCUBATE M3/M7 · PLAN/LAB ONLY.**
This is an **uninstalled offline race reference**, not a production safety repair, a permission system or an attestation of actual lab isolation.

## Ownership and files

This isolated branch adds three new paths only:
- `lab/scope_stepup_revalidation_reference_20261015.py`: pure in-memory review oracle.
- `tests/test_scope_stepup_revalidation_reference_20261015.py`: deterministic race, type and expiry regressions.
- This document.

It does **not** change [the #1172 operator step-up producer](https://github.com/Zennay/Lightup/pull/1172), [the #107 canonical executor](https://github.com/Zennay/Lightup/pull/107), [the independent #1451 real-executor RED acceptance](https://github.com/Zennay/Lightup/pull/1451), main, workflow YAML, ingress, runners, deployments or any customer records.

## What the reference actually checks

Only `lab-*` fictional identifiers can be loaded. Both exact-built-in datetime boundaries must be timezone-aware, strictly ordered and current. The synthetic review claim must exactly match run, tenant/client, engagement, asset, tool, capability and risk-5 reference. A separate tool-registry snapshot must match the requested tool/capability/risk.

A deliberately external `isolation_probe` callback runs **after** taking an epoch snapshot and **before** the final synchronized state comparison. Any update, revoke, reissue of the same values (ABA), or tool replacement increments the epoch. Revalidation atomically rejects changed epochs and claim/registry mismatches. All failures yield a generic `HOLD` object without customer fields. A consistent fictional snapshot yields only `REVIEW_ONLY`, never authority.

All six receipt flags are **literally false**: `authorization_verified`, `permit_issued`, `execution_enabled`, `dispatch_allowed`, `merge_approved` and `release_approved`. The sole side effect is a local in-memory review counter; no network, disk, database, subprocess, DNS, target, handler or exploit operation exists.

## Verification

Run from repository root:

```sh
python -m unittest discover -s tests -p 'test_scope_stepup_revalidation_reference_20261015.py' -v
```

The fifty-seven tests cover matching synthetic snapshot (review-only), revoked/missing grant, both temporal boundaries, seven mismatched identities, tool swaps, bad probe outcomes, same-thread revoke/swap/reissue, two synchronized cross-thread races, four-round concurrent four-reader revocation fanout, tool-registry ABA, revoke/restore ABA, and two frozen-request mutation/laundering canaries, caller-object mutation, wrong datetime values, string subclass/boolean/polymorphic shapes and redacted output.

The normal full project suite may run on GitHub-hosted CI. **Never conflate hosted tests with registered permanent VPS proof** or green unit tests with production safety.

## Critical remaining gaps: not solved here

1. The *current production/executor source* can still execute the wrong handler after review. This reference **does not lock across actual callback/handler invocation**. A last check on its own cannot close a post-check race; the executor owner must implement atomic/transactional registry + approval resolution across real admission/dispatch, including revocation.
2. Actual operator-only durable approval issuance, expiry/revocation, authentication, stable run/client/engagement/asset/tool/destination provenance and risk authority must be sourced from trusted persisted systems, not model data, local lab strings or an in-memory reference.
3. An installed, independently verified isolation/egress gate is required. Calling `isolation_probe=lambda: True` in these tests **never** proves physical/virtual machine isolation.
4. Every real executor entry point (including raw ToolExecutor), any actual handler and evidence persistence must deny before side effects on revoked/stale/mutated/untrusted state. Preserve original input and exact source identity; do not promote intentionally failing #1451 RED canaries to release evidence.
5. Owner integration, independent privacy/security review, exact integrated SHA hosted Python 3.11/3.14 + producer integration, a separately **permanently registered** VPS runner execution, and explicit human GO remain absent.

**Never merge, deploy, activate, issue real grants, scan real targets or claim a release pass from this reference.**

## Observed first hosted preflight (superseded before W2)

The first exact SHA `5c40664050fb6458d1553b167d303ce4b4aa8176` hosted preflight [#38760164774](https://github.com/Zennay/Lightup/actions/runs/38760164774) executed all 15 original new test methods **OK** on both Python 3.11 and 3.14. The full suite ran 1,252 tests and failed one **unrelated pre-existing** `test_scope_legacy_falsy_window_301_red_20261014.test_all_inputs_remain_unchanged_after_pure_scope_decision` because its fixed expiry time had elapsed; the owning [#301/#1452](https://github.com/Zennay/Lightup/pull/1452) fixture fix has not been imported. Producer jobs were skipped; overall check was FAILED, not green. W2 adds three own race methods (18 total) on a new immutable head: do not apply the older CI receipt to W2. Do not edit the fixture owned by another PR.

## W3 hardened caller identity (20 own tests)

The mutable caller-owned ReviewRequest is now copied to a fresh exact ReviewRequest **before** invoking any isolation probe. After the callback the reference rejects even a matching-looking mutated request, including a formerly out-of-scope request rewritten to match the trusted snapshot. This protects the in-memory **review-only** verdict against in-process data mutation; it does not authorize I/O or close real executor check/use races. New tests specifically corrupt the original frozen dataclass using `object.__setattr__` on both originally valid and originally invalid claims. All current hosted receipts from earlier immutable heads are superseded until this exact latest SHA is verified.

## W4 timezone callback safety

Only exact built-in fixed-offset `datetime.timezone` objects are accepted on review-window and evaluation timestamps. Custom `tzinfo` subclasses (including those capable of triggering arbitrary callbacks, errors or resource access) are rejected before invoking `utcoffset`, including while the ledger lock is held. An additional synthetic test uses a custom timezone that raises on invocation and proves **zero calls**. This conservative offline shape rule can reject otherwise sensible IANA `ZoneInfo` times; it does not replace the source owner's production time-policy design. A new exact-SHA run is required; the previous W3 checks cannot validate W4.

## W5/W6 synthetic seal, required isolation probe and fresh-time callback

A reviewer can no longer emit even `REVIEW_ONLY` without an explicitly callable `isolation_probe` returning the literal built-in `True`. Stored approval and tool snapshots have separately pinned immutable tuples of exact field values. This detects in-place tampering of supposedly frozen Python dataclass instances (including widening the original expiry timestamp) that does **not** increment the normal epoch. The tuples are **diagnostic canaries**, not a secure enclave: arbitrary Python code with access to the same process can still rewrite other private attributes or race after the final check.

A caller may additionally pass `fresh_clock_probe` to obtain a second synthetic datetime observation **after** the isolation callback. It must return an exact built-in aware datetime with an exact fixed-offset `timezone` and cannot move backward relative to `now`. If the new instant is at or beyond the exclusive expiry, the whole review yields `HOLD`; the clock callback runs outside the ledger lock, and revocation while it runs invalidates the epoch. Missing optional freshness callback intentionally means the initial **synthetic fixed instant** is used; thus `REVIEW_ONLY` must *never* be interpreted as current live consent or proof of freshness. A source owner must provide a trusted time source and verify immediately before real dispatch. The offline race oracle itself does not do so.

Ten new methods cover missing/noncallable isolation probes, approval expiry/registry in-place tampering, unchanged callers, only-once valid probe, expired/valid post-callback time, malformed/non-monotone times, revocation during clock read and invalid/erroring callback. Own suite now **46** tests, pending exact latest-head hosted verification. All previous run receipts are superseded.

**Release fence remains DRAFT/HOLD.** No customer identities, network endpoints, production wiring, grants, permissions, real I/O or scanning.

## W7 receipt integrity: no forged success labels

The standalone `ReviewReceipt.as_dict()` now emits only one of two strict and non-authorizing states. It validates exact built-in status/reason pairs and six literal `False` fields; if a caller constructs, subclasses or mutates a receipt to claim `APPROVED`, `RELEASE`, an inconsistent `REVIEW_ONLY` reason, a sensitive value or a truthy permission field, output collapses to generic `HOLD` with no sensitive identifier. **This constrains this reference's own output only; it cannot establish authenticity or defend against arbitrary hostile Python with direct class/code access.** Three synthetic tests cover forged status/reason, all six mutated flags and subclass confusion. Own suite: **41 isolated tests**. Older hosted receipts are not exact-current-HEAD proof.

The independent permanently registered VPS runner, integrated producer canaries, actual operator approval and execution gating remain required. No activation/merge/deployment.

## W8 result-instance isolation

The earlier `_HOLD` and `_REVIEW` global dataclass instances were shared by all callers. Despite `frozen=True`, test-process code could use `object.__setattr__` to rewrite the shared result status and contaminate **future** review receipts. Each call now creates its own `ReviewReceipt` value. The output serializer also catches deleted/missing receipt fields and produces a generic non-authorizing `HOLD` instead of an exception or leaked detail. Three real synthetic tests check HOLD poisoning, REVIEW_ONLY poisoning, and missing fields. The **43 own methods** are not production authorization checks.

The Python interpreter is not a trusted boundary against malicious in-process code; there is no production handler or release path in this branch.

## W9 strict synthetic step-up issuance chronology and expiry

`ReviewRequest` includes an exact fixed-offset aware `started_at` instant. An offline `ReferenceApproval` is now well-formed only when approval was strictly issued *before* the run began and the run began *before* the approval's exclusive expiry. Its total grant validity is no longer allowed to exceed **24 hours**. The synthetic review also rejects a clock observation prior to the submitted run start, and the separately sealed tuples pin this new timestamp across an untrusted callback. Four new regression methods require denial for post-run/equal-time approval, 24-hour-plus-one-microsecond windows, malformed run clock values and callback mutation of the run's start timestamp. Exactly 24 hours is accepted as a fictional review boundary but **never** as permission.

This is an offline policy oracle. It does not prove operator identity, tenant consent, durable issuance, revocation or real handler admission; those remain owned by source PRs #1172 and #107. New own suite **46 tests**, exact-latest-hosted and separate registered VPS CI status must be checked after the code changes.

## W10 actual hosted regression and receipt storage repair

Hosted [W9 preflight #38763523776](https://github.com/Zennay/Lightup/actions/runs/38763523776) on preceding immutable `9020e209...` executed 41 own methods but reported **two failing subtests** within the newly written deleted-field receipt regression on **both Python 3.11 and 3.14**, in addition to the unrelated original #301 date-expired fixture. The two failures were real own implementation bugs: a deleted frozen dataclass instance field could still be read as the `False` class default, so a partial result was incorrectly classified as REVIEW_ONLY. This was not an installed runtime/target test and **must never be counted green**.

The reference serializer has now been corrected to compare exactly the required eight keys of the **actual instance dictionary**, reject absent or extra fields before testing six literal booleans, and return a generic HOLD on malformed/subclassed values. Two additional tests independently pin Python's surprising `getattr` class-fallback behavior and injected private fields. New total **46** own tests pending new exact SHA verification. This corrects only synthetic receipt integrity, not real approvals.

Prior W9 and earlier hosted receipts are superseded. Full-suite #301 owner and permanent VPS runner remain unrelated independent gates. Keep DRAFT/HOLD.

## W11 exact timestamp representation seal

The previous review seal stored raw aware `datetime` values; Python considers two timestamps with different UTC offsets but the same absolute instant equal, and may also compare timestamps with different `fold` bits equal. A mutation of an already-approved timestamp into a different representation could therefore pass the purported exact representation seal. W11 now seals every approval-issued, expiry and run-start timestamp as a tuple of year/month/day/hour/minute/second/microsecond/fold/UTC offset, and checks the caller snapshot through the same canonical field extractor after the isolation probe. This is **review-only integrity**, not authorization or time-source trust. Three more tests assert that equal absolute time/different offset and equal datetime/different fold mutation produces HOLD, including one mutation of caller-held request during callback. Own suite **51 tests**; fresh exact-W11-hosted and registered VPS evidence still required. Do not promote older SHA results.

## W12 terminal revocation of disposable review lifetime

In the previous reference, `revoke()` cleared the stored approval but `replace_synthetic_reference()` could immediately reinstall an identical approval on the same reviewer. That left an implicit path to reinterpret a revoked in-memory run as fresh. The fixture now keeps a terminal `_closed` bit after revocation; it will reject any future approval or registered-tool replacement, including attempts using a **different** run ID. A genuinely separate synthetic run can only use a new `OfflineRevalidationFence` instance. A closed instance immediately returns generic HOLD without invoking an untrusted isolation verifier or clock callback; repeat revoke is safe.

Five real independent tests cover same-approval resurrection, different-run resurrection versus fresh reviewer, callbacks suppressed after revocation, attempted reinstatement from within the callback, and idempotent repeated revocation. The older ABA test now explicitly asserts that reinstallation is denied, rather than relying on an exception masked by HOLD. Own suite rises from 46 to **51 synthetic methods**, pending immutable final-head GitHub validation. This reference has no durable approval database: "_closed" is an in-process review-only canary, **not** actual production revocation or protection against arbitrary code within the process. #107/#1172 integration, real egress isolation, #301 fixture owner, registered VPS evidence, independent privacy/security and explicit human GO remain necessary. DRAFT/HOLD.

## W13 immutable intake snapshot consistency and deterministic mutation fixtures

The previous `replace_synthetic_reference` validated the **caller-owned** approval and registry *before* copying its request, timestamps and tool fields into the local ledger. A separate same-process actor could modify those supposedly frozen dataclasses between validation and copying. W13 now captures the exact approval and tool field tuples, copies them, and refuses intake unless (1) the copied grant and registry definitions are still well formed, (2) the copied field representations match the pre-copy seals, and (3) the original caller-owned values still match those seals immediately before storing the local snapshot. All checks happen before assigning the new ledger state. This narrows ordinary check/copy races; it is **not** a transactional or tamperproof guarantee against arbitrary hostile code or real dispatch.

Three new source-level deterministic fixtures use temporary `unittest.mock.patch.object` hooks on exact dataclass field reads (no timers/network) to change grant expiry into a forbidden >24-hour window, mutate a still-well-formed asset identity, and swap a still-well-formed capability during the actual copy point. Each must raise `ValueError` and leave the receiving local ledger entirely uninitialized. This raises the independent synthetic suite to **57 tests**, pending GitHub-hosted final exact-HEAD proof. Permanent registered VPS, source-owner #1172/#107 and #301 fixture remain independent gates. DRAFT/HOLD.

## W14 independent registry copy fence and revocation erasure

`replace_synthetic_tool` (the independent registry refresh endpoint) used to validate the caller's exact `ToolSnapshot` and later re-read its fields to install a new snapshot, without verifying the source remained unchanged in between. W14 now seals the original tool/capability/risk triple, constructs a new exact snapshot under the local mutex, then verifies the copied snapshot is still well formed and both copies exactly match the original before changing the registry epoch. An invalid or raced replacement preserves the original valid in-memory registry and epoch.

After terminal `revoke()`, both the approval and tool snapshots/seals are now discarded, so old synthetic capability metadata cannot linger on the closed reviewer. Three additional opt-in tests prove (1) a deterministically injected capability swap **during** standalone tool replacement is rejected without erasing previously approved synthetic state, (2) terminal revoke discards both reference halves, and (3) malformed tool replacement does not increment the epoch. No handler or network is involved. Own suite now **57 tests**; exact current-hosted and permanently registered VPS proof must be read independently before any outcome claim. DRAFT/HOLD.

## W15 pre-callback denial and single shared two-phase snapshot validator

Before W15, the offline reference took an epoch and invoked the supplied isolation probe **even if the current stored approval was absent, expired, for the wrong tenant/asset/tool/risk, or the registry seal was corrupted**. The outcome still HOLDed, but an unnecessary untrusted callback could do work, disclose metadata or make testing hard to reason about. W15 extracts one under-lock `_valid_snapshot_locked` contract (exact approval+registry lineage, original run start, time bounds and seals); it now checks that contract **before any user-provided isolation or clock callback**, and repeats the same full contract after those callbacks with epoch and caller identity revalidation. This is only an offline review reference, **not an installed runtime authorizer**. A fictitious callback returning `True` is not proof of isolation.

Six deterministic regressions assert no callback on missing/revoked, wrong-tenant/target/tool/risk, expired/premature and corrupted snapshots; valid ones invoke isolation and clock once each, and a legitimate registry epoch update during the callback must HOLD at the second phase. New suite **63** synthetic methods on three new owned paths only. Preceding W14 exact hosted proof of 57/57 owned tests is superseded until this head's logs are audited; existing #301 fixture, missing registered VPS proof and #107/#1172 integration remain unresolved. **DRAFT/HOLD · NO MERGE/DEPLOY/TARGET/GRANT.**

## W16 single-run approval lifetime and registry-rotation re-approval fence

The previous disposable offline reviewer could replace an existing well-formed approval with a different valid synthetic run/client/asset/capability or a widened approval expiry. A standalone tool-registry refresh with the **same public metadata** could also leave the old approval intact; a changed backing handler would not necessarily alter these three visible fields. W16 now pins the **first exact approved request and issuance/expiry shape** to one reviewer lifetime. Subsequent `replace_synthetic_reference` accepts only that identical seal; for a different run/target/capability or newly widened window the caller must construct an entirely new disposable reviewer and supply new review information. This prevents accidental authority laundering **inside the toy oracle only**; the data remains synthetic and not operator-signed.

Any successful `replace_synthetic_tool` now invalidates the current approval regardless of whether tool/capability/risk strings appear unchanged, while advancing the epoch. An explicit new intake of **exactly the previous synthetic approval** can resume *REVIEW_ONLY* for this toy fixture; **this does not prove a live operator reapproved a changed handler and must never be wired into real dispatch**. The real owner must instead bind immutable trusted registry/handler version and durable operator decision atomically at actual handler invocation. Terminal revoke removes even the internal pinned synthetic approval history.

Six new tests assert no retargeting to another run, tenant, engagement, asset or capability and no expiry widening; same-value registry refresh invalidates a previously reviewed record without firing untrusted callbacks; identical re-intake is structurally review-only; revoke erases the synthetic bound lineage. With W15's six callback-gating regressions, suite grows from **57 to 69** non-authorizing unit methods. Exact-head GitHub 3.11/3.14 hosted, producer and separate permanent registered VPS checks remain required; a green *own* matrix would **not** resolve the pre-existing #301 fixture or #107/#1172 real-source admission gaps. **INCUBATE · DRAFT/HOLD.**

## W17 damaged or incomplete in-memory records must HOLD, never crash

Even a `frozen=True` Python dataclass can lose a required field in-process through `object.__delattr__`. Before W17, `ReviewRequest.is_synthetic()`, `ReferenceApproval.is_well_formed()`, `ToolSnapshot.is_well_formed()` and the locked snapshot comparison could propagate `AttributeError` or another shape-related exception instead of rejecting the record. The offline reference now deliberately treats absent/wrong-typed request, time, approval and tool fields as invalid in the three shape validators and the shared two-phase snapshot validator. Generic results remain `HOLD / not_verified`, six permission fields false, and an impossible state is refused **before calling the supplied isolation or clock callback**.

Five extra test methods exercise **20 malformed-field subcases**: eight deleted request fields, three deleted intake approval fields, three deleted intake registry fields, three damaged stored approval fields and three damaged stored registry fields. They prove initial intake rejection without changing the existing epoch, review HOLD without invoking user callbacks on damaged current snapshots, and preservation of a previously valid synthetic review when an invalid replacement is refused. Own total grows from **69 to 74 test methods**. This hardens toy-data handling only. Trustworthy persisted consent, non-model operator identity, genuine lab isolation, immutable tool dispatch and external authorization are **not** implemented by this file. Source owners #107/#1172 and independent red gate #1451 remain responsible. All outputs DRAFT/HOLD, never authority.

## W18 deletion exactly during intake or final review

W17 covered already-missing dataclass fields, but a mutation at the exact **check → copy** seam could still trigger uncaught `AttributeError` while composing the private review snapshot, or during the second lock-held request comparison. W18 now normalizes shape-related `AttributeError`, `TypeError` and `ValueError` at these read boundaries. For admission/intake the operation raises an opaque, documented `ValueError` **without changing the original approval, registry or epoch**; for a review result it emits generic `HOLD/not_verified`. Corruption of an installed approval or tool *during* the isolation callback is denied at the second review phase.

Five additional deterministic regression methods use temporary field-read interception or callback mutation and prove: deleted asset during approval copying causes generic `ValueError` without partial store, deleted caller asset during review copying causes HOLD without calling the verifier, deleted capability during standalone registry replacement preserves the former valid snapshot, and deleted approved expiry or capability **after precheck** denies without incrementing the successful-review counter. No real handler, filesystem, network, target, grant or proof bundle is involved.

Total **79 synthetic offline unittest methods** across this owned branch; exact-final-HEAD Python 3.11/3.14 hosted, real producer integration and separately permanently registered VPS jobs must be verified, and the full suite may still fail the independently owned #301 clock fixture. Neither this sample's read-lock nor generic HOLD constitutes the installed source-owner fix for #1173, real isolation or approval authority. DRAFT/HOLD, no merge/deploy/scans.
