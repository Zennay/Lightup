# Issue #1487 — LAB_ONLY permit provenance (offline source acceptance)

**Posture:** LightUp INCUBATE M3/M7; PLAN/LAB ONLY; **DRAFT/HOLD**. This branch is *only* additive tests and documentation. No original `activation.py`, `scope.py`, `models.py`, service, workflow, worker-owned branch, runner or deploy change.

## Installed-source observation on main e73b7445c87ad239bdb03c50a99078ef93163b02

`ActivationPolicy.validate()` checks presence of `activation_reference` only for AUTHORIZED. `ActivationGate.issue()` currently uses `activation_reference or "LAB"` for LAB_ONLY. As a result an omitted/empty reference stamps the same literal `LAB` in independent synthetic permits, a whitespace-only value remains whitespace, and truthy arbitrary objects can become permit audit references. The source generates distinct random `permit_id` values; this finding **does not imply permit-ID collisions** or prove a real handler/adapter consumed such a claim.

This is a *new LAB_ONLY operator/session provenance decision*, not issue #498's AUTHORIZED reference identity, #125's mode enum identity, #1476's policy rebinding, #1480's time-of-issue check, or issue #120/#726's capability binding. It is not an authorization grant, exploitation report, or customer consent.

## Deterministic offline acceptance

Run against **actual installed source**:

```sh
PYTHONPATH=src python -m unittest tests.test_scope_lab_reference_provenance_1487_20261016 -v
```

- Ordinary controls: explicit canonical synthetic LAB reference is embedded in the returned in-memory permit; PLAN_ONLY denies; LAB_ONLY never promotes an explicitly authorized public fictional name into lab scope.
- Ordinary *current source witnesses*: omitted or empty reference stamps `LAB`; whitespace remains; numeric and `str` subclass references propagate. These ordinary witnesses prevent an unrelated exception from being mistaken for a source RED.
- **Four deliberately unresolved `expectedFailure` contracts:** missing, whitespace-only, non-string and `str` subclass reference should be rejected during gate construction. They are **not passing security repairs**. After the original source owner actually fixes construction, update the witnesses and remove all expected-failure markers only if the strict assertions then genuinely PASS.
- During each test the socket factory, DNS resolution, subprocess launcher and shell invocation are patched to fail; all targets are fake loopback or `.example.test`; the permit remains an in-memory dataclass and nothing is dispatched.

## Source owner decisions and safe handoff

1. Determine whether every LAB_ONLY lab *session* needs a durable, independently authenticated operator/run reference (stronger than exact-string syntax). Prefer explicit user/operator evidence over accepting any string as permission.
2. Require exact `str` (not subclass), bounded and non-blank canonical reference at the trusted policy construction boundary if this design is approved; decide whether PLAN_ONLY should reject/ignore unused references separately.
3. Preserve real activation mode typing, scope classification, grant/revocation, target-capability binding, tenant/risk limits and installed ingress/egress. An audit reference alone MUST NEVER grant authority.
4. Independently review the original source owner branch, host CI on exact immutable HEAD **and separately prove a canonical registered VPS run**, followed by consent, privacy/security and human GO. Hosted test green with expected REDs is not a release decision.

**Never merge, deploy, enable live scans, issue real grants, call tools, or touch real assets as part of this draft.**

## W2 — independent review-only batch helper (not wired to the gate)

The new optional `src/lightup/lab_reference_review_1487.py` provides `review_lab_reference_batch(object) -> LabReferenceReview`. It **does not modify** `ActivationPolicy`, `ActivationGate`, `ScopePolicy`, a grant, an adapter, handlers, CI or the installed source owner. It neither reads trusted records nor performs any I/O. This is a conservative **offline syntactic preflight only**, not a client/session authority proof.

- Exact built-in tuple of **1–64** built-in strings; each reference **8–128** ASCII characters with conservative `LAB-` uppercase alphanumeric hyphen-separated syntax. This review subset is intentionally stricter than the current application; valid real naming schemes may require owner adaptation. There is **no automatic normalization or coercion** and no implication that other formats are malicious.
- Duplicates, generic `LAB`, blank strings, Unicode confusables, path/URL characters, numerics, boolean values, polymorphic string/tuple subclasses, out-of-range sizes and mixed-invalid batches all produce a single constant **HOLD**.
- A canonical nonduplicate synthetic batch returns only **REVIEW_ONLY**, NEVER `ALLOW`, `APPROVED`, a permit or grant. The frozen response has four literal `False` authority flags, no input details and no caller/customer identifiers. Syntax checks do not verify global uniqueness, operator identity, consent, real scope or revocation.
- Fourteen additive independent tests include shuffled 128-case order-invariance, placement-based atomic denial, no mutable response, and injected failures for filesystem, DNS, socket, SQLite and subprocess paths.

Run the new opt-in tests separately:
```sh
PYTHONPATH=src python -m unittest tests.test_lab_reference_review_1487_20261016 -v
```

**W1 exact-head hosted evidence, preserved without promotion to W2:** SHA `f28dc31fe990702030e4ce9bbd310bc1b41c16b9`, [#38897379357](https://github.com/Zennay/Lightup/actions/runs/38897379357): both Python3.11/3.14 own 12 tests behaved as intended (8 ordinary PASS + 4 still-open source expected-RED); overall 1,249 tests FAILED due to *unrelated* #301 already-expired fixed-date fixture; integration SKIPPED. The registered-permanent [CI #38897379130](https://github.com/Zennay/Lightup/actions/runs/38897379130) was QUEUED. This evidence is **not proof of W2 head**, full green or the actual source fix. Verify W2 only from its own exact SHA job logs.

**Still DRAFT/HOLD, not installable authority; human source-owner review is required before any wiring or release.**

## W3 — bounded cross-batch replay review and immutable receipt shape

The original no-authority source module is now hardened with two *non-authorizing* features:

1. `review_lab_reference_history(prior_references, proposed_references)` validates **exact built-in tuples** holding at most 64 distinct canonical *synthetic* references each. Prior may be empty, the proposed batch must be nonempty. Any malformed inputs, duplicates inside either batch, reused prior reference or more than 64 records return a single constant `HOLD`. A clean non-overlapping synthetic set returns only `REVIEW_ONLY` with all authority flags false. The check is a short, pure *supplied-window* comparison, **not** a live persisted ledger or evidence of historical uniqueness. If the supplied history omits a previous reference, that replay cannot be detected.
2. `LabReferenceReview.__post_init__` prevents ordinary constructor calls from fabricating `ALLOW` / `APPROVED`, true flags, numeric/nullable false-lookalikes or nonliteral status objects. The receipt remains frozen. This protects the shape of this *unwired* review output; it is **not a security token**, since a caller can still construct `REVIEW_ONLY`, monkeypatch Python, or supply false history. Never authorize or dispatch from this object.

The new additive `tests/test_lab_reference_history_1487_20261016.py` has **14 test methods** covering 0/1/64/65 boundary items in both tuple inputs, repeated or cross-batch references, 256 seeded permutation rounds (each valid and replayed), adversarial string/tuple subclasses, Unicode aliases, forged authority fields, frozen receipts and injected no-filesystem/DNS/network/SQLite/process/shell guards. Synthetic references only, no original source/gates modified.

Run `PYTHONPATH=src python -m unittest tests.test_lab_reference_history_1487_20261016 tests.test_lab_reference_review_1487_20261016 tests.test_scope_lab_reference_provenance_1487_20261016 -v`. W3 totals **40 own tests** (14 history + 14 batch + 12 source), with **4 deliberately still OPEN production source expected-REDs** in the 12 source methods. These totals are code counts, not proof that W3 completed CI on its latest immutable SHA. Use the exact new hosted/vps run logs and do not promote W2 evidence.

Source owner must additionally assess authoritative session lineage (operator/client consent, asset/capability scopes, durability, revocation, exact issuer, time/window), and whether references are globally unique/replay-proof. Untrusted `prior_references` are never sufficient to prove consent. **DRAFT/HOLD; do not wire it into a permit gate, merge, deploy or scan.**

## W4 — real legacy gate versus non-authorizing receipt boundary

The *installed current source* in `lightup.activation.ActivationGate` is now exercised with actual `LabReferenceReview` objects, but only for fictional in-memory loopback permits in `tests/test_lab_reference_non_authority_1487_20261016.py`. These **10 extra owned tests** distinguish six important concepts:

- `REVIEW_ONLY` and `HOLD` are explicitly NOT authorization and all receipt authority fields are false.
- Ordinary current-source witness: the original `ActivationGate` accepts an arbitrary non-string receipt passed as LAB_ONLY `activation_reference` and embeds it unchanged in an inert permit. This is a source input-contract problem, not evidence a downstream adapter ever dispatched.
- **Two NEW deliberately OPEN `expectedFailure` source requirements:** an actual LAB_ONLY gate constructor should fail closed when given `REVIEW_ONLY` or `HOLD` objects as provenance. These are separate explicit interface canaries in addition to W1's four lower-level reference-shape REDs.
- PLAN_ONLY still refuses an inert loopback request and LAB_ONLY never treats a public fictional hostname as private-lab scope merely because a caller supplies `REVIEW_ONLY`.
- Two independent LAB_ONLY gates can stamp the same fallback generic `LAB` (and even identical caller-asserted references) on different random permit IDs. Unique `permit_id` is not unique operator/session provenance.
- In-test sockets, DNS, shell and process entry points are patched to error; no actual network, grant persistence, tools or scans. This does not alter activation, scope or other owner files.

**W4 owned total is 50 methods, 44 ordinary expected PASS + 6 intentionally OPEN production expectedFailure.** This is a logical expected count, not a claim until original exact W4 SHA hosted Python 3.11/3.14 job logs are inspected. The inherited `#301` unrelated date-expired full-suite error and unassigned permanent VPS runner remain separate; do not claim CI green or activation source repaired. Do not wire a `LabReferenceReview` into the gate! Original source-owner only, review first.

## W5 — fictional session-lineage relationship preflight (still non-authorizing)

This branch adds **one independent, optional, non-authorizing source helper**:
`src/lightup/lab_session_lineage_1487.py` with frozen `FictionalLabLineageClaim` and pure `review_fictional_lab_lineage(claims, assessment_time)`.

The caller must explicitly supply all values: a LAB reference, synthetic operator, session, engagement, asset, capability IDs, a UTC start/end window, a Boolean revocation claim, and an evaluation instant. **Every value, including the clock and any `revoked=False` flag, is entirely *untrusted*, not retrieved from durable LightUp storage or an authenticated identity provider. This function cannot distinguish a fabricated claim from authentic consent and MUST NEVER become an actual permit gate.**

The helper checks only internal shape/relationship consistency:
- Exact built-in tuple of 1..64 **exact** `FictionalLabLineageClaim` values; exact shape and conservative uppercase ASCII synthetic ID markers, with no polymorphic string comparisons/coercion.
- Reuses the owned exact LAB reference format checker. Rejects duplicates of claimed reference or session ID within the same supplied batch; this does not prove global historical uniqueness.
- Requires exact UTC aware built-in datetime instants with `fold=0`, no timezone conversion; inclusive observed start/end, strictly positive duration up to eight hours; strict `bool False` revocation *claim*. These are **review-contract limits**, not any production policy, and may need owner-approved adaptation.
- A malformed/contradictory or oversize mixed batch returns one constant `HOLD`; an internally self-consistent batch returns only `REVIEW_ONLY` with four literal false authority flags. Neither grants release, verifies permission, authenticates actor, proves storage, provides up-to-the-second revocation nor accesses network, filesystem, OS, database, process or a tool handler.
- Input and output are immutable by normal dataclass APIs, without serializing even fictional actor IDs into a receipt. A malicious caller can construct or alter user-supplied facts; this is a *format preflight*, not trusted evidence.

The additive `tests/test_lab_session_lineage_1487_20261016.py` contains **18 independent** test methods (exact dataclass/type checking, junk/Unicode aliases, 0/1/64/65 boundaries, precise UTC time inclusive edges and 8h window, stale caller-controlled clock counterexample, polymorphic timestamps, duplicate sessions/references, revocation type confusion, 200 deterministic permutation/revocation rounds, mixed-claim atomicity, immutability and patch-guarded no-I/O proof). Run solely for review:

```sh
PYTHONPATH=src python -m unittest tests.test_lab_session_lineage_1487_20261016 -v
```

W5 now has **68 owned test methods in six new tests files**: original 50 (44 ordinary + 6 intentional OPEN source expected-RED) plus 18 new self-contained ordinary methods. **This is a planned code count, not evidence of CI success**; rely only on latest immutable-head hosted Python 3.11/3.14 raw logs, distinguish the existing #301 unrelated expired fixture and the canonical self-hosted VPS lane. Do not merge, wire to ActivationGate, deploy, or claim customer/operator consent.
