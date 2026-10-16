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
