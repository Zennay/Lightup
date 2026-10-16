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
