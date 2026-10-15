# LightUp #297 — current-main public configuration admission canaries (2026-10-15)

**Posture: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. No merge, deployment, real grant, target interaction or scans.**

## Why this exists

The installed `ScopePolicy.decide` in `src/lightup/scope.py` checks `explicit_hosts` and returns `EXPLICIT_HOST` without evaluating malformed `explicit_networks`. The same policy's explicit-IP branch will parse networks and reject invalid syntax. Therefore public authorization acceptance depends on which of two target shapes is presented, even though the configuration is the same.

This independent current-main proof complements [issue #297](https://github.com/Zennay/Lightup/issues/297) and older independent [draft PR #1239](https://github.com/Zennay/Lightup/pull/1239), which has an **uninstalled** optional validator. It is not another installed validator and does **not** fix the source defect.

## Added source acceptance

`tests/test_scope_297_current_main_atomic_public_config_20261015.py` invokes the actual installed `ScopePolicy.decide` and current `models.Target` / `Authorization` directly. The synthetic owner/reference and imaginary `example.test` domain are *not* customer consent.

Eight `@unittest.expectedFailure` contracts specify **denial**, not mere diagnostics, when any unrelated configured public CIDR is malformed, including invalid IPv4 and IPv6 prefix lengths, mixed valid/invalid CIDR entries, an HTTPS-form target, and an auth-disabled policy. On unpatched source, these paths return `allowed=True`, demonstrating a still-open source defect; `expectedFailure` is **not** remediation.

Ten ordinary tests preserve canonical positive host authorization, unknown-host denial, the no-grant denial path, public-IP requirements, a non-authorizing parse failure, configuration immutability, and three ordinary source witnesses (a six-vector actual unsafe-allow matrix, two reverse-direction unsafe network allows, and an assertion check) distinguishing real missing denials from unrelated exceptions. Per-test socket construction and DNS lookups are patched to fail; no network or filesystem side effects. Tests use standard-library unittest only.

## How to reproduce

```sh
PYTHONPATH=src python -m unittest -v tests/test_scope_297_current_main_atomic_public_config_20261015.py
```

If the repository's test directory is not a Python package, run the same module by discovery instead:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_297_current_main_atomic_public_config_20261015.py' -v
```

**Acceptance:** eight explicit source RED cases remain reported as *expected failures* before source-owner remediation, while all ten ordinary controls pass. After owner-reviewed installed source remediation, promote the six REDs to ordinary tests and require zero permitted public decisions from malformed whole-policy config, without target I/O and without changing correct canonical policy behavior.

## Ownership / dependency boundaries

- Do not edit `src/lightup/scope.py`, `models.py`, other workers' existing tests, `#100`, `#1239`, or active scope branches.
- The authority to change production source and publish grants remains with the appointed source / security owner.
- Real durable customer consent, revocation before I/O, tenant+asset+capability binding, lab egress limits, security/privacy review, exact-commit hosted and permanently registered VPS CI proof, and explicit human approval remain release gates.
- A failing unrelated #301 wall-clock fixture must be recorded separately, never hidden as expected-RED for #297.
- No claim of full CI green, production safety, release or customer permission follows from this tests-only branch.

Keep the issue open and this PR draft until actual source-level enforcement is integrated and independently verified.
