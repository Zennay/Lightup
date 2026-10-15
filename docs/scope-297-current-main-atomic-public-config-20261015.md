# LightUp #297 — current-main public configuration admission canaries (2026-10-15)

**Posture: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. No merge, deployment, real grant, target interaction or scans.**

## Why this exists

The installed `ScopePolicy.decide` in `src/lightup/scope.py` checks `explicit_hosts` and returns `EXPLICIT_HOST` without evaluating malformed `explicit_networks`. The same policy's explicit-IP branch will parse networks and reject invalid syntax. Therefore public authorization acceptance depends on which of two target shapes is presented, even though the configuration is the same.

This independent current-main proof complements [issue #297](https://github.com/Zennay/Lightup/issues/297) and older independent [draft PR #1239](https://github.com/Zennay/Lightup/pull/1239), which has an **uninstalled** optional validator. It is not another installed validator and does **not** fix the source defect.

## Added source acceptance

`tests/test_scope_297_current_main_atomic_public_config_20261015.py` invokes the actual installed `ScopePolicy.decide` and current `models.Target` / `Authorization` directly. The synthetic owner/reference and imaginary `example.test` domain are *not* customer consent.

Eight `@unittest.expectedFailure` contracts specify **denial**, not mere diagnostics. Six show that malformed CIDR policy entries must not be ignored via an allowlisted public hostname (including IPv4/IPv6 prefix errors, mixed valid/invalid CIDRs, HTTPS-form targets and auth-disabled mode). Two more prove the reverse direction: malformed non-string hostname policy entries (integer or bytes) must not be ignored when deciding a public IP inside an otherwise valid allowlisted network. On unpatched source, these paths return `allowed=True`, demonstrating a still-open source defect; `expectedFailure` is **not** remediation.

Ten ordinary tests preserve canonical positive host authorization, unknown-host denial, the no-grant denial path, public-IP requirements, a non-authorizing parse failure, configuration immutability, and three ordinary source witnesses (a six-vector actual unsafe-allow matrix, two reverse-direction unsafe network allows, and an assertion check) distinguishing real missing denials from unrelated exceptions. Per-test socket construction and DNS lookups are patched to fail; no network or filesystem side effects. Tests use standard-library unittest only.

## How to reproduce

```sh
PYTHONPATH=src python -m unittest -v tests/test_scope_297_current_main_atomic_public_config_20261015.py
```

If the repository's test directory is not a Python package, run the same module by discovery instead:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_297_current_main_atomic_public_config_20261015.py' -v
```

**Acceptance:** eight explicit source RED cases remain reported as *expected failures* before source-owner remediation, while all ten ordinary controls pass. After owner-reviewed installed source remediation, promote all eight REDs to ordinary tests and require zero permitted public decisions from malformed whole-policy config, without target I/O and without changing correct canonical policy behavior.

## Ownership / dependency boundaries

- Do not edit `src/lightup/scope.py`, `models.py`, other workers' existing tests, `#100`, `#1239`, or active scope branches.
- The authority to change production source and publish grants remains with the appointed source / security owner.
- Real durable customer consent, revocation before I/O, tenant+asset+capability binding, lab egress limits, security/privacy review, exact-commit hosted and permanently registered VPS CI proof, and explicit human approval remain release gates.
- A failing unrelated #301 wall-clock fixture must be recorded separately, never hidden as expected-RED for #297.
- No claim of full CI green, production safety, release or customer permission follows from this tests-only branch.

Keep the issue open and this PR draft until actual source-level enforcement is integrated and independently verified.


## W4: installed-source reviewer CLI, without granting authority

In addition to the 18 real installed-source unit contracts, the draft now includes:
- `scripts/scope_297_atomic_policy_witness_20261015.py` — one-command, **hardcoded fictional inputs only** diagnostic on the actual installed `ScopePolicy.decide`. Reports eight known host/network cross-path cases without publishing the input targets or fake grant data, includes DNS/socket tripwires, and **always exits code 2 / HOLD**.
- `tests/test_scope_297_atomic_policy_witness_cli_20261015.py` — 14 separate deterministic offline controls on real source behavior, JSON/Dutch output, immutable hold flags, user-supplied-target refusal, no network/shell/files, privacy-minimal unexpected decision/constructor exception review and future *deny* behavior staying HOLD.

Invocation from the repo root:

```sh
python scripts/scope_297_atomic_policy_witness_20261015.py
python scripts/scope_297_atomic_policy_witness_20261015.py --json
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_297_atomic_policy_witness_cli_20261015.py' -v
```

Operational execution intentionally returns **2** regardless of observations; that exit code is not a CI regression. Use the unittest command (not the CLI exit status) to check the reporter's behavior. The command has **no --target, --client, --grant, --hosts, --networks, --run, --scan, --authorize, --deploy or --release input**. It cannot grant authority to a real target or use an external config to change cases.

Important: unlike the independent opt-in shape validator in [draft #1239](https://github.com/Zennay/Lightup/pull/1239), this tool **does not validate/rewrite configs or compute a permit**. It only illustrates the actual still-unsafe decisions of installed source for fixed fictional proof points. Even if the installed source later denies all eight, the report remains HOLD pending full operator/security/privacy and release checks. A source exception is reported generically as ERROR_REVIEW, not treated as a safe release pass. Human interpretation of tests and exact commit CI logs is mandatory.

Do not run against a live target, connect to production, merge, or deploy this draft for these review outputs.

### Constructor-hardening compatibility (W5)

A future source-owner fix may fail closed **at `ScopePolicy(...)` construction**, before the decision call. The standalone reporter deliberately records that as generic `ERROR_REVIEW` with `HOLD`, redacted details, and permanently false permission flags rather than crashing or falsely declaring a successful authorization. A new separate regression checks exception privacy and refusal when a strict constructor raises. A source fix is only considered approved through ordinary denial acceptance + integrated owner review, not this diagnostic.

### W6: blocked network attempt gets its own review status

The reporter now distinguishes an attempted source-level socket or DNS operation from an unrelated constructor/decision exception. Any such attempt is blocked **before I/O** and recorded as `NETWORK_BLOCKED_REVIEW` with `network_blocked_review_count`, while status and all permission flags remain strictly HOLD/false. Two dedicated synthetic hostile-source tests demonstrate socket creation and DNS resolution cannot escape the tripwires and cannot be mistaken for an authorization success. Do not interpret zero blocked attempts as proof of complete runtime network isolation; this is only the standalone reporter's own isolated Python context.
