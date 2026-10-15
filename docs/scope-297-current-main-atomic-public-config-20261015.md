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

In addition to the 25 real installed-source unit contracts, the draft now includes:
- `scripts/scope_297_atomic_policy_witness_20261015.py` — one-command, **hardcoded fictional inputs only** diagnostic on the actual installed `ScopePolicy.decide`. Reports eight known host/network cross-path cases without publishing the input targets or fake grant data, includes DNS/socket tripwires, and **always exits code 2 / HOLD**.
- `tests/test_scope_297_atomic_policy_witness_cli_20261015.py` — 23 separate deterministic offline controls on real source behavior, JSON/Dutch output, immutable hold flags, user-supplied-target refusal, no network/shell/files, privacy-minimal unexpected decision/constructor exception review and future *deny* behavior staying HOLD.

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

### W7: swallowed DNS/socket exceptions cannot hide attempted network I/O

The standalone synthetic-only CLI now tracks blocked operations **per case** rather than inferring that no network attempt happened merely because `ScopePolicy.decide` returned a normal decision. A source callback can catch its own `NetworkAttemptBlocked` exception; its attempted access is still recorded as `NETWORK_BLOCKED_REVIEW` ahead of any `UNSAFE_ALLOW` or `DENIED_REVIEW` classification. The network tripwire uses a scoped `ExitStack` and restores every patched module-level API after exit. This is a best-effort Python API tripwire only, **not process/container/VPS-level egress isolation**.

The tripwire covers common Python socket and resolver entry points: `socket`, `socketpair`, `create_connection`, `create_server`, `getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr`, `getnameinfo` and `getfqdn`. Six new offline unittest methods prove that swallowed socket/DNS exceptions still count, cases do not taint each other, helper entry points are intercepted, and patched APIs are restored. **23 CLI tests** total; the 25 installed-source controls are unchanged.

Even a report of zero intercepted attempts cannot establish network isolation. The whole review remains non-authorizing with status HOLD, exit code 2 and all `can_*` flags false. Current commit CI evidence must be pinned separately from earlier runs and cannot be inferred from the prior 14-test branch.

### W8: owner-readable cross-path failure totals and non-mutable permissions

The same offline report now explains *why* the synthetic installed-source permissions are unsafe in Dutch, with separate fixed-family summaries: six invalid-network-policy-to-hostname bypasses and two invalid-host-policy-to-network bypasses. It also gives the product source owner's required remediation direction: validate both public host and network policy together before any public grant or permit. No extra target details or grant values are printed.

The six always-false authority flags are wrapped in a `MappingProxyType` before every report copies them, so callers cannot mutate the global defaults to true. Three deterministic offline tests require both family counts, no automatic success after an imagined source repair, and attempted authority-flag mutation to raise `TypeError`. Total reporter tests: **23**, independent of the 22 installed-source acceptance tests. Reporting remains **exit 2 / HOLD** and does not implement or grant production authorization.

### W9: 58 genuine installed-source matrix admissions (not just one expected failure)

The own installed-source regression module now additionally contains **two deliberate source RED aggregations and two separate ordinary source-witness tests**. Every aggregation computes *all* actual installed `ScopePolicy.decide` decisions before asserting the intended zero-authorization invariant; the ordinary witnesses require the observed unsafe allow behavior with exact reason, so a crash cannot be accepted as a valid RED.

- Network policy → public hostname: ten wholly malformed CIDRs × four legitimate spellings/URL forms of a **fictional** exact hostname = **40 true installed-source decisions**.
- Host policy → explicit public network: six non-string malformed host entries × three documentation-only addresses within an explicitly configured synthetic network = **18 true installed-source decisions**.
- Overall **58 additional direct source admission decisions** with no real targets or sockets; this proves wider coverage of the *same #297 whole-configuration atomicity requirement*, not independent new vulnerabilities or a production patch.

After adding these, the original file has **15 ordinary tests and 10 intentionally expected source-RED cases**. The separate reporter file has **23 ordinary HOLD tests**. The product source owner must convert all 10 RED requirements to ordinary passing denials when repairing default `ScopePolicy`. All other security and runner release gates remain unchanged.

### W10: preserve real canonical authority semantics through owner repair

Three new **ordinary passing** current-installed-source golden controls cover (a) correctly allowlisted fictional IPv4 and bracketed IPv6 documentation networks with a synthetic current grant, (b) neighboring unlisted IPv4 and IPv6 targets staying `OUT_OF_SCOPE`, and (c) expired fictional grants staying `AUTHORIZATION_EXPIRED` for valid host, IPv4 and IPv6 public scopes. These preserve legitimate existing behavior when the production owner eventually tightens the default whole-policy validation; they do not authorize any actual target and do not change owner source code. All artificial values are hardcoded and there is no network I/O.

The source-test file now has **15 ordinary checks + 10 deliberately expected source REDs**, and the reporter-test file has **23 ordinary HOLD checks**. After source remediation, only the 10 RED requirements should become ordinary passing denials; do not weaken the valid canonical positive and negative contracts.

### W12: test-only original ten-RED owner-remediation reference (NO PRODUCTION SOURCE CHANGE)

`tests/test_scope_297_atomic_reference_20261015.py` is an **entirely new, standalone, installed-source test module** providing a deliberately minimal *temporarily monkeypatched* `ScopePolicy.decide` test reference. It checks the **entire configured host and network shape before public host/IP decisions**, then delegates all well-shaped policies to the **actual installed original source**. Only one synthetic Python test process is patched; production `src/lightup/scope.py`, worker `#100`, and the separate uninstalled config-review `#1239` remain completely unchanged.

Eight ordinary unittest methods verify: **all ten exact #297 source-RED methods turn into passing denial conditions under the reference**, all eight offline CLI examples become **DENIED_REVIEW, still HOLD**; bogus cross-path hosts and CIDRs fail closed; all well-formed synthetic host, IPv4, bracketed IPv6 permissions remain accepted with a synthetic valid grant; missing or expired grants remain denied; malformed container shapes are refused before parsing; and the original installed-source method is restored after the temporary monkeypatch. These are **non-authorizing proof-of-fix acceptance contracts, NOT an implemented fix**. In particular, after the temporary patch exits, the original installed source still allows a documented intentionally invalid cross-path config, establishing a real pending ownership dependency.

This test-only reference validates the behavioral direction in which the #100 source owner could safely implement issue #297; it does not authorize ANY real customer, scan, network destination, merge or deploy. It cannot replace review of canonical host normalization, validation of all mutable object shapes, actual production source changes, private egress, synthetic/real scopes, registered VPS CI and an explicit operator sign-off. CLI remains exit 2/HOLD even when reference logic denies everything.
