# #1565 — Canonical scope-decision offline witness (DRAFT/HOLD)

## Purpose and ownership

This is an **independent offline diagnostic** on the immutable base `e73b7445c87ad239bdb03c50a99078ef93163b02`. It reads the current checkout's real `ScopePolicy.decide()` and `ScopeDecision` but never modifies the scope evaluator or auth state. New files are limited to the `scope_offline_authority_witness_20261017` script/test and this doc. Active owner branches and PRs (including #1564, #1538, #1486 and #346) are not rewritten.

LightUp remains **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. The witness is neither customer consent nor operator signoff nor authorization of any asset. Its `REVIEW_ONLY` is *not* a GitHub merge-go, grant, execution, security-review, deployment or release verdict.

## Execute locally in a disposable checkout

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_scope_offline_authority_witness_20261017.py -v
PYTHONDONTWRITEBYTECODE=1 python3 scripts/scope_offline_authority_witness_20261017.py --offline-lab-only
```

On an installed canonical evaluator that matches the fixed matrix, the CLI emits exactly one sorted ASCII JSON object:
- `schema=lightup.scope-offline-decision-witness.v1`
- `status=REVIEW_ONLY`, `reason=canonical_synthetic_matrix_matches`, `checked=11`, a SHA-256 of ordered observed synthetic classifications
- `client_consent_verified`, `operator_consent_verified`, `authorization_granted`, `dispatch_allowed`, `scan_allowed`, `deployment_allowed` and `release_allowed`: exact JSON `false`
- exit status **3**, never 0.

With missing/malformed opt-in, a changed decision (allow, reason, host), bad shape/schema or evaluation exception, the result is `HOLD`, with a generic failure reason, seven false authority flags, no matrix hash, and exit status **2**. No input/exception text, URL, IP or consent reference is emitted.

## Real test surface

The fixed in-memory matrix uses loopback IP/hostname, private lab IP (allowed and lab-disabled), out-of-scope public IP, a synthetically allowlisted `.example.test` hostname with and without a **fictional, unsourced** `Authorization`, explicit public CIDR with and without that same fictional object, removed explicit-host allowlist, and blank-target denial.

This is a deterministic **behavior witness**, not a proof that the policy is secure for all targets. Canonical examples with a synthetic authorization show existing `ScopePolicy` semantics in an **offline unit invocation only**. They do not create grants or prove that an actual human approved any asset. No DNS, socket, HTTP, scan, subprocess handler, credentials, database, production data or target-capable runner step occurs in the witness itself. The subprocess regression launches only another Python process running the same offline witness.

## Verified execution (17 October 2026)

On the connected authorized zSSH host, a dedicated disposable checkout at exact source head `d30a1e2e9deeacb4ba72c98a23b728488628d057` passed **16/16 dedicated unittest methods** on Python 3.14.4. Negative mutation controls rejected incorrect allow/host/reason/boolean return values, bad opt-in, identity-spoofing objects and evaluator crashes without yielding authority. The live CLI control produced `REVIEW_ONLY/3`, while the no-opt-in control produced `HOLD/2`, both with seven hard-coded `false` authority flags. Git status was clean; no other workers' paths were edited.

The earlier, same-branch full original unit suite on head `705b525ec485f5779ad9a2846e10e036ccb7039d` ran 1,251 tests and returned **5 FAIL, 23 expected failures**. Failures included pre-existing #301 date-fixture and #1535 registry-history issues; other failures are not independently baseline-proven. This **does not** constitute full-project green or release evidence. The new two polymorphism tests added afterwards have dedicated green proof, not a new full-suite result.

## Independent original-main regression comparison

On the connected zSSH VPS, two separate clean, isolated checkouts were used for the same original RED tests: untouched main `e73b7445c87ad239bdb03c50a99078ef93163b02` and this branch at `cea9050c9f85fe41aa7db45f088a51aa6c692741`. The **same five precise failing subtests** occurred in both, across 34 top-level unittest methods:

- `test_scope_composed_native_offline_cli_20261014.py`: 3 unittest methods; two fail because registry-history CLI returns 92 instead of 2/3.
- `test_scope_legacy_falsy_window_301_red_20261014.py`: 19 methods; one time-fixture assertion fails on both heads.
- `test_scope_offline_cli_socket_fleet_20261014.py`: 12 methods; two registry-history CLI subprocess cases return 92 instead of 2/3.

This directly reproduces pre-existing defects for those exact failing testcases; it is **not** a claim of a complete original-main full-suite pass or a source-owner repair. Own new witness remains **16/16 PASS**. No extra named LightUp self-hosted runner workflow was started.

## Gate interpretation

- Green unit tests validate the witness's own classification, deterministic receipt, zero-network boundary, no authority flags and mutation-detection sensitivities.
- `REVIEW_ONLY` cannot release any blocker. Source-owner #301 time-gate defects, other open source REDs, independent authentic client/operator approval, at-use revocation, review, correct hosted + named registered permanent VPS exact-head CI and explicit HUMAN GO remain required.
- **Do not merge/deploy/scan/grant/dispatch/release** this issue's code merely because the witness passes.
