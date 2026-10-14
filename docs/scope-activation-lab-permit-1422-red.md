# Scope #1422 — LAB_ONLY ActivationGate permit-chain acceptance (offline)

Status: **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE OR DEPLOY.**

## Real, independently testable gap

Current `ScopePolicy.decide` classifies some non-globally-routable
special-use IP literals as `PRIVATE_LAB` using `ipaddress.is_private`
or `is_link_local`. The next actual source layer,
`ActivationGate.issue` in `LAB_ONLY` mode, trusts that result and
constructs an in-memory `ExecutionPermit`, even without tenant/owner
authorization. This compounds the source classification defect in #1422.

This independent acceptance pack exercises the **real current
`ActivationGate.issue` implementation**, unlike #1423 (scope decision
classification), #1426 (installed-policy audit), #1427 (literal matrix)
and #1425 (reference-only reviewer). It does not modify their files.

## Usage (synthetic, no network)

```sh
python scripts/audit_scope_activation_lab_permit_1422_offline.py
python -m unittest tests.test_scope_activation_lab_permit_1422_red -v
```

The audit uses built-in synthetic IP literals, creates no real token:
`lightup.activation.token_urlsafe` is mocked to a fixed, clearly fake
value. Network socket creation and DNS resolver calls are blocked within
the in-memory audit. Neither the in-memory permit nor its ID are
persisted, printed, passed to an adapter, or dispatched.

The CLI emits a fixed privacy-minimal single-line JSON receipt.
`HOLD` returns 2 for a failure/violation; `REVIEW_ONLY` returns 3
if every fixture eventually passes. **Never exit 0** and six separate
authorization/permit/dispatch/scan/merge/release flags always remain
literal `false` regardless of results. The receipt counts synthetic
observations but never includes literal addresses, token values,
customer targets, references or exception text. Invalid arguments
return a nonreflective HOLD without reading stdin.

## Coverage

- Six supported exact synthetic loopback/RFC1918/ULA controls.
- Ten unsafe synthetic documentation/benchmark/unspecified/
  broadcast/link-local/IPv4-mapped alias examples that **must fail before permit
  issuance**. These are deliberately `@expectedFailure` in existing
  vulnerable source, with separate assertion-trace integrity canaries.
- Real in-memory permit metadata integrity checks verify exact synthetic
  target binding, capability, activation mode/reference, fixed mocked token
  identity, and exact current-call UTC timestamp bounds (deny stale/future
  issued tokens and polymorphic string subclasses). Forged metadata mutants are
  caught as additional HOLD violations; no permit is ever dispatched.
- Disable `allow_private_lab` and confirm non-loopback samples cannot
  be issued a LAB_ONLY permit.
- Four additional real `ScopePolicy` + `ActivationGate.issue` controls:
  syntactically allowed **explicit host/network** with a synthetic owner
  reference or with deliberately disabled public-authorization policy
  never crosses into a LAB_ONLY permit. They run through both the separate
  direct source tests **and the CLI auditor**: 46 private-lab/PLAN decisions
  plus four explicitly permitted public decisions and six missing/expired/
  not-yet-valid public authorizations = **56 synthetic observations**.
  Even a fake token creation *before* public gate denial increments HOLD.
  The six added cases exercise **real owner/time checks** for a separately
  allowlisted public `.test` hostname and documentation IP network: missing
  `Authorization`, a UTC-valid-from in year 2099, or UTC-valid-until in year
  2000. `ScopePolicy` must return `AUTHORIZATION_MISSING` or
  `AUTHORIZATION_EXPIRED` and the real LAB_ONLY `ActivationGate.issue` must
  terminate without generating a token. A mutation issuing a token before
  denial for the three synthetic network cases must add three HOLD breaches.
  This does not create actual consent or exercise AUTHORIZED mode;
  token creation is a hard failure.
- `PLAN_ONLY` terminally rejects all sixteen fixtures.
- CLI real subprocess exit/status/privacy contracts and source-error
  fail-closed behavior.
- An in-process synthetic mint counter guards the **real token-creation
  boundary**, not just the returned permit or final exception. LAB_ONLY
  valid fixtures must mint exactly once; denied lab-scope fixtures,
  disabled private-lab policy and PLAN_ONLY must mint **zero** even if
  code creates a token before raising PermissionError. Three independent
  synthetic mutation cases deliberately mint in deny paths or double-mint
  a valid lab sample, and must increment HOLD violations. This does not
  mint real grants or touch executable adapters.
- The synthetic token factory additionally verifies the original
  `token_urlsafe(24)` byte-length request is an **exact built-in integer**.
  A mock returning the same fixed token must not conceal a zero/short,
  longer/different, boolean, floating-point or textual entropy request.
  Seven alternative-length mutants and six positional/keyword-shape
  mutants construct otherwise valid fake in-memory permits. Explicit
  built-in integer 24 **as the sole positional argument** is required;
  omitting it and relying on the optional default is not accepted.
  Every mutant must increase HOLD violations. This
  remains a unit-level regression, not cryptographic entropy attestation.
- The temporary diagnostic Python I/O guards now cover **construction**
  of the three real `ScopePolicy`/`ActivationGate` objects, not just
  their later `issue()` calls. Six harmless constructor I/O mutants
  (nonexistent file/FD, invalid write descriptor, in-memory SQLite,
  socket creation) must fail closed without reaching the unguarded API.
  A constructor that mints even a synthetic token is independently
  counted as HOLD regardless of later clean permits. Neither
  constructor nor issue may turn `SystemExit(0)` into a successful
  CLI exit: the audit emits one fixed HOLD receipt and exit 2.
  This is **Python-only defensive instrumentation**, NOT process,
  native syscall, thread or import-time isolation.
- Python-only defense-in-depth during audit: blocks ordinary
  `builtins.open`, `Path.open`, `os.open`, `os.write`, `os.system`,
  `sqlite3.connect`, `subprocess.Popen`, network socket creation and basic
  name lookups. Distinct no-I/O mutant regressions must visibly trip each
  guard, return a nonreflective HOLD and restore monkeypatched functions.
  These Python hooks **cannot** mediate native POSIX aliases, threads,
  alternate system calls or malicious imports: **not an OS sandbox**, not
  authority, not evidence of real isolation. Run only on trusted offline CI.
- No tested address is contacted, scanned, resolved or authenticated.

### Source-owner remediation simulation (non-authorizing)

An additional mutation regression patches only the in-memory **class**
`ScopePolicy.decide` during one unit test. It denies the ten documented
unsafe literals while leaving the real production files untouched. The
whole 56-check real `ActivationGate` chain must then return exactly
`REVIEW_ONLY`, zero violations and exit code **3**, with all six authority,
scan, grant and release flags still `false`. This is a simulated source
repair, **NOT a real source fix or evidence of authorization**. A second
mutation additionally denies a genuinely valid loopback control and must
return **HOLD with exactly one violation**, showing that over-restrictive
fixes are also visible instead of silently disappearing.

### Release blocker / source-owner handoff

Owner of production PR #100 must repair `ScopePolicy`'s private-lab
classification using an explicitly reviewed membership rule, then
independently re-run the real `ActivationGate.issue` chain and promote
the ten intentional RED canaries to ordinary passing tests. Any
genuine permit authority needs verified customer scope, active
revocation, original ingress and executor-owner integration, exact
hosted and **registered permanent VPS** raw jobs, independent
security/privacy review and explicit human release approval. A
synthetic green audit alone is **never authorization**.

Ownership: exactly three new, uniquely named files on an independent
branch; no other worker files, production source, workflows, runners,
deployment, GitHub Actions configuration, grants or public targets
changed.
