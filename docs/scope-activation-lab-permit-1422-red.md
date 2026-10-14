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
  identity, and timezone-aware timestamp. Forged metadata mutants are
  caught as additional HOLD violations; no permit is ever dispatched.
- Disable `allow_private_lab` and confirm non-loopback samples cannot
  be issued a LAB_ONLY permit.
- `PLAN_ONLY` terminally rejects all sixteen fixtures.
- CLI real subprocess exit/status/privacy contracts and source-error
  fail-closed behavior.
- Python-only defense-in-depth during audit: blocks ordinary
  `builtins.open`, `Path.open`, `os.open`, `os.write`, `os.system`,
  `sqlite3.connect`, `subprocess.Popen`, network socket creation and basic
  name lookups. Distinct no-I/O mutant regressions must visibly trip each
  guard, return a nonreflective HOLD and restore monkeypatched functions.
  These Python hooks **cannot** mediate native POSIX aliases, threads,
  alternate system calls or malicious imports: **not an OS sandbox**, not
  authority, not evidence of real isolation. Run only on trusted offline CI.
- No tested address is contacted, scanned, resolved or authenticated.

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
