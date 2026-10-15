# Scope issue #291 — bare IPv6 identity source regression (2026-10-15)

**State:** INCUBATE M3/M7 · **DRAFT/HOLD**. This branch is a
non-authorizing, tests-and-documentation-only acceptance for the unmerged
production owner. It does not authorize, deploy, scan or issue grants.

## Why this matters

The current installed `ScopePolicy.normalize_host()` passes a bare IPv6
literal to `urlparse("//" + value)`. For example, synthetic
`2606:4700:4700::1111` becomes normalized host `2606`, **not** the
literal. A policy explicitly admitting the unrelated DNS label `2606`
can then return `EXPLICIT_HOST` for the IPv6 target. An attached
`Authorization(owner=..., reference=...)` does not cure this lexical
identity substitution. These are *in-memory hypothetical inputs*, not
permission to test the displayed addresses.

## Exact source acceptance

New file `tests/test_scope_291_bare_ipv6_truncation_current_main_20261015.py`:

- Four **real expected-RED** cases prove bare IPv6 must never turn into
  a shortened name, that a synthetic explicit-host allowlist cannot
  admit the mismatched IPv6 literal, a fabricated authorization
  claim on the wrong identity, and the **real ActivationGate** handing out a
  synthetic in-memory execution permit for that falsely matched identity.
- Six **normal green/witness controls** prove bracketed IPv6 remains intact,
  explicit `/128` network membership still requires an authorization
  object under the existing canonical flow, and the same literal in
  bracketed form cannot accidentally match an unrelated host or network. A
  PLAN_ONLY/LAB_ONLY comparators still reject the fake active request; a
  standalone network-tripwire self-test proves DNS/socket monkeypatches really
  reject calls. A RED-integrity witness reruns the four intentional failures
  and rejects masked crashes, accidental success and network-trigger errors.
- All tests are pure in-process: actual DNS lookups, sockets and outbound
  connections are patched to raise immediately. No real network
  assessment or other active operation is performed.

A source-owner fix may **either** parse a bare literal to its complete
canonical address **or** explicitly reject it as `INVALID_TARGET`.
A truncated hextet must never become an authorized DNS-host identity.

Run in an isolated repository checkout:

```bash
PYTHONPATH=src python -m unittest -v \
  tests.test_scope_291_bare_ipv6_truncation_current_main_20261015
```

**Important:** `unittest.expectedFailure` is a red-signal quarantine,
not a successful security fix. The four source-negative cases must
report exactly as **expected failures**, not ordinary passing tests or
unexpected successes. The owner must repair the installed source and
convert these cases to normal green tests before considering this
specific issue resolved.

## Ownership and release boundaries

- No edits to `src/lightup/scope.py`, production admission, planners,
  orchestrators, other source-owner branches, workflows or runner.
- Issue [#291](https://github.com/Zennay/Lightup/issues/291) remains
  **open** pending the separate production owner; do not merge this
  branch as an implicit repair of the vulnerability.
- Independent review must also cover #1289 strict target syntax, #1422
  private-lab classification, and #177 actual request-bound consent.
- Hosted checks at exact immutable SHA, registered self-hosted VPS
  execution, independent security/privacy review and explicit human
  release are distinct gates. None is conferred by these tests.

## Current HEAD validation discipline

A passing general unittest suite with three intentional expected failures is
**not** a repaired parser. Inspect the exact branch commit's CI jobs; hosted
GitHub Actions jobs are distinct from a job actually executed on the registered
permanent VPS runner. Never reuse an earlier SHA's green jobs as proof after a
new test/documentation commit. The local negative cases are expected to remain
RED until the production source owner repairs the identity boundary.

## Distinguishing synthetic and real permits

The new `ActivationGate` expected-RED case instantiates a purely in-memory
fictional `Authorization` and asks the real production gate to deny an
unrelated bare IPv6 target. Current source instead produces a synthetic
`ExecutionPermit` bound to the truncated hextet. No adapter executes, no
customer has consented, no network traffic occurs, and the returned object is
not a real authorized grant. Both PLAN_ONLY and LAB_ONLY are checked as green
denial comparators; neither permits the same request. This is an explicit
acceptance requirement for the existing source owner, not a proposal to
activate targets.
