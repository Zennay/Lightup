# Installed percent-encoded host scope boundary · #366

**Status: INCUBATE M3/M7 · offline synthetic acceptance only · DRAFT/HOLD.**
This is a direct installed-`ScopePolicy` test, not a new authorization adapter. No real domain, public scanning, DNS lookup, network call, grant, execution, merge or deployment.

## Why this test exists

PR [#1017](https://github.com/Zennay/Lightup/pull/1017) already explores encoded aliases in a separate **single-segment reference grammar**. This isolated follow-up is deliberately different: it calls the **real checked-out** `src/lightup/scope.py` against `Target` objects and both a synthetically attached time-current `Authorization` and missing-authorization controls. An independent correct parser does not establish what the installed code does.

The regression records four authorization boundaries:

1. Encoded dots and other escaped characters in hostname text are not equivalent to an exact declared host; decoded-looking allowlist **prefixes** do not grant membership.
2. Encoded `localhost` or `127.0.0.1` text does not inherit a loopback exception.
3. An encoded documentation IPv4 address does not match an explicit CIDR entry.
4. The unencoded control host/IP continue to require authorization for public scope, while actual unencoded loopback retains its normal existing semantics.

All names use the reserved `.test` domain and RFC 5737 documentation IPv4, with no external target. A mocked socket/DNS trap makes any attempted outbound resolution a failing test.

## Reproduce on the checkout

```sh
python -m unittest discover -s tests -p 'test_scope_366_installed_percent_host_20261015.py' -v
```

**Expected:** all ordinary tests PASS on the current installed `ScopePolicy`. These are neither `expectedFailure` tests nor proof that runtime dispatch is safe. A different URL/HTTP adapter could reinterpret a hostname after this scope decision; the source owner must validate the **same exact canonical authority** through actual admission and network dispatch before authorizing real target access.

## Owner boundaries and blockers

- Existing PR #1017 owns the standalone lexical segment reference; this branch does not edit that branch or its paths.
- Scope/adapter owner PR #100 and active target parsing owner PR #1290 own any production parsing/authorization fixes. This branch does **not** change production modules or claiming merged behavior.
- Runtime executor/grants PR #107, durable evidence #1454/#1455, independent operator step-up #1172/#1173, customer consent, lab ingress/egress enforcement and original self-hosted CI remain separate release gates.
- Existing #301 real-time fixture can fail the full hosted unit suite; own tests succeeding does not override that failure. Verify exact-head Python 3.11/3.14 and permanent registered runner independently.
- **No merge, no deploy, no live grant, no real scan, no GO.** An explicit human release decision and independent privacy/security review remain necessary.

Branch origin: main `e73b7445c87ad239bdb03c50a99078ef93163b02` (2026-10-15 observation). Only new paths are allowed.
