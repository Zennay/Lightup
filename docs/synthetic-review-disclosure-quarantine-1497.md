# #1497 — Fictional scope-review handoff privacy quarantine

**LightUp: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This work is an isolated, opt-in, non-authorizing privacy hint before copying offline notes into issues, Notion or operator review. It is **not connected** to `ScopePolicy`, `ActivationGate`, `ExecutionPolicy`, any authorization resolver, handlers, scanning, or persistence.

## Operator usage (fictional data only)

```bash
PYTHONPATH=src python -m lightup.synthetic_review_disclosure_cli_1497 --synthetic-only \
  < examples/fictional_review_handoff_1497.json
# REVIEW_ONLY -> exit 2; generic HOLD -> exit 3; never exit 0
```

The CLI reads at most 32,769 stdin bytes to enforce a 32,768-byte hard JSON boundary. It accepts only a JSON array of 1–16 literal strings. The pure API `review_fictional_handoff_notes(tuple_of_notes)` only accepts a builtin tuple of exact builtin strings: at most 4,096 ASCII bytes per string and 32,768 bytes total. Every note must contain at least one exact lower-case, single-label `*.example.test` hostname. Unrecognized dotted hostnames, IPv4/IPv6, email/address punctuation, HTTP URLs, control/Unicode/bidi text, basic secret markers and dangerous markup are quarantined atomically. It never echoes the source content or the rejection reason. Results are frozen and contain only status, generic fixed notice, count and the four immutable literal false authority flags.

**Importantly, this is NOT a comprehensive secret detector, DLP certification or safe-to-publish claim.** Innocuous text may be blocked, and secrets/real targets in unrecognized forms may escape matching. REVIEW_ONLY indicates merely that these conservative tests did not spot forbidden patterns. Review all human-readable content with an authorized privacy/security owner before publishing; no CLIENT/OPERATOR identity, consent, validity window, revocation or execution permission can be established by this module.

The tool is deliberately absent from any live intake, scanner, grant, release or runtime paths. Issue [#1497](https://github.com/Zennay/Lightup/issues/1497) and draft PR own this independent test-only/offline utility; existing worker branches/PRs and production source stay unchanged. Full original hosted suite and verified registered permanent VPS checks, source-owner/privacy review, authentic client/operator consent, durable revocation-at-use and explicit human GO remain required before any wider change. No merge, deploy, live customers or real scans.
