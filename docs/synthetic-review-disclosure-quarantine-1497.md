# #1497 — Fictional scope-review handoff privacy quarantine

**LightUp: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This work is an isolated, opt-in, non-authorizing privacy hint before copying offline notes into issues, Notion or operator review. It is **not connected** to `ScopePolicy`, `ActivationGate`, `ExecutionPolicy`, any authorization resolver, handlers, scanning, or persistence.

## Operator usage (fictional data only)

```bash
PYTHONPATH=src python -m lightup.synthetic_review_disclosure_cli_1497 --synthetic-only \
  < examples/fictional_review_handoff_1497.json
# REVIEW_ONLY -> exit 2; generic HOLD -> exit 3; never exit 0
```

The CLI reads at most 32,769 stdin bytes to enforce a 32,768-byte hard JSON boundary. It accepts only a JSON array of 1–16 literal strings. The pure API `review_fictional_handoff_notes(tuple_of_notes)` only accepts a builtin tuple of exact builtin strings: at most 4,096 ASCII bytes per string and 32,768 bytes total. Only the following complete canonical fictional format can pass to REVIEW_ONLY — **arbitrary free text never does**:

```text
Asset alpha.example.test; capability header_read; proposed risk 2.
```

Every note must match this exact punctuation/spacing and one lower-case single-label `*.example.test` hostname (max 63-character DNS label), an explicitly fictional capability from `header_read`, `tls_review`, `service_inventory`, or `passive_discovery`, and a single integer risk `1`–`5`. Canonical IDNA/punycode `xn--` labels are deliberately denied even in fictional names to avoid display ambiguity. A maximum of 16 proposals is accepted. A duplicate `(asset, capability)` pair, even with different risk, atomically rejects the whole batch. Exact canonical grammar rejects extra prose, hidden contact details, self-declared approvals, ambiguous assets, URLs, emails, IPv4/IPv6, controls/Unicode/bidi, secret-like text, HTML or forged fields because none can match the complete record. The notes and output are not connected to any actual capability registry, grant or risk calculation. It never echoes the source content or the rejection reason. Results are frozen and contain only status, generic fixed notice, count and four immutable literal false authority flags. The returned dataclass also rejects direct noncanonical status/notice/count combinations and does not accept authority flags as constructor parameters; **it is not an authenticated or tamper-proof security token**.

**Importantly, this is NOT a comprehensive secret detector, DLP certification or safe-to-publish claim.** Innocuous text may be blocked, and secrets/real targets in unrecognized forms may escape matching. REVIEW_ONLY only confirms a bounded, fictional, syntactically canonical sample, without any statement about the origin, ownership, real-world safety or approval of that sample. Review all human-readable content with an authorized privacy/security owner before publishing; no CLIENT/OPERATOR identity, consent, validity window, revocation or execution permission can be established by this module.

The tool is deliberately absent from any live intake, scanner, grant, release or runtime paths. Issue [#1497](https://github.com/Zennay/Lightup/issues/1497) and draft PR own this independent test-only/offline utility; existing worker branches/PRs and production source stay unchanged. Full original hosted suite and verified registered permanent VPS checks, source-owner/privacy review, authentic client/operator consent, durable revocation-at-use and explicit human GO remain required before any wider change. No merge, deploy, live customers or real scans.

The CLI result now uses an **exact versioned standalone format**: `contract=FICTIONAL-SCOPE-HANDOFF-1497-V1`, `status`, `notice`, `reviewed_notes`, and the four constant false authority fields. Consumers must not confuse this with any other LightUp permit/grant/consent or synthetic review format. It is deliberately not a signed artifact or independently verifiable attestation.

## Active negative acceptance

`examples/fictional_review_handoff_hold_1497.json` deliberately contains a fictional approval claim and must produce only generic HOLD with exit `3`, `reviewed_notes=0`, four false authority flags, and **no original input echo**. The dedicated hosted workflow executes both positive (exit `2`) and negative (exit `3`) cases under Python 3.11 and 3.14, alongside full isolated ordinary unittest coverage. CI outcome on one commit does not guarantee main, canonical VPS, live consent or production safety.
