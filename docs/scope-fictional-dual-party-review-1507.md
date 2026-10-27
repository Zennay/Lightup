# Fictional dual-party review consistency (#1507)

**POSTURE: INCUBATE M3/M7 — PLAN/LAB ONLY — DRAFT/HOLD.** This isolated module is not wired into the LightUp runtime. It never authenticates a person or consent and cannot issue permits, grants, scans, releases or dispatches.

## Why this separate slice exists

Two operator-facing **fictional** acknowledgements may appear to agree, or may differ in asset, risk, capabilities, decision, revocation or UTC validity window. The independent pure `review_fictional_acknowledgements((client, operator), review_at)` function checks only structural consistency and gives an immutable, value-free result:

- `HOLD`: malformed input, bad identity, non-canonical fictional `.example.test` asset, duplicate roles, mismatched scope or timing, denial, revocation, expired/future claim, timezone or exact-type ambiguity, or missing review timestamp.
- `REVIEW_ONLY`: two distinct caller-supplied fictional client/operator claims agree in their *contents* and fictional clock interval. **NOT AUTHORIZED.** Claim agreement is not proof either person exists, authenticated the statement, actually consented or can grant any authority.

Four literal `False` flags always ship with every result: `authorized=False`, `consent_verified=False`, `dispatch_allowed=False`, `release_allowed=False`.

## Built-in limits / trust model

The input is exactly a built-in 2-tuple of exact frozen `FictionalAcknowledgement` records. Roles are only `client` and `operator`; synthetic actor IDs must have the matching `fictional-<role>-...` prefix and be different. Case IDs are bounded lowercase `case-...`, fictional assets only ASCII lowercase one-label `*.example.test` with no double dash or punycode marker. Capability tuples are non-empty, sorted, unique and drawn from `inventory`, `observe`, `report` (labels, not runnable capabilities). Risk is exact built-in integer 1–5 (not boolean). Timestamps must be exact built-in aware UTC-second datetimes with `fold=0`, an interval >0 and <=24h, and review instant `issued_at <= review_at < expires_at`. Both records must have the same case, asset, capability tuple, risk, issuance and expiry; both must explicitly say `acknowledge` and `revoked is False`.

This input is intentionally *untrusted* and can be coordinated/fabricated; even indistinguishable fake records and a forged clock still return only REVIEW_ONLY. There is no signature verification, trusted identity, real customer identifiers, verified consent or revocation-at-use. No input-derived values appear in the result, including on errors.

## Isolated checks

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_fictional_dual_party*_1507.py' -v
```

The dedicated SHA-pinned read-only GitHub workflow runs both the pure reviewer and opt-in subprocess CLI suites on Python 3.11 and 3.14, without using a self-hosted runner or interfering with original workflows. An isolated PASS is never full hosted or permanent VPS evidence.

## Separate opt-in stdin CLI

Run without touching a target, grant or database:

```bash
PYTHONPATH=src python -m lightup.fictional_dual_party_cli_1507 < tests/fixtures/fictional_dual_party_valid_1507.json
# prints REVIEW_ONLY, process exit 2 (never exit 0)
PYTHONPATH=src python -m lightup.fictional_dual_party_cli_1507 < tests/fixtures/fictional_dual_party_revoked_1507.json
# prints HOLD, process exit 3
```

Input must be **fully canonical sorted-key ASCII JSON** in a 4,096-byte maximum envelope with exact `schema=fictional_dual_party_v1`, `review_at` exact ISO UTC second timestamp ending `Z`, and exactly two `claims`. Each claim has exactly the ten named dataclass fields; `capabilities` is a JSON list converted internally to an immutable tuple. Duplicate keys at any depth, escaped/noncanonical variants, trailing bytes, unknown fields, Unicode, malformed dates, all non-JSON constants and oversized stdin atomically HOLD. The CLI reads from stdin through EOF and emits only one constant token. **Never pipe real customer information to it**, and do not misinterpret exit 2 as a successful authorization. Use only fictional examples. The process does not make network or target calls.

The dedicated normal unittest suite includes actual split-pipe subprocess delivery, valid/revoked fixture checks, object-type and UTC attacks, duplicate-key/extra-data checks, NUL corruption and deterministic bit-flip fuzz on synthetic bytes. No real names or actual customer identifiers are used.

## Explicit scope/ownership fence

All files are entirely new `#1507`-owned paths. No import in production authentication, policy, grant issuance, queue, handler or scanner. Existing active owner PRs #1492/#1494/#1496/#1498/#1500/#1502/#1504/#1506 and source-owner branches remain untouched. **Do not merge or deploy** until original security/privacy owner review, genuine separate verified client **and** operator consent, at-use revocation, original source defect remediation, exact-head full hosted CI and an actually registered permanent `vps-bb300bba` run (#1144), plus explicit human GO. This is an offline review aid, not a release gate implementation.
