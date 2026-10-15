# Offline authorization expiry-cohort review (2026-10-15)

**LightUp: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is an optional **non-authorizing report of untrusted claims**, not a grant, consent, scan preflight, execution permit, installation guide or release gate. It complements open time-window issue #347 without satisfying its producer acceptance or altering another worker's source.

## Problem

A scope reviewer needs an **aggregate, privacy-minimal view** of time-window metadata without reading client identifiers, exposing authorized assets or quietly treating a parseable date as customer permission. Existing source-owner grant issuance and executor PRs own actual runtime authorization and revocation. Their work must not be bypassed by a standalone report.

## Added self-owned files

- `scripts/review_scope_expiry_cohort_20261015_offline.py` — independent, pure-stdlib, stdin-only CLI.
- `tests/test_scope_expiry_cohort_20261015_offline.py` — real subprocess and direct unit regressions.
- This document.

No production imports, router wiring, SDK calls, network requests, persistent reads/writes, grant creation, grant mutation, scanning, runner/workflow edits, or changes to existing files.

## Strict input

Send UTF-8 JSON (maximum **16 KiB**) on stdin, without CLI flags. The only accepted shape is:

```json
{
  "as_of_utc": "2026-10-15T12:00:00Z",
  "horizon_hours": 24,
  "windows": [
    {"valid_from": "2026-10-14T12:00:00Z",
     "valid_until": "2026-10-16T12:00:00Z"}
  ]
}
```

- Exactly three top-level fields; no unknown properties or identifiers anywhere.
- 1–32 anonymous windows; only two datetime fields each; no client, hostname, asset, engagement, risk, tool, approval or secret accepted.
- Literal built-in JSON integer for horizon, 1–720 hours; no booleans, negative-zero, float/exponent aliases, five-digit oversized integers, duplicates or nonfinite constants.
- All dates are exact ASCII UTC `YYYY-MM-DDTHH:MM:SSZ`; reject Unicode digit lookalikes, offsets, noncanonical parsing, 24:00 rollover, invalid calendar dates, and empty/inverted periods. This avoids Python-version-dependent normalization.
- `as_of_utc` is a **user-supplied preview instant**, not evidence of an authenticated system clock.
- Any malformed member causes **atomic HOLD**; never show a partial healthy count.

## Result contract

A structurally valid packet prints exactly one opaque JSON line and exits **3**, `REVIEW_ONLY`. Counts are mutually exclusive: `expired` (after inclusive end), `not_yet_started` (before start), `current_expiring_within_horizon`, and `current_later`. A malformed packet prints generic `HOLD`, exits **2** and reports **no counts**. Both results carry *six literal false bits*:

```json
{"authorization_verified":false,"permit_issued":false,"dispatch_enabled":false,"merge_approved":false,"deploy_approved":false,"release_approved":false}
```

No zero exit is possible for a normal input. No input values, timestamps, paths, client identifiers, or raw JSON snippets are echoed; even REVIEW_ONLY cannot show which anonymous row contributed to a count. A REVIEW_ONLY aggregation is not evidence of persisted, authentic, approved, current or non-revoked authorization.

## Verification

```sh
python -m unittest discover -s tests -p 'test_scope_expiry_cohort_20261015_offline.py' -v
```

Use fictional windows only. Tests include real CLI invocation, 16 KiB bound, strict JSON shape, duplicate keys, wrong types, 24:00 rollover, Unicode decimal disguises, inclusive temporal boundaries and no authority flags. They do not initiate target traffic.

## Required independent source-owner handoff

Real-world authorization still requires: independently authenticated customer/operator consent; original request–grant FK and exact tenant/scope matching; revocation and time validity checked from trusted storage immediately before **each** dispatch; canonical DNS/network destination binding; separate destructive-lab human step-up; branch/run/runner attestation; independent security and privacy review and explicit human release. This reviewer is neither a substitute nor a prerequisite for those gates.

**Do not merge/deploy/activate just because these isolated tests are green.** Keep this PR in DRAFT/HOLD until source-owner collision review and an exact immutable-head hosted **and** registered permanent VPS test plus human approval.
