# Revised remediation reviewer raw-response bound

Issue: #816

## Purpose

The revised-remediation verifier has its own JSON response parser. Provider
`max_output_tokens` is a request hint, not a trusted parser boundary, so this
independent parser needs its own explicit aggregate response ceiling before
decoding untrusted provider output.

The existing 4,000-character summary limit is applied only after
`json.loads()`; it therefore cannot protect the pre-schema parsing boundary.

## V1 contract

The raw revised-remediation reviewer response is limited to **32,768
characters**.

The guard must execute before `json.loads()` and must:

- preserve canonical revised-review JSON unchanged;
- reject oversized input without invoking the JSON parser;
- never truncate, partially parse, recover, or normalize oversized input;
- preserve duplicate-key rejection and the exact top-level response schema;
- preserve the required-check and decision-coherence rules;
- preserve the existing 4,000-character parsed-summary ceiling.

The limit is intentionally provider independent.

## Acceptance proof

`tests/test_future_remediation_text_revision_review_raw_response_bound.py`
contains:

- a canonical approved revised-review green control;
- a valid JSON response whose aggregate size is independently proven to exceed
  32,768 characters;
- a patched `json.loads` sentinel proving oversized input must be rejected
  before parsing;
- a `ValueError` regression contract carried on the #246 source-owner head.

The branch is pinned directly to active PR #246 exact head
`d995cf57e20f99956fe20b9b8b05d41b64e02765`.

## Collision boundary

The acceptance contract originated as tests/docs-only work and is now absorbed by source-owner PR #246 with the minimal pre-parse raw-response guard.

This is separate from #815 because the first-pass and revised-remediation
reviewers have independent source modules and independent promotion stacks. It
also does not change response-content typing, provider/model identity,
persisted-review integrity, snapshot isolation, scope authorization, or any
execution-capable path.

## Safety

Parser reliability narrowing only. No target interaction, evidence collection,
tool/remediation/retest execution, code/config application, deployment, verdict
creation, or attack-path mutation.
