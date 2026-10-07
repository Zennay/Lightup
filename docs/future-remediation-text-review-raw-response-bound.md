# Remediation reviewer raw-response bound

Issue: #815

## Purpose

The remediation verifier asks a provider for a small structured response, but
provider output must still be treated as untrusted. `max_output_tokens` is a
request hint rather than a trusted parser boundary.

The raw response therefore needs an explicit total-size guard before any JSON
decoding occurs. The existing 4,000-character summary limit is too late to
serve that purpose because `json.loads()` has already processed the entire
response by then.

## V1 contract

The raw remediation-review response is limited to **32,768 characters**.

The guard must run before `json.loads()` and must:

- keep normal canonical reviewer JSON accepted unchanged;
- reject oversized input without parsing any part of it;
- avoid truncation, partial parsing, recovery, or best-effort normalization;
- preserve the existing exact top-level schema and duplicate-key rejection;
- preserve the existing required-check and decision-coherence rules;
- preserve the 4,000-character parsed-summary limit.

This is intentionally provider independent.

## Acceptance proof

`tests/test_future_remediation_text_review_raw_response_bound.py` provides:

- a canonical approved-review green control;
- a valid JSON response whose aggregate size is independently proven to exceed
  32,768 characters;
- a patched `json.loads` sentinel that fails the test if an oversized response
  reaches the JSON parser;
- an expected-RED `ValueError` contract for the current #217 source head.

The branch is pinned directly to active PR #217 exact head
`d7e3c1e5f21726a2dfd6bd9133e3823a06402160`.

## Collision boundary

Tests and documentation only. PR #217 retains all production ownership of
`src/lightup/future_remediation_text_review.py`.

This is distinct from response-content runtime typing (#786), reviewer
provider/model identity, persisted-review integrity, snapshot isolation,
summary canonicality, scope authorization, and any execution-capable path.

## Safety

Parser reliability narrowing only. No target interaction, evidence collection,
tool/remediation/retest execution, code/config application, deployment, verdict
creation, or attack-path mutation.
