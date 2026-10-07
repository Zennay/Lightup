# Implementation planner raw-response bound

Issue: #817

## Purpose

The remediation implementation planner already validates a strongly bounded
decoded JSON structure. Those field, text and collection limits do not protect
the work performed **before** schema validation: provider output currently
reaches `json.loads()` without an aggregate raw-response ceiling.

Provider `max_output_tokens` is a request hint and must not be treated as a
trusted parser boundary.

## V1 contract

The raw implementation-planner response is limited to **65,536 characters**.

The guard must run before `json.loads()` and must:

- preserve ordinary canonical planner JSON unchanged;
- reject an oversized response before JSON decoding;
- avoid truncation, partial parsing, sampling, recovery, or normalization;
- preserve all existing duplicate-key, schema, plan-item, text and collection
  bounds from #235/#277.

The ceiling is provider independent.

## Acceptance proof

`tests/test_future_remediation_implementation_plan_raw_response_bound.py`
contains:

- a canonical valid implementation-plan response green control;
- an oversized response created only by prepending JSON-legal whitespace to
  that exact canonical response, so the decoded artifact would otherwise be
  unchanged;
- an independent assertion that the raw envelope exceeds 65,536 characters;
- a patched `json.loads` sentinel proving rejection must happen before parsing.

This distinguishes the pre-parse envelope from #277's decoded structural
limits. The branch is pinned directly to active PR #235 exact head
`7113d1ee886d3d08124c4253083030bf867a7109`.

## Collision boundary

Tests and documentation only. PR #235 retains production ownership of
`src/lightup/future_remediation_implementation_plan.py`; #277 retains decoded
planner-output structural-bound ownership.

No handoff/persistence, review/revision, scope authorization or
execution-capable source is modified.

## Safety

Parser reliability narrowing only. No target interaction, evidence collection,
code/config generation or application, tool/remediation/retest execution,
deployment, verdict creation, or attack-path mutation.
