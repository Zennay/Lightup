# ST5 implementation-plan reviewer raw response bound

Issue: #820  
Source owner: #281 implementation branch  
Pinned head: `ef2dd5d534d0d0e67f73aa2546d4b190d432f63c`

## Contract

The implementation-plan reviewer must treat the provider response as an untrusted envelope before JSON decoding.

The v1 raw response ceiling is **32,768 characters**.

- exact-limit raw text remains eligible for normal parsing;
- text above the ceiling fails before `json.loads`;
- oversized input is not truncated, sampled, partially parsed or recovered;
- the existing exact schema, recursive duplicate-key rejection, five required checks, decision/check coherence and 4,000-character summary bound remain unchanged.

The provider request's 900-token limit is only a request hint. It is not a trusted parser boundary.

## Regression shape

The acceptance test pads otherwise canonical reviewer JSON with leading JSON whitespace. This isolates the aggregate envelope size from the existing decoded summary limit.

For the oversized case, `json.loads` is replaced with a sentinel that raises immediately if called. The expected contract therefore proves ordering: raw length must be rejected before JSON decoding begins.

## Collision boundary

This sidecar adds tests/docs only and does not modify `src/lightup/**`.

Distinct nearby ownership:

- #815 — first remediation-text reviewer raw response;
- #816 — revised remediation-text reviewer raw response;
- #817 — implementation planner raw response;
- #813 — implementation-plan reviewer model independence;
- #281 — all production reviewer source.

## Safety

Pure in-memory parser reliability testing. No external model/network/target interaction, code/config generation, tool execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
