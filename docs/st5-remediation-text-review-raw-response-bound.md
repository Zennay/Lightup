# ST5 remediation reviewer raw-response bound

Issue: #815

## Purpose

The independent remediation-text reviewer must bound provider output before
attempting JSON parsing. The provider's `max_output_tokens` request is not a
trusted response envelope, and the existing 4,000-character summary limit is
applied only after the full JSON document has already been parsed.

## Acceptance contract

This tests/docs-only child is pinned directly above source-owner PR #217 head
`d7e3c1e5f21726a2dfd6bd9133e3823a06402160`.

The regression proves:

- ordinary canonical reviewer JSON remains accepted;
- an exact 32,768-character raw reviewer response remains accepted;
- a 32,769-character response fails closed with a bounded-response error;
- the oversized case is rejected before `json.loads` is invoked;
- no truncation or partial parsing is used;
- existing non-executable authority remains false.

## Expected pre-fix result

The canonical and exact-boundary controls are green. The oversized response is
intentionally RED on the pinned #217 implementation because
`_parse_reviewer_content(raw)` currently calls `json.loads(raw, ...)` before
any aggregate raw-response size check.

## Ownership and collision boundary

This branch adds only a dedicated regression module and this contract document.
It does not modify `src/lightup/future_remediation_text_review.py` or any other
production source. PR #217 remains the sole source owner.

The source-owner fix should enforce the 32,768-character ceiling after the
existing exact-string/non-empty guard and before the JSON parser call, while
preserving duplicate-key rejection, exact schema validation, decision/check
coherence, the 4,000-character summary bound, and all fail-closed action flags.

## Safety

Repository-only defensive validation. No target interaction, tool execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation is introduced.
