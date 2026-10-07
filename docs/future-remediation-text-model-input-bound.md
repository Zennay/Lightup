# Remediation advisor model-input bound

Issue: #814

## Purpose

The remediation-text producer already limits generated output to 1,200 tokens
and rejects responses above 16,000 characters. Its evidence-bound input prompt
must have an equally explicit aggregate size envelope before the provider is
called.

Per-field identifier limits are not enough by themselves: a remediation request
may contain many valid items and evidence references. Without a total input
bound, the serialized user prompt can grow arbitrarily with request cardinality.

## V1 contract

The final serialized remediation-advisor **user message**, including its framing
text and evidence-bound JSON, is limited to **65,536 characters**.

The guard must:

- preserve normal canonical requests unchanged;
- measure the exact final user-message content that would be submitted;
- reject an oversized payload before `ModelGateway.complete()`;
- never truncate, summarize, silently drop, reorder, or sample remediation
  items or evidence references to fit;
- leave caller-owned request state unchanged on rejection;
- preserve the existing rule that raw evidence source/metadata, credentials,
  authorization references, target arguments and customer source/config are not
  added to the prompt.

This is a provider-neutral reliability and data-minimization ceiling, not an
estimate of any specific provider's token context window.

## Acceptance proof

`tests/test_future_remediation_text_model_input_bound.py` contains:

- a green control showing the canonical producer request fits within 65,536
  characters and remains input-atomic;
- an aggregate request with 120 bounded-shape remediation items whose serialized
  prompt exceeds the ceiling;
- a regression requiring that oversized payload to raise
  `ValueError` rather than be emitted or silently reduced;
- caller-input preservation after rejection.

The branch is pinned directly to active PR #207 exact head
`eaf03f3b672867ef3a22107e3c03ceeaedfb5ef7`.

## Collision boundary

The acceptance contract originated as tests/docs-only work and is now absorbed by source-owner PR #207 together with the minimal producer guard in `src/lightup/future_remediation_text_proposal.py`.

This slice does not alter proposal persistence, content normalization,
provider/model identity, review/revision flows, scope authorization, execution
policy, target interaction, remediation application, retest execution,
deployment, verdicts, or attack-path state.

## Safety

Model-input reliability/data-minimization narrowing only. No network target,
tool call, evidence collection, code/config application, remediation/retest
execution, deployment, verdict creation, or attack-path mutation.
