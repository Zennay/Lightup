# Lab evaluation evidence/remediation metric integrity

Issue: #834  
Source owner: PR #169 (`src/lightup/labeval.py`)  
Acceptance branch: `chatgpt/labeval-evidence-remediation-metrics-integrity-red-20261007`

## Problem

LightUp uses `EvaluationMetrics` to score evidence quality, remediation quality,
reproducibility and retest correctness in the isolated lab. Those scores and
their supporting counters/runtime/cost metadata are evidence used to decide
whether later security workflows are trustworthy.

The current validator checks only score ranges and negative counters. Python's
numeric coercion therefore admits benchmark state that the intended schema
cannot represent reliably, including booleans as scores/counters, fractional
counters, and negative or non-finite runtime/cost values.

## Required contract

- quality scores are exact built-in `int`/`float` numbers, never `bool`,
  finite, and within `0..1`;
- finding/coverage/violation/intervention/tool counters are exact built-in
  non-negative `int` values;
- runtime and compute cost are exact built-in `int`/`float` numbers, never
  `bool`, finite, and non-negative;
- existing canonical metrics remain accepted unchanged;
- invalid metrics fail before `LabEvaluationHarness.records` is mutated.

## Expected RED

This child intentionally adds acceptance proof only. The current PR #169 source
still accepts at least the boolean/fractional counter cases and invalid
runtime/cost cases, so the new regression module is expected RED until the
`labeval.py` source owner absorbs the narrow validation repair.

## Collision boundary

PR #169 already owns `src/lightup/labeval.py` for harness-minted context
binding. This child does not modify that file or its context-binding tests. It
adds exactly one focused metrics regression module and this document.

No scope decision, authorization, model call, target interaction, collection,
tool execution, remediation/retest execution, deployment, verdict or
attack-path state is changed.
