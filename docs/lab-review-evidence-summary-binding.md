# Lab review evidence-summary binding

Issue: #840  
Parent: #839 verifier verdict contract

## Problem

The verifier prompt says it judges whether a finding is supported by its
evidence summary. Planner-driven lab results previously discarded
`ToolResult.summary`, while the review pipeline looked only for a top-level
`evidence_id` that planner-driven results do not contain.

A verifier could therefore decide `CONFIRMED`, `UNCERTAIN` or `REJECTED`
without receiving either the finding-local evidence reference or the evidence
summary produced by the tool.

## Contract

Each finding emitted by a lab assessment carries the local `ToolResult.summary`.
Before the verifier is called, the review pipeline requires:

- one non-empty evidence summary, at most 4096 characters;
- one to 64 non-empty evidence references;
- planner-driven per-finding references when present;
- the legacy single-run top-level evidence id only as the baseline fallback.

The verifier user payload receives `evidence_summary` and `evidence_ids`.
Raw evidence payload bytes are never forwarded to the model.

Missing/oversized evidence metadata fails before any model role is invoked.
The subsequent verdict semantic gate from #839 remains unchanged.

## Safety

This is lab-only evidence plumbing and read-only model input shaping. It adds no
target interaction, scope/authorization change, tool invocation,
remediation/retest execution, deployment, security-verdict authority or
attack-path mutation.
