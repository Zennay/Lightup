# LightUp source integration: scope-safe plans + bounded model intake

**Phase:** INCUBATE M3/M7 — PLAN/LAB ONLY — DRAFT/HOLD.

## Working code integrated from existing source owners

The original unmerged [#204](https://github.com/Zennay/Lightup/pull/204) (issue #203) already designed a scope-reason-bound capability catalog. This branch carries that behavior forward in original `src/lightup/orchestrator.py`, adding exact decision-object and reason/coherence checks. A plan for explicitly scoped public assets includes PLANNING capabilities, **not** LAB_ONLY capabilities. Local loopback/private-lab plans can still list the existing lab-only catalog; plans never enable execution.

The original unmerged [#180](https://github.com/Zennay/Lightup/pull/180) (issue #179) already designed planner argument/asset binding. This branch integrates the corresponding `src/lightup/ai/planner.py` guard: an untrusted model's `host` or `url` parameter for LAB_ACTIVE must be a real canonical exact string naming **the same target that the approved lab scenario contains**. Mismatched local, private or public destinations are refused **before** a PlannedCall is produced. ANALYSIS metadata is not interpreted as a new network target.

Original PR branches and acceptance suites are preserved unchanged; this branch is an independent combined source integration for owner review, not a replacement for their acceptance/security signoff.

## New functional behavior: strict bounded model-produced JSON

The actual planner now refuses a non-string, empty or >65,536-character model response before JSON decoding. Recursive duplicate object keys and explicit nonfinite JSON constants are refused before last-wins semantics. Huge-exponent numeric floats are also rejected. A plan must contain 1–64 entries, each with exact canonical tool and scenario-target identity, only recognized fields, and an argument mapping limited to 32 entries. Ordinary existing valid tool parameters are still dispatched only through the original executor's policy gates. No model invocation, scanner, target, tool handler or real execution is used by this source update.

These boundaries are *not* signed assessment permissions. They do not authenticate client/operator approval, durable grants, action-time revocation, live destination resolution or tenant lineage. Mandatory original full exact-head hosted and permanent registered named VPS CI, original issue owner review, independent security/privacy and explicit HUMAN GO remain mandatory before merging/deploying. No QA/regression/testsuites authored or manually executed.

## Source-only acceptance at time of development

Original VPS via connected zSSH; Python AST parse and `git diff --check` used to inspect changed source. This is not a green CI verdict and does not replace the original blocked admission gates.
