# ST5 freshness-constraints consumer success atomicity

Issue: #759  
Pinned source owner: PR #131 @ `bbea958e01d3f0f83603f6b8e217255a9c19e1cc`

## Contract

A successful strict + live freshness-constraints consumption must be observationally read-only with respect to the caller-owned persisted payload.

Using the real #131 producer fixture and a JSON-decoded canonical constraints object, the acceptance proof requires repeated successful consumption to:

- return the exact canonical typed constraints;
- preserve full persisted value equality;
- preserve the root and every recursive dict/list object identity;
- preserve dict key order and list order;
- remain deterministic across repeated calls.

## Ownership and non-overlap

This branch adds tests/docs only. PR #131 retains production consumer source ownership. #756 owns rejection-path atomicity, #754 owns fail-fast ordering, and #748 owns outer persisted runtime-type exactness.

## Safety

Success-path input-integrity proof only. No evidence collection, capability/tool selection, target interaction, remediation/retest execution, deployment, classification, verdict creation or attack-path mutation is introduced.

Keep this branch-only while root #62 canonical LightUp CI remains queued; do not add duplicate runner pressure.
