# ST4 direct security-delta report construction

Issue: #328  
Base: merged `main` at `1abc16a66fc490b1ba7272890dfbf498482fca9c`

The canonical ST4 report builder already rebuilds a graph-diff preview against live lineage. This child closes the in-process bypass around that builder: direct dataclass construction and `dataclasses.replace()` now preserve the same immutable reporting semantics instead of allowing contradictory state to exist before downstream ST5 validation.

## Direct report-item invariant

`FutureAttackPathSecurityDeltaReportItem` now requires:

- non-empty change, subject and resolution identities;
- canonical lowercase resolution SHA-256;
- actual classification and graph-diff action enum members;
- the exact canonical classification → graph-diff action mapping;
- tuple-backed effect/current-path/evidence/capability lineage;
- unique non-empty string elements in those lineage tuples.

## Direct report invariant

`FutureAttackPathSecurityDeltaReport` now requires:

- exact ST4 schema and non-empty client/twin/change identities;
- non-negative exact-int twin versions;
- canonical proposal, impact-analysis, preview and report SHA-256 values;
- a non-empty tuple of exact validated report items;
- unique change and resolution identities;
- no current attack-path ID claimed by different changes;
- insufficient-evidence state derived from actual item classifications;
- exact `report_complete=true`;
- exact `attack_path_mutation_allowed=false`;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`;
- a canonical lowercase SHA-256 representation for `report_sha256`.

A deliberately stale but syntactically canonical report digest remains constructible. Existing downstream live-lineage regressions rely on creating exactly that stale artifact and proving the consumer rejects it. Digest **recomputation/equality** therefore stays at the established live consumer boundary rather than being silently moved into the dataclass constructor.

## Safety

Integrity narrowing only. This change does not add target interaction, evidence collection, tool execution, remediation/retest execution, deployment, future-state resolution, verdict creation, or attack-path mutation.

## Collision boundary

The #328 branch changes only:

- `src/lightup/future_attack_path_security_delta_report.py`;
- `tests/test_future_attack_path_security_delta_report_direct_construction.py`;
- `docs/future-attack-path-security-delta-report-direct-construction.md`.

It does not modify graph-diff preview/resolution code, remediation/retest-plan files (#190/#320/#325), evidence-bundle/authoring files, implementation-planning files, or scope-authorization work.
