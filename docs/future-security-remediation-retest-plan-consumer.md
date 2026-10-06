# ST5 persisted remediation/retest plan consumer

This boundary composes the strict serialization handoff from #190 with the
existing live ST5 plan builder.

A caller may provide either raw JSON text or an already-decoded object. Raw
JSON is decoded only by the duplicate-key-safe #190 parser; object input is
handled only by the same strict typed parser. The resulting
`FutureSecurityRemediationRetestPlan` is never returned directly.

Before return, the consumer rebuilds the plan with
`build_future_security_remediation_retest_plan` from the supplied live
security-delta report, graph-diff preview, transition proposal, resolutions,
RunContexts, and StateStore. The parsed plan must equal that canonical live
rebuild exactly. Report, resolution, run/evidence, tenant, or other upstream
lineage drift therefore fails closed.

This is an integrity and ingestion boundary only. It does not authorize
evidence collection, target interaction, tool selection or execution,
remediation execution, future-state retest execution, deployment,
classification selection, transition resolution, or attack-path mutation.
The plan remains `execution_allowed=false`,
`deployment_authorized=false`, `attack_path_mutation_allowed=false`,
`future_semantics=unresolved`, and `security_verdict=not_evaluated`.

## Dependency and ownership

This slice is stacked directly on draft PR #190 at exact parent head
`aac21848e91d767b62c9206f2830598e23e2b0a5`. It adds new files only and
does not modify #190, PR #60 remediation-evidence work, or the #62-rooted
persisted evidence-remediation chain. If #190 moves or lands, restack and
re-prove this child before promotion.
