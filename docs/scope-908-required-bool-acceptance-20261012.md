# #908 — exact-boolean tool parameter admission (offline RED)

**Status:** DRAFT / HOLD / NO MERGE / NO DEPLOY. LightUp **Incubate M3/M7; PLAN/LAB only**.

## Ownership and purpose
This acceptance child starts at source-owner [PR #156](https://github.com/Zennay/Lightup/pull/156) exact SHA e84f2cd74d24f143c02b38cc05cb1c4c64352966. Only two NEW files are touched: tests/test_scope_908_required_bool_acceptance_20261012.py and docs/scope-908-required-bool-acceptance-20261012.md. Do not alter src/lightup/ai/orchestration.py, existing tests, ToolExecutor, execution policy, engagements, state, web, grants or evidence producers. Source owner retains sole repair ownership.

## Defect and fix acceptance
ToolParameter.required is annotation-only. ToolDefinition.validate_arguments() uses Python truthiness, so 0, empty string, None, empty tuple/dict or an arbitrary falsey object can silently turn a purportedly mandatory argument into an optional one. Truthy non-bools are likewise noncanonical.
Accept registration only when type(parameter.required) is bool. Every malformed value must fail with OrchestrationError BEFORE registry insertion, without invoking an untrusted truthiness/coercion callback. Denial never creates execution authority.

## Tests
- Three GREEN controls: True requires a present typed argument; False permits omission but type-checks present data; bool differs from int despite subclassing.
- Eleven intentional RED / expectedFailure methods: 0, empty string, None, empty tuple, empty dict, 1, nonempty string, a custom falsey object and an object whose __bool__ raises, plus late-invalid nested parameters preserving an existing registration and a direct-validate falsey-marker canary. Each demands fail-closed rejection, unchanged registry and zero handler invocations.
- No real handlers are executed. Synthetic in-process objects only; no DNS, sockets, target interaction, scans, permits, credential use or production data.

Local isolated command (run only on actual checked-out branch):
    PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_908_required_bool_acceptance_20261012.py' -v

Expected pre-repair shape: 14 methods, 3 normal successes, 11 expected failures, 0 errors. This is a specification, not a claimed CI result. expectedFailure is NOT a fix; once the source owner repairs the implementation, unexpected successes intentionally fail CI until annotations are reviewed and removed.

## Hold/release checklist
1. Verify this exact two-path add-only diff against immutable #156 head.
2. Check exact-head Python 3.11 and 3.14 hosted unit and real-producer integration logs; do not infer success.
3. Require separate exact-head permanent registered [self-hosted, zcloud, vps] CI on vps-bb300bba; queued is not accepted.
4. Original ToolRegistry source owner implements installed admission and removes expectedFailure only after true acceptance, independently reviewing tenant/grant/capability/risk/revocation behavior.
5. Reconcile latest main, independent security/privacy review and explicit human release approval. NO MERGE / NO DEPLOY / NO TARGET EXECUTION in this lane.

References: [issue #908](https://github.com/Zennay/Lightup/issues/908), [source owner #156](https://github.com/Zennay/Lightup/pull/156), [separate schema-container issue #911](https://github.com/Zennay/Lightup/issues/911).
