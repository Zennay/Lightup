# #911 — immutable ToolDefinition parameter schema acceptance

**LightUp Incubate M3/M7 PLAN/LAB only. DRAFT / HOLD / NO MERGE / NO DEPLOY.**

## Exact owner boundary
Independent synthetic acceptance stacked on immutable ToolRegistry source-owner PR #156 SHA e84f2cd74d24f143c02b38cc05cb1c4c64352966. Exactly two newly added paths: tests/test_scope_911_immutable_schema_acceptance_20261012.py and docs/scope-911-immutable-schema-acceptance-20261012.md. Production orchestration, existing tests, executor, grants, domain, policy, web and other workers remain untouched.

## Defect and required authorization invariant
ToolDefinition is frozen, but its parameters annotation does not enforce runtime tuple identity. If a mutable list is retained on a registered definition, a caller can delete a required ToolParameter after registry admission; subsequent validate_arguments({}) no longer rejects the missing required argument. Duck objects and subclassed ToolParameter objects introduce other dynamic schema behavior.
Registry admission MUST require type(definition.parameters) is tuple and every item must satisfy type(item) is ToolParameter. Refuse list, set, mapping, custom iterable, subclass and duck objects before registry insertion. Rejecting invalid schemas must not call handlers or schema iterable callbacks or mutate existing registry entries. This shape check is a necessary but insufficient part of trusted execution authorization.

## Evidence contract
- Three GREEN controls: exact tuple-backed required argument, exact empty tuple, and frozen attribute assignment refusal (which alone is insufficient).
- Eight deliberate expectedFailure canaries: mutable list, set, mapping, hostile iterable, ToolParameter subclass, duck object, post-registration mutable-list removal of mandatory parameter, and late invalid nested parameter with a pre-existing valid tool.
- Synthetic in-process objects only. Fake handler deliberately raises if invoked. No DNS, sockets, public targets, active assessments, scans, evidence, credentials, permit issuance or grants.

Local isolated invocation:
    PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_911_immutable_schema_acceptance_20261012.py' -v

Expected before source-owner repair: 11 methods, 3 normal successes, 8 expected failures, 0 errors. This is the intended RED shape, not an asserted tested outcome. ExpectedFailure must not be treated as installed security. Following a real owner fix, remove annotations only once genuine green tests prove the boundary.

## Hold until
1. Exact-head hosted Python 3.11/3.14 unit and real-producer integration evidence.
2. Separate exact-head permanent registered vps-bb300bba [self-hosted, zcloud, vps] LightUp CI success.
3. Source-owner #156 implementation and review of #911 and #908 distinct boundaries; all RED canaries become standard passing tests.
4. Latest-main composition, original owners, security/privacy and tenant/grant/revocation checks, and explicit human release approval.

Never merge or deploy this lab-only acceptance by itself. [Issue #911](https://github.com/Zennay/Lightup/issues/911) · [Source owner #156](https://github.com/Zennay/Lightup/pull/156) · [Separate bool issue #908](https://github.com/Zennay/Lightup/issues/908).
