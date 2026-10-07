# State run authorization provenance contract

## Boundary

`StateStore.create_run()` is the durable boundary that binds a persisted run mode to any authorization provenance carried by that run. It must reject ambiguous or contradictory state before a row is inserted.

The durable run-mode vocabulary is:

- `plan_only` for planning-only ledger work;
- `analysis_only`;
- `passive_discovery`;
- `lab_autonomous`;
- `authorized_assessment`.

The four assessment modes come from `lightup.engagements.AssessmentMode`. Exact built-in strings matching these canonical values remain accepted for existing callers. Unknown values and string subclasses are rejected instead of being normalized.

The older activation-gate values `lab_only` and `authorized` are not durable assessment run modes and are therefore rejected at this boundary.

## Authorization-reference invariant

Only `authorized_assessment` runs may carry `authorization_ref`.

For an authorized assessment, the reference must be:

- present;
- an exact built-in `str`;
- non-empty;
- already canonical, with no leading or trailing whitespace.

`plan_only`, `analysis_only`, `passive_discovery`, and `lab_autonomous` runs must persist `authorization_ref = NULL`. Supplying a reference for any of those modes is rejected before persistence.

## Failure semantics

Validation happens before `run_id` persistence. Invalid mode/provenance combinations therefore leave the `runs` table unchanged.

The boundary does not:

- create or validate an authorization grant;
- widen target scope;
- issue execution permits;
- interact with a target;
- perform scanning, remediation, retesting, deployment, verdict creation, or attack-path mutation.

It only prevents durable run provenance from claiming authorization semantics that contradict the run mode.

## Regression coverage

`tests/test_state_authorization_provenance.py` covers:

- default `plan_only` persistence;
- enum-backed analysis/passive/lab persistence;
- compatibility with exact canonical string callers, including existing `lab_autonomous` ST5 paths;
- valid enum and string `authorized_assessment` persistence;
- unknown and legacy activation-mode rejection;
- string-subclass mode rejection;
- authorization references on every non-authorized mode;
- missing, blank, whitespace-normalized, and string-subclass authorization references;
- no-row persistence for every rejection path.
