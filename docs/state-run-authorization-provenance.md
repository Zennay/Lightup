# State run authorization provenance contract

## Boundary

`StateStore.create_run()` is the durable boundary that binds a persisted run mode to any authorization provenance carried by that run. It must reject ambiguous or contradictory state before a row is inserted.

The canonical mode vocabulary comes from `lightup.activation.ActivationMode`:

- `plan_only`
- `lab_only`
- `authorized`

Exact built-in strings matching those values remain accepted for existing callers. Unknown values and string subclasses are rejected instead of being normalized.

## Authorization-reference invariant

Only `authorized` runs may carry `authorization_ref`.

For an authorized run, the reference must be:

- present;
- an exact built-in `str`;
- non-empty;
- already canonical, with no leading or trailing whitespace.

`plan_only` and `lab_only` runs must persist `authorization_ref = NULL`. Supplying a reference for either mode is rejected before persistence.

## Failure semantics

Validation happens before `run_id` persistence. Invalid mode/provenance combinations therefore leave the `runs` table unchanged.

The boundary does not:

- create or validate a grant;
- widen scope;
- issue execution permits;
- interact with a target;
- perform scanning, remediation, retesting, deployment, verdict creation, or attack-path mutation.

It only prevents durable run provenance from claiming authorization semantics that contradict the run mode.

## Regression coverage

`tests/test_state_authorization_provenance.py` covers:

- default plan-only persistence;
- lab-only enum persistence;
- compatibility with exact canonical string callers;
- valid authorized persistence;
- unknown-mode rejection;
- string-subclass mode rejection;
- authorization references on non-authorized modes;
- missing, blank, whitespace-normalized, and string-subclass authorization references;
- no-row persistence for every rejection path.
