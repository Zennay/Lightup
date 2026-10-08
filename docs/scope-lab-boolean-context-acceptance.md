# LAB_ACTIVE canonical lab-context acceptance

## Purpose

The lab exception in `ExecutionPolicy.decide` currently uses `if not request.is_lab`.
A non-boolean truthy value can therefore mark an otherwise ordinary request as
lab execution, despite the `ExecutionRequest.is_lab: bool` annotation.
The LAB_ACTIVE exemption must only be granted when
`type(request.is_lab) is bool` and its value is `True`.

## Offline acceptance contract

- `True` keeps the established isolated-lab policy result.
- `False` denies the exception.
- Strings, numbers (including `1` and `-1`), sequences, mappings and objects
  never acquire lab status merely through Python truthiness.
- Invalid types fail closed without dispatch, target I/O or evidence mutation.

Run locally with `pytest -q tests/test_scope_lab_boolean_context_acceptance.py`.
The truthy invalid cases are **expected RED** until the owning execution-policy
production PR implements the narrow exact-type check.

## Ownership / safety

This acceptance sidecar adds tests and documentation only. The execution-policy
production owner retains `src/lightup/execution_policy.py`; do not merge this
acceptance contract as a green-gate claim before the owner fixes the behavior.
No network traffic, scanning, exploitation, target execution, deployment or
widening of privileges is introduced.
