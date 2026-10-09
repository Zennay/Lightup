# Argument-hook denial boundary — offline acceptance

This document accompanies draft PR #1146 and `tests/test_scope_argument_key_hook_boundary_20261009.py`.

## What is proven by the reference tests

The standalone `validate_unambiguous_arguments` helper rejects untrusted argument-key and registry-key objects before invoking their `__hash__` or `__eq__` methods. Rejected duplicate or invalid names never require formatting an untrusted value via `__str__` or `__repr__`. Malformed pair subclasses do not get a chance to run `__len__` / `__iter__`, and invalid registry metadata denies before argument-container iteration. Exact built-in string key/value remains a positive control.

These checks run entirely in memory. They are **not authorization**, and the helper remains unintegrated in the actual production `ToolExecutor`. Tests using a temporary dispatcher patch are test-only proof.

## Reproduce

With the LightUp Python package installed in the test environment:

```sh
python -m unittest discover -s tests -p 'test_scope_argument_key_hook_boundary_20261009.py' -v
```

## Integration checklist for the assigned source owner (PR #107)

1. Use trusted registry-owned schema and reject malformed duplicate/forged keys **before** lossy `dict(...)` conversion or handler invocation.
2. Check persisted tenant/engagement/asset/capability/risk consent and trusted destination identity; deny stale or revoked approval immediately before any actual I/O.
3. On denial, assert zero real handler calls, sockets, queue writes, or action-evidence persistence. Include a single authorized lab-positive control.
4. Preserve a commit-specific test report for hosted Python 3.11/3.14 and permanent VPS jobs on the **same commit SHA**.
5. Require independent source/security review before production merge or any live-target activation.

Duplicate-argument RED contract belongs to PR #966; trusted destination work belongs to #1092/#1093. This document does not authorize changes to those branches.

**Release state: DRAFT / HOLD. No real targets, network scanning, grants, merge, deployment, or activation.**

## Schema callback ordering acceptance (2026-10-09)

The focused suite also checks that unknown keys, duplicates, and malformed registry parameter kinds are rejected before calling `ToolDefinition.validate_arguments`. The canonical built-in STRING positive control invokes that callback exactly once with the validated mapping. These are **offline helper contracts**, not authorization to execute, scan, or target anything.
