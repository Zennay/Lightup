# #905 — canonical private-lab CLI opt-in (source-owner acceptance)

Status: **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. This document and
`tests/test_scope_cli_policy_marker_905.py` are additive, offline acceptance
artifacts. They are pinned above source-owner PR #100 head
`ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`; this branch does not
repair, merge, or take ownership of `src/lightup/cli.py`.

## Specific source gap

The PR #100 `lightup.cli._policy` uses
`allow_private_lab=bool(args.allow_private_lab)`. An external caller of the
function can construct `argparse.Namespace(allow_private_lab="false", ...)`.
Despite looking like a denial, that string is truthy and is converted to
`True`. `ScopePolicy` then treats an ordinary private IP as a LAB shortcut,
without proving client/operator consent. This is a config-to-authority bug,
not an argparse command-line flag bug.

## Exact acceptance contract for the source owner

1. Reject every non-`bool` marker *before* constructing or consulting
   `ScopePolicy`, including `"false"`, `"0"`, `1`, `0`, `None` and
   objects implementing `__bool__`. Use controlled `ValueError`.
2. Exact built-in `False` denies an ordinary private address;
   exact built-in `True` permits only the existing private-lab candidate
   decision, without expanding public target authority.
3. The supported argparse default and explicit flag continue supplying exact
   built-in booleans; namespace values remain unchanged.
4. Do not coerce caller-supplied values with `bool(...)`, call DNS, contact
   a target, enable a scanner, issue a grant or change deployment/release gates.

## Test migration

Run (read-only, no secrets/network targets):

```sh
PYTHONPATH=src python -m unittest discover -s tests \
  -p 'test_scope_cli*_905.py' -v
```

The seven ordinary positive tests must PASS on PR #100. The eight
`@unittest.expectedFailure` cases prove **unfixed source-owner RED debt**
on the pinned branch; **expected failure is not a safe implementation**.
Additional `tests/test_scope_cli_precoercion_905.py` shows that even a custom marker's `__bool__` must **never be invoked** before denial (including a throwing hook). When PR #100's owner makes the production change, remove those decorators
and require all fifteen methods to pass as ordinary tests, in both Python
3.11 and 3.14, and verify the entire repository and real registered
`vps-bb300bba` workflows. An unexpected success in CI is a signal to
reconcile this test migration, not permission to bypass the gate.

## Ownership and release fence

The source-owner PR #100 retains its existing `cli.py`, `scope.py`,
activation, and executor files. Issue #905 owns these new test/doc paths only.
No import from this document/test may be treated as authentication,
operator approval, a grant, revocation-at-use proof, or permission to
dispatch. Separate, independently verified client and operator consent,
at-use revocation, privacy/security review, exact-head full hosted CI,
registered permanent VPS green and explicit HUMAN GO are still required.
No merge, real target, scanner, dispatch, activation or deploy here.
