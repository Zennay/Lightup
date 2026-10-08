# Offline authorization policy replay contract

This test-only contract protects the separation of **decision evaluation** from **authority mutation** for the existing `ExecutionPolicy` API.

## Expected behavior

- Replaying the same eligible request returns the same decision without modifying its request, grant or scope.
- An allowed request must never prime a different request: excluded assets, unlisted capabilities and above-limit risk remain denied even when interleaved with successful evaluations.
- A separate active request with no grant is denied even after a successful authorized evaluation.
- Expired and not-yet-valid grants remain denied when their decisions are interleaved with decisions for a valid grant; successful evaluation must not cache time authority across requests.
- Test identifiers use reserved `.example.test` and do not resolve or contact any address.

The test suite pins existing product behavior, not a new source implementation. It does not cover the mutable authorization/resolver/executor lifetime boundaries owned by other branches. It intentionally avoids `src/lightup/execution_policy.py`, `src/lightup/engagements.py`, `src/lightup/domain.py`, `src/lightup/tool_executor.py` and deployment files.

## Local / CI verification

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_authorization_policy_replay_contract.py' -v
```

All tests use in-memory inputs only. They do not dispatch handlers, call transport adapters, perform scanning, provision services or authorize a real target.

## Integration guidance

Integrate independently of source-owner PR #100 (execution policy / grant contract) and PR #107 (ToolExecutor). If future changes allow decisions to cache or leak an earlier authorization into a later request, these replay tests must fail rather than be relaxed.
