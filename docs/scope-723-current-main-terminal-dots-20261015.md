# Current-main scope terminal-dot acceptance (#723 / #724)

**Status: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is not a production policy change, grant, authorization, scan, release approval, or merge/deployment instruction.

## Why this exists

The installed `ScopePolicy.normalize_host` and policy-side explicit-host membership use `rstrip(".")`. That strips **all** trailing DNS dots, not only a single syntactic root dot. Consequently, malformed target spelling `localhost..` inherits loopback, while an allowlisted synthetic hostname with two or three ending dots can inherit explicit-host authority. It also allows malformed policy entries ending in multiple dots to match otherwise canonical targets. These are source defects; a passing suite with documented expected failures does not repair them.

The previously owned #723/#724 branch was pinned to 2026-10-07 `main`. This **separate**, current-main acceptance slice adds exactly one new test module and this new review document without changing or replacing its files, the production source owner #100, or any live executor/target-capable code.

## Implemented contract

`tests/test_scope_723_current_main_terminal_dots_20261015.py` uses actual installed `Target`, `ScopePolicy`, and `Authorization` objects from source, but all values are **fictional, in-memory fixtures**; their synthetic Authorization is not a grant or evidence of customer/operator consent.

- Six installed-source negative tests intentionally use `@expectedFailure` to keep unfixed deny conditions clearly **RED**: target-side two/three dots, policy-side two/three dots, and `localhost` two/three dots.
- Positive controls keep single-dot DNS root spelling, canonical case folding, plain `localhost`, and denied unknown hosts working.
- Independent unittest result inspection refuses masked exceptions, skipped REDs, and accidentally successful source negatives.
- Pure in-memory tests patch socket/DNS entry points to refuse target interactions and confirm no policy/fixture mutation.

## To validate

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_723_current_main_terminal_dots_20261015.py' -v
PYTHONPATH=src python -m unittest discover -s tests -v
```

Inspect raw Python 3.11 and 3.14 hosted producer/unit logs **for this exact immutable PR SHA**. Any unexpectedSuccess means the source may have changed and the REDs must be re-reviewed and converted to ordinary passing regression tests; never hide it. A permanently registered VPS runner run is a distinct unproven gate until verified on the same SHA.

## Source-owner and release conditions

Owner of `src/lightup/scope.py` (#100) must implement fail-closed parsing/configuration validation, preserve single-root-dot semantics, and convert each negative assertion to normal PASS on the installed implementation. Additional actual binding to #177 customer/operator approval, #347 grant/window/revocation before I/O, tenant, asset, capability, destination/ingress identity, independent privacy/security review, latest-main and permanent VPS proof, and explicit human release authorization are all **required separately**. Hosted test green, even if complete, confers **zero** target scope and must not trigger scan, merge, or deploy.
