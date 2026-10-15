# Current-main scope terminal-dot acceptance (#723 / #724)

**Status: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is not a production policy change, grant, authorization, scan, release approval, or merge/deployment instruction.

## Why this exists

The installed `ScopePolicy.normalize_host` and policy-side explicit-host membership use `rstrip(".")`. That strips **all** trailing DNS dots, not only a single syntactic root dot. Consequently, malformed target spelling `localhost..` inherits loopback, while an allowlisted synthetic hostname with two or three ending dots can inherit explicit-host authority. It also allows malformed policy entries ending in multiple dots to match otherwise canonical targets. These are source defects; a passing suite with documented expected failures does not repair them.

The previously owned #723/#724 branch was pinned to 2026-10-07 `main`. This **separate**, current-main acceptance slice adds exactly one new test module and this new review document without changing or replacing its files, the production source owner #100, or any live executor/target-capable code.

## Implemented contract

`tests/test_scope_723_current_main_terminal_dots_20261015.py` uses actual installed `Target`, `ScopePolicy`, and `Authorization` objects from source, but all values are **fictional, in-memory fixtures**; their synthetic Authorization is not a grant or evidence of customer/operator consent.

- Nine installed-source negative tests intentionally use `@expectedFailure` to keep unfixed deny conditions clearly **RED**: target-side two/three dots, policy-side two/three dots, and `localhost` two/three dots.
- Positive controls keep single-dot DNS root spelling, canonical case folding, plain `localhost`, and denied unknown hosts working.
- Independent unittest result inspection refuses masked exceptions, skipped REDs, and accidentally successful source negatives. A separate negative mutation test deliberately raises a synthetic TypeError to demonstrate that the integrity verifier distinguishes it from the genuine source AssertionError.
- Pure in-memory tests patch socket/DNS entry points to refuse target interactions and confirm no policy/fixture mutation.


## W2: 192-case current-main root-dot / URL regression sweep (2026-10-15)

This same self-owned suite now adds **three** independent genuine installed-source **expected-RED** cases, each materializing **64** actual decisions before asserting an unsafe allow was observed:

1. **Target boundary:** 32 trailing-dot counts (2–33) × two input forms (bare hostname and HTTPS URL with synthetic path). All malformed identities must deny; the current installed `rstrip(".")` source does not.
2. **Configuration boundary:** 32 malformed declared-host trailing-dot counts × canonical and singly rooted input host. Invalid policy entries must not authorize the valid spelling.
3. **Loopback boundary:** 32 malformed `localhost` trailing-dot counts × uppercase hostname and HTTP URL forms, with `allow_private_lab=False` and no synthetic grant. Loopback shorthand must not silently mint authority.

The source is still expected RED on every one of these three aggregation tests; green CI means the **tests correctly detected an unfixed bug**, not that 192 denial assertions passed. The isolated witness inspects the exact `AssertionError("True is not false")` rather than treating arbitrary crashes as acceptable expected-RED.

Three further green controls verify untrusted missing authorization never acts as consent, different hostname identities stay disjoint, and a deliberately injected TypeError is detected as a **wrong** RED witness (not silently accepted).

**No production-policy update or live I/O**. None of these synthetic URLs is resolved or contacted. The production source owner #100 must make these negative cases ordinary passing assertions after a separately reviewed repair. Raw Python3.11/3.14 hosted integration evidence is valid **only for the immutable HEAD tested**, not for prior commits; registered permanent VPS approval is a separate gate.

## To validate

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_723_current_main_terminal_dots_20261015.py' -v
PYTHONPATH=src python -m unittest discover -s tests -v
```

Inspect raw Python 3.11 and 3.14 hosted producer/unit logs **for this exact immutable PR SHA**. Any unexpectedSuccess means the source may have changed and the REDs must be re-reviewed and converted to ordinary passing regression tests; never hide it. A permanently registered VPS runner run is a distinct unproven gate until verified on the same SHA.

## Source-owner and release conditions

Owner of `src/lightup/scope.py` (#100) must implement fail-closed parsing/configuration validation, preserve single-root-dot semantics, and convert each negative assertion to normal PASS on the installed implementation. Additional actual binding to #177 customer/operator approval, #347 grant/window/revocation before I/O, tenant, asset, capability, destination/ingress identity, independent privacy/security review, latest-main and permanent VPS proof, and explicit human release authorization are all **required separately**. Hosted test green, even if complete, confers **zero** target scope and must not trigger scan, merge, or deploy.
