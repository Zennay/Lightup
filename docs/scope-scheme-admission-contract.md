# Scheme-aware scope admission — RED acceptance contract

## Finding
On current main, `ScopePolicy.normalize_host()` uses `urlparse(...).hostname` without checking the parsed URI scheme. Thus `ftp://allowed.example.test/file`, `file://allowed.example.test/etc/passwd`, and arbitrary `custom://` URLs can inherit the same host membership as an explicitly allowlisted HTTP(S) target. This conflates resource identifiers with web-target identifiers. The central admission boundary should not issue an ALLOWED decision for unsupported URI schemes.

## Desired invariant
An absolute URI with a declared scheme other than `http` or `https` must be rejected as INVALID_TARGET before host authorization. Valid HTTP(S) host membership stays unchanged. Plain hostnames and IP literals retain existing behavior. Unsupported schemes also may not inherit implicit loopback or private-lab shortcuts (`ftp://localhost`, `file://127.0.0.1`, `custom://10.1.2.3`). No DNS lookup, socket I/O or target access is needed to decide this.

## Acceptance
Run `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_scheme_admission_contract.py' -v`. On the original implementation, unsupported-scheme assertions are intentionally RED. This branch only pins the contract; it does **not** alter the current executable policy or claim the gate has been fixed. The source-owning scope PR must absorb the acceptance test and fix it before activation.

## Ownership and boundaries
Tests/docs only; do not touch `src/lightup/scope.py`, `src/lightup/models.py`, activation, execution policy, domain, target workers, deployment, or other concurrent scopes. Offline-only; no target interaction or authority widening.
