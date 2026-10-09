# Scope authorization: UI status is not authority (offline reference)

**Status:** Reference contract only. This document and its isolated unit test do not integrate with the production scope gate or authorize any assessment.

## Boundary

A rendered status (green badge, `Approved` label, frontend `approved` boolean, link to a grant or cached dashboard response) must never create or restore authority. The test's issuer-verified decision is a *synthetic fixture*, not a real verified grant. A production dispatcher must consume a current issuer-owned authorization decision, confirm exact tenant/request/revision/capability bindings and check revocation and risk constraints at dispatch time.

## Regression examples

- Green UI with absent or revoked authorization must deny.
- A display link pointing to a different tenant cannot move authority.
- Previous revisions and other capabilities cannot inherit a green badge.
- Truthy flags, subclass envelopes and unverified issuers do not pass the reference predicate.
- Both claimed and issuer identity strings must be exact printable ASCII without surrounding whitespace, control bytes, Unicode confusables, empty values or values over 128 characters. This reference-only grammar is intentionally restrictive and must not be silently treated as the production canonicalization policy.
- Boolean revision values are rejected even though Python treats `True == 1`.
- Actual ASCII CR/LF/NUL/DEL characters (not their escaped textual spellings) must fail lexical identity checks.
- Both claimed and issuer-owned request/capability values are checked for malformed identity syntax.
- Metamorphic tests vary badge labels, approved booleans and displayed grant references while holding the trusted decision fixed; the outcome must remain unchanged.
- Presentation data is not even dereferenced by the authorization predicate; display objects may be malformed or hostile.
- Valid synthetic issuer decisions do not depend on cosmetic state.

- Hostile identity or issuer fields with custom equality/truthiness must be rejected without evaluating attacker-controlled methods.
- Revisions must be positive exact integers on both sides; strings, booleans, containers and floats are not revisions.

## Run (offline only)

```bash
python -m unittest discover -s tests -p 'test_scope_ui_status_nonauthority_reference.py' -v
```

## Integration gate

The production source owner must decide the authoritative issuer/revocation API, add a real dispatch-path regression, obtain exact-head hosted and self-hosted VPS test evidence, and review before promotion. This proposal intentionally makes no production changes and performs no network, DNS, target, scanning, capability or deployment action.
