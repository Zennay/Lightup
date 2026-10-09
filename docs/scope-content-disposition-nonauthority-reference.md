# Content-Disposition cannot authorize assessment dispatch

This is a **synthetic, offline consistency reference** for the scope-authorization review lane. It adds no production enforcement, issuer authentication, permission issuance or target execution.

## Boundary

An HTTP response's `Content-Disposition` and its `filename`, `filename*`, `name` or similar parameters are untrusted presentation metadata. These fields cannot mint, extend, revive, transfer, revoke or otherwise modify a scope authorization grant. Neither an "approved" download filename nor any transformed/decoded filename substitutes for authenticated issuer permission.

Before any future target-capable dispatch, the production scope gate must independently verify issuer provenance, current grant/revocation state, exact tenant/request/asset/capability bindings, revision and expiry, operator approval, allowed risk and target boundaries. Headers may be retained for sanitized evidence **only after** the authorization decision, never used as a trusted authorization source.

## Offline contract

`tests/test_scope_content_disposition_nonauthority_reference.py` exercises 10 pure-stdlib `unittest` cases: spoofed approval filenames, RFC 5987-style parameters, control bytes, untrusted object protocols, revoked and unverified grants, field mismatches on either side, matched-invalid fields, type-confused revisions, forged subclasses and immutable fixture envelopes.

Run:

```bash
python -m unittest discover -s tests -p 'test_scope_content_disposition_nonauthority_reference.py' -v
```

An affirmative reference result is **not real authorization**: the issuer_verified flag in the fixture is synthetic and cryptographically proves nothing. The production ToolExecutor and scope owners must review integration separately. Do not activate a live target based on these tests.

## Release proof

Keep the change draft until (1) exact-head hosted Python 3.11 and Python 3.14 regression evidence, (2) canonical permanent VPS CI on that same head, (3) production owner review, and (4) a verified no-overlap diff. Previous-head runs are not evidence for a changed commit. No DNS, sockets, scanners, credentials, grants, target interactions or deployments are required for this reference.
