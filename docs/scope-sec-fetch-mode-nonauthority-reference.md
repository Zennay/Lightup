# Sec-Fetch-Mode is not authorization evidence

The HTTP `Sec-Fetch-Mode` fetch-metadata request header describes browser request context. Values such as `same-origin`, `navigate`, `cors`, `no-cors`, and `websocket` are **not** an issuer-signed approval, target ownership proof, tenant binding, risk acceptance or valid execution grant.

## Isolation invariant

Changing, omitting or spoofing `Sec-Fetch-Mode` cannot mint, revive, transfer, broaden, or revoke authorization. Execution must still verify issuer-controlled grant provenance, the current non-revoked state, exact tenant/request/asset/capability binding, intended mode/risk, freshness, and the current policy decision in the production gate. The header may be relevant to CSRF defenses, but is never a substitute for scope authorization.

## Offline reference and limitation

`python -m unittest discover -s tests -p 'test_scope_sec_fetch_mode_nonauthority_reference.py' -v`

Nine stdlib-only synthetic regression methods model necessary binding consistency, inactive/unverified approvals, strict revisions and booleans, malformed identities, polymorphic envelopes and hostile header objects. The positive fixture's `issuer_verified=True` flag is synthetic and **does not authenticate a real issuer**. This is not connected to the production executor; passing tests cannot establish active target permission.

## Merge gates

Maintain draft until **exact-head** Python 3.11/3.14 tests, canonical permanent VPS CI, and scope-owner integration review are proven. No production executor, scanner, target, DNS/network, grant issuance, dispatch, permission activation or deployment modifications. Real target activation stays off.
