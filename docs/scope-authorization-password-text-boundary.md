# Exact password text at the credential boundary

Issue: #806  
Pinned source owner: PR #670 at `68318a318d828815bc50002114f64037ed06387e`

## Required invariant

Every password that crosses the domain credential-hash boundary must be an exact
built-in `str`. String subclasses are rejected rather than normalized or trusted,
because subclasses can override behavior such as `encode()` while presenting a
different visible value.

The boundary applies consistently to:

- password verification;
- authentication;
- password replacement.

Canonical exact strings retain the existing minimum-length and scrypt behavior.

## Acceptance proof

`tests/test_scope_authorization_password_text_boundary.py` proves:

1. an exact built-in password still verifies and authenticates;
2. a same-text `str` subclass is rejected;
3. a visibly wrong subclass that overrides `encode()` cannot authenticate using
   the real password bytes, and rejection leaves login-failure/session state
   unchanged;
4. a polymorphic password update cannot replace the credential or revoke an
   existing session, and the original exact password remains valid.

The subclass cases are intentionally expected RED on the pinned PR #670 source
head because `_hash_password()` currently trusts the annotation and calls
caller-controlled string behavior.

## Ownership and runner posture

This branch is acceptance-only: one regression module plus this document and no
production-source changes. PR #670 retains `src/lightup/domain.py` ownership.
Keep branch-only while permanent LightUp self-hosted capacity is occupied; do not
create or retrigger a workflow solely to reproduce the known expected-RED state.

No DNS/network I/O, target interaction, scanning, model/tool execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation is introduced.
