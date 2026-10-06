# Scope authorization: legacy Authorization provenance acceptance

Issue: #299

This tests/docs-only contract is stacked on exact PR #100 head
`ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`.

A legacy `Authorization` that authorizes public scope must carry canonical,
non-empty client provenance in both `owner` and `reference`. Blank,
whitespace-only, and non-string provenance may fail by rejection or explicit
validation error, but must never produce an allowed public decision.

The regression uses a canonical exact asset binding so failures cannot be
mistaken for #100's asset-scope checks. A canonical owner/reference pair is
retained as the positive control.

Expected RED on #100: the public scope gate checks revocation, time and asset
binding but does not validate `owner` or `reference`, so all six malformed
provenance cases still authorize the host.

This branch does not modify `models.py`, `scope.py`, activation, domain,
state, execution policy, webapp, or target-capable code. Source ownership
remains with #100/#105 and their stacked activation hardening.

Safety: authorization provenance narrowing only; no target interaction,
network I/O, scanning, execution, remediation/retest, deployment, verdict
creation, or attack-path mutation.
