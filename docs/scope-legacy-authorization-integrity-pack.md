# Legacy Authorization integrity acceptance pack

Pinned source owner: draft PR #100 at `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`.

This composition branch collects the collision-free acceptance contracts for the
legacy public-scope `Authorization` boundary without modifying its production
source.

Included issues:

- #299: canonical non-empty owner/reference provenance;
- #300: immutable snapshot semantics for authorization asset scope;
- #301: exact timezone-aware datetime-or-None stored time boundaries;
- #302: exact trusted Authorization object boundary;
- #403: explicit evaluation-time input must be datetime-or-None and malformed
  caller clocks fail closed;
- #721: terminal DNS-root-dot canonicalization removes at most one dot, so
  malformed multi-dot host text cannot inherit canonical asset authority;
- #722: stale revocation actor/reason provenance without `revoked_at` cannot
  retain public-scope authority;
- #729: legacy owner/reference provenance must be exact built-in strings, so
  polymorphic string subclasses cannot spoof canonical-looking validation.

## Validation posture

The canonical #100 scope/activation smoke suite remains the green control. The
eight acceptance modules are expected RED until the source owner absorbs their
narrowing guards. Historical #299-#302 proof established exactly 17 expected
failures per Python interpreter; #403 adds exactly 5; #721 adds exactly 2
malformed multi-dot failures; #722 adds exactly 3 stale-revocation-provenance
failures; #729 adds exactly 2 polymorphic-provenance failures. Canonical
single-root-dot, canonical unrevoked/revoked, and canonical exact-provenance
controls remain green, for a combined expected count of 29 failures per
interpreter.

## Ownership and stop line

This branch is composition-only: tests and documentation only. It does not edit
`src/lightup/models.py`, `src/lightup/scope.py`, activation, domain,
execution policy, sessions, target workers, evidence remediation, deployment,
verdict, or attack-path code.

Do not merge this expected-RED pack ahead of PR #100. It is a source-owner
absorption/proof target, not an independent implementation.
