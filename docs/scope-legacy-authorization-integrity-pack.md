# Legacy Authorization integrity acceptance pack

Pinned source owner: draft PR #100 at `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`.

This successor composition branch collects the collision-free acceptance contracts
for the legacy public-scope `Authorization` boundary without modifying its
production source.

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
  polymorphic string subclasses cannot spoof canonical-looking validation;
- #730: legacy asset scope requires an exact built-in tuple of exact built-in
  strings, blocking tuple-iteration and asset-string canonicalization spoofing;
- #731: stored `valid_from` / `valid_until` must reject `datetime`
  subclasses before validity-window comparison;
- #733: an explicit `is_current(now=...)` evaluation instant must reject
  `datetime` subclasses before caller-controlled rich comparison can affect
  authorization validity.

## Validation posture

The canonical #100 scope/activation smoke suite remains the green control. The
eleven acceptance modules are expected RED until the source owner absorbs their
narrowing guards. Historical #299-#302 proof established exactly 17 expected
failures per Python interpreter; #403 adds exactly 5; #721 adds exactly 2
malformed multi-dot failures; #722 adds exactly 3 stale-revocation-provenance
failures; #729 adds exactly 2 polymorphic-provenance failures; #730 adds exactly
2 canonical asset-scope type failures; #731 adds exactly 2 stored-datetime
subclass failures; #733 adds exactly 2 explicit evaluation-datetime subclass
failures. Canonical single-root-dot, canonical unrevoked/revoked, canonical
exact provenance, ordinary foreign asset, canonical exact asset scope, canonical
stored datetimes, and canonical exact evaluation instants remain green, for a
combined expected count of **35 failures per interpreter**.

## Composition lineage

This branch starts from the latest prior successor pack at
`6aa05c90785a2412749472a23b3b389ac4545470` and adds only the already-isolated
#731 and #733 tests/docs plus this manifest update. The standalone #731/#733
branches remain untouched.

## Ownership and stop line

This branch is composition-only: tests and documentation only. It does not edit
`src/lightup/models.py`, `src/lightup/scope.py`, activation, domain,
execution policy, sessions, target workers, evidence remediation, deployment,
verdict, or attack-path code.

Do not merge this expected-RED pack ahead of PR #100. It is a source-owner
absorption/proof target, not an independent implementation.
