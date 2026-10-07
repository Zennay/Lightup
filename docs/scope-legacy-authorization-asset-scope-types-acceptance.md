# Legacy Authorization asset-scope type acceptance

Tracking: #730  
Parent contract: #300  
Pinned source owner: draft PR #100 at `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`

## Contract

The legacy public-scope `Authorization.assets` boundary is canonical only when:

- `type(assets) is tuple`;
- every entry satisfies `type(item) is str`.

A tuple subclass must not substitute a different iterable view of authorization scope. A polymorphic string entry must not override canonicalization methods to inherit another host identity.

#300 remains the owner for mutable caller-collection snapshot isolation. #730 adds only the missing exact container/item type contract.

## Expected RED on the pinned source owner

PR #100 currently iterates `self.assets` and calls overridable string methods without first establishing exact container/item types.

Two acceptance methods are therefore expected RED:

1. tuple subclass iteration substitutes `security.example.test` despite a foreign stored payload;
2. a foreign `str` subclass returns `security.example.test` from `.strip()`.

The ordinary foreign exact-string denial and canonical exact-tuple allow controls remain green.

## Collision boundary

Tests and documentation only. The existing #300 branch remains untouched. No edits to `src/lightup/models.py`, `src/lightup/scope.py`, #719, activation/capability source, durable grants/sessions, execution policy, target-capable workers, evidence-remediation, deployment, verdict or attack-path code.

PR #100 retains all production-source ownership.

## Safety

Authorization scope narrowing/integrity only. Offline/in-memory proof; no DNS/network I/O, target interaction, scanning, exploit behavior, authority widening, remediation/retest execution, deployment, verdict creation or attack-path mutation.
