# Legacy Authorization provenance exact-type acceptance

Tracking: #729  
Parent contract: #299  
Pinned source owner: draft PR #100 at `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`

## Contract

Legacy public-scope authorization provenance must be exact built-in text.

- `type(owner) is str`;
- `type(reference) is str`;
- polymorphic `str` subclasses are rejected even if they present canonical-looking text through overridden methods;
- canonical exact owner/reference strings retain existing authorized-host behavior.

This is an exact-type child of #299. #299 already owns blank, whitespace-only, and ordinary non-string provenance acceptance.

## Expected RED on the pinned source owner

PR #100 currently does not validate legacy `Authorization.owner` or `reference` before public scope is authorized.

The two polymorphic-provenance methods therefore remain allowed and are expected RED. The canonical exact-string control remains green.

The adversarial subclass intentionally stores a foreign value while returning canonical-looking text from `.strip()`. This prevents a later repair from relying only on overridable caller behavior.

## Collision boundary

Tests and documentation only. The existing #299 branch remains untouched. No edits to `src/lightup/models.py`, `src/lightup/scope.py`, activation/capability source, durable grants/sessions, execution policy, target-capable workers, evidence-remediation, deployment, verdict or attack-path code.

PR #100 retains all production-source ownership.

## Safety

Authorization provenance narrowing only. Offline/in-memory proof; no DNS/network I/O, target interaction, scanning, exploit behavior, authority widening, remediation/retest execution, deployment, verdict creation or attack-path mutation.
