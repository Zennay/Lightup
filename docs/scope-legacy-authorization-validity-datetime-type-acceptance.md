# Legacy Authorization validity datetime exact-type acceptance

Tracking: #731  
Parent contract: #301  
Pinned source owner: draft PR #100 at `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`

## Contract

Legacy `Authorization.valid_from` and `valid_until` must be either `None` or exact built-in timezone-aware `datetime` objects.

A `datetime` subclass must not participate in the authorization-window comparison because Python reflected rich-comparison dispatch lets the subclass override how a trusted exact `now` compares against it.

#301 remains the owner for the broader timestamp-type contract. #731 adds the missing subclass comparison-spoof acceptance.

## Expected RED on the pinned source owner

PR #100 currently performs ordinary rich comparisons:

- `now < self.valid_from`;
- `now > self.valid_until`.

The adversarial datetime subclass returns `False` from both `__gt__` and `__lt__`.

Two acceptance methods are expected RED:

1. an underlying future `valid_from` bypasses the not-before check;
2. an underlying expired `valid_until` bypasses the expiry check.

Canonical exact future and expired datetimes remain denied as the green control.

## Collision boundary

Tests and documentation only. The existing #301 branch remains untouched. No edits to `src/lightup/models.py`, scope/activation/capability source, durable temporal work (#347/#470/#647), sessions, execution policy, target-capable workers, evidence-remediation, deployment, verdict or attack-path code.

PR #100 retains all production-source ownership.

## Safety

Authorization time-window narrowing only. Offline/in-memory proof; no DNS/network I/O, target interaction, scanning, exploit behavior, authority widening, remediation/retest execution, deployment, verdict creation or attack-path mutation.
