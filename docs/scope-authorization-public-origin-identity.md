# Production public-origin runtime identity

Issue: #919

Pinned source owner: draft PR #202 exact head
`0a6eb118de5153eb72115cc871122175b8d54dfd`.

## Problem

`WebSecurity.public_origin` is retained as the caller-supplied object.
`origin()` accepts any `isinstance(value, str)`, while
`urllib.parse.urlsplit()` invokes overridable string methods including
`lstrip()`.

A stateful string subclass can therefore present the configured HTTPS origin
during construction and a different expected host during later request
validation.

## Required invariant

For any non-null production origin:

- `type(public_origin) is str`;
- canonical exact HTTPS origins retain current behavior;
- exact HTTP origins remain rejected;
- same-text and stateful/polymorphic string subclasses fail closed before
  configuration is admitted;
- request trust never depends on caller-controlled string behavior after
  construction.

## Collision boundary

This branch adds one regression module and this document only.

PR #202 retains all `src/lightup/webapp/security.py` source ownership. #918
separately covers the runtime identity of `trusted_proxy_ip`.

No web routing/session, domain/state, scope, activation, execution policy,
ToolRegistry, target-capable, evidence-remediation, deployment, verdict or
attack-path source is modified.

## Safety

Offline transport-trust narrowing only. No network listener, target
interaction, scanning, capability execution, remediation/retest execution or
deployment.
