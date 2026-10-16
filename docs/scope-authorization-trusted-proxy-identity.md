# Trusted proxy runtime identity

Issue: #918

Pinned source owner: draft PR #202 exact head
`0a6eb118de5153eb72115cc871122175b8d54dfd`.

## Problem

Production `WebSecurity` validates `trusted_proxy_ip` with
`ip_address(...).is_loopback`, but retains the original caller object and
later compares it directly to the socket peer:

`REMOTE_ADDR != trusted_proxy_ip`.

A string subclass can store the canonical loopback text `127.0.0.1`, pass the
configuration check, and override equality so a remote address compares equal.
That turns polymorphic configuration behavior into production proxy trust.

## Required invariant

At production WebSecurity construction:

- `trusted_proxy_ip` is an exact built-in string;
- it still parses to a loopback address;
- canonical exact IPv4/IPv6 loopback configuration remains valid;
- same-text and equality-spoofing subclasses fail closed;
- request validation never delegates trusted-peer equality to caller-defined
  string behavior.

## Collision boundary

This branch adds one regression module and this document only.

PR #202 retains `src/lightup/webapp/security.py` production ownership and its
development REMOTE_ADDR hardening. No webapp routing/session, domain/state,
scope, activation, execution policy, ToolRegistry, target-capable,
evidence-remediation, deployment, verdict or attack-path source is modified.

## Safety

Offline transport-trust narrowing only. No network listener, target
interaction, scanning, capability execution, remediation/retest execution or
deployment.
