# IP literals stay on the explicit-network path

LightUp keeps hostname policy and IP-network policy as separate authorization kinds.

## Invariant

A canonical public IP literal is classified as an IP before explicit-host matching. Therefore:

- adding `8.8.8.8` to `explicit_hosts` does not authorize the IP;
- turning off the public-authorization requirement does not make an IP literal fall through to host matching;
- an exact `8.8.8.8/32` entry in `explicit_networks` uses the explicit-network path and still requires current authorization;
- loopback literals remain classified as loopback before either public allowlist path.

## Why this matters

Allowing an IP literal to fall through to hostname policy would create two different authorization mechanisms for the same asset kind and could bypass network-specific review or normalization. Public IP scope should therefore remain explicit CIDR/network policy, even for a single /32 address.

## Regression contract

`tests/test_scope_ip_policy_path.py` proves these rules entirely in memory. It performs no DNS resolution, sockets, HTTP, target interaction, scanning, execution, remediation/retest, deployment, or attack-path mutation.
