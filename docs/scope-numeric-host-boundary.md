# Ambiguous numeric host boundary

LightUp classifies only canonical IP literals through Python's strict `ipaddress` parser. Legacy/browser-style numeric host aliases do not inherit IP scope authority.

## Invariant

The following forms remain ordinary non-authorized host text rather than being reinterpreted as IPv4 addresses:

- shorthand IPv4 such as `127.1`;
- integer IPv4 such as `2130706433`;
- hexadecimal forms such as `0x7f000001`;
- octal-like dotted forms such as `0177.0.0.1`;
- zero-padded dotted forms such as `127.000.000.001`.

They therefore cannot inherit loopback/private classification or match an explicit IPv4 CIDR. Canonical literals such as `127.0.0.1` continue through the normal IP classification path.

## Why this is fail-closed

Some URL stacks, browsers, or legacy resolvers have historically accepted non-canonical numeric spellings. Treating those spellings as aliases inside the authorization boundary would silently enlarge an existing IP allowlist. LightUp instead requires one canonical syntactic identity and never delegates scope classification to browser/resolver interpretation.

## Regression contract

`tests/test_scope_numeric_host_boundary.py` proves these rules entirely in memory. No DNS, sockets, HTTP, target interaction, scanning, execution, remediation/retest, deployment, or attack-path mutation is involved.
