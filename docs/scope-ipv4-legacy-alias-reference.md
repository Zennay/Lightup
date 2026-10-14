# IPv4 legacy numeric aliases — offline reference

Status: proposed reference contract ONLY; not an authorization gate.

Legacy parsers can accept integer, hexadecimal, octal-like, abbreviated, or zero-padded representations of an IPv4 address. Authorization admission and dispatch using different parsers can disagree about host identity.

For a field explicitly typed as an IPv4 host literal, the proposed reference permits only exactly four ASCII decimal octets (0..255), with no leading zeroes except the single zero. Canonical round-trip must match exactly. Deny legacy aliases, Unicode lookalikes, whitespace, URI schemes, ports, CIDR suffixes, wrong types and oversized values. URI, CIDR and host parsing must have distinct typed entry points, not permissive string normalization.

A positive parse result conveys IDENTITY ONLY and grants no authority. Production owner PR #107 must enforce one identity across admission, live scope revalidation, resolver and dispatch; retain tenant, owner consent, revocation, risk and operator activation gates. No real-target activation is implied.

Run offline: python -m unittest discover -s tests -p test_scope_ipv4_legacy_alias_reference.py -v

This two-file package changes no production code. No network, DNS, scanning, grants, target interaction or active capability execution. No hosted/VPS proof is claimed. Owner review and exact-head CI plus permanent VPS evidence are required for integration.
