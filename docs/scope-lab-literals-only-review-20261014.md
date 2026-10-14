# Offline lab IP literal review — #103 (independent acceptance)

**Status: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/SCANS.**

This opt-in **review helper** is a collision-free, independent companion to existing
source-owner [PR #100](https://github.com/Zennay/Lightup/pull/100) and
[issue #103](https://github.com/Zennay/Lightup/issues/103). Neither is edited.
It is deliberately not wired into `ScopePolicy`, `ActivationGate`, the web app,
the active executor, CI workflows, any worker runner, or deploy scripts.

## Why it matters

Python `ipaddress.is_private` is **not ownership evidence** or a sufficient
definition of a safe laboratory. It includes special-use IP ranges that
must not automatically count as a host in our own lab. The legacy
`ScopePolicy(allow_private_lab=True)` currently shortcuts on
`is_private or is_link_local`; #100 owns the source repair. This helper
tests a deliberately narrower address *shape* independently.

## Exact contract

- Input: one ASCII **bare IP literal** via standard input (optional final LF),
  at most 256 bytes overall, no URL, port, CIDR, brackets, zone ID,
  whitespace, userinfo or hostname. Exact built-in Python `str` only.
- `REVIEW_ONLY`: loopback `127.0.0.0/8`, `::1`; RFC1918
  `10/8`, `172.16/12`, `192.168/16`; locally assigned IPv6 ULA
  `fd00::/8`. This states only that a textual address matches the
  selected class, **not** that it belongs to a permitted test asset.
- `HOLD`: all other addresses, notably unspecified, documentation,
  multicast, link-local, benchmarking, protocol-translation
  (IPv4-mapped IPv6), reserved and globally-routable ranges.
  The unassigned `fc00::/8` half of ULA space also stays on HOLD.
- Output: fixed minimal JSON with a status, fixed reason, coarse class,
  schema version and five **always-false** authority flags. Never echoes
  the supplied address, tenant, owner, authorization reference or claim.
  HOLD exits 2; REVIEW_ONLY exits 0 **but remains entirely non-authorizing**.

## Synthetic command

```sh
printf '10.1.2.3\n' | python3 scripts/check_scope_lab_literal_offline.py
python3 -m unittest discover -s tests -p 'test_scope_lab_literal_offline.py' -v
```

No DNS, network, target probing, file writes, artifact signing, external model,
permission issuance, real target activation, human consent verification, or
filesystem inspection takes place. Exit status 0 does **not** enable any scan.

## Required source-owner handoff

Before any actual source integration, #100 and independent security reviewers
must decide lab ownership/allowlist mapping, authorization lineage, operation
window, IPv6 temporary/privacy addresses, interfaces, rebinding, requested
capability, tenant separation, revocation and exact asset binding. Merely
matching RFC1918/ULA/loopback never supplies any of these. Exact latest
HEAD hosted Python3.11/3.14 and *permanent registered VPS* evidence plus
human release approval remain separate mandatory gates. This draft must not
merge or deploy on the strength of passing synthetic tests.
