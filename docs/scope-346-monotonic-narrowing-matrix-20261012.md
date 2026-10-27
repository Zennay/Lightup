# LightUp #346 — legacy scope-policy narrowing contract (offline, 2026-10-12)

**State: review-only / DRAFT / HOLD / NO MERGE / NO DEPLOY.** This is a **tests/docs-only** characterization of the currently shipped in-memory `ScopePolicy` decision behavior, *not* authorization to interact with any host. It does not repair installed per-I/O authorization, verify consent, issue grants, or establish production safety.

## Origin, isolation and ownership

- GitHub issue: https://github.com/Zennay/Lightup/issues/346
- Immutable starting `main`: `05b80319cd0581fed21fe9d8f565bcb0a56cd2df`
- Branch: `chatgpt/scope-346-policy-narrowing-matrix-20261012`
- Intended diff: **only this new document and** `tests/test_scope_346_monotonic_narrowing_matrix_20261012.py`.
- Original production `src/lightup/scope.py`, `src/lightup/models.py`, ToolExecutor/authorization, risk-5 lab-stepup branches, active scope-window #1128/PR #1236, public config #297/PR #1239, default web/ingress, stored grants and evidence modules are explicitly **out of scope**. They are owned by other review streams.

## Formal invariant

For canonical policies `P` and `Q`, define `Q ⪯ P` when all are true:

1. `Q.explicit_hosts ⊆ P.explicit_hosts`;
2. `Q.explicit_networks ⊆ P.explicit_networks` (set of identical canonical CIDR strings);
3. `Q.allow_private_lab` cannot be `True` unless `P.allow_private_lab` is also `True`;
4. `Q.require_authorization_for_public` cannot be `False` if `P` was `True`.

For any fixed synthetic target `T`, monotonicity requires
`Q.decide(T).allowed ⇒ P.decide(T).allowed`.
The normalized host must also be unchanged as configuration narrows. The reason may legitimately change from allow to deny, or remain an allow reason; denial reason alone is **never authority**.

The tests enumerate all **128 canonical policies** from two public hosts, two IPv4 CIDRs, one IPv6 CIDR and two boolean policy switches, and compare each ordered narrowing pair across 17 synthetic target representations. Cases include public bracketed IPv6 URLs, IPv6 link and unique-local context, IPv6 loopback, IPv4/IPv6 address allowlist withdrawal, hostname/URL normalization, unrelated public addresses and optional purely synthetic `Authorization` objects. Separate controls establish expected host/network withdrawal, public-authorization tightening, lab opt-out, loopback behavior, denial retention, deterministic re-evaluation, exact input/policy preservation, and absence of socket/DNS interaction.

## Offline reproduction

```bash
PYTHONPATH=src python -m unittest -v tests.test_scope_346_monotonic_narrowing_matrix_20261012
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src:tests python -m unittest discover -s tests/integration -v
```

The first command addresses only the narrow #346 characterization; full-suite/real-producer canaries and permanently registered VPS CI must be independently checked at **the exact committed PR HEAD**. GitHub-hosted `LightUp offline preflight` is diagnostic and is **not** substitute proof for the permanent `[self-hosted,zcloud,vps]` workflow on `vps-bb300bba`.

## Limits and release gate

These tests exercise current policy semantics, **not** trusted signer/issuer, persisted tenant binding, live revocation, permission windows, immutable allowlists, redirect authorization, DNS rebinding, per-I/O enforcement or ability to authorize actual active security tests. Even a green monotonicity matrix on this branch does **not** prove that public hosts cannot be accidentally admitted by malformed policy fields; that is independently tracked by #297/PR #1239. Python `ipaddress` and URL parsing behavior are explicitly not redefined here.

Maintain LightUp Notion **Incubate M3/M7 PLAN/LAB ONLY**. Do not merge, deploy or activate without current-main composition checks, original source owners, independent authorization/privacy review, exact-head hosted preflight and separate permanent VPS CI success, and explicit human release approval. No live client, target, scan, assessment, grant, remediation, retest or security verdict is part of this work.
