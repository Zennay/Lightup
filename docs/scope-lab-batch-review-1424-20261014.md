# W37 — Atomic offline batch review of lab IP literals (#1424)

**INCUBATE M3/M7 · PLAN/LAB ONLY.** This standalone opt-in tool never authorizes a target or active work, grants permissions, issues a scan permit, activates a runner, or deploys.

## Why
The preceding optional single-literal reviewer [#1425](https://github.com/Zennay/Lightup/pull/1425) can classify a *candidate* loopback/RFC1918/ULA IP for a human review. Reviewing a list one at a time creates the risk that an operator treats early positive entries as valid even when a later entry is out-of-scope. W37 adds an **atomic** all-or-HOLD batch check, still strictly advisory.

## Operator usage
No filesystem input or URLs; pipe a synthetic, explicitly provided JSON document (maximum **4096 bytes**) to the optional script:

```bash
printf '%s' '{"literals":["127.0.0.1","10.0.0.1","fd00::1"]}' \\
  | python scripts/review_scope_lab_batch_1424_offline.py --stdin-json
# JSON status REVIEW_ONLY / reviewed_count 3, exit 3 (not authorization)

printf '%s' '{"literals":["10.0.0.1","192.0.2.1"]}' \\
  | python scripts/review_scope_lab_batch_1424_offline.py --stdin-json
# JSON status HOLD / reviewed_count 0, exit 2 (never emits a partial success)
```

- Exactly one argument `--stdin-json`; otherwise return a fixed HOLD without reading stdin. No target literals, raw manifest, operator username, client ID, path, or exception details are printed.
- Exactly one JSON object with exactly one `literals` field; must be a list of **1–16 distinct, exact canonical built-in IP-literal strings**. Duplicate JSON keys anywhere (including nested objects), second JSON documents, nonfinite numbers, malformed UTF-8, extra fields, non-string items, empty lists, duplicate literals, and lengths outside bounds all HOLD.
- Each literal must produce `REVIEW_ONLY` from `review_lab_literal`, which accepts only IPv4 loopback/RFC1918 or IPv6 loopback/ULA. A **single** public/documentation/benchmark/reserved/malformed item causes *whole-batch HOLD* and count zero.
- Fixed, privacy-minimal JSON keys: `status`, `reviewed_count`, `authorization_verified=false`, `permit_issued=false`, `execution_enabled=false`, `merge_approved=false`, `release_approved=false`.
- Exit **2 for HOLD, 3 for REVIEW_ONLY, never 0**. The result carries no customer/grant/tenant/capability/time/revocation proof, cannot be used as a permission token and must not connect to target-active execution. A successful preview only says the strings have the right literal syntax and static lab-address class.
- No DNS/HTTP/socket, filesystem target lookups, scans, exploit activity, credentials, evidence mutation, remediation, self-hosted worker change or deployment. Input is read from stdin only under a deliberate opt-in switch and never stored.

## Safety validation
`tests/test_scope_lab_batch_1424_offline.py` includes direct atomic positives/negatives, separate hostile JSON cases, type-confusion canaries, no-I/O monkeypatches, and **real Python subprocess** CLI privacy/exit checks. Run on both Python 3.11 and 3.14 with the full unit suite and real producer integration on **the exact PR head**:

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_lab_batch_1424_offline.py' -v
```

The active source owner [PR #100](https://github.com/Zennay/Lightup/pull/100) remains responsible for fixing the **installed** scope auto-admission weakness [#1422](https://github.com/Zennay/Lightup/issues/1422). This feature deliberately cannot fix that installed production bug. Original `scope.py`, activation, execution policy, tenant CIDR workers, workflow configuration, VPS runner and deployment are not touched. Keep the new batch reviewer DRAFT/HOLD until hosted and permanent VPS evidence plus source/security review have been independently checked.
