# LightUp original authorization source composition — 20 October 2026

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This branch is a reviewable source composition, not a release, merge approval, real consent, or permit for active targets.

Exact original unmodified source-owner commits integrated as full ancestry using ordinary Git merges:

- **#1570 domain:** `ddafadd91759fecb82a8ac662d546a3be8177b51` — persisted approved-request to authorization-grant lineage and tenant/current-grant narrowing in `src/lightup/domain.py`, plus `grant_request_binding.py`.
- **#1613 web:** `ee8edb6725c34bc8258a689eb3cfc69584b9733d` — original operator/client portal boundary, cookie ingress, opaque domain errors and tenant CSV defensive presentation, including previous original #1612 source.
- **#182 strict web decisions:** `8c97eb0490bc0d5d1bfdb883c9d1434f6b21749c` — literal approval/rejection and explicit risk/days parameters; original source and existing original test files retained without modifying tests or running QA.

Original owner branch heads are unchanged. The independent integration base is original #1570 head (not `main`). No target, grant, scan, deploy, workflow edit, CI rerun, test authoring or QA execution performed. Source compilation alone is **not** acceptance.

## Actual runner dependency and blockers

GitHub repository runner #21 `vps-bb300bba-lightup` is registered but `offline`. Its original system service `actions.runner.Zennay-Lightup.vps-bb300bba-lightup.service` shows failed `oom-kill`, exited 2026-10-19 22:13 UTC, `Restart=no`. At 2026-10-20 07:24 UTC: root partition 94% full, both swapfiles consume almost 8 GiB swap, host load about 18. LightUp repo `LightUp CI` original required labels `[self-hosted,zcloud,vps]`; this runner advertises `[self-hosted,lightup,vps]` and is currently unusable even if it starts until genuine runner administration verifies/reconciles labels. The original offline preflight requires `[self-hosted,lightup,vps]`. Do not weaken CI labels, self-hosted trusted runner proof, or allow PR code to compromise shared workers.

Connected zSSH's declared `systemd_capabilities.inspect` and `.restart` are both empty; an explicit inspection request refused service access. No privileged-systemctl workaround, other-worker interruption, swaps reset, broad deletion or forced restart. **Authorized runner owner must** coordinate capacity recovery, verify GitHub-side registration and trust boundary, safely restore the real permanent LightUp runner and correct legitimate runner labels while preserving canonical workflow's required `[self-hosted,zcloud,vps]`, obtain actual paired original exact-head hosted and named-VPS CI records.

**Still mandatory before main integration:** original code owner acceptance, independent privacy/security/browser review, CI under the original approved SHA including exact named VPS, request/grant tenant provenance, proper separately authenticated current client and operator consent, revocation at action/use, explicit human GO. Historical canary/acceptance failures must not be skipped. No release, real targets, grant, or production service until then.
